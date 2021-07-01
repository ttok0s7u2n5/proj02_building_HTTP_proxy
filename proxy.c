/*
* 2021 Spring EE323 Computer Network
* Project #2 Building an HTTP Proxy
* Author: Heewon Yang
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAXLINE 65535
#define MINLINE 4
#define MAXBUF 5000
#define BACKLOG 10

#define RIO_BUFSIZE 8192
typedef struct {
    int rio_fd;                /* Descriptor for this internal buf */
    int rio_cnt;               /* Unread bytes in internal buf */
    char *rio_bufptr;          /* Next unread byte in internal buf */
    char rio_buf[RIO_BUFSIZE]; /* Internal buffer */
} rio_t;

static const char *user_agent_hdr = "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.3) Gecko/20120305 Firefox/10.0.3\r\n";
static const char *conn_hdr = "Connection: close\r\n";
static const char *prox_hdr = "Proxy-Connection: close\r\n";
static const char *connection_key = "Connection";
static const char *user_agent_key= "User-Agent";
static const char *proxy_connection_key = "Proxy-Connection";
static const char *defaultport = "80";
static const char *warning = "warning.or.kr";
static const char host_key[] = "Host";
static const char blacklistDir[] = "./blacklist.txt";
static const char badRequest[] = "HTTP/1.0 400 Bad Request\r\n";
static const char serviceUnavailable[] = "HTTP/1.0 503 Service Unavailable\r\n";

/* Retrieved my code "proxy.c" from github
 * "https://github.com/ttok0s7u2n5/CS230_LAB7/blob/main/proxy.c"
 * I did similar project in CS230 system programming class in last semester
 */
int parse_url(char *url, char *host, char *port, char *path) {
    char *curr = url;
    if (strncmp(url, "http://", 7) != 0) {
        return -1;
    }
    curr += 7;
    char *copy = host;
    strncpy(port, "80\0", 3);
    strncpy(path, "/\0", 2);

    while (*curr != '\0') {
        if (*curr == '/') {
            *copy = '\0';
            copy = path;
        }
        else if (*curr == ":") {
            curr++;
            *copy = '\0';
            copy = port;
        }
        *copy = *curr;
        curr++;
        copy++;
    }
    *copy = '\0';
    return 0;
}

int open_host_port(char *host, char *port) {
    int sockfd, rc;
    struct addrinfo hints, *listp, *p;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    hints.ai_flags |= AI_ADDRCONFIG;
    if ((rc = getaddrinfo(host, port, &hints, &listp)) != 0) {
        fprintf(stderr, "getaddrinfo failed (%s:%s): %s\n", host, port, gai_strerror(rc));
        return -2;
    }
    for (p = listp; p; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
            continue; // fail
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) != -1)
            break; // success
        if (close(sockfd) < 0) { // try again
            fprintf(stderr, "open_host_port: close failed: %s\n", strerror(errno));
            return -1;
        }
    }
    freeaddrinfo(listp);
    if (!p) { return -1; }
    else { return sockfd; }
}

/*
* Adapted Robust I/O functions
* from Computer Systems: A Programmer's Perspective (3rd ed) on chapter 10
* "http://csapp.cs.cmu.edu/3e/ics3/code/src/csapp.c"
*/
/* Robustly read maximum n bytes */
static ssize_t rio_read(rio_t *rp, char *usrbuf, size_t n)
{
    int cnt;
    while (rp->rio_cnt <= 0) {
    rp->rio_cnt = read(rp->rio_fd, rp->rio_buf,
               sizeof(rp->rio_buf));
    if (rp->rio_cnt < 0) {
        if (errno != EINTR)
        return -1;
    }
    else if (rp->rio_cnt == 0)
        return 0;
    else
        rp->rio_bufptr = rp->rio_buf; // reset pt
    }
    cnt = n;
    if (rp->rio_cnt < n)
    cnt = rp->rio_cnt;
    memcpy(usrbuf, rp->rio_bufptr, cnt);
    rp->rio_bufptr += cnt;
    rp->rio_cnt -= cnt;
    return cnt;
}

/* Robustly initialize */
void rio_readinitb(rio_t *rp, int fd)
{
    rp->rio_fd = fd;
    rp->rio_cnt = 0;
    rp->rio_bufptr = rp->rio_buf;
}

/* Robustly read a line with maxlen bytes limit */
ssize_t rio_readlineb(rio_t *rp, void *usrbuf, size_t maxlen)
{
    int n, rc;
    char c, *bufp = usrbuf;

    for (n = 1; n < maxlen; n++) {
        if ((rc = rio_read(rp, &c, 1)) == 1) {
        *bufp++ = c;
            if (c == '\n') {
                n++;
             break;
            }
        }
        else if (rc == 0) {
            if (n == 1) { return 0; }
            else { break; }
        }
        else { return -1; }
    }
    *bufp = 0;
    return n-1;
}

/* Robustly read maximum n bytes */
int read_packet(int sockfd, unsigned char *buf, size_t n)
{
    if (n == 0) { return n; }

    size_t nleft = n;
    size_t nread;
    size_t totalread = 0;

    while (nleft > 0) {
        if ((nread = (size_t) read(sockfd, buf + totalread, nleft)) < 0) {
            if (errno == EINTR) { /* interrupted by sig handler return */
                    nread = 0;        /* and call read() again */
            }
            else {
                return -1;        /* errno set by read() */
            }
        }
        else if (nread == 0) {
            break;                /* EOF */
        }
        nleft -= nread;
        totalread += nread;
    }
    return totalread;
}

/* Robustly write maximum n bytes */
int write_packet(int sockfd, unsigned char *buf, size_t n)
{
    if (n == 0) { return n;}

    size_t nleft = n;
    size_t nwritten;
    size_t totalwrote = 0;

    while (nleft > 0) {
            if ((nwritten = (size_t) write(sockfd, buf + totalwrote, nleft)) <= 0) {
                    if (errno == EINTR) { /* interrupted by sig handler return */
                        nwritten = 0;     /* and call write() again */
                    }
                    else {
                        return -1;        /* errno set by write() */
                    }
            }
            nleft -= nwritten;
            totalwrote += nwritten;
        }
        return totalwrote;
}

/* Adapted the code to handle SIGCHLD from "https://stackoverflow.com/questions/7171722/how-can-i-handle-sigchld" */
/* Handler for SIGCHLD that calls waitpid for reap all the zombie processes */
static void sigchld_handler(int sig)
{
    pid_t pid;
    int status;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {}
}
/* Register the SIGCHLD handler */
static void register_handler(void)
{
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, 0) == -1) {
        perror(0);
        exit(1);
    }
}

void doit(int connfd)
{
    int servfd, warnfd; // server file descriptor & warning.or.kr file descriptor
    int black = 0;
    char ebuf[MAXBUF];
    char buf[MAXBUF], host[MAXBUF], path[MAXBUF], port[MAXBUF];
    char line[MAXBUF], sbuf[MAXBUF];
    char *rbuf;
    rio_t rio, srio;
    
    rio_readinitb(&rio, connfd);
    rio_readlineb(&rio, buf, MAXLINE);
    
    char method[MAXBUF], version[MAXBUF], url[MAXBUF];
    char request_hdr[MAXBUF], host_hdr[MAXBUF], other_hdr[MAXBUF], hhost[MAXBUF];
    
    sscanf(buf, "%s %s %s", method, url, version);
    printf("method: '%s', url: '%s' , version: '%s'\n", method, url, version);

    if (strcmp(method, "GET") != 0) { // if method is not GET, 400 Bad Request
        printf("We only use GET method\n");
        sprintf(ebuf, "%s", badRequest);
        write_packet(connfd, ebuf, strlen(ebuf));
        return;
    }
    if (strncmp(url, "http://", 7) != 0) { // if host is invalid, 503 Service Unavailable
        printf("URL should start with http:// \n");
        sprintf(ebuf, "%s", serviceUnavailable);
        write_packet(connfd, ebuf, strlen(ebuf));
        return;
    }
    if (strcmp(version, "HTTP/1.0") != 0) { // if the version is not HTTP/1.0, 400 Bad Request
        printf("Please use HTTP/1.0 \n");
        sprintf(ebuf, "%s", badRequest);
        write_packet(connfd, ebuf, strlen(ebuf));
        return;
    }
    parse_url(url, host, port, path);
    //printf("host: '%s', port: '%s', path: '%s'\n", host, port, path);
    
    sprintf(request_hdr, "GET %s HTTP/1.0\r\n", path);
    
    memset(buf, 0, MAXBUF);
    while (rio_readlineb(&rio, buf, MAXLINE) > 0) {
        if (!strcmp(buf, "\r\n")) {
            break;
        }
        if (!strncasecmp(buf, host_key, strlen(host_key))) {
            strcpy(host_hdr, buf);
            continue;
        }
        if (!(strncasecmp(buf,connection_key,strlen(connection_key))
                || strncasecmp(buf,proxy_connection_key,strlen(proxy_connection_key))
                || strncasecmp(buf,user_agent_key,strlen(user_agent_key)))) {
            strcat(other_hdr, buf);
        }
    }
    if (strlen(host_hdr) == 0) { // if there's no host header, 400 Bad Request
        printf("We must need a host header\n");
        sprintf(ebuf, "%s", badRequest);
        write_packet(connfd, ebuf, strlen(ebuf));
        return;
    }
    else {
        sscanf(host_hdr, "Host: %s", hhost);
        printf("host_hdr: %s\n", host_hdr);
        if (strcmp(host, hhost)) { // if two hosts are different, 400 Bad Request
            printf("Host is different\n");
            sprintf(ebuf, "%s", badRequest);
            write_packet(connfd, ebuf, strlen(ebuf));
            exit(1);
        }
    }

    //printf("Parsing Success\n");
    sprintf(sbuf, "%s%s%s%s%s%s\r\n",
            request_hdr,
            host_hdr,
            conn_hdr,
            prox_hdr,
            user_agent_hdr,
            other_hdr);
    
    if (!isatty(STDIN_FILENO)) {
        //printf("STDIN exists\n");
        if (fread(line, 1, MAXBUF, stdin) <= 0) { // EOF
            fprintf(stderr, "EOF\n");
            exit(1);
        }
        if (strstr(line, host) != NULL) {
                black = 1;
        }
        else { black = 0; }
    }
    
    if (black == 1) { // if the host is in blacklist.txt
        printf("Host exists in blacklist\n");
        printf("Connecting to waring.or.kr...\n");
        warnfd = open_host_port(warning, defaultport);
        if (warnfd < 0) {
            printf("Connection to warning.or.kr failed\n");
            return;
        }
        
        rio_readinitb(&srio, warnfd);
        
        printf("Sending request to warning.or.kr...\n");
        write_packet(warnfd, sbuf, strlen(sbuf));
        
        size_t n;
        printf("Receiving response from warning.or.kr and sending it to client...\n");
        while ((n = rio_readlineb(&srio, buf, MAXLINE)) != 0) {
            write_packet(connfd, buf, n);
        }
        
        printf("Closing connection to warning.or.kr...\n");
        close(warnfd);
        exit(0);
    }
    
    printf("Connecting to server %s...\n", host);
    servfd = open_host_port(host, port);
    if (servfd < 0) {
        printf("Connection to server %s failed\n", host);
        return;
    }
    
    rio_readinitb(&srio, servfd);
    
    //printf("Sending request to server %s...\n", host);
    write_packet(servfd, sbuf, strlen(sbuf));
    
    size_t n;
    //printf("Receiving response from server %s and sending it to client...\n", host);
    while ((n = rio_readlineb(&srio, buf, MAXLINE)) != 0) {
        write_packet(connfd, buf, n);
    }
    
    //printf("Closing connection to server %s...\n", host);
    close(servfd);
}

void *proxy_thread(void *vargp)
{
    int connfd = (int) vargp;
    doit(connfd);
    //printf("Closing connection to client...\n");
    if (close(connfd) < 0) {
        fprintf(stderr,"close error\n");
        exit(1);
    }
}

int main(int argc, char **argv)
{
    int sockfd, connfd; // listen on sockfd, new connection on connfd
    struct sockaddr_in sa;
    struct sockaddr_in ca;
    socklen_t sin_size;
    int port_no;
    char p[MAXBUF];

    register_handler();
    signal(SIGPIPE, SIG_IGN);
    
    if (argc != 2) {
        fprintf(stderr, "usage :%s <port> \n", argv[0]);
        exit(1);
    }
    else {
        strncpy(p, argv[1], strlen(argv[1]));
        port_no = atoi(p);
    }
    
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port_no);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sin_size = sizeof(ca);
    
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) { // proxy fd
        fprintf(stderr, "Socket creation error\n");
        return -1;
    }
    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    if (bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "Bind error\n");
        return -1;
    }
    
    if (listen(sockfd, BACKLOG) < 0) {
        fprintf(stderr, "Listen error\n");
        return -1;
    }
    
    while (1) {
        
        if ((connfd = accept(sockfd, (struct sockaddr *)&ca, &sin_size)) < 0) {
            fprintf(stderr, "Accept error\n");
            return -1;
        }
        fprintf(stderr, "Connecting to client ... \n");

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        pthread_t thread;
        pthread_create(&thread, &attr, proxy_thread, (void *)connfd);
    }
    close(sockfd);
    return 0;
}

