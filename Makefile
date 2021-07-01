CC=gcc
CFLAGS= -g -Wall
LDFLAGS = -lpthread

all: proxy

proxy: proxy.c
	$(CC) $(CFLAGS) -o proxy proxy.c $(LDFLAGS)

clean:
	rm proxy

