PROGS=	server client
server_SRCS=	server.c
client_SRCS=	client.c
MAN=

CFLAGS=	-pthread -g -O0

LDFLAGS=-L.. 
LDADD=	../lib9p.a -lsbuf

.include <bsd.progs.mk>
