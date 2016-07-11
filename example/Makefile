PROGS=	server client
server_SRCS=	server.c
client_SRCS=	client.c
MAN=

CFLAGS=	-pthread -g -O0

LDFLAGS=-L.. -static
LDADD=	-l9p -lsbuf

.include <bsd.progs.mk>
