LIB=		9p
SHLIB_MAJOR=	1
SRCS=		lib9p.c connection.c request.c log.c transport/socket.c backend/fs.c
INCS=		lib9p.h fcall.h log.h backend/fs.h
CFLAGS=		-g -O0

.include <bsd.lib.mk>
