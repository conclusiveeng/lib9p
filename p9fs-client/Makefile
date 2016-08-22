# $FreeBSD$

#.PATH=	${.CURDIR}/../../fs/p9fs

KMOD=	p9fs

SRCS+=	p9fs_client_proto.c
SRCS+=	p9fs_subr.c
SRCS+=	p9fs_vfsops.c
SRCS+=	p9fs_vnops.c
SRCS+=	vnode_if.h

LDFLAGS=-L..
LDADD=	../lib9p.a

.include <bsd.kmod.mk>
