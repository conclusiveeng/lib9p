/*-
 * Copyright (c) 2015 Will Andrews.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS        
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED   
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR       
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS        
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR           
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF             
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS         
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN          
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)          
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE       
 * POSSIBILITY OF SUCH DAMAGE.                                                      
 */

/*
 * Plan9 filesystem (9P2000.u) subroutines.  This file is intended primarily
 * for Plan9-specific details.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/types.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <netinet/in.h>
#include <sys/limits.h>
#include <sys/vnode.h>

#include "p9fs_proto.h"
#include "p9fs_subr.h"
#include "../lib9p.h"
#include "../client.h"

static MALLOC_DEFINE(M_P9REQ, "p9fsreq", "Request structures for p9fs");
static MALLOC_DEFINE(M_P9FS, "p9fs", "P9FS client data");

/* borrowed from ctl_ha.c; there has to be a better way */

static u_int
sbavail(struct sockbuf *sb)
{
	return (sb->sb_cc);
}

/*
 * mp is the Plan9 payload on input; on output it is the response payload.
 */
int
p9fs_msg_send(struct l9p_client_rpc *msg)
{
	int error, flags;
	struct uio uio;
	struct mbuf *control = NULL;
	struct thread *td = curthread;
	struct p9fs_session *p9s = msg->client_context;
	struct l9p_client_connection *conn = &p9s->connection;
	struct l9p_socket_context *socket_ctx = conn->context;
	uint16_t tag;
	
	tag = msg->tag;
	
	uio.uio_iov = msg->message_data.lm_iov;
	uio.uio_iovcnt = msg->message_data.lm_niov;
	uio.uio_offset = 0;
	uio.uio_resid = msg->message_data.lm_size;
	uio.uio_rw = UIO_WRITE;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_td = td;
	
	mtx_lock(&p9s->p9s_lock);
	if (p9s->p9s_state >= P9S_CLOSING) {
		mtx_unlock(&p9s->p9s_lock);
		return (ECONNABORTED);
	}
	p9s->p9s_threads++;
	mtx_unlock(&p9s->p9s_lock);

	flags = 0;
	error = sosend(socket_ctx->p9s_sock, &socket_ctx->p9s_sockaddr, &uio, NULL, control,
		       flags, td);
	printf("%s(%d):  error = %d\n", __FUNCTION__, __LINE__, error);
	if (error == EMSGSIZE) {
		SOCKBUF_LOCK(&socket_ctx->p9s_sock->so_snd);
		sbwait(&socket_ctx->p9s_sock->so_snd);
		SOCKBUF_UNLOCK(&socket_ctx->p9s_sock->so_snd);
	}

	mtx_lock(&p9s->p9s_lock);

	printf("%s(%d):  error = %d\n", __FUNCTION__, __LINE__, error);
	/* Ensure any response is disposed of in case of a local error. */

	p9s->p9s_threads--;
	wakeup(p9s);
	mtx_unlock(&p9s->p9s_lock);

	return (error);
}

/*
 * I have no idea how this is supposed to work.
 * What we need to do is first get four bytes from
 * the connection, to indicate the message size; then
 * we need to allocate enough space for the message, get
 * that many bytes, and put it in the allocated memory.
 *
 * XXX
 * So this is completely wrong.
 * Forget the sleep/wakeup on req; to do that, it needs
 * to be refactored significantly.  This function needs to
 * simply use soreceive(), and if it doesn't match the tag,
 * then we're out of luck and drop it.  The send function
 * above needs to lose the sleep as well.
 */
int
p9fs_msg_recv(struct l9p_client_rpc *msg)
{
	struct p9fs_session *p9s = msg->client_context;
	struct l9p_client_connection *conn = &p9s->connection;
	struct l9p_socket_context *socket_ctx = conn->context;
	struct p9fs_recv *p9r = &p9s->p9s_recv;
	struct uio uio = { 0 };
	int error = 0, rcvflag;
	struct sockaddr **psa = NULL;
	uint32_t record_length = 0;
	struct iovec reclen_iovec = { .iov_len = sizeof(record_length), .iov_base = &record_length };
	uint8_t *data_buffer = NULL;

	p9r->p9r_soupcalls++;
again:
	/* Is the socket still waiting for a new record's size? */
	if (p9r->p9r_resid == 0) {
		if (sbavail(&socket_ctx->p9s_sock->so_rcv) < sizeof (p9r->p9r_resid)
		 || (socket_ctx->p9s_sock->so_rcv.sb_state & SBS_CANTRCVMORE) != 0
		 || socket_ctx->p9s_sock->so_error != 0)
			goto out;

		uio.uio_resid = sizeof (p9r->p9r_resid);
		uio.uio_iov = &reclen_iovec;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_rw = UIO_READ;
	} else {
		uio.uio_resid = p9r->p9r_resid;
		
	}

	/* Drop the sockbuf lock and do the soreceive call. */
	SOCKBUF_UNLOCK(&socket_ctx->p9s_sock->so_rcv);
	rcvflag = MSG_DONTWAIT | MSG_SOCALLBCK;
	error = soreceive(socket_ctx->p9s_sock, psa, &uio, NULL, NULL, &rcvflag);
	SOCKBUF_LOCK(&socket_ctx->p9s_sock->so_rcv);

	/* Process errors from soreceive(). */
	if (error == EWOULDBLOCK)
		goto out;
	if (error != 0) {
		mtx_lock(&p9s->p9s_lock);
		p9r->p9r_error = error;
		mtx_unlock(&p9s->p9s_lock);
		goto out;
	}

	if (p9r->p9r_resid == 0) {
		/* Copy in the size, subtract itself, and reclaim the mbuf. */
		p9r->p9r_resid = record_length - sizeof(record_length);
		data_buffer = l9p_calloc(1, record_length);
		if (data_buffer == NULL) {
			error = ENOMEM;
			goto out;
		}
		bcopy(&record_length, data_buffer, sizeof(record_length));
		msg->response_data.lm_iov[0].iov_base = data_buffer;
		msg->response_data.lm_iov[0].iov_len = record_length;
		uio.uio_iov = msg->response_data.lm_iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = sizeof(record_length);
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_rw = UIO_READ;
		uio.uio_resid = record_length - sizeof(record_length);
		p9r->p9r_resid = p9r->p9r_size - sizeof (p9r->p9r_size);
		/* Record size is known now; retrieve the rest. */
		goto again;
	}

	/* If we have a complete record, match it to a request via tag. */
	p9r->p9r_resid = uio.uio_resid;
	if (p9r->p9r_resid == 0) {
		uint16_t tag;

		// Should deal with byte order!
		bcopy(data_buffer + offsetof(struct l9p_hdr, tag),
		      &tag, sizeof(tag));

		if (tag != msg->tag) {
			l9p_free(data_buffer);
			error = EIO;
			p9r->p9r_msg = NULL;
		}
	}

out:
	p9r->p9r_soupcalls--;
	return (error);
}

void
p9fs_init_session(struct p9fs_session *p9s)
{
	mtx_init(&p9s->p9s_lock, "p9s->p9s_lock", NULL, MTX_DEF);
	TAILQ_INIT(&p9s->p9s_recv.p9r_reqs);
	(void) strlcpy(p9s->p9s_uname, "root", sizeof ("root"));
	p9s->p9s_uid = 0;
	p9s->p9s_afid = NOFID;
	/*
	 * XXX Although there can be more FIDs, the unit accounting subroutines
	 *     flatten these values to int arguments rather than u_int.
	 *     This will limit the number of outstanding vnodes for a p9fs
	 *     mount to 64k.
	 */
	p9s->connection.fids = new_unrhdr(1, INT_MAX - 1, &p9s->p9s_lock);
	p9s->connection.tags = new_unrhdr(1, UINT16_MAX - 1, &p9s->p9s_lock);
	// Need to set this up properly
	// I need to properly refactor the client stuff here
	//p9s->p9s_socktype = SOCK_STREAM;
	//p9s->p9s_proto = IPPROTO_TCP;
}

void
p9fs_close_session(struct p9fs_session *p9s)
{
	struct l9p_client_connection *conn = &p9s->connection;
	struct l9p_socket_context *socket_ctx = conn->context;
	
	mtx_lock(&p9s->p9s_lock);
	if (socket_ctx->p9s_sock != NULL) {
		struct p9fs_recv *p9r = &p9s->p9s_recv;
		struct sockbuf *rcv = &socket_ctx->p9s_sock->so_rcv;

		p9s->p9s_state = P9S_CLOSING;
		mtx_unlock(&p9s->p9s_lock);

		SOCKBUF_LOCK(rcv);
		soupcall_clear(socket_ctx->p9s_sock, SO_RCV);
		while (p9r->p9r_soupcalls > 0)
			(void) msleep(&p9r->p9r_soupcalls, SOCKBUF_MTX(rcv),
			    0, "p9rcvup", 0);
		SOCKBUF_UNLOCK(rcv);
		(void) soclose(socket_ctx->p9s_sock);

		/*
		 * XXX Can there really be any such threads?  If vflush()
		 *     has completed, there shouldn't be.  See if we can
		 *     remove this and related code later.
		 */
		mtx_lock(&p9s->p9s_lock);
		while (p9s->p9s_threads > 0)
			msleep(p9s, &p9s->p9s_lock, 0, "p9sclose", 0);
		p9s->p9s_state = P9S_CLOSED;
	}
	mtx_unlock(&p9s->p9s_lock);

	/* Would like to explicitly clunk ROOTFID here, but soupcall gone. */
	delete_unrhdr(conn->fids);
	delete_unrhdr(conn->tags);
}

/* FID & tag management.  Makes use of subr_unit, since it's the best fit. */
uint32_t
p9fs_getfid(struct l9p_client_connection *conn)
{
	return (alloc_unr(conn->fids));
}
void
p9fs_relfid(struct l9p_client_connection *conn, uint32_t fid)
{
	free_unr(conn->fids, fid);
}
uint16_t
p9fs_gettag(struct l9p_client_connection *conn)
{
	return (alloc_unr(conn->tags));
}
void
p9fs_reltag(struct l9p_client_connection *conn, uint16_t tag)
{
	free_unr(conn->tags, tag);
}

void *
l9p_malloc(size_t sz)
{
	return malloc(sz, M_P9FS, M_WAITOK | M_ZERO);
}
void *
l9p_calloc(size_t n, size_t sz)
{
	return malloc(n * sz, M_P9FS, M_WAITOK | M_ZERO);
}
void
l9p_free(void *ptr)
{
	free(ptr, M_P9FS);
}
