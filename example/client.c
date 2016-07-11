/*
 * Copyright 2016 Jakub Klama <jceel@FreeBSD.org>
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <netdb.h>

#ifdef __APPLE__
# include "../apple_endian.h"
#else
# include <sys/endian.h>
#endif

#include "../lib9p.h"
#include "../lib9p_impl.h"
#include "../client.h"

struct socket_connection {
	int s;
};

static int
socket_send(struct l9p_client_connection *conn, struct iovec *iov)
{
	struct socket_connection *ctx = conn->context;
	ssize_t nwritten;

	// Should wrap some of this up in macros or functions
	nwritten = write(ctx->s, iov->iov_base, iov->iov_len);
	if (nwritten == -1)
		return (errno);
	if ((size_t)nwritten != iov->iov_len)
		abort();	// for now
	return 0;
}

static int
socket_recv(struct l9p_client_connection *conn, uint16_t tag, union l9p_fcall **response)
{
	uint32_t msg_size;
	uint8_t *msg_buffer;
	ssize_t nread;
	int error;
	struct socket_connection *ctx = conn->context;
	union l9p_fcall *tfcp;
	struct iovec iovc;

	tfcp = l9p_calloc(1, sizeof(*tfcp));
	if (tfcp == NULL)
		return (ENOMEM);

	nread = read(ctx->s, &msg_size, sizeof(msg_size));
	if (nread == -1) {
		warn("Could not read message size");
		return (errno);
	}
	if ((size_t)nread != sizeof(msg_size)) {
		warnx("Expected to read %zu, only read %zd", sizeof(msg_size), nread);
		return (ERANGE);
	}
	msg_buffer = l9p_calloc(1, le32toh(msg_size));
	if (msg_buffer == NULL) {
		return (ENOMEM);
	}
	bcopy(&msg_size, msg_buffer, sizeof(msg_size));
	msg_size = le32toh(msg_size);
	nread = read(ctx->s, msg_buffer + sizeof(msg_size), msg_size - sizeof(msg_size));
	if (nread != (msg_size - sizeof(msg_size))) {
		if (nread == -1)
			return (errno);
		warnx("Expected to read %zu, only read %zd", msg_size - sizeof(msg_size), nread);
		l9p_free(msg_buffer);
		return (EINVAL);
	}
	iovc.iov_base = msg_buffer;
	iovc.iov_len = msg_size;
	error = client_unpack_message(conn, &iovc, tfcp);

	l9p_free(msg_buffer);
	*response = tfcp;
	if (tag != NOTAG)
		release_tag(conn, (*response)->hdr.tag);
	if (error == 0) {
		if ((*response)->hdr.tag != tag) {
			warnx("Tag is out of sync, dropping buffer (%#x vs %#x)", (*response)->hdr.tag, tag);
//			l9p_free(*response);
//			return (EINVAL);
		}
	}
	return (error);
}
static int
get_socket(char *host, char *port)
{
	struct addrinfo *ai, *res, hints = { .ai_family = PF_UNSPEC, .ai_socktype = SOCK_STREAM, };
	int retval = -1;

	if (getaddrinfo(host, port, &hints, &ai) == -1)
		return (-1);

	for (res = ai; res; res = res->ai_next) {
		int val = 1;
		int s = socket(res->ai_family,
			       res->ai_socktype,
			       res->ai_protocol);

		if (s == -1) {
			continue;
		}
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

		if (connect(s, res->ai_addr, res->ai_addrlen) == -1) {
			close(s);
			continue;
		}
		retval = s;
		break;
	}
	return (retval);
}

static int
socket_connection_init(struct l9p_client_connection *conn, char *host, char *port)
{
	struct socket_connection *ctx = l9p_calloc(1, sizeof(*ctx));

	if (ctx == NULL)
		return (ENOMEM);

	bzero(conn, sizeof(*conn));
	conn->context = ctx;
	conn->lc_max_io_size = 1024 * 1024;	// temporary, will be overwritten by server
	conn->lc_version = L9P_2000;
	conn->send_msg = socket_send;
	conn->recv_msg = socket_recv;
	conn->fids = (void*)0;
	conn->tags = (void*)0;

	ctx->s = get_socket(host, port);
	return 1;

}

static void __attribute__((noreturn))
usage(const char *progname)
{
	errx(1, "Usage: %s [-p port] [hostname]", progname);
}

static enum l9p_version
L9P_VERSION(char *version) {

	if (strcmp(version, "9P2000") == 0)
		return (L9P_2000);
	else if (strcmp(version, "9P2000.u") == 0)
		return (L9P_2000U);
	else if (strcmp(version, "9P2000.L") == 0)
		return (L9P_2000L);
	else
		return (L9P_INVALID_VERSION);
}

int
talk(struct l9p_client_connection *conn, union l9p_fcall *transmit, union l9p_fcall **response)
{
	struct iovec iovc = { 0, 0 };
	struct sbuf *sb = sbuf_new_auto();
	int error = 0;
	uint16_t tag = transmit->hdr.tag;

	error = client_pack_message(conn, &iovc, transmit);
	if (error)
		goto done;

	error = conn->send_msg(conn, &iovc);
	if (error)
		goto done;
	
	error = conn->recv_msg(conn, tag, response);
	release_tag(conn, tag);
	if (error)
		goto done;

	if ((*response)->hdr.type == L9P_RERROR)
		error = (int)(*response)->error.errnum;

done:
	if (iovc.iov_base)
		l9p_free(iovc.iov_base);
	sbuf_delete(sb);
	return (error);
}

int
main(int ac, char *av[])
{
	struct l9p_client_connection conn;
	char *host = "localhost";
	char *port = "564";
	int c;
	char *progname = av[0];
	int remote = -1;

	while ((c = getopt(ac, av, "p:")) != -1) {
		switch (c) {
		case 'p':	port = strdup(optarg); break;
		default:	usage(av[0]); break;
		}
	}
	ac -= optind;
	av += optind;

	if (ac > 1)
		usage(progname);
	if (ac == 1)
		host = strdup(av[0]);

	printf("Host %s, port %s\n", host, port);

	if (socket_connection_init(&conn, host, port) == -1) {
		err(1, "Could not connect to %s:%s", host, port);
	} else {
		int rv;
		union l9p_fcall *fcp, fcall;
		uint16_t tag;
		char *version = "9P2000.u"; // or 9P2000.u
		struct iovec iovc;
		struct sbuf *sb = sbuf_new_auto();

		rv = p9_msg(&conn, &fcall, L9P_TVERSION, &tag, 1024 * 1024, version);
		if (rv) {
			errc(1, rv, "Could not create p9 message");
		}
		rv = client_pack_message(&conn, &iovc, &fcall);
		if (rv) {
			errc(1, rv, "Could not pack p9 message");
		}
		rv = conn.send_msg(&conn, &iovc);
		l9p_free(iovc.iov_base);
		if (rv) {
			errc(1, rv,"Could not write p9 version message");
		}
		rv = conn.recv_msg(&conn, tag, &fcp);
		if (rv) {
			errc(1, rv, "Could not read p9 version response");
		}
		if (fcp->hdr.type == L9P_RERROR) {
			errc(1, (int)fcp->error.errnum, "Got error resposne from server");
		}
		if (fcp->hdr.type != L9P_RVERSION) {
			errx(1, "Got an invalid response to version message, type %d", fcp->hdr.type);
		}
		printf("Response max size = %u, version = %s\n",
		       fcp->version.msize, fcp->version.version);
		conn.lc_max_io_size = fcp->version.msize;
		conn.lc_version = L9P_VERSION(fcp->version.version);
		if (strcmp(version, fcp->version.version) != 0) {
			errx(1, "Incompatible P9 versions");
		}
		l9p_freefcall(fcp);
		l9p_free(fcp);

		conn.root_fid = get_fid(&conn);
#if 0
		rv = p9_msg(&conn, &fcall, L9P_TATTACH, &tag, conn.root_fid, NOFID, "sef", "", (uint32_t)geteuid());
		if (rv) {
			errc(1, rv, "Could not create p9 attach message");
		}
		rv = client_pack_message(&conn, &iovc, &fcall);
#else
		rv = packed_p9_msg(&conn, &iovc, L9P_TATTACH, &tag, conn.root_fid, NOFID, "sef", "", (uint32_t)geteuid());
#endif
		if (rv) {
			errc(1, rv, "Could not pack p9 attach message");
		}
		rv = conn.send_msg(&conn, &iovc);
		l9p_free(iovc.iov_base);
		if (rv) {
			errc(1, rv, "Could not send attach message");
		}
		rv = conn.recv_msg(&conn, tag, &fcp);
		if (rv != 0) {
			errc(1, rv, "Could not receive rattach message");
		}
		l9p_freefcall(fcp);
		l9p_free(fcp);

		rv = packed_p9_msg(&conn, &iovc, L9P_TSTAT, &tag, conn.root_fid);
		if (rv) {
			errc(1, rv, "Could not pack p9 tstat message");
		}
		rv = conn.send_msg(&conn, &iovc);
		l9p_free(iovc.iov_base);
		if (rv) {
			errc(1, rv, "Could not send tstat message");
		}

		rv = conn.recv_msg(&conn, tag,  &fcp);
		if (rv) {
			errc(1, rv, "Could not recieve rstat message");
		}
		l9p_describe_fcall(fcp, conn.lc_version, sb);
		puts(sbuf_data(sb));
		sbuf_clear(sb);

		l9p_freefcall(fcp);
		l9p_free(fcp);

		uint32_t new_fid = get_fid(&conn);

#define TESTFILE "testfile"

		rv = p9_msg(&conn, &fcall, L9P_TWALK, &tag, conn.root_fid, new_fid, TESTFILE, NULL);
		if (rv) {
			errc(1, rv, "Could not create twalk message");
		}
		rv = talk(&conn, &fcall, &fcp);
		l9p_freefcall(&fcall);

		if (rv) {
			errc(1, rv, "twalk %s", TESTFILE);
		}
		l9p_describe_fcall(fcp, conn.lc_version, sb);
		puts(sbuf_data(sb));
		sbuf_clear(sb);

		l9p_freefcall(fcp);
		l9p_free(fcp);
#if 1
		rv = p9_msg(&conn, &fcall, L9P_TOPEN, &tag, new_fid, L9P_OREAD);
		if (rv) {
			errc(1, rv, "Could not create p9 topen message");
		}
		rv = talk(&conn, &fcall, &fcp);
		l9p_freefcall(&fcall);
		if (rv) {
			errc(1, rv, "topen");
		}
#else
		rv = packed_p9_msg(&conn, &iovc, L9P_TOPEN, &tag, new_fid, L9P_OREAD);
		if (rv) {
			errc(1, rv, "Could not pack p9 topen message");
		}
		rv = conn.send_msg(&conn, &iovc);
		l9p_free(iovc.iov_base);
		if (rv) {
			errc(1, rv, "Could not send topen message");
		}
		
		rv = conn.recv_msg(&conn, tag, &fcp);
		if (rv) {
			errc(1, rv, "Could not receive ropen message");
		}
#endif
		l9p_describe_fcall(fcp, conn.lc_version, sb);
		puts(sbuf_data(sb));
		sbuf_clear(sb);

		l9p_freefcall(fcp);
		l9p_free(fcp);
		release_fid(&conn, new_fid);
		sbuf_delete(sb);

	}
	
	close(remote);

	
	return 0;
}
