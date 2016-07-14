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

static uint16_t
default_get_tag(struct l9p_client_connection *conn)
{
	uint16_t current = (uint16_t)(conn->tags);

	current++;
	conn->tags = (void*)current;
	return current;
}

static void
default_release_tag(struct l9p_client_connection *conn, uint16_t tag)
{
	uint16_t current = (uint16_t)(conn->tags);

	// This would be bad if we had a tag leak
	if (tag == current) {
		current--;
		conn->tags = (void*)current;
	}
}

static uint32_t
default_get_fid(struct l9p_client_connection *conn)
{
	uint32_t current = (uint32_t)(conn->fids);

	current++;
	conn->fids = (void*)current;
	return current;
}

static void
default_release_fid(struct l9p_client_connection *conn, uint32_t fid)
{
	uint32_t current = (uint32_t)(conn->fids);

	// This would be bad if we had a tag leak
	if (fid == current) {
		current--;
		conn->fids = (void*)current;
	}
}

static int
socket_send(struct l9p_client_rpc *msg)
{
	struct l9p_client_connection *conn = msg->conn;
	struct socket_connection *ctx = conn->context;
	struct l9p_message *request = &msg->message_data;
	ssize_t nwritten;
	size_t indx;
	size_t total = 0;

	for (indx = 0; indx < request->lm_niov; indx++) {
		size_t offset = 0;
		struct iovec *cur = &request->lm_iov[indx];

		while (offset < cur->iov_len) {
			nwritten = write(ctx->s, ((uint8_t*)cur->iov_base) + offset, cur->iov_len - offset);
			if (nwritten == -1) {
				return (errno);
			}
			offset += (size_t)nwritten;
		}
		total += offset;
	}
	return 0;
}

static int
socket_recv(struct l9p_client_rpc *msg)
{
	struct l9p_client_connection *conn = msg->conn;
	struct socket_connection *ctx = conn->context;
	struct l9p_message *request = &msg->response_data;
	uint32_t msg_size;
	uint8_t *msg_buffer;
	ssize_t nread;

	bzero(request, sizeof(*request));
	request->lm_mode = L9P_UNPACK;

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
	request->lm_iov[0].iov_base = msg_buffer;
	request->lm_iov[0].iov_len = msg_size;
	request->lm_niov = 1;
	return (0);
}

static int
get_socket(char *host, char *port)
{
	struct addrinfo *ai, *res, hints = { .ai_family = PF_UNSPEC, .ai_socktype = SOCK_STREAM, };
	int retval = -1;
	int error;

	if ((error = getaddrinfo(host, port, &hints, &ai)) != 0) {
		warnx("Could not resolve %s:%s: %s", host, port, gai_strerror(error));
		return (-1);
	}

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
	conn->get_tag = default_get_tag;
	conn->release_tag = default_release_tag;
	conn->get_fid = default_get_fid;
	conn->release_fid = default_release_fid;

	conn->fids = (void*)0;
	conn->tags = (void*)0;

	ctx->s = get_socket(host, port);
	if (ctx->s == -1)
		return -1;
	return 0;

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
		struct l9p_client_rpc rpc = {.conn = &conn };
		uint16_t tag;
		char *version = "9P2000.u"; // or 9P2000.u
		struct sbuf *sb = sbuf_new_auto();

		rv = p9_msg(&conn, &rpc.message, L9P_TVERSION, &tag, 1024 * 1024, version);
		if (rv) {
			errc(1, rv, "Could not create p9 message");
		}

		rv = p9_send_and_reply(&rpc);
		// Don't need to l9p_freefcall(&fcall) because nothing was allocated during it.

		if (rv) {
			errc(1, rv, "tversion");
		}

		l9p_describe_fcall(&rpc.response, conn.lc_version, sb);
		printf("%s\n", sbuf_data(sb));
		sbuf_clear(sb);

		conn.lc_max_io_size = rpc.response.version.msize;
		conn.lc_version = L9P_VERSION(rpc.response.version.version);
		if (strcmp(version, rpc.response.version.version) != 0) {
			errx(1, "Incompatible P9 versions");
		}
		l9p_freefcall(&rpc.response);

		conn.root_fid = conn.get_fid(&conn);

		rv = p9_msg(&conn, &rpc.message, L9P_TATTACH, &tag, conn.root_fid, NOFID, "sef", "", (uint32_t)geteuid());
		if (rv) {
			errc(1, rv, "Could not create p9 attach message");
		}

		rv = p9_send_and_reply(&rpc);

		if (rv) {
			errc(1, rv, "tattach");
		}
		l9p_describe_fcall(&rpc.response, conn.lc_version, sb);
		puts(sbuf_data(sb));
		sbuf_clear(sb);

		l9p_freefcall(&rpc.response);

		rv = p9_msg(&conn, &rpc.message, L9P_TSTAT, &tag, conn.root_fid);
		if (rv) {
			errc(1, rv, "Could not pack p9 tstat message");
		}
		rv = p9_send_and_reply(&rpc);
		if (rv) {
			errc(1, rv, "tstat of root fid");
		}

		l9p_describe_fcall(&rpc.response, conn.lc_version, sb);
		puts(sbuf_data(sb));
		sbuf_clear(sb);

		l9p_freefcall(&rpc.response);

		{
			uint32_t root_read = conn.get_fid(&conn);
			// Let's try to open up the root directory for reading
			rv = p9_msg(&conn, &rpc.message, L9P_TWALK, &tag, conn.root_fid, root_read, NULL);
			if (rv == 0)
				rv = p9_send_and_reply(&rpc);
			if (rv == 0) {
				l9p_describe_fcall(&rpc.response, conn.lc_version, sb);
				puts(sbuf_data(sb));
				sbuf_clear(sb);
				l9p_freefcall(&rpc.response);
				rv = p9_msg(&conn, &rpc.message, L9P_TOPEN, &tag, root_read, L9P_OREAD);
			}
			if (rv == 0) {
				rv = p9_send_and_reply(&rpc);
			}
			if (rv == 0) {
				l9p_describe_fcall(&rpc.response, conn.lc_version, sb);
				puts(sbuf_data(sb));
				sbuf_clear(sb);
				l9p_freefcall(&rpc.message);
				l9p_freefcall(&rpc.response);
				rv = p9_msg(&conn, &rpc.message, L9P_TREAD, &tag, root_read, (uint64_t)0, 1024);
			}
			if (rv == 0) {
				rv = p9_send_and_reply(&rpc);
				if (rv == 0) {
					struct l9p_stat s9buf;
					ssize_t x;

					l9p_describe_fcall(&rpc.response, conn.lc_version, sb);
					puts(sbuf_data(sb));
					sbuf_clear(sb);
					
					while ((x = l9p_pustat(&rpc.response_data, &s9buf, conn.lc_version)) > 0) {
						printf("\tDirectory entry %s\n", s9buf.name);
						l9p_freestat(&s9buf);
					}
				}
				l9p_freefcall(&rpc.response);
			}
			rv = p9_msg(&conn, &rpc.message, L9P_TCLUNK, &tag, root_read);
			rv = p9_send_and_reply(&rpc);
			conn.release_fid(&conn, root_read);
		}

		uint32_t new_fid = conn.get_fid(&conn);

#define TESTFILE "testfile"

		rv = p9_msg(&conn, &rpc.message, L9P_TWALK, &tag, conn.root_fid, new_fid, TESTFILE, NULL);
		if (rv) {
			errc(1, rv, "Could not create twalk message");
		}
		rv = p9_send_and_reply(&rpc);
		l9p_freefcall(&rpc.message);

		if (rv) {
			errc(1, rv, "twalk %s", TESTFILE);
		}
		l9p_describe_fcall(&rpc.response, conn.lc_version, sb);
		puts(sbuf_data(sb));
		sbuf_clear(sb);

		l9p_freefcall(&rpc.response);

		rv = p9_msg(&conn, &rpc.message, L9P_TOPEN, &tag, new_fid, L9P_OREAD);
		if (rv) {
			errc(1, rv, "Could not create p9 topen message");
		}
		rv = p9_send_and_reply(&rpc);
		l9p_freefcall(&rpc.message);
		if (rv) {
			errc(1, rv, "topen");
		}

		l9p_describe_fcall(&rpc.response, conn.lc_version, sb);
		puts(sbuf_data(sb));
		sbuf_clear(sb);

		l9p_freefcall(&rpc.response);
		conn.release_fid(&conn, new_fid);
		sbuf_delete(sb);
	}
	close(remote);

	
	return 0;
}
