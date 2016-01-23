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

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/event.h>
#include <netdb.h>
#include "../lib9p.h"
#include "../log.h"
#include "socket.h" 

struct l9p_socket_softc
{
	struct l9p_connection *ls_conn;
	struct sockaddr ls_sockaddr;
	socklen_t ls_socklen;
	pthread_t ls_thread;
	int ls_fd;
};

static int l9p_socket_readmsg(struct l9p_socket_softc *, void **, size_t *);
static void l9p_socket_sendmsg(void *, size_t, void *);
static void *l9p_socket_thread(void *);
static int xread(int, void *, size_t);
static int xwrite(int, void *, size_t);

int
l9p_start_server(struct l9p_server *server, const char *host, const char *port)
{
	struct addrinfo *res, *res0, hints;
	struct kevent kev[2];
	struct kevent event[2];
	int err, kq, i, val, evs, nsockets = 0;
	int sockets[2];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	err = getaddrinfo(host, port, &hints, &res0);

	if (err)
		return (-1);

	for (res = res0; res; res = res->ai_next) {
		int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

		val = 1;
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

		if (s < 0)
			continue;
		
		if (bind(s, res->ai_addr, res->ai_addrlen) < 0) {
			close(s);
			continue;
		}

		sockets[nsockets] = s;
		EV_SET(&kev[nsockets++], s, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
		listen(s, 10);
	}

	kq = kqueue();
	kevent(kq, kev, nsockets, NULL, 0, NULL);

	for (;;) {
		evs = kevent(kq, NULL, 0, event, nsockets, NULL);
		if (evs < 0) {

		}

		for (i = 0; i < evs; i++) {
			struct sockaddr client_addr;
			socklen_t client_addr_len;
			int news = accept(event[i].ident, &client_addr,
			    &client_addr_len);

			if (news < 0) {
				l9p_logf(L9P_WARNING, "accept(): %s", strerror(errno));
				continue;
			}

			l9p_socket_accept(server, news, &client_addr,
			    client_addr_len);
		}
	}

}

void
l9p_socket_accept(struct l9p_server *server, int conn_fd,
    struct sockaddr *client_addr, socklen_t client_addr_len)
{
	struct l9p_socket_softc *sc;
	struct l9p_connection *conn;
	char host[NI_MAXHOST + 1];
	char serv[NI_MAXSERV + 1];
	int err;

	err = getnameinfo(client_addr, client_addr_len, host, NI_MAXHOST, serv,
	    NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);

	if (err != 0) {
		l9p_logf(L9P_WARNING, "cannot look up client name: %s",
		    gai_strerror(err));
	} else
		l9p_logf(L9P_INFO, "new connection from %s:%s", host, serv);

	if (l9p_connection_init(server, &conn) != 0) {
		l9p_logf(L9P_ERROR, "cannot create new connection");
	}

	sc = malloc(sizeof(sc));
	sc->ls_conn = conn;
	sc->ls_fd = conn_fd;

	l9p_connection_on_send_request(conn, l9p_socket_sendmsg, sc);
	pthread_create(&sc->ls_thread, NULL, l9p_socket_thread, sc);
}

static void *
l9p_socket_thread(void *arg)
{	
	struct l9p_socket_softc *sc = (struct l9p_socket_softc *)arg;
	void *buf;
	size_t length;

	for (;;) {
		if (l9p_socket_readmsg(sc, &buf, &length) != 0)
			break;

		l9p_connection_recv(sc->ls_conn, buf, length);
	}

	l9p_logf(L9P_INFO, "connection closed");
	return (NULL);
}

static int
l9p_socket_readmsg(struct l9p_socket_softc *sc, void **buf, size_t *size)
{
	uint32_t msize;
	void *buffer;
	int fd = sc->ls_fd;

	if (xread(fd, &msize, sizeof(uint32_t)) != sizeof(uint32_t)) {
		l9p_logf(L9P_ERROR, "short read: %s", strerror(errno));
		return (-1);
	}

	msize -= sizeof(msize);
	buffer = malloc(msize);

	if (xread(fd, buffer, msize) != msize) {
		l9p_logf(L9P_ERROR, "short read: %s", strerror(errno));
		return (-1);
	}

	*size = msize;
	*buf = buffer;
	l9p_logf(L9P_INFO, "%p: read complete message, buf=%p size=%d", sc->ls_conn, buffer, msize);

	return (0);
}

static void
l9p_socket_sendmsg(void *buf, size_t len, void *arg)
{
	struct l9p_socket_softc *sc = (struct l9p_socket_softc *)arg;
	uint32_t msize = (uint32_t)len + sizeof(uint32_t);

	l9p_logf(L9P_DEBUG, "%p: sending reply, buf=%p, size=%d", arg, buf, len);

	if (xwrite(sc->ls_fd, &msize, sizeof(uint32_t)) != sizeof(uint32_t)) {
		l9p_logf(L9P_ERROR, "short write: %s", strerror(errno));
		return;
	}

	if (xwrite(sc->ls_fd, buf, len) != len) {
		l9p_logf(L9P_ERROR, "short write: %s", strerror(errno));
		return;
	}
}

static int
xread(int fd, void *buf, size_t count)
{
	size_t done = 0;
	int ret;

	while (done < count) {
		ret = read(fd, buf + done, count - done);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			return (-1);
		}

		if (ret == 0)
			return (done);

		done += ret;
	}

	return (done);
}

static int
xwrite(int fd, void *buf, size_t count)
{
	size_t done = 0;
	int ret;

	while (done < count) {
		ret = write(fd, buf + done, count - done);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			return (-1);
		}

		if (ret == 0)
			return (done);

		done += ret;
	}

	return (done);	
}
