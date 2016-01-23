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
#include <sys/queue.h>
#include "lib9p.h"

int
l9p_server_init(struct l9p_server **serverp, struct l9p_backend *backend)
{
    struct l9p_server *server;

    server = malloc(sizeof(*server));
    server->ls_backend = backend;
    LIST_INIT(&server->ls_conns);

    *serverp = server;
    return (0);
}

int
l9p_connection_init(struct l9p_server *server, struct l9p_connection **conn)
{
    struct l9p_connection *newconn;

    newconn = malloc(sizeof(*newconn));
    LIST_INSERT_HEAD(&server->ls_conns, newconn, lc_link);
    *conn = newconn;

    return (0);
}

void
l9p_connection_free(struct l9p_connection *conn)
{

}

void
l9p_connection_on_send_request(struct l9p_connection *conn,
    void (*cb)(void *, size_t, void *), void *softc)
{

    conn->lc_send_request = cb;
    conn->lc_send_request_aux = softc;
}

void
l9p_connection_recv(struct l9p_connection *conn, void *buf, size_t len)
{
    struct l9p_message msg;
    struct l9p_request *req;

    req = malloc(sizeof(struct l9p_request));
    req->lr_conn = conn;
    msg.lm_buffer = buf;
    msg.lm_pos = buf;
    msg.lm_end = buf + len;
    msg.lm_mode = L9P_UNPACK;

    if (l9p_pufcall(&msg, &req->lr_req) != 0) {

    }

    l9p_dispatch_request(req);
}

void
l9p_connection_close(struct l9p_connection *conn)
{

}

struct l9p_openfile *
l9p_connection_find_fid(struct l9p_connection *conn, uint32_t fid)
{
    struct l9p_openfile *i;

    LIST_FOREACH(i, &conn->lc_files, lo_link) {
        if (i->lo_fid == fid)
            return (i);
    }

    return (NULL);
}

struct l9p_request *
l9p_connection_find_tag(struct l9p_connection *conn, uint32_t tag)
{
    struct l9p_request *i;

    LIST_FOREACH(i, &conn->lc_requests, lr_link) {
        if (i->lr_tag == tag)
            return (i);
    }

    return (NULL);
}
