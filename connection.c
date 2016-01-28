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
#include <string.h>
#include <errno.h>
#include <sys/queue.h>
#include "lib9p.h"
#include "log.h"

int
l9p_server_init(struct l9p_server **serverp, struct l9p_backend *backend)
{
    struct l9p_server *server;

    server = calloc(1, sizeof(*server));
    server->ls_max_version = L9P_2000;
    server->ls_backend = backend;
    LIST_INIT(&server->ls_conns);

    *serverp = server;
    return (0);
}

int
l9p_connection_init(struct l9p_server *server, struct l9p_connection **conn)
{
    struct l9p_connection *newconn;

    newconn = calloc(1, sizeof(*newconn));
    newconn->lc_server = server;
    newconn->lc_msize = L9P_DEFAULT_MSIZE;
    LIST_INIT(&newconn->lc_requests);
    LIST_INIT(&newconn->lc_files);
    LIST_INSERT_HEAD(&server->ls_conns, newconn, lc_link);
    *conn = newconn;

    return (0);
}

void
l9p_connection_free(struct l9p_connection *conn)
{

    LIST_REMOVE(conn, lc_link);
    free(conn);
}

void
l9p_connection_on_send_response(struct l9p_connection *conn,
    l9p_send_response_t cb, void *aux)
{

    conn->lc_send_response = cb;
    conn->lc_send_response_aux = aux;
}

void
l9p_connection_on_get_response_buffer(struct l9p_connection *conn,
    l9p_get_response_buffer_t cb, void *aux)
{

    conn->lc_get_response_buffer = cb;
    conn->lc_get_response_buffer_aux = aux;
}

void
l9p_connection_recv(struct l9p_connection *conn, const struct iovec *iov,
    const size_t niov, void *aux)
{
    struct l9p_request *req;

    req = calloc(1, sizeof(struct l9p_request));
    req->lr_aux = aux;
    req->lr_conn = conn;
    LIST_INSERT_HEAD(&conn->lc_requests, req, lr_link);

    req->lr_req_msg.lm_mode = L9P_UNPACK;
    req->lr_req_msg.lm_niov = niov;
    memcpy(req->lr_req_msg.lm_iov, iov, sizeof(struct iovec) * niov);
    
    req->lr_resp_msg.lm_mode = L9P_PACK;

    if (l9p_pufcall(&req->lr_req_msg, &req->lr_req, conn->lc_version) != 0) {
        L9P_LOG(L9P_WARNING, "cannot unpack received message");
        return;
    }

    if (conn->lc_get_response_buffer(req, req->lr_resp_msg.lm_iov,
        &req->lr_resp_msg.lm_niov, conn->lc_get_response_buffer_aux) != 0) {
        L9P_LOG(L9P_WARNING, "cannot obtain buffers for response");
        return;
    }

    l9p_dispatch_request(req);
}

void
l9p_connection_close(struct l9p_connection *conn)
{

}

struct l9p_openfile *
l9p_connection_alloc_fid(struct l9p_connection *conn, uint32_t fid)
{
    struct l9p_openfile *file;

    if (l9p_connection_find_fid(conn, fid) != NULL) {
        errno = EEXIST;
        return (NULL);
    }

    file = calloc(1, sizeof(struct l9p_openfile));
    file->lo_fid = fid;
    file->lo_conn = conn;
    LIST_INSERT_HEAD(&conn->lc_files, file, lo_link);

    return (file);
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

void
l9p_connection_remove_fid(struct l9p_connection *conn, struct l9p_openfile *fid)
{

    LIST_REMOVE(fid, lo_link);
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
