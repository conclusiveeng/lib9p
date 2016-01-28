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
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/sbuf.h>
#include "lib9p.h"
#include "fcall.h"
#include "log.h"

#define N(x)    (sizeof(x) / sizeof(x[0]))

static void l9p_dispatch_tversion(struct l9p_request *req);
static void l9p_dispatch_tattach(struct l9p_request *req);
static void l9p_dispatch_tclunk(struct l9p_request *req);
static void l9p_dispatch_tflush(struct l9p_request *req);
static void l9p_dispatch_tcreate(struct l9p_request *req);
static void l9p_dispatch_topen(struct l9p_request *req);
static void l9p_dispatch_tread(struct l9p_request *req);
static void l9p_dispatch_tremove(struct l9p_request *req);
static void l9p_dispatch_tstat(struct l9p_request *req);
static void l9p_dispatch_twalk(struct l9p_request *req);
static void l9p_dispatch_twrite(struct l9p_request *req);
static void l9p_dispatch_twstat(struct l9p_request *req);

static const struct
{
    enum l9p_ftype type;
    void (*handler)(struct l9p_request *);
} l9p_handlers[] = {
    {L9P_TVERSION, l9p_dispatch_tversion},
    {L9P_TATTACH, l9p_dispatch_tattach},
    {L9P_TCLUNK, l9p_dispatch_tclunk},
    {L9P_TFLUSH, l9p_dispatch_tflush},
    {L9P_TCREATE, l9p_dispatch_tcreate},
    {L9P_TOPEN, l9p_dispatch_topen},
    {L9P_TREAD, l9p_dispatch_tread},
    {L9P_TWRITE, l9p_dispatch_twrite},
    {L9P_TREMOVE, l9p_dispatch_tremove},
    {L9P_TSTAT, l9p_dispatch_tstat},
    {L9P_TWALK, l9p_dispatch_twalk},
    {L9P_TWSTAT, l9p_dispatch_twstat}
};

static const char *l9p_versions[] = {
    "9P2000",
    "9P2000.u",
    "9P2000.L"
};

void
l9p_dispatch_request(struct l9p_request *req)
{
    struct l9p_connection *conn = req->lr_conn;
    struct sbuf *sb = sbuf_new_auto();
    int i;

    l9p_describe_fcall(&req->lr_req, L9P_2000, sb);
    sbuf_done(sb);

    L9P_LOG(L9P_DEBUG, "%s", sbuf_data(sb));
    sbuf_delete(sb);

    req->lr_tag = req->lr_req.hdr.tag;

    for (i = 0; i < N(l9p_handlers); i++) {
        if (req->lr_req.hdr.type == l9p_handlers[i].type) {
            l9p_handlers[i].handler(req);
            return;
        }
    }

    L9P_LOG(L9P_WARNING, "unknown request of type %d", req->lr_req.hdr.type);
    l9p_respond(req, L9P_ENOFUNC);
}

void
l9p_respond(struct l9p_request *req, int errnum)
{
    struct l9p_connection *conn = req->lr_conn;
    struct sbuf *sb = sbuf_new_auto();
    size_t iosize;

    switch (req->lr_req.hdr.type) {
    case L9P_TCLUNK:
        l9p_connection_remove_fid(conn, req->lr_fid);
        break;
    }

    req->lr_resp.hdr.tag = req->lr_req.hdr.tag;

    if (errnum == 0)
        req->lr_resp.hdr.type = req->lr_req.hdr.type + 1;
    else {
        req->lr_resp.hdr.type = L9P_RERROR;
        req->lr_resp.error.ename = strerror(errnum);
	req->lr_resp.error.errnum = errnum;
    }

    l9p_describe_fcall(&req->lr_resp, L9P_2000, sb);
    sbuf_done(sb);

    L9P_LOG(L9P_DEBUG, "%s", sbuf_data(sb));
    sbuf_delete(sb);    

    if (l9p_pufcall(&req->lr_resp_msg, &req->lr_resp, conn->lc_version) != 0) {
        L9P_LOG(L9P_ERROR, "cannot pack response");
        goto out;
    }

    iosize = req->lr_resp_msg.lm_size;

    /* Include I/O size in calculation for Rread response */
    if (req->lr_resp.hdr.type == L9P_RREAD)
        iosize += req->lr_resp.io.count;

    conn->lc_send_response(req, req->lr_resp_msg.lm_iov,
        req->lr_resp_msg.lm_niov, iosize, conn->lc_send_response_aux);

out:
    LIST_REMOVE(req, lr_link);
    free(req);
}

int
l9p_pack_stat(struct l9p_request *req, struct l9p_stat *st)
{
    struct l9p_connection *conn = req->lr_conn;
    struct l9p_message *msg = &req->lr_readdir_msg;
    uint16_t size = l9p_sizeof_stat(st, conn->lc_version);

    if (msg->lm_size == 0) {
        /* Initialize message */
        msg->lm_mode = L9P_PACK;
        msg->lm_niov = req->lr_data_niov;
        memcpy(msg->lm_iov, req->lr_data_iov, sizeof(struct iovec) * req->lr_data_niov);
    }

    if (l9p_pustat(msg, st, conn->lc_version) < 0)
        return (-1);

    req->lr_resp.io.count += size;
    return (0);
}

static void
l9p_dispatch_tversion(struct l9p_request *req)
{
    struct l9p_connection *conn = req->lr_conn;
    enum l9p_version remote_version = L9P_INVALID_VERSION;
    int i;

    for (i = 0; i < N(l9p_versions); i++) {
        if (strcmp(req->lr_req.version.version, l9p_versions[i]) == 0) {
            remote_version = (enum l9p_version)i;
            break;
        }
    }

    if (remote_version == L9P_INVALID_VERSION) {
        L9P_LOG(L9P_ERROR, "unsupported remote version: %s",
            req->lr_req.version.version);
        l9p_respond(req, L9P_ENOFUNC);
        return;
    }

    L9P_LOG(L9P_INFO, "remote version: %s", l9p_versions[remote_version]);
    L9P_LOG(L9P_INFO, "local version: %s",
        l9p_versions[conn->lc_server->ls_max_version]);

    conn->lc_version = MIN(remote_version, conn->lc_server->ls_max_version);
    conn->lc_msize = MIN(req->lr_req.version.msize, conn->lc_msize);
    conn->lc_max_io_size = conn->lc_msize - 24;
    req->lr_resp.version.version = strdup(l9p_versions[conn->lc_version]);
    req->lr_resp.version.msize = conn->lc_msize;
    l9p_respond(req, NULL);
}

static void
l9p_dispatch_tattach(struct l9p_request *req)
{
    struct l9p_connection *conn = req->lr_conn;

    req->lr_fid = l9p_connection_alloc_fid(conn, req->lr_req.hdr.fid);
    conn->lc_server->ls_backend->attach(conn->lc_server->ls_backend->softc, req);
}

static void
l9p_dispatch_tclunk(struct l9p_request *req)
{
    struct l9p_connection *conn = req->lr_conn;

    req->lr_fid = l9p_connection_find_fid(conn, req->lr_req.hdr.fid);
    if (!req->lr_fid) {
        l9p_respond(req, L9P_ENOFID);
        return;
    }

    conn->lc_server->ls_backend->clunk(conn->lc_server->ls_backend->softc, req);
}

static void
l9p_dispatch_tflush(struct l9p_request *req)
{
    struct l9p_connection *conn = req->lr_conn;

    if (!conn->lc_server->ls_backend->flush) {
        l9p_respond(req, L9P_ENOFUNC);
        return;
    }

    conn->lc_server->ls_backend->flush(conn->lc_server->ls_backend->softc, req);
}

static void
l9p_dispatch_tcreate(struct l9p_request *req)
{
    struct l9p_connection *conn = req->lr_conn;
    struct l9p_openfile *fid;

    if (l9p_connection_find_fid(conn, req->lr_req.tcreate.hdr.fid) != NULL) {
        l9p_respond(req, L9P_ENOFID);
        return;
    }

    req->lr_fid = l9p_connection_alloc_fid(conn, req->lr_req.tattach.afid);
    conn->lc_server->ls_backend->create(conn->lc_server->ls_backend->softc, req);
}

static void
l9p_dispatch_topen(struct l9p_request *req)
{
    struct l9p_connection *conn = req->lr_conn;
    struct l9p_openfile *fid;

    req->lr_fid = l9p_connection_find_fid(conn, req->lr_req.topen.hdr.fid);
    if (!req->lr_fid) {
        l9p_respond(req, L9P_ENOFID);
        return;
    }

    if (!conn->lc_server->ls_backend->open) {
        l9p_respond(req, L9P_ENOFUNC);
        return;
    }

    conn->lc_server->ls_backend->open(conn->lc_server->ls_backend->softc, req);
}

static void
l9p_dispatch_tread(struct l9p_request *req)
{
    struct l9p_connection *conn = req->lr_conn;
    struct l9p_openfile *fid;

    req->lr_fid = l9p_connection_find_fid(conn, req->lr_req.hdr.fid);
    if (!req->lr_fid) {
        l9p_respond(req, L9P_ENOFID);
        return;
    }

    l9p_seek_iov(req->lr_resp_msg.lm_iov, req->lr_resp_msg.lm_niov,
        req->lr_data_iov, &req->lr_data_niov, 11);

    conn->lc_server->ls_backend->read(conn->lc_server->ls_backend->softc, req);
}

static void
l9p_dispatch_tremove(struct l9p_request *req)
{

}

static void
l9p_dispatch_tstat(struct l9p_request *req)
{
    struct l9p_connection *conn = req->lr_conn;
    struct l9p_openfile *fid;

    req->lr_fid = l9p_connection_find_fid(conn, req->lr_req.twalk.hdr.fid);
    if (!req->lr_fid) {
        l9p_respond(req, L9P_ENOFID);
        return;
    }

    if (!conn->lc_server->ls_backend->stat) {
        l9p_respond(req, L9P_ENOFUNC);
        return;
    }

    conn->lc_server->ls_backend->stat(conn->lc_server->ls_backend->softc, req);
}

static void
l9p_dispatch_twalk(struct l9p_request *req)
{
    struct l9p_connection *conn = req->lr_conn;
    struct l9p_openfile *fid;

    req->lr_fid = l9p_connection_find_fid(conn, req->lr_req.twalk.hdr.fid);
    if (!req->lr_fid) {
        l9p_respond(req, L9P_ENOFID);
        return;
    }

    if (req->lr_req.twalk.hdr.fid != req->lr_req.twalk.newfid) {
        req->lr_newfid = l9p_connection_alloc_fid(conn, req->lr_req.twalk.newfid);
        if (req->lr_newfid == NULL) {
            l9p_respond(req, L9P_ENOFID);
            return;
        }
    }

    if (!conn->lc_server->ls_backend->walk) {
        l9p_respond(req, L9P_ENOFUNC);
        return;
    }

    conn->lc_server->ls_backend->walk(conn->lc_server->ls_backend->softc, req);
}

static void
l9p_dispatch_twrite(struct l9p_request *req)
{

}

static void
l9p_dispatch_twstat(struct l9p_request *req)
{

}
