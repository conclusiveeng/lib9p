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


#include <string.h>
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

static struct
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

void
l9p_dispatch_request(struct l9p_request *req)
{
    struct l9p_connection *conn = req->lr_conn;
    int i;

    l9p_logf(L9P_INFO, "new request of type %d", req->lr_req.hdr.type);
    req->lr_tag = req->lr_req.hdr.tag;

    for (i = 0; i < N(l9p_handlers); i++) {
        if (req->lr_req.hdr.type == l9p_handlers[i].type) {
            l9p_handlers[i].handler(req);
            return;
        }
    }
}

void
l9p_respond(struct l9p_request *req, const char *error)
{
    struct l9p_connection *conn = req->lr_conn;
    struct l9p_message msg;
    void *buf = malloc(1024 * 1024);

    msg.lm_buffer = buf;
    msg.lm_pos = buf;
    msg.lm_end = buf + (1024 * 1024);
    msg.lm_mode = L9P_PACK;

    switch (req->lr_req.hdr.type) {
    case L9P_TVERSION:
        break;
    }

    req->lr_resp.hdr.tag = req->lr_req.hdr.tag;

    if (error == NULL)
        req->lr_resp.hdr.type = req->lr_req.hdr.type + 1;
    else {
        req->lr_resp.hdr.type = L9P_RERROR;
        req->lr_resp.error.ename = error;
    }

    if (l9p_pufcall(&msg, &req->lr_resp) != 0) {

    }

    conn->lc_send_request(msg.lm_buffer, msg.lm_pos - msg.lm_buffer, conn->lc_send_request_aux);
}

static void
l9p_dispatch_tversion(struct l9p_request *req)
{
    if (!strcmp(req->lr_req.version.version, "9P"))
        req->lr_resp.version.version = "9P";
    else if (!strcmp(req->lr_req.version.version, "9P2000"))
        req->lr_resp.version.version = "9P2000";
    else
        req->lr_resp.version.version = "unknown";

    req->lr_resp.version.msize = req->lr_resp.version.msize;
    l9p_respond(req, NULL);
}

static void
l9p_dispatch_tattach(struct l9p_request *req)
{

}

static void
l9p_dispatch_tclunk(struct l9p_request *req)
{

}

static void
l9p_dispatch_tflush(struct l9p_request *req)
{

}

static void
l9p_dispatch_tcreate(struct l9p_request *req)
{
    struct l9p_connection *conn = req->lr_conn;
    struct l9p_openfile *fid;

    if (l9p_connection_find_fid(conn, req->lr_req.tcreate.hdr.fid) != NULL) {
        l9p_respond(req, "x");
        return;
    }

    fid = malloc(sizeof(struct l9p_openfile));
    fid->lo_fid = req->lr_req.tcreate.hdr.fid;
    fid->lo_conn = conn;
    LIST_INSERT_HEAD(&conn->lc_files, fid, lo_link);

    conn->lc_server->ls_backend->create(conn->lc_server->ls_backend->softc, req);
}

static void
l9p_dispatch_topen(struct l9p_request *req)
{
    struct l9p_connection *conn = req->lr_conn;
    struct l9p_openfile *fid;

    fid = l9p_connection_find_fid(conn, req->lr_req.topen.hdr.fid);
    if (!fid) {
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

    fid = l9p_connection_find_fid(conn, req->lr_req.tcreate.hdr.fid);
    if (!fid) {
        l9p_respond(req, L9P_ENOFID);
        return;
    }
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


}

static void
l9p_dispatch_twalk(struct l9p_request *req)
{
    struct l9p_connection *conn = req->lr_conn;
    struct l9p_openfile *fid;

    fid = l9p_connection_find_fid(conn, req->lr_req.twalk.hdr.fid);
    if (!fid) {
        l9p_respond(req, L9P_ENOFID);
        return;
    }

    if (req->lr_req.twalk.hdr.fid != req->lr_req.twalk.newfid) {

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
