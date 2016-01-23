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


#ifndef LIB9P_LIB9P_H
#define LIB9P_LIB9P_H

#include <sys/types.h>
#include <sys/queue.h>
#include <pthread.h>
#include "fcall.h"

#define L9P_ENOFID "FID does not exist"
#define L9P_ENOFUNC "Function not implemented"
#define L9P_EINTR "Interrupted"

enum l9p_pack_mode
{
    L9P_PACK,
    L9P_UNPACK
};

enum l9p_integer_type
{
    L9P_BYTE = 1,
    L9P_WORD = 2,
    L9P_DWORD = 4,
    L9P_QWORD = 8
};

struct l9p_message
{
    enum l9p_pack_mode lm_mode;
    uint8_t *lm_buffer;
    uint8_t *lm_pos;
    uint8_t *lm_end;
};

struct l9p_request
{
    uint32_t lr_tag;
    union l9p_fcall lr_req;
    union l9p_fcall lr_resp;
    struct l9p_openfile *lr_fid;
    struct l9p_openfile *lr_newfid;
    struct l9p_connection *lr_conn;
    pthread_t lr_thread;
    LIST_ENTRY(l9p_request) lr_link;
};

struct l9p_openfile
{
    char *lo_uid;
    void *lo_aux;
    uint32_t lo_fid;
    struct l9p_qid lo_qid;
    struct l9p_connection *lo_conn;
    LIST_ENTRY(l9p_openfile) lo_link;
};

struct l9p_connection
{
    struct l9p_server *lc_server;
    pthread_mutex_t lc_send_lock;
    void (*lc_send_request)(const void *, const size_t, void *);
    void *lc_send_request_aux;
    void *lc_softc;
    LIST_HEAD(, l9p_request) lc_requests;
    LIST_HEAD(, l9p_openfile) lc_files;
    LIST_ENTRY(l9p_connection) lc_link;
};

struct l9p_server
{
    struct l9p_backend *ls_backend;
    LIST_HEAD(, l9p_connection) ls_conns;
};

struct l9p_backend
{
    void *softc;
    void (*attach)(void *, struct l9p_request *);
    void (*clunk)(void *, struct l9p_request *);
    void (*create)(void *, struct l9p_request *);
    void (*flush)(void *, struct l9p_request *);
    void (*open)(void *, struct l9p_request *);
    void (*read)(void *, struct l9p_request *);
    void (*remove)(void *, struct l9p_request *);
    void (*stat)(void *, struct l9p_request *);
    void (*walk)(void *, struct l9p_request *);
    void (*write)(void *, struct l9p_request *);
    void (*wstat)(void *, struct l9p_request *);
    void (*freefid)(void *, struct l9p_openfile *);
};

int l9p_pufcall(struct l9p_message *msg, union l9p_fcall *fcall);
int l9p_fustat(struct l9p_message *msg, struct l9p_stat *s);
uint16_t l9p_sizeof_stat(struct l9p_stat *stat);
int l9p_pack_stat(struct l9p_request *req, struct l9p_stat *s);

int l9p_server_init(struct l9p_server **, struct l9p_backend *backend);

int l9p_connection_init(struct l9p_server *server, struct l9p_connection **conn);
void l9p_connection_free(struct l9p_connection *conn);
void l9p_connection_on_send_request(struct l9p_connection *conn, void (*cb)(void *, size_t, void *), void *);
void l9p_connection_recv(struct l9p_connection *conn, void *buf, size_t len);
void l9p_connection_close(struct l9p_connection *conn);
struct l9p_openfile *l9p_connection_find_fid(struct l9p_connection *conn, uint32_t fid);
struct l9p_request *l9p_connection_find_tag(struct l9p_connection *conn, uint32_t tag);
void l9p_respond(struct l9p_request *req, const char *error);

#endif //LIB9P_LIB9P_H
