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

 /*
  * Based on libixp code: ©2007-2010 Kris Maglione <maglione.k at Gmail>
  */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "lib9p.h"

#define N(ary)          (sizeof(ary) / sizeof(*ary))
#define STRING_SIZE(s)  (L9P_WORD + strlen(s))
#define QID_SIZE        (L9P_BYTE + L9P_DWORD + L9P_QWORD)

static void l9p_puint(struct l9p_message *, enum l9p_integer_type, uint32_t *);
static inline void l9p_pu8(struct l9p_message *, uint8_t *);
static inline void l9p_pu16(struct l9p_message *, uint16_t *);
static inline void l9p_pu32(struct l9p_message *, uint32_t *);
static inline void l9p_pu64(struct l9p_message *, uint64_t *);
static void l9p_pustring(struct l9p_message *, char **s);
static void l9p_pustrings(struct l9p_message *, uint16_t *,char *[], size_t);
static void l9p_pudata(struct l9p_message *, uint8_t **, size_t);
static void l9p_puqid(struct l9p_message *, struct l9p_qid *);
static void l9p_puqids(struct l9p_message *, uint16_t *, struct l9p_qid *q,
    size_t);
static void l9p_pustat(struct l9p_message *, struct l9p_stat *);
static uint16_t l9p_sizeof_stat(struct l9p_stat *);


static void
l9p_puint(struct l9p_message *msg, enum l9p_integer_type size, uint32_t *val)
{
    uint8_t *pos;
    int v;

    if(msg->lm_pos + size <= msg->lm_end) {
        pos = (uint8_t*)msg->lm_pos;
        switch (msg->lm_mode) {
            case L9P_PACK:
                v = *val;
                switch (size) {
                    case L9P_DWORD:
                        pos[3] = v>>24;
                        pos[2] = v>>16;
                    case L9P_WORD:
                        pos[1] = v>>8;
                    case L9P_BYTE:
                        pos[0] = v;
                        break;
                }
            case L9P_UNPACK:
                v = 0;
                switch (size) {
                    case L9P_DWORD:
                        v |= pos[3]<<24;
                        v |= pos[2]<<16;
                    case L9P_WORD:
                        v |= pos[1]<<8;
                    case L9P_BYTE:
                        v |= pos[0];
                        break;
                }
                *val = v;
        }
    }
    msg->lm_pos += size;
}

static inline void
l9p_pu8(struct l9p_message *msg, uint8_t *val)
{
    uint32_t v;

    v = *val;
    l9p_puint(msg, L9P_BYTE, &v);
    *val = (uint8_t)v;
}

static inline void
l9p_pu16(struct l9p_message *msg, uint16_t *val)
{
    uint32_t v;

    v = *val;
    l9p_puint(msg, L9P_WORD, &v);
    *val = (uint16_t)v;
}

static inline void
l9p_pu32(struct l9p_message *msg, uint32_t *val)
{
    l9p_puint(msg, L9P_DWORD, val);
}

static inline void
l9p_pu64(struct l9p_message *msg, uint64_t *val)
{
    uint32_t vl, vb;

    vl = (uint)*val;
    vb = (uint)(*val>>32);
    l9p_puint(msg, L9P_DWORD, &vl);
    l9p_puint(msg, L9P_DWORD, &vb);
    *val = vl | ((uint64_t)vb<<32);
}

static void
l9p_pustring(struct l9p_message *msg, char **s)
{
    uint16_t len;

    if(msg->lm_mode == L9P_PACK)
        len = strlen(*s);
    l9p_pu16(msg, &len);

    if (msg->lm_pos + len <= msg->lm_end) {
        if (msg->lm_mode == L9P_UNPACK) {
            *s = malloc(len + 1);
            memcpy(*s, msg->lm_pos, len);
            (*s)[len] = '\0';
        } else
            memcpy(msg->lm_pos, *s, len);
    }
    msg->lm_pos += len;
}

static void
l9p_pustrings(struct l9p_message *msg, uint16_t *num, char *strings[],
    size_t max)
{
    char *s;
    uint i, size;
    uint16_t len;

    l9p_pu16(msg, num);
    if (*num > max) {
        msg->lm_pos = msg->lm_end+1;
        return;
    }

    s = NULL;

    if (msg->lm_mode == L9P_UNPACK) {
        s = msg->lm_pos;
        size = 0;
        for (i = 0; i < *num; i++) {
            l9p_pu16(msg, &len);
            msg->lm_pos += len;
            size += len;
            if (msg->lm_pos > msg->lm_end)
                return;
        }
        msg->lm_pos = s;
        size += *num;
        s = malloc(size);
    }

    for (i = 0; i < *num; i++) {
        if (msg->lm_mode == L9P_PACK)
            len = strlen(strings[i]);
        l9p_pu16(msg, &len);

        if (msg->lm_mode == L9P_UNPACK) {
            memcpy(s, msg->lm_pos, len);
            strings[i] = (char*)s;
            s += len;
            msg->lm_pos += len;
            *s++ = '\0';
        } else
            l9p_pudata(msg, &strings[i], len);
    }
}

static void
l9p_pudata(struct l9p_message *msg, uint8_t **data, size_t len)
{
    if (msg->lm_pos + len <= msg->lm_end) {
        if (msg->lm_mode == L9P_UNPACK) {
            *data = malloc(len);
            memcpy(*data, msg->lm_pos, len);
        } else
            memcpy(msg->lm_pos, *data, len);
    }
    msg->lm_pos += len;
}

static void
l9p_puqid(struct l9p_message *msg, struct l9p_qid *qid)
{
    l9p_pu8(msg, &qid->type);
    l9p_pu32(msg, &qid->version);
    l9p_pu64(msg, &qid->path);
}

static void
l9p_puqids(struct l9p_message *msg, uint16_t *num, struct l9p_qid *qids,
    size_t max)
{
    int i;
    l9p_pu16(msg, num);
    if (*num > max) {
        msg->lm_pos = msg->lm_end + 1;
        return;
    }

    for (i = 0; i < *num; i++)
        l9p_puqid(msg, &qids[i]);
}

static void
l9p_pustat(struct l9p_message *msg, struct l9p_stat *stat)
{
    uint16_t size;

    if(msg->lm_mode == L9P_PACK)
        size = l9p_sizeof_stat(stat) - 2;

    l9p_pu16(msg, &size);
    l9p_pu16(msg, &stat->type);
    l9p_pu32(msg, &stat->dev);
    l9p_puqid(msg, &stat->qid);
    l9p_pu32(msg, &stat->mode);
    l9p_pu32(msg, &stat->atime);
    l9p_pu32(msg, &stat->mtime);
    l9p_pu64(msg, &stat->length);
    l9p_pustring(msg, &stat->name);
    l9p_pustring(msg, &stat->uid);
    l9p_pustring(msg, &stat->gid);
    l9p_pustring(msg, &stat->muid);
}

int
l9p_pufcall(struct l9p_message *msg, union l9p_fcall *fcall)
{
    l9p_pu8(msg, &fcall->hdr.type);
    l9p_pu16(msg, &fcall->hdr.tag);

    switch (fcall->hdr.type) {
        case L9P_TVERSION:
        case L9P_RVERSION:
            l9p_pu32(msg, &fcall->version.msize);
            l9p_pustring(msg, &fcall->version.version);
            break;
        case L9P_TAUTH:
            l9p_pu32(msg, &fcall->tauth.afid);
            l9p_pustring(msg, &fcall->tauth.uname);
            l9p_pustring(msg, &fcall->tauth.aname);
            break;
        case L9P_RAUTH:
            l9p_puqid(msg, &fcall->rauth.aqid);
            break;
        case L9P_RATTACH:
            l9p_puqid(msg, &fcall->rattach.qid);
            break;
        case L9P_TATTACH:
            l9p_pu32(msg, &fcall->hdr.fid);
            l9p_pu32(msg, &fcall->tattach.afid);
            l9p_pustring(msg, &fcall->tattach.uname);
            l9p_pustring(msg, &fcall->tattach.aname);
            break;
        case L9P_RERROR:
            l9p_pustring(msg, &fcall->error.ename);
            break;
        case L9P_TFLUSH:
            l9p_pu16(msg, &fcall->tflush.oldtag);
            break;
        case L9P_TWALK:
            l9p_pu32(msg, &fcall->hdr.fid);
            l9p_pu32(msg, &fcall->twalk.newfid);
            l9p_pustrings(msg, &fcall->twalk.nwname, fcall->twalk.wname,
                N(fcall->twalk.wname));
            break;
        case L9P_RWALK:
            l9p_puqids(msg, &fcall->rwalk.nwqid, fcall->rwalk.wqid,
                N(fcall->rwalk.wqid));
            break;
        case L9P_TOPEN:
            l9p_pu32(msg, &fcall->hdr.fid);
            l9p_pu8(msg, &fcall->topen.mode);
            break;
        case L9P_ROPEN:
        case L9P_RCREATE:
            l9p_puqid(msg, &fcall->ropen.qid);
            l9p_pu32(msg, &fcall->ropen.iounit);
            break;
        case L9P_TCREATE:
            l9p_pu32(msg, &fcall->hdr.fid);
            l9p_pustring(msg, &fcall->tcreate.name);
            l9p_pu32(msg, &fcall->tcreate.perm);
            l9p_pu8(msg, &fcall->tcreate.mode);
            break;
        case L9P_TREMOVE:
            l9p_pu32(msg, &fcall->hdr.fid);
            l9p_pu64(msg, &fcall->io.offset);
            l9p_pu32(msg, &fcall->io.count);
            break;
        case L9P_RREAD:
            l9p_pu32(msg, &fcall->io.count);
            l9p_pudata(msg, &fcall->io.data, fcall->io.count);
            break;
        case L9P_TWRITE:
            l9p_pu32(msg, &fcall->hdr.fid);
            l9p_pu64(msg, &fcall->io.offset);
            l9p_pu32(msg, &fcall->io.count);
            l9p_pudata(msg, &fcall->io.data, fcall->io.count);
            break;
        case L9P_RWRITE:
            l9p_pu32(msg, &fcall->io.count);
            break;
        case L9P_TCLUNK:
        case L9P_TSTAT:
            l9p_pu32(msg, &fcall->hdr.fid);
            break;
        case L9P_RSTAT:
            l9p_pu16(msg, &fcall->rstat.nstat);
            l9p_pudata(msg, (char**)&fcall->rstat.stat, fcall->rstat.nstat);
            break;
        case L9P_TWSTAT: {
            uint16_t size;
            l9p_pu32(msg, &fcall->hdr.fid);
            l9p_pu16(msg, &size);
            l9p_pustat(msg, &fcall->twstat.stat);
            break;
        }
    }
}

static uint16_t
l9p_sizeof_stat(struct l9p_stat *stat) {
    return L9P_WORD /* size */
        + L9P_WORD /* type */
        + L9P_DWORD /* dev */
        + QID_SIZE /* qid */
        + 3 * L9P_DWORD /* mode, atime, mtime */
        + L9P_DWORD /* length */
        + STRING_SIZE(stat->name)
        + STRING_SIZE(stat->uid)
        + STRING_SIZE(stat->gid)
        + STRING_SIZE(stat->muid);
}
