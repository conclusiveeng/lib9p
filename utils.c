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
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/param.h>
#include <sys/uio.h>
#if defined(__FreeBSD__)
#include <sys/sbuf.h>
#else
#include "sbuf/sbuf.h"
#endif
#include "lib9p.h"
#include "fcall.h"

static void l9p_describe_fid(const char *, uint32_t, struct sbuf *);
static void l9p_describe_mode(const char *, uint32_t, struct sbuf *);
static void l9p_describe_perm(const char *, uint32_t, struct sbuf *);
static void l9p_describe_qid(const char *, struct l9p_qid *, struct sbuf *);
static void l9p_describe_stat(const char *, struct l9p_stat *, struct sbuf *);

/*
 * Using indexed initializers, we can have these occur in any order.
 * Using adjacent-string concatenation ("T" #name, "R" #name), we
 * get both Tfoo and Rfoo strings with one copy of the name.
 * Alas, there is no stupid cpp trick to lowercase-ify, so we
 * have to write each name twice.  In which case we might as well
 * make the second one a string in the first place and not bother
 * with the stringizing.
 */
#define X(NAME, name)	[L9P_T##NAME - L9P__FIRST] = "T" name, \
			[L9P_R##NAME - L9P__FIRST] = "R" name
static const char *ftype_names[] = {
	X(VERSION,	"version"),
	X(AUTH,		"auth"),
	X(ATTACH,	"attach"),
	X(ERROR,	"error"),
	X(FLUSH,	"flush"),
	X(WALK,		"walk"),
	X(OPEN,		"open"),
	X(CREATE,	"create"),
	X(READ,		"read"),
	X(WRITE,	"write"),
	X(CLUNK,	"clunk"),
	X(REMOVE,	"remove"),
	X(STAT,		"stat"),
	X(WSTAT,	"wstat"),
};
#undef X

void
l9p_seek_iov(struct iovec *iov1, size_t niov1, struct iovec *iov2,
    size_t *niov2, size_t seek)
{
	size_t remainder = 0;
	size_t left = seek;
	size_t i, j;

	for (i = 0; i < niov1; i++) {
		size_t toseek = MIN(left, iov1[i].iov_len);
		left -= toseek;

		if (toseek == iov1[i].iov_len)
			continue;

		if (left == 0) {
			remainder = toseek;
			break;
		}
	}

	for (j = i; j < niov1; j++) {
		iov2[j - i].iov_base = (char *)iov1[j].iov_base + remainder;
		iov2[j - i].iov_len = iov1[j].iov_len - remainder;
		remainder = 0;
	}

	*niov2 = j - i;
}

size_t
l9p_truncate_iov(struct iovec *iov, size_t niov, size_t length)
{
	size_t i, done = 0;

	for (i = 0; i < niov; i++) {
		size_t toseek = MIN(length - done, iov[i].iov_len);
		done += toseek;

		if (toseek < iov[i].iov_len) {
			iov[i].iov_len = toseek;
			return (i + 1);
		}
	}

	return (niov);
}

/*
 * Show file ID.
 */
static void
l9p_describe_fid(const char *str, uint32_t fid, struct sbuf *sb)
{

	sbuf_printf(sb, "%s%" PRIu32, str, fid);
}

/*
 * Show file mode (O_RDWR, O_RDONLY, etc) - note that upper bits
 * may be set for .L open.
 *
 * For now we just decode in hex.
 */
static void
l9p_describe_mode(const char *str, uint32_t mode, struct sbuf *sb)
{

	sbuf_printf(sb, "%s%" PRIx32, str, mode);
}

/*
 * Show permissions (rwx etc).
 */
static void
l9p_describe_perm(const char *str, uint32_t mode, struct sbuf *sb)
{
	char pbuf[12];

	strmode(mode & 0777, pbuf);
	sbuf_printf(sb, "%s%" PRIx32 "<%.9s>", str, mode, pbuf + 1);
}

/*
 * Show qid (<type, version, path> tuple).
 */
static void
l9p_describe_qid(const char *str, struct l9p_qid *qid, struct sbuf *sb)
{

	assert(qid != NULL);
	assert(sb != NULL);

	sbuf_printf(sb, "%s<0x%02x,%u,0x%016" PRIx64 ">", str,
	    qid->type, qid->version, qid->path);
}

static void
l9p_describe_stat(const char *str, struct l9p_stat *st, struct sbuf *sb)
{

	assert(st != NULL);
	assert(sb != NULL);

	sbuf_printf(sb, "%stype=0x%04x dev=%d name=\"%s\" uid=\"%s\"",
	    str, st->type, st->dev, st->name, st->uid);
}

void
l9p_describe_fcall(union l9p_fcall *fcall, enum l9p_version version,
    struct sbuf *sb)
{
	uint8_t type;
	int i;

	assert(fcall != NULL);
	assert(sb != NULL);
	assert(version <= L9P_2000L && version >= L9P_2000);

	type = fcall->hdr.type;

	if (type < L9P__FIRST || type >= L9P__LAST_PLUS_1 ||
	    ftype_names[type - L9P__FIRST] == NULL) {
		sbuf_printf(sb, "<unknown request %d> tag=%d", type,
		    fcall->hdr.tag);
		return;
	}

	sbuf_printf(sb, "%s tag=%d", ftype_names[type - L9P__FIRST],
	    fcall->hdr.tag);

	switch (type) {

	case L9P_TVERSION:
	case L9P_RVERSION:
		sbuf_printf(sb, " version=\"%s\" msize=%d", fcall->version.version,
		    fcall->version.msize);
		return;

	case L9P_TAUTH:
		l9p_describe_fid(" afid=", fcall->hdr.fid, sb);
		sbuf_printf(sb, " uname=\"%s\" aname=\"%s\"",
		    fcall->tauth.uname, fcall->tauth.aname);
		return;

	case L9P_TATTACH:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		l9p_describe_fid(" afid=", fcall->tattach.afid, sb);
		sbuf_printf(sb, " uname=\"%s\" aname=\"%s\"",
		    fcall->tattach.uname, fcall->tattach.aname);
		if (version >= L9P_2000U)
			sbuf_printf(sb, " n_uname=%d", fcall->tattach.n_uname);
		return;

	case L9P_RERROR:
		sbuf_printf(sb, " ename=\"%s\" errnum=%d", fcall->error.ename,
		    fcall->error.errnum);
		return;

	case L9P_TFLUSH:
		sbuf_printf(sb, " oldtag=%d", fcall->tflush.oldtag);
		return;

	case L9P_TWALK:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		l9p_describe_fid(" newfid=", fcall->twalk.newfid, sb);
		sbuf_cat(sb, " wname=\"");
		for (i = 0; i < fcall->twalk.nwname; i++)
			sbuf_printf(sb, "%s%s", i == 0 ? "" : "/",
			    fcall->twalk.wname[i]);
		sbuf_cat(sb, "\"");
		return;

	case L9P_RWALK:
		sbuf_printf(sb, " wqid=[");
		for (i = 0; i < fcall->rwalk.nwqid; i++)
			l9p_describe_qid(i == 0 ? "" : ",",
			    &fcall->rwalk.wqid[i], sb);
		sbuf_cat(sb, "]");
		return;

	case L9P_TOPEN:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		l9p_describe_mode(" mode=", fcall->tcreate.mode, sb);
		return;

	case L9P_ROPEN:
		l9p_describe_qid(" qid=", &fcall->ropen.qid, sb);
		sbuf_printf(sb, " iounit=%d", fcall->ropen.iounit);
		return;

	case L9P_TCREATE:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		sbuf_printf(sb, " name=\"%s\" perm=0x%08x mode=%d",
		    fcall->tcreate.name, fcall->tcreate.perm,
		    fcall->tcreate.mode);
		l9p_describe_perm(" perm=", fcall->tcreate.perm, sb);
		l9p_describe_mode(" mode=", fcall->tcreate.mode, sb);
		return;

	case L9P_RCREATE:
		return;

	case L9P_TREAD:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		sbuf_printf(sb, " offset=%" PRIu64 " count=%" PRIu32,
		    fcall->io.offset, fcall->io.count);
		return;

	case L9P_RREAD:
	case L9P_RWRITE:
		sbuf_printf(sb, " count=%" PRIu32, fcall->io.count);
		return;

	case L9P_TWRITE:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		sbuf_printf(sb, " offset=%" PRIu64 " count=%" PRIu32,
		    fcall->io.offset, fcall->io.count);
		return;

	case L9P_TCLUNK:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		return;

	case L9P_TREMOVE:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		return;

	case L9P_RREMOVE:
		return;

	case L9P_TSTAT:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		return;

	case L9P_RSTAT:
		l9p_describe_stat(" ", &fcall->rstat.stat, sb);
		return;

	case L9P_TWSTAT:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		l9p_describe_stat(" ", &fcall->twstat.stat, sb);
		return;

	case L9P_RWSTAT:
		return;
	}
}
