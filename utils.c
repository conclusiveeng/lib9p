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
#ifdef __APPLE__
# include "apple_endian.h"
#else
# include <sys/endian.h>
#endif
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
static void l9p_describe_size(const char *, uint64_t, struct sbuf *);
static void l9p_describe_ugid(const char *, uint32_t, struct sbuf *);

/*
 * Using indexed initializers, we can have these occur in any order.
 * Using adjacent-string concatenation ("T" #name, "R" #name), we
 * get both Tfoo and Rfoo strings with one copy of the name.
 * Alas, there is no stupid cpp trick to lowercase-ify, so we
 * have to write each name twice.  In which case we might as well
 * make the second one a string in the first place and not bother
 * with the stringizing.
 *
 * This table must match up with the enum list in fcall.h.
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
	X(STATFS,	"statfs"),
	X(LOPEN,	"lopen"),
	X(LCREATE,	"lcreate"),
	X(SYMLINK,	"symlink"),
	X(MKNOD,	"mknod"),
	X(RENAME,	"rename"),
	X(READLINK,	"readlink"),
	X(GETATTR,	"getattr"),
	X(XATTRWALK,	"xattrwalk"),
	X(XATTRCREATE,	"xattrcreate"),
	X(READDIR,	"readdir"),
	X(FSYNC,	"fsync"),
	X(LOCK,		"lock"),
	X(GETLOCK,	"getlock"),
	X(LINK,		"link"),
	X(MKDIR,	"mkdir"),
	X(RENAMEAT,	"renameat"),
	X(UNLINKAT,	"unlinkat"),
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
 * Show user or group ID.
 */
static void
l9p_describe_ugid(const char *str, uint32_t ugid, struct sbuf *sb)
{

	sbuf_printf(sb, "%s%" PRIu32, str, ugid);
}

/*
 * Show file mode (O_RDWR, O_RDONLY, etc) - note that upper bits
 * may be set for .L open, where this is called "flags".
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

	sbuf_printf(sb, "%s<0x%02x,%u,0x%016" PRIx64 ">", str,
	    qid->type, qid->version, qid->path);
}

/*
 * Show size.
 */
static void
l9p_describe_size(const char *str, uint64_t size, struct sbuf *sb)
{

	sbuf_printf(sb, "%s%" PRIu64, str, size);
}

static void
l9p_describe_stat(const char *str, struct l9p_stat *st, struct sbuf *sb)
{

	assert(st != NULL);

	sbuf_printf(sb, "%stype=0x%04x dev=%d name=\"%s\" uid=\"%s\"",
	    str, st->type, st->dev, st->name, st->uid);
}

void
l9p_describe_statfs(const char *str, struct l9p_statfs *st, struct sbuf *sb)
{

	assert(st != NULL);

	sbuf_printf(sb, "%stype=0x%04lx bsize=%lu blocks=%" PRIu64
	    " bfree=%" PRIu64 " bavail=%" PRIu64 " files=%" PRIu64
	    " ffree=%" PRIu64 " fsid=0x%" PRIx64 " namelen=%lu>",
	    str, (u_long)st->type, (u_long)st->bsize, st->blocks,
	    st->bfree, st->bavail, st->files,
	    st->ffree, st->fsid, st->namelen);
}

/*
 * Decode a <seconds,nsec> timestamp.
 *
 * Perhaps should use asctime_r.  For now, raw values.
 */
static void
l9p_describe_time(struct sbuf *sb, const char *s, uint64_t sec, uint64_t nsec)
{

	sbuf_cat(sb, s);
	if (nsec > 999999999)
		sbuf_printf(sb, "%llu.<invalid nsec %llu>)", sec, nsec);
	else
		sbuf_printf(sb, "%llu.%09llu", sec, nsec);
}

/*
 * Decode readdir data (.L format, variable length names).
 */
static void
l9p_describe_readdir(struct sbuf *sb, struct l9p_f_io *io)
{
	uint64_t o;
	uint32_t count, offset;
	uint16_t len;
	uint8_t type;
	char *p;
	int i, size, printlen;

	count = io->count;
	if (count == 0) {
		sbuf_printf(sb, " EOF (count=0)");
		return;
	}

	sbuf_printf(sb, " count=%" PRIu32 " [", count);
	p = io->data;
	for (i = 0, offset = 0; offset < count; i++, offset += size) {
		sbuf_printf(sb, i ? ", " : " ");

		/* entry length: qid[13] + offset[8] + type[1] + name[s] */
		if (offset + 13 + 8 + 1 + 2 > count) {
			sbuf_printf(sb, " bad count");
			break;
		}

		l9p_describe_qid(" qid=", (void *)p, sb);
		p += 13;
		memcpy(&o, p, 8);
		p += 8;
		type = *p++;
		memcpy(&len, p, 2);
		p += 2;

		o = le64toh(o);
		len = le16toh(len);

		size = 13 + 8 + 1 + 2 + len;

		if (offset + size > count) {
			sbuf_printf(sb, " bad count");
			break;
		}

		if ((printlen = len) > 255)
			printlen = 255;
		sbuf_printf(sb, " type=%d namelen=%d name=\"%.*s\"",
		    type, len, printlen, p);

		p += len;
	}
	sbuf_printf(sb, "]=%d dir entries", i);
}

void
l9p_describe_fcall(union l9p_fcall *fcall, enum l9p_version version,
    struct sbuf *sb)
{
	uint32_t mask;
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
	case L9P_RLCREATE:
	case L9P_RLOPEN:
		l9p_describe_qid(" qid=", &fcall->ropen.qid, sb);
		sbuf_printf(sb, " iounit=%d", fcall->ropen.iounit);
		return;

	case L9P_TCREATE:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		sbuf_printf(sb, " name=\"%s\"", fcall->tcreate.name);
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
	case L9P_TREADDIR:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		sbuf_printf(sb, " offset=%" PRIu64 " count=%" PRIu32,
		    fcall->io.offset, fcall->io.count);
		return;

	case L9P_TCLUNK:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		sbuf_printf(sb, " fid=%d", fcall->hdr.fid);
		return;

	case L9P_RCLUNK:
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

	case L9P_TSTATFS:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		return;

	case L9P_RSTATFS:
		l9p_describe_statfs(" ", &fcall->rstatfs.statfs, sb);
		return;

	case L9P_TLOPEN:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		l9p_describe_mode(" flags=", fcall->tlcreate.flags, sb);
		return;

	case L9P_TLCREATE:
	case L9P_TMKDIR:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		sbuf_printf(sb, " name=\"%s\"", fcall->tlcreate.name);
		/* confusing: "flags" is open-mode, "mode" is permissions */
		l9p_describe_mode(" flags=", fcall->tlcreate.flags, sb);
		l9p_describe_perm(" mode=", fcall->tlcreate.mode, sb);
		l9p_describe_ugid(" gid=", fcall->tlcreate.gid, sb);
		return;

	case L9P_TSYMLINK:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		sbuf_printf(sb, " name=\"%s\" symtgt=\"%s\"",
		    fcall->tsymlink.name, fcall->tsymlink.symtgt);
		l9p_describe_ugid(" gid=", fcall->tsymlink.gid, sb);
		return;

	case L9P_RSYMLINK:
	case L9P_RMKDIR:
	case L9P_RMKNOD:
		l9p_describe_qid(" qid=", &fcall->ropen.qid, sb);
		return;

	case L9P_TMKNOD:
		l9p_describe_fid(" dfid=", fcall->hdr.fid, sb);
		sbuf_printf(sb, " name=\"%s\"", fcall->tmknod.name);
		/* can't just use permission decode: mode contains blk/chr */
		sbuf_printf(sb, " mode=0x%08x major=%u minor=%u",
		    fcall->tmknod.mode,
		    fcall->tmknod.major, fcall->tmknod.minor);
		l9p_describe_ugid(" gid=", fcall->tmknod.gid, sb);
		return;

	case L9P_TRENAME:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		l9p_describe_fid(" dfid=", fcall->trename.dfid, sb);
		sbuf_printf(sb, " name=\"%s\"", fcall->trename.name);
		return;

	case L9P_RRENAME:
		return;

	case L9P_TREADLINK:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		return;

	case L9P_RREADLINK:
		sbuf_printf(sb, " target=\"%s\"", fcall->rreadlink.target);
		return;

	case L9P_TGETATTR:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		mask = fcall->tgetattr.request_mask;
		sbuf_printf(sb, " request_mask=0x%08x", mask);
		/* XXX decode request_mask later */
		return;

	case L9P_RGETATTR:
		mask = fcall->rgetattr.valid;
		sbuf_printf(sb, " valid=0x%08x", mask);
		l9p_describe_qid(" qid=", &fcall->rgetattr.qid, sb);
		if (mask & L9PL_GETATTR_MODE)
			sbuf_printf(sb, " mode=0x%08x", fcall->rgetattr.mode);
		if (mask & L9PL_GETATTR_UID)
			l9p_describe_ugid(" uid=", fcall->rgetattr.uid, sb);
		if (mask & L9PL_GETATTR_GID)
			l9p_describe_ugid(" gid=", fcall->rgetattr.gid, sb);
		if (mask & L9PL_GETATTR_NLINK)
			sbuf_printf(sb, " nlink=%" PRIu64,
			    fcall->rgetattr.nlink);
		if (mask & L9PL_GETATTR_RDEV)
			sbuf_printf(sb, " rdev=0x%" PRIx64,
			    fcall->rgetattr.rdev);
		if (mask & L9PL_GETATTR_SIZE)
			l9p_describe_size(" size=", fcall->rgetattr.size, sb);
		if (mask & L9PL_GETATTR_BLOCKS)
			sbuf_printf(sb, " blksize=%" PRIu64 " blocks=%" PRIu64,
			    fcall->rgetattr.blksize, fcall->rgetattr.blocks);
		if (mask & L9PL_GETATTR_ATIME)
			l9p_describe_time(sb, " atime=",
			    fcall->rgetattr.atime_sec,
			    fcall->rgetattr.atime_nsec);
		if (mask & L9PL_GETATTR_MTIME)
			l9p_describe_time(sb, " mtime=",
			    fcall->rgetattr.mtime_sec,
			    fcall->rgetattr.mtime_nsec);
		if (mask & L9PL_GETATTR_CTIME)
			l9p_describe_time(sb, " ctime=",
			    fcall->rgetattr.ctime_sec,
			    fcall->rgetattr.ctime_nsec);
		if (mask & L9PL_GETATTR_BTIME)
			l9p_describe_time(sb, " btime=",
			    fcall->rgetattr.btime_sec,
			    fcall->rgetattr.btime_nsec);
		if (mask & L9PL_GETATTR_GEN)
			sbuf_printf(sb, " gen=0x%" PRIx64, fcall->rgetattr.gen);
		if (mask & L9PL_GETATTR_DATA_VERSION)
			sbuf_printf(sb, " data_version=0x%" PRIx64,
			    fcall->rgetattr.data_version);
		return;

	case L9P_TSETATTR:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		mask = fcall->tsetattr.valid;
		sbuf_printf(sb, " valid=0x%08x", mask);
		if (mask & L9PL_SETATTR_MODE)
			sbuf_printf(sb, " mode=0x%08x", fcall->tsetattr.mode);
		if (mask & L9PL_SETATTR_UID)
			l9p_describe_ugid(" uid=", fcall->tsetattr.uid, sb);
		if (mask & L9PL_SETATTR_GID)
			l9p_describe_ugid(" uid=", fcall->tsetattr.gid, sb);
		if (mask & L9PL_SETATTR_SIZE)
			l9p_describe_size(" size=", fcall->tsetattr.size, sb);
		if (mask & L9PL_SETATTR_ATIME) {
			if (mask & L9PL_SETATTR_ATIME_SET)
				l9p_describe_time(sb, " atime=",
				    fcall->tsetattr.atime_sec,
				    fcall->tsetattr.atime_nsec);
			else
				sbuf_printf(sb, " atime=now");
		}
		if (mask & L9PL_SETATTR_MTIME) {
			if (mask & L9PL_SETATTR_MTIME_SET)
				l9p_describe_time(sb, " mtime=",
				    fcall->tsetattr.mtime_sec,
				    fcall->tsetattr.mtime_nsec);
			else
				sbuf_printf(sb, " mtime=now");
		}
		return;

	case L9P_RSETATTR:
		return;

	case L9P_TXATTRWALK:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		l9p_describe_fid(" newfid=", fcall->txattrwalk.newfid, sb);
		sbuf_printf(sb, " name=\"%s\"", fcall->txattrwalk.name);
		return;

	case L9P_RXATTRWALK:
		l9p_describe_size(" size=", fcall->rxattrwalk.size, sb);
		return;

	case L9P_TXATTRCREATE:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		sbuf_printf(sb, " name=\"%s\"", fcall->txattrcreate.name);
		l9p_describe_size(" size=", fcall->txattrcreate.attr_size, sb);
		sbuf_printf(sb, " flags=%" PRIu32, fcall->txattrcreate.flags);
		return;

	case L9P_RXATTRCREATE:
		return;

	case L9P_RREADDIR:
		l9p_describe_readdir(sb, &fcall->io);
		return;

	case L9P_TFSYNC:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		return;

	case L9P_RFSYNC:
		return;

	case L9P_TLOCK:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		/* decode better later */
		sbuf_printf(sb, " type=%d flags=0x%" PRIx32
		    " start=" PRIu64 " length=" PRIu64
		    " proc_id=0x" PRIx32 " client_id=\"%s\"",
		    fcall->tlock.type, fcall->tlock.flags,
		    fcall->tlock.start, fcall->tlock.length,
		    fcall->tlock.proc_id, fcall->tlock.client_id);
		return;

	case L9P_RLOCK:
		sbuf_printf(sb, " status=%d", fcall->rlock.status);
		return;

	case L9P_TGETLOCK:
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		/* FALLTHROUGH */

	case L9P_RGETLOCK:
		/* decode better later */
		sbuf_printf(sb, " type=%d "
		    " start=" PRIu64 " length=" PRIu64
		    " proc_id=0x" PRIx32 " client_id=\"%s\"",
		    fcall->getlock.type,
		    fcall->getlock.start, fcall->getlock.length,
		    fcall->getlock.proc_id, fcall->getlock.client_id);
		return;

	case L9P_TLINK:
		l9p_describe_fid(" dfid=", fcall->tlink.dfid, sb);
		l9p_describe_fid(" fid=", fcall->hdr.fid, sb);
		return;

	case L9P_RLINK:
		return;

	case L9P_TRENAMEAT:
		l9p_describe_fid(" olddirfid=", fcall->hdr.fid, sb);
		sbuf_printf(sb, " oldname=\"%s\"", fcall->trenameat.oldname);
		l9p_describe_fid(" newdirfid=", fcall->trenameat.newdirfid, sb);
		sbuf_printf(sb, " newname=\"%s\"", fcall->trenameat.newname);
		return;

	case L9P_RRENAMEAT:
		return;

	case L9P_TUNLINKAT:
		l9p_describe_fid(" dirfd=", fcall->hdr.fid, sb);
		sbuf_printf(sb, " name=\"%s\" flags=0x%08" PRIx32,
		    fcall->tlcreate.name, fcall->tlcreate.flags);
		return;

	case L9P_RUNLINKAT:
		return;

	default:
		sbuf_printf(sb, " <missing case in %s()>", __func__);
	}
}
