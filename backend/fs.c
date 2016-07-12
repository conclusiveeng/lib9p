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
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <libgen.h>
#include "../lib9p.h"
#include "../lib9p_impl.h"
#include "../fid.h"
#include "../log.h"
#include "../rfuncs.h"
#include "backend.h"
#include "fs.h"

#if defined(__FreeBSD__)
  #include <sys/param.h>
  #if __FreeBSD_version >= 1000000
    #define	HAVE_BINDAT
  #endif
#endif

#if defined(__FreeBSD__)
  #define	HAVE_BIRTHTIME
#endif

#if defined(__FreeBSD__)
  /* should probably check version but fstatat has been in for ages */
  #define HAVE_FSTATAT
#endif

#if defined(__APPLE__)
  #include "Availability.h"
  #if __MAC_OS_X_VERSION_MIN_REQUIRED > 1090
    #define HAVE_FSTATAT
  #endif
#endif

struct fs_softc {
	const char *fs_rootpath;
	bool fs_readonly;
};

struct openfile {
	DIR *dir;
	int fd;
	char *name;
	uid_t uid;
	gid_t gid;
};

/*
 * Internal functions (except inline functions).
 */
static int fs_buildname(struct l9p_fid *, char *, char *, size_t);
static int fs_oflags_dotu(int, int *);
static int fs_oflags_dotl(uint32_t, int *, enum l9p_omode *);
static struct openfile *open_fid(const char *);
static void dostat(struct l9p_stat *, char *, struct stat *, bool dotu);
static void dostatfs(struct l9p_statfs *, struct statfs *, long);
static bool check_access(struct stat *, uid_t, gid_t, enum l9p_omode);
static void generate_qid(struct stat *, struct l9p_qid *);

/*
 * Internal functions implementing backend.
 */
static int fs_attach(void *, struct l9p_request *);
static int fs_clunk(void *, struct l9p_request *);
static int fs_create(void *, struct l9p_request *);
static int fs_flush(void *, struct l9p_request *);
static int fs_open(void *, struct l9p_request *);
static int fs_read(void *, struct l9p_request *);
static int fs_remove(void *, struct l9p_request *);
static int fs_stat(void *, struct l9p_request *);
static int fs_walk(void *, struct l9p_request *);
static int fs_write(void *, struct l9p_request *);
static int fs_wstat(void *, struct l9p_request *);
static int fs_statfs(void *, struct l9p_request *);
static int fs_lopen(void *, struct l9p_request *);
static int fs_lcreate(void *, struct l9p_request *);
static int fs_symlink(void *, struct l9p_request *);
static int fs_mknod(void *, struct l9p_request *);
static int fs_rename(void *, struct l9p_request *);
static int fs_readlink(void *, struct l9p_request *);
static int fs_getattr(void *, struct l9p_request *);
static int fs_setattr(void *, struct l9p_request *);
static int fs_xattrwalk(void *, struct l9p_request *);
static int fs_xattrcreate(void *, struct l9p_request *);
static int fs_readdir(void *, struct l9p_request *);
static int fs_fsync(void *, struct l9p_request *);
static int fs_lock(void *, struct l9p_request *);
static int fs_getlock(void *, struct l9p_request *);
static int fs_link(void *, struct l9p_request *);
static int fs_renameat(void *softc, struct l9p_request *req);
static int fs_unlinkat(void *softc, struct l9p_request *req);
static void fs_freefid(void *softc, struct l9p_fid *f);

/*
 * Convert from 9p2000 open/create mode to Unix-style O_* flags.
 * This includes 9p2000.u extensions, but not 9p2000.L protocol,
 * which has entirely different open, create, etc., flag bits.
 *
 * The <mode> given here is the one-byte (uint8_t) "mode"
 * argument to Tcreate or Topen, so it can have at most 8 bits.
 *
 * https://swtch.com/plan9port/man/man9/open.html and
 * http://plan9.bell-labs.com/magic/man2html/5/open
 * both say:
 *
 *   The [low two bits of the] mode field determines the
 *   type of I/O ... [I]f mode has the OTRUNC (0x10) bit
 *   set, the file is to be truncated, which requires write
 *   permission ...; if the mode has the ORCLOSE (0x40) bit
 *   set, the file is to be removed when the fid is clunked,
 *   which requires permission to remove the file from its
 *   directory.  All other bits in mode should be zero.  It
 *   is illegal to write a directory, truncate it, or
 *   attempt to remove it on close.
 *
 * 9P2000.u may add ODIRECT (0x80); this is not completely clear.
 * The fcall.h header defines OCEXEC (0x20) as well, but it makes
 * no sense to send this to a server.  There seem to be no bits
 * 0x04 and 0x08.
 *
 * We always turn on O_NOCTTY since as a server, we never want
 * to gain a controlling terminal.  We always turn on O_NOFOLLOW
 * for reasons described elsewhere.
 */
static int
fs_oflags_dotu(int mode, int *aflags)
{
	int flags;
#define	CONVERT(theirs, ours) \
	do { \
		if (mode & (theirs)) { \
			mode &= ~(theirs); \
			flags |= ours; \
		} \
	} while (0)

	switch (mode & L9P_OACCMODE) {

	case L9P_OREAD:
	default:
		flags = O_RDONLY;
		break;

	case L9P_OWRITE:
		flags = O_WRONLY;
		break;

	case L9P_ORDWR:
		flags = O_RDWR;
		break;

	case L9P_OEXEC:
		if (mode & L9P_OTRUNC)
			return (EINVAL);
		flags = O_RDONLY;
		break;
	}

	flags |= O_NOCTTY | O_NOFOLLOW;

	CONVERT(L9P_OTRUNC, O_TRUNC);

	/*
	 * Now take away some flags locally:
	 *   the access mode (already translated)
	 *   ORCLOSE - caller only
	 *   OCEXEC - makes no sense in server
	 *   ODIRECT - not applicable here
	 * If there are any flag bits left after this,
	 * we were unable to translate them.  For now, let's
	 * treat this as EINVAL so that we can catch problems.
	 */
	mode &= ~(L9P_OACCMODE | L9P_ORCLOSE | L9P_OCEXEC | L9P_ODIRECT);
	if (mode != 0) {
		L9P_LOG(L9P_INFO,
		    "fs_oflags_dotu: untranslated bits: %#x",
		    (unsigned)mode);
		return (EINVAL);
	}

	*aflags = flags;
	return (0);
#undef CONVERT
}

/*
 * Convert from 9P2000.L (Linux) open mode bits to O_* flags.
 * See fs_oflags_dotu above.
 *
 * Linux currently does not have open-for-exec, but there is a
 * proposal for it using O_PATH|O_NOFOLLOW, now handled here.
 *
 * We may eventually also set L9P_ORCLOSE for L_O_TMPFILE.
 */
static int
fs_oflags_dotl(uint32_t l_mode, int *aflags, enum l9p_omode *ap9)
{
	int flags;
	enum l9p_omode p9;
#define	CLEAR(theirs)	l_mode &= ~(uint32_t)(theirs)
#define	CONVERT(theirs, ours) \
	do { \
		if (l_mode & (theirs)) { \
			CLEAR(theirs); \
			flags |= ours; \
		} \
	} while (0)

	/*
	 * Linux O_RDONLY, O_WRONLY, O_RDWR (0,1,2) match BSD/MacOS.
	 */
	flags = l_mode & O_ACCMODE;
	if (flags == 3)
		return (EINVAL);
	CLEAR(O_ACCMODE);

	if ((l_mode & (L9P_L_O_PATH | L9P_L_O_NOFOLLOW)) ==
		    (L9P_L_O_PATH | L9P_L_O_NOFOLLOW)) {
		CLEAR(L9P_L_O_PATH | L9P_L_O_NOFOLLOW);
		p9 = L9P_OEXEC;
	} else {
		/*
		 * Slightly dirty, but same dirt, really, as
		 * setting flags from l_mode & O_ACCMODE.
		 */
		p9 = (enum l9p_omode)flags;	/* slightly dirty */
	}

	/* turn L_O_TMPFILE into L9P_ORCLOSE in *p9? */
	if (l_mode & L9P_L_O_TRUNC)
		p9 |= L9P_OTRUNC;	/* but don't CLEAR yet */

	flags |= O_NOCTTY | O_NOFOLLOW;

	/*
	 * L_O_CREAT seems to be noise, since we get separate open
	 * and create.  But it is actually set sometimes.  We just
	 * throw it out here; create ops must set it themselves and
	 * open ops have no permissions bits and hence cannot create.
	 *
	 * L_O_EXCL does make sense on create ops, i.e., we can
	 * take a create op with or without L_O_EXCL.  We pass that
	 * through.
	 */
	CLEAR(L9P_L_O_CREAT);
	CONVERT(L9P_L_O_EXCL, O_EXCL);
	CONVERT(L9P_L_O_TRUNC, O_TRUNC);
	CONVERT(L9P_L_O_DIRECTORY, O_DIRECTORY);
	CONVERT(L9P_L_O_APPEND, O_APPEND);
	CONVERT(L9P_L_O_NONBLOCK, O_NONBLOCK);

	/*
	 * Discard these as useless noise at our (server) end.
	 * (NOATIME might be useful but we can only set it on a
	 * per-mount basis.)
	 */
	CLEAR(L9P_L_O_CLOEXEC);
	CLEAR(L9P_L_O_DIRECT);
	CLEAR(L9P_L_O_DSYNC);
	CLEAR(L9P_L_O_FASYNC);
	CLEAR(L9P_L_O_LARGEFILE);
	CLEAR(L9P_L_O_NOATIME);
	CLEAR(L9P_L_O_NOCTTY);
	CLEAR(L9P_L_O_NOFOLLOW);
	CLEAR(L9P_L_O_SYNC);

	if (l_mode != 0) {
		L9P_LOG(L9P_INFO,
		    "fs_oflags_dotl: untranslated bits: %#x",
		    (unsigned)l_mode);
		return (EINVAL);
	}

	*aflags = flags;
	*ap9 = p9;
	return (0);
#undef CLEAR
#undef CONVERT
}

/*
 * Build full name of file by appending given name to directory name.
 */
static int
fs_buildname(struct l9p_fid *dir, char *name, char *buf, size_t size)
{
	struct openfile *dirf = dir->lo_aux;
	size_t dlen, nlen1;

	assert(dirf != NULL);
	dlen = strlen(dirf->name);
	nlen1 = strlen(name) + 1;	/* +1 for '\0' */
	if (dlen + 1 + nlen1 > size)
		return (ENAMETOOLONG);
	memcpy(buf, dirf->name, dlen);
	buf[dlen] = '/';
	memcpy(buf + dlen + 1, name, nlen1);
	return (0);
}

/*
 * Allocate new open-file data structure to attach to a fid.
 */
static struct openfile *
open_fid(const char *path)
{
	struct openfile *ret;

	ret = l9p_calloc(1, sizeof(*ret));
	ret->fd = -1;
	ret->name = strdup(path);
	if (ret->name == NULL) {
		free(ret);
		return (NULL);
	}
	return (ret);
}

static void
dostat(struct l9p_stat *s, char *name, struct stat *buf, bool dotu)
{
	struct passwd *user;
	struct group *group;

	memset(s, 0, sizeof(struct l9p_stat));

	generate_qid(buf, &s->qid);

	s->type = 0;
	s->dev = 0;
	s->mode = buf->st_mode & 0777;

	if (S_ISDIR(buf->st_mode))
		s->mode |= L9P_DMDIR;

	if (S_ISLNK(buf->st_mode) && dotu)
		s->mode |= L9P_DMSYMLINK;

	if (S_ISCHR(buf->st_mode) || S_ISBLK(buf->st_mode))
		s->mode |= L9P_DMDEVICE;

	if (S_ISSOCK(buf->st_mode))
		s->mode |= L9P_DMSOCKET;

	if (S_ISFIFO(buf->st_mode))
		s->mode |= L9P_DMNAMEDPIPE;

	s->atime = (uint32_t)buf->st_atime;
	s->mtime = (uint32_t)buf->st_mtime;
	s->length = (uint64_t)buf->st_size;

	s->name = r_basename(name, NULL, 0);

	if (!dotu) {
		struct r_pgdata udata, gdata;

		user = r_getpwuid(buf->st_uid, &udata);
		group = r_getgrgid(buf->st_gid, &gdata);
		s->uid = user != NULL ? strdup(user->pw_name) : NULL;
		s->gid = group != NULL ? strdup(group->gr_name) : NULL;
		s->muid = user != NULL ? strdup(user->pw_name) : NULL;
		r_pgfree(&udata);
		r_pgfree(&gdata);
	} else {
		/*
		 * When using 9P2000.u, we don't need to bother about
		 * providing user and group names in textual form.
		 *
		 * NB: if the asprintf()s fail, s->extension should
		 * be unset so we can ignore these.
		 */
		s->n_uid = buf->st_uid;
		s->n_gid = buf->st_gid;
		s->n_muid = buf->st_uid;

		if (S_ISLNK(buf->st_mode)) {
			char target[MAXPATHLEN];
			ssize_t ret = readlink(name, target, MAXPATHLEN);

			if (ret < 0) {
				s->extension = NULL;
				return;
			}

			s->extension = strndup(target, (size_t)ret);
		}

		if (S_ISBLK(buf->st_mode)) {
			asprintf(&s->extension, "b %d %d", major(buf->st_rdev),
			    minor(buf->st_rdev));
		}

		if (S_ISCHR(buf->st_mode)) {
			asprintf(&s->extension, "c %d %d", major(buf->st_rdev),
			    minor(buf->st_rdev));
		}
	}
}

static void dostatfs(struct l9p_statfs *out, struct statfs *in, long namelen)
{

	out->type = L9P_FSTYPE;
	out->bsize = in->f_bsize;
	out->blocks = in->f_blocks;
	out->bfree = in->f_bfree;
	out->bavail = in->f_bavail;
	out->files = in->f_files;
	out->ffree = in->f_ffree;
	out->fsid = ((uint64_t)in->f_fsid.val[0] << 32) | (uint64_t)in->f_fsid.val[1];
	out->namelen = (uint32_t)namelen;
}

static void
generate_qid(struct stat *buf, struct l9p_qid *qid)
{
	qid->path = buf->st_ino;
	qid->version = 0;

	if (S_ISREG(buf->st_mode))
		qid->type |= L9P_QTFILE;

	if (S_ISDIR(buf->st_mode))
		qid->type |= L9P_QTDIR;

	if (S_ISLNK(buf->st_mode))
		qid->type |= L9P_QTSYMLINK;
}

static bool
check_access(struct stat *st, uid_t uid, gid_t gid, enum l9p_omode omode)
{
	struct passwd *pwd = NULL;
#ifdef __FreeBSD__	/* XXX need better way to determine this */
	gid_t groups[NGROUPS_MAX];
#else
	int groups[NGROUPS_MAX];
#endif
	int ngroups = NGROUPS_MAX;
	int i, mask;

	if (uid == 0)
		return (true);

	/*
	 * This is a bit dirty (using the well known mode bits instead
	 * of the S_I[RWX]{USR,GRP,OTH} macros), but lets us be very
	 * efficient about it.
	 *
	 * Note that L9P_OTRUNC requires write access to the file.
	 * (L9P_ORCLOSE requires write access to the parent directory,
	 * but the caller must do that check.)
	 */
	switch (omode & L9P_OACCMODE) {
	case L9P_ORDWR:
		mask = 0600;
		break;
	case L9P_OREAD:
	default:
		mask = 0400;
		break;
	case L9P_OWRITE:
		mask = 0200;
		break;
	case L9P_OEXEC:
		mask = 0100;
		break;
	}
	if (omode & L9P_OTRUNC)
		mask |= 0400;

	/*
	 * Normal Unix semantics are: apply user permissions first
	 * and if these fail, reject the request entirely.  Current
	 * lib9p semantics go on to allow group or other as well.
	 *
	 * Also, we check "other" before "group" because group check
	 * is expensive.  (Perhaps should cache uid -> gid mappings?)
	 */
	if (st->st_uid == uid) {
		if ((st->st_mode & mask) == mask)
			return (true);
	}

	/* Check for "other" access */
	mask >>= 6;
	if ((st->st_mode & mask) == mask)
		return (true);

	/* Check for group access - XXX: not thread safe */
	mask <<= 3;
	pwd = getpwuid(uid);

	if (pwd != NULL && gid == (gid_t)-1)
		/* Passed-in gid (if any) takes precedence */
		gid = pwd->pw_gid;

	if (pwd == NULL && gid == (gid_t)-1)
		/*
		 * At this point we don't know know the gid and we can't
		 * look it up - refusing access is all we can do.
		 */
		return (false);

	if (pwd != NULL)
		getgrouplist(pwd->pw_name, (int)gid, groups, &ngroups);
	else {
		/* Use passed-in gid (guaranteed to be valid at this point) */
		ngroups = 1;
		groups[0] = (int)gid;
	}

	for (i = 0; i < ngroups; i++) {
		if (st->st_gid == (gid_t)groups[i]) {
			if ((st->st_mode & mask) == mask)
				return (true);
		}
	}

	return (false);
}

static int
fs_attach(void *softc, struct l9p_request *req)
{
	struct fs_softc *sc = (struct fs_softc *)softc;
	struct openfile *file;
	struct passwd *pwd;
	struct stat st;
	uid_t uid;
	int error;

	assert(req->lr_fid != NULL);

	uid = req->lr_req.tattach.n_uname;
	if (req->lr_conn->lc_version >= L9P_2000U && uid != (uid_t)-1) {
		pwd = getpwuid(uid);
		if (pwd == NULL)
			L9P_LOG(L9P_DEBUG,
			    "Tattach: uid %lu: no such user",
			    (u_long)uid);
	} else {
		pwd = getpwnam(req->lr_req.tattach.uname);
		if (pwd == NULL)
			L9P_LOG(L9P_DEBUG,
			    "Tattach: %s: no such user",
			    req->lr_req.tattach.uname);
	}

	if (pwd == NULL && req->lr_conn->lc_version != L9P_2000L)
		return (EPERM);

	error = 0;
	if (lstat(sc->fs_rootpath, &st) != 0)
		error = errno;
	else if (!S_ISDIR(st.st_mode))
		error = ENOTDIR;
	if (error) {
		L9P_LOG(L9P_DEBUG,
		    "Tattach: denying access to \"%s\": %s",
		    sc->fs_rootpath, strerror(error));
		/*
		 * Pass ENOENT and ENOTDIR through for diagnosis;
		 * others become EPERM.  This should not leak too
		 * much security.
		 */
		return (error == ENOENT || error == ENOTDIR ? error : EPERM);
	}

	file = open_fid(sc->fs_rootpath);
	if (file == NULL)
		return (ENOMEM);

	file->uid = pwd != NULL ? pwd->pw_uid : uid;
	file->gid = pwd != NULL ? pwd->pw_gid : (uid_t)-1;
	req->lr_fid->lo_aux = file;
	generate_qid(&st, &req->lr_resp.rattach.qid);
	return (0);
}

static int
fs_clunk(void *softc __unused, struct l9p_request *req)
{
	struct openfile *file;

	file = req->lr_fid->lo_aux;
	assert(file != NULL);

	if (file->dir) {
		closedir(file->dir);
		file->dir = NULL;
	} else if (file->fd != -1) {
		close(file->fd);
		file->fd = -1;
	}

	return (0);
}

/*
 * Internal helpers for create ops.
 *
 * Currently these are mostly trivial since this is meant to be
 * semantically identical to the previous version of the code, but
 * they will be modified to handle additional details correctly in
 * a subsequent commit.
 */
static inline int
internal_mkdir(char *newname, mode_t mode, struct stat *st)
{

	/*
	 * https://swtch.com/plan9port/man/man9/open.html
	 * says that permissions are actually
	 * perm & (~0777 | (dir.perm & 0777)).
	 * This seems a bit restrictive; probably
	 * there should be a control knob for this.
	 */
	mode &= (~0777 | (st->st_mode & 0777));
	if (mkdir(newname, mode) != 0)
		return (errno);
	return (0);
}

static inline int
internal_symlink(char *symtgt, char *newname)
{

	if (symlink(symtgt, newname) != 0)
		return (errno);
	return (0);
}

static inline int
internal_mkfifo(char *newname, mode_t mode)
{

	if (mkfifo(newname, mode) != 0)
		return (errno);
	return (0);
}


static inline int
internal_mksocket(struct openfile *file __unused, char *newname,
    char *reqname __unused)
{
	struct sockaddr_un sun;
	char *path;
	int error = 0;
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	int fd;

	if (s < 0)
		return (errno);

	path = newname;
	fd = -1;
#ifdef HAVE_BINDAT
	/* Try bindat() if needed. */
	if (strlen(path) >= sizeof(sun.sun_path)) {
		fd = open(file->name, O_RDONLY | O_NOFOLLOW);
		if (fd >= 0)
			path = reqname;
	}
#endif

	/*
	 * Can only create the socket if the path will fit.
	 * Even if we are using bindat() there are limits
	 * (the API for AF_UNIX sockets is ... not good).
	 *
	 * Note: in theory we can fill sun_path to the end
	 * (omitting a terminating '\0') but in at least one
	 * Unix-like system, this was known to behave oddly,
	 * so we test for ">=" rather than just ">".
	 */
	if (strlen(path) >= sizeof(sun.sun_path)) {
		error = ENAMETOOLONG;
		goto out;
	}
	sun.sun_family = AF_UNIX;
	sun.sun_len = sizeof(struct sockaddr_un);
	strncpy(sun.sun_path, path, sizeof(sun.sun_path));

#ifdef HAVE_BINDAT
	if (fd >= 0) {
		if (bindat(fd, s, (struct sockaddr *)&sun, sun.sun_len) < 0)
			error = errno;
		goto out;	/* done now, for good or ill */
	}
#endif

	if (bind(s, (struct sockaddr *)&sun, sun.sun_len) < 0)
		error = errno;
out:

	/*
	 * It's not clear which error should override, although
	 * ideally we should never see either close() call fail.
	 * In any case we do want to try to close both fd and s,
	 * always.  Let's set error only if it is not already set,
	 * so that all exit paths can use the same code.
	 */
	if (fd >= 0 && close(fd) != 0)
		if (error == 0)
			error = errno;
	if (close(s) != 0)
		if (error == 0)
			error = errno;

	return (error);
}

static inline int
internal_mknod(struct l9p_request *req, char *newname, mode_t mode)
{
	char type;
	unsigned int major, minor;

	/*
	 * ??? Should this be testing < 3?  For now, allow a single
	 * integer mode with minor==0 implied.
	 */
	minor = 0;
	if (sscanf(req->lr_req.tcreate.extension, "%c %u %u",
	    &type, &major, &minor) < 2) {
		return (EINVAL);
	}

	switch (type) {
	case 'b':
		mode |= S_IFBLK;
		break;
	case 'c':
		mode |= S_IFCHR;
		break;
	default:
		return (EINVAL);
	}
	if (mknod(newname, mode, makedev(major, minor)) != 0)
		return (errno);
	return (0);
}

/*
 * Create ops.
 *
 * We are to create a new file under some existing path,
 * where the new file's name is in the Tcreate request and the
 * existing path is due to a fid-based file (req->lr_fid_lo_aux).
 *
 * Some ops (regular open) set file->fd, most do not.
 */
static int
fs_create(void *softc, struct l9p_request *req)
{
	struct fs_softc *sc = softc;
	struct openfile *file;
	struct l9p_fid *dir;
	struct stat st;
	mode_t mode;
	char *name;
	char newname[MAXPATHLEN];
	int error;

	if (sc->fs_readonly)
		return (EROFS);

	dir = req->lr_fid;
	name = req->lr_req.tcreate.name;

	error = fs_buildname(dir, name, newname, sizeof(newname));
	if (error)
		return (error);

	/*
	 * Containing directory must exist and allow access.
	 *
	 * There is a race here between test and subsequent
	 * operation, which we cannot close in general, but
	 * ideally, no one should be changing things underneath
	 * us.  It might therefore also be nice to keep cached
	 * lstat data, but we leave that to future optimization
	 * (after profiling).
	 */
	file = dir->lo_aux;
	if (lstat(file->name, &st) != 0)
		return (errno);
	if (!S_ISDIR(st.st_mode))
		return (ENOTDIR);
	if (!check_access(&st, file->uid, file->gid, L9P_OWRITE))
		return (EPERM);

	mode = req->lr_req.tcreate.perm & 0777;

	if (req->lr_req.tcreate.perm & L9P_DMDIR)
		error = internal_mkdir(newname, mode, &st);
	else if (req->lr_req.tcreate.perm & L9P_DMSYMLINK)
		error = internal_symlink(req->lr_req.tcreate.extension,
		    newname);
	else if (req->lr_req.tcreate.perm & L9P_DMNAMEDPIPE)
		error = internal_mkfifo(newname, mode);
	else if (req->lr_req.tcreate.perm & L9P_DMSOCKET)
		error = internal_mksocket(file, newname,
		    req->lr_req.tcreate.name);
	else if (req->lr_req.tcreate.perm & L9P_DMDEVICE)
		error = internal_mknod(req, newname, mode);
	else {
		enum l9p_omode p9;
		int flags;

		p9 = req->lr_req.tcreate.mode;
		error = fs_oflags_dotu(p9, &flags);
		if (error)
			return (error);
		/*
		 * https://swtch.com/plan9port/man/man9/open.html and
		 * http://plan9.bell-labs.com/magic/man2html/5/open
		 * both say that permissions are actually
		 * perm & (~0666 | (dir.perm & 0666)).
		 * This seems a bit restrictive; probably
		 * there should be a control knob for this.
		 */
		mode &= (~0666 | st.st_mode) & 0666;

		/* Create is always exclusive so O_TRUNC is irrelevant. */
		file->fd = open(newname, flags | O_CREAT | O_EXCL, mode);
		if (file->fd < 0)
			error = errno;
	}

	if (error)
		return (error);

	if (lchown(newname, file->uid, file->gid) != 0 ||
	    lstat(newname, &st) != 0)
		return (errno);

	generate_qid(&st, &req->lr_resp.rcreate.qid);
	return (error);
}

static int
fs_flush(void *softc __unused, struct l9p_request *req __unused)
{

	/* XXX: not used because this transport is synchronous */
	return (0);
}

/*
 * Internal form of open: stat file and verify permissions (from p9
 * argument), then open the file-or-directory, leaving the internal
 * openfile fields set up.  If we cannot open the file, return a
 * suitable error number, and leave everything unchanged.
 *
 * To mitigate the race between permissions testing and the actual
 * open, we can stat the file twice (once with lstat() before open,
 * then with fstat() after).  We assume O_NOFOLLOW is set in flags,
 * so if some other race-winner substitutes in a symlink we won't
 * open it here.  (However, embedded symlinks, if they occur, are
 * still an issue.  Ideally we would like to have an O_NEVERFOLLOW
 * that fails on embedded symlinks, and a way to pass this to
 * lstat() as well.)
 *
 * When we use opendir() we cannot pass O_NOFOLLOW, so we must rely
 * on substitution-detection via fstat().  To simplify the code we
 * just always re-check.
 *
 * (For a proper fix in the future, we can require openat(), keep
 * each parent directory open during walk etc, and allow only final
 * name components with O_NOFOLLOW.)
 *
 * On successful return, st has been filled in.
 */
static int
fs_iopen(void *softc, struct l9p_fid *fid, int flags, enum l9p_omode p9,
    struct stat *stp)
{
	struct fs_softc *sc = softc;
	struct openfile *file;
	struct stat first;
	char *name;
	int fd;
	DIR *dirp;

	/* Forbid write ops on read-only file system. */
	if (sc->fs_readonly) {
		if ((flags & O_TRUNC) != 0)
			return (EROFS);
		if ((flags & O_ACCMODE) != O_RDONLY)
			return (EROFS);
		if (p9 & L9P_ORCLOSE)
			return (EROFS);
	}

	file = fid->lo_aux;
	assert(file != NULL);
	name = file->name;

	if (lstat(name, &first) != 0)
		return (errno);
	if (S_ISLNK(first.st_mode))
		return (EPERM);
	if (!check_access(&first, file->uid, file->gid, p9))
		return (EPERM);

	if (S_ISDIR(first.st_mode)) {
		/* Forbid write or truncate on directory. */
		if ((flags & O_ACCMODE) != O_RDONLY || (flags & O_TRUNC))
			return (EPERM);
		dirp = opendir(name);
		if (dirp == NULL)
			return (EPERM);
		fd = dirfd(dirp);
	} else {
		dirp = NULL;
		fd = open(name, flags);
		if (fd < 0)
			return (EPERM);
	}

	/*
	 * We have a valid fd, and maybe non-null dirp.  Re-check
	 * the file, and fail if st_dev or st_ino changed.
	 */
	if (fstat(fd, stp) != 0 ||
	    first.st_dev != stp->st_dev ||
	    first.st_ino != stp->st_ino) {
		if (dirp != NULL)
			(void) closedir(dirp);
		else
			(void) close(fd);
		return (EPERM);
	}
	if (dirp != NULL)
		file->dir = dirp;
	else
		file->fd = fd;
	return (0);
}

static int
fs_open(void *softc, struct l9p_request *req)
{
	struct l9p_fid *fid = req->lr_fid;
	struct stat st;
	enum l9p_omode p9;
	int error, flags;

	p9 = req->lr_req.topen.mode;
	error = fs_oflags_dotu(p9, &flags);
	if (error)
		return (error);

	error = fs_iopen(softc, fid, flags, p9, &st);
	if (error)
		return (error);

	generate_qid(&st, &req->lr_resp.ropen.qid);
	req->lr_resp.ropen.iounit = req->lr_conn->lc_max_io_size;
	return (0);
}

/*
 * Helper for directory read.  We want to run an lstat on each
 * file name within the directory.  This is a lot faster if we
 * have lstatat (or fstatat with AT_SYMLINK_NOFOLLOW), but not
 * all systems do, so hide the ifdef-ed code in an inline function.
 */
static inline int
fs_lstatat(struct openfile *file, char *name, struct stat *st)
{
#ifdef HAVE_FSTATAT
	return (fstatat(dirfd(file->dir), name, st, AT_SYMLINK_NOFOLLOW));
#else
	char buf[MAXPATHLEN];

	if (strlcpy(buf, file->name, sizeof(buf)) >= sizeof(buf) ||
	    strlcat(buf, name, sizeof(buf)) >= sizeof(buf))
		return (-1);
	return (lstat(name, st));
#endif
}

static int
fs_read(void *softc __unused, struct l9p_request *req)
{
	struct openfile *file;
	struct l9p_stat l9stat;
	bool dotu = req->lr_conn->lc_version >= L9P_2000U;
	ssize_t ret;

	file = req->lr_fid->lo_aux;
	assert(file != NULL);

	if (file->dir != NULL) {
		struct dirent *d;
		struct stat st;
		struct l9p_message msg;
		long o;

		/*
		 * Must use telldir before readdir since seekdir
		 * takes cookie values.  Unfortunately this wastes
		 * a lot of time (and memory) building unneeded
		 * cookies that can only be flushed by closing
		 * the directory.
		 *
		 * NB: FreeBSD libc seekdir has SINGLEUSE defined,
		 * so in fact, we can discard the cookies by
		 * calling seekdir on them.  This clears up wasted
		 * memory at the cost of even more wasted time...
		 *
		 * XXX: readdir/telldir/seekdir not thread safe
		 */
		l9p_init_msg(&msg, req, L9P_PACK);
		for (;;) {
			o = telldir(file->dir);
			d = readdir(file->dir);
			if (d == NULL)
				break;
			if (fs_lstatat(file, d->d_name, &st))
				continue;
			dostat(&l9stat, d->d_name, &st, dotu);
			if (l9p_pack_stat(&msg, req, &l9stat) != 0) {
				seekdir(file->dir, o);
				break;
			}
#if defined(__FreeBSD__)
			seekdir(file->dir, o);
			(void) readdir(file->dir);
#endif
		}
	} else {
		size_t niov = l9p_truncate_iov(req->lr_data_iov,
                    req->lr_data_niov, req->lr_req.io.count);

#if defined(__FreeBSD__)
		ret = preadv(file->fd, req->lr_data_iov, niov,
		    req->lr_req.io.offset);
#else
		/* XXX: not thread safe, should really use aio_listio. */
		if (lseek(file->fd, (off_t)req->lr_req.io.offset, SEEK_SET) < 0)
			return (errno);

		ret = (uint32_t)readv(file->fd, req->lr_data_iov, (int)niov);
#endif

		if (ret < 0)
			return (errno);

		req->lr_resp.io.count = (uint32_t)ret;
	}

	return (0);
}

static int
fs_remove(void *softc, struct l9p_request *req)
{
	struct fs_softc *sc = softc;
	struct openfile *file;
	struct stat st;

	file = req->lr_fid->lo_aux;
	assert(file);

	if (sc->fs_readonly)
		return (EROFS);

	if (lstat(file->name, &st) != 0)
		return (errno);

	if (!check_access(&st, file->uid, file->gid, L9P_OWRITE))
		return (EPERM);

	if (S_ISDIR(st.st_mode)) {
		if (rmdir(file->name) != 0)
			return (errno);
	} else {
		if (unlink(file->name) != 0)
			return (errno);
	}

	return (0);
}

static int
fs_stat(void *softc __unused, struct l9p_request *req)
{
	struct openfile *file;
	struct stat st;
	bool dotu = req->lr_conn->lc_version >= L9P_2000U;

	file = req->lr_fid->lo_aux;
	assert(file);

	lstat(file->name, &st);
	dostat(&req->lr_resp.rstat.stat, file->name, &st, dotu);

	return (0);
}

static int
fs_walk(void *softc, struct l9p_request *req)
{
	struct fs_softc *sc = softc;
	struct stat st;
	struct openfile *file = req->lr_fid->lo_aux;
	struct openfile *newfile;
	size_t clen, namelen, need;
	char *comp, *succ, *next, *swtmp;
	bool atroot;
	bool dotdot;
	int i, nwname;
	int error = 0;
	char namebufs[2][MAXPATHLEN];

	/*
	 * https://swtch.com/plan9port/man/man9/walk.html:
	 *
	 *    It is legal for nwname to be zero, in which case newfid
	 *    will represent the same file as fid and the walk will
	 *    usually succeed; this is equivalent to walking to dot.
	 * [Aside: it's not clear if we should test S_ISDIR here.]
	 *    ...
	 *    The name ".." ... represents the parent directory.
	 *    The name "." ... is not used in the protocol.
	 *    ... A walk of the name ".." in the root directory
	 *    of the server is equivalent to a walk with no name
	 *    elements.
	 *
	 * Note that req.twalk.nwname never exceeds L9P_MAX_WELEM,
	 * so it is safe to convert to plain int.
	 *
	 * We are to return an error only if the first walk fails,
	 * else stop at the end of the names or on the first error.
	 * The final fid is based on the last name successfully
	 * walked.
	 *
	 * Note that we *do* get Twalk requests with nwname==0 on files.
	 *
	 * Set up "successful name" buffer pointer with base fid name,
	 * initially.  We'll swap each new success into it as we go.
	 *
	 * Invariant: atroot and stat data correspond to current
	 * (succ) path.
	 */
	succ = namebufs[0];
	next = namebufs[1];
	namelen = strlcpy(succ, file->name, MAXPATHLEN);
	if (namelen >= MAXPATHLEN)
		return (ENAMETOOLONG);
	if (lstat(succ, &st) < 0)
		return (errno);
	atroot = strcmp(succ, sc->fs_rootpath) == 0;

	nwname = (int)req->lr_req.twalk.nwname;

	for (i = 0; i < nwname; i++) {
		/*
		 * Must have execute permission to search a directory.
		 * Then, look up each component in its directory-so-far.
		 * Check for ".." along the way, handlng specially
		 * as needed.  Forbid "/" in name components.
		 *
		 */
		if (!S_ISDIR(st.st_mode)) {
			error = ENOTDIR;
			goto out;
		}
		if (!check_access(&st, file->uid, file->gid, L9P_OEXEC)) {
			L9P_LOG(L9P_DEBUG,
			    "Twalk: denying dir-walk on \"%s\" for uid %u",
			    succ, (unsigned)file->uid);
			error = EPERM;
			goto out;
		}
		comp = req->lr_req.twalk.wname[i];
		if (strchr(comp, '/') != NULL) {
			error = EINVAL;
			break;
		}

		clen = strlen(comp);
		dotdot = false;

		/*
		 * Build next pathname (into "next").  If "..",
		 * just strip one name component off the success
		 * name so far.  Since we know this name fits, the
		 * stripped down version also fits.  Otherwise,
		 * the name is the base name plus '/' plus the
		 * component name plus terminating '\0'; this may
		 * or may not fit.
		 */
		if (comp[0] == '.') {
			if (clen == 1) {
				error = EINVAL;
				break;
			}
			if (comp[1] == '.' && clen == 2)
				dotdot = true;
		}
		if (dotdot) {
			/*
			 * It's not clear how ".." at root should
			 * be handled when i > 0.  Obeying the man
			 * page exactly, we reset i to 0 and stop,
			 * declaring terminal success.
			 *
			 * Otherwise, we just climbed up one level
			 * so adjust "atroot".
			 */
			if (atroot) {
				i = 0;
				break;
			}
			(void) r_dirname(succ, next, MAXPATHLEN);
			namelen = strlen(next);
			atroot = strcmp(next, sc->fs_rootpath) == 0;
		} else {
			need = namelen + 1 + clen + 1;
			if (need > MAXPATHLEN) {
				error = ENAMETOOLONG;
				break;
			}
			memcpy(next, file->name, namelen);
			next[namelen++] = '/';
			memcpy(&next[namelen], comp, clen + 1);
			namelen += clen;
			/*
			 * Since name is never ".", we are necessarily
			 * descending below the root now.
			 */
			atroot = false;
		}

		if (lstat(next, &st) < 0) {
			error = ENOENT;
			break;
		}

		/*
		 * Success: generate qid and swap this
		 * successful name into place.
		 */
		generate_qid(&st, &req->lr_resp.rwalk.wqid[i]);
		swtmp = succ;
		succ = next;
		next = swtmp;
	}

	/*
	 * Fail only if we failed on the first name.
	 * Otherwise we succeeded on something, and "succ"
	 * points to the last successful name in namebufs[].
	 */
	if (error) {
		if (i == 0)
			goto out;
		error = 0;
	}

	newfile = open_fid(succ);
	if (newfile == NULL) {
		error = ENOMEM;
		goto out;
	}
	newfile->uid = file->uid;
	newfile->gid = file->gid;
	req->lr_newfid->lo_aux = newfile;
	req->lr_resp.rwalk.nwqid = (uint16_t)i;
out:
	return (error);
}

static int
fs_write(void *softc, struct l9p_request *req)
{
	struct fs_softc *sc = softc;
	struct openfile *file;
	ssize_t ret;

	file = req->lr_fid->lo_aux;
	assert(file != NULL);

	if (sc->fs_readonly)
		return (EROFS);

	size_t niov = l9p_truncate_iov(req->lr_data_iov,
            req->lr_data_niov, req->lr_req.io.count);

#if defined(__FreeBSD__)
	ret = pwritev(file->fd, req->lr_data_iov, niov,
	    req->lr_req.io.offset);
#else
	/* XXX: not thread safe, should really use aio_listio. */
	if (lseek(file->fd, (off_t)req->lr_req.io.offset, SEEK_SET) < 0)
		return (errno);

	ret = writev(file->fd, req->lr_data_iov,
	    (int)niov);
#endif

	if (ret < 0)
		return (errno);

	req->lr_resp.io.count = (uint32_t)ret;
	return (0);
}

static int
fs_wstat(void *softc, struct l9p_request *req)
{
	struct fs_softc *sc = softc;
	struct openfile *file;
	struct l9p_stat *l9stat = &req->lr_req.twstat.stat;
	int error = 0;

	file = req->lr_fid->lo_aux;
	assert(file != NULL);

	/*
	 * XXX:
	 *
	 * stat(9P) sez:
	 *
	 * Either all the changes in wstat request happen, or none of them
	 * does: if the request succeeds, all changes were made; if it fails,
	 * none were.
	 *
	 * Atomicity is clearly missing in current implementation.
	 */

	if (sc->fs_readonly)
		return (EROFS);

	if (l9stat->atime != (uint32_t)~0) {
		/* XXX: not implemented, ignore */
	}

	if (l9stat->mtime != (uint32_t)~0) {
		/* XXX: not implemented, ignore */
	}

	if (l9stat->dev != (uint32_t)~0) {
		error = EPERM;
		goto out;
	}

	if (l9stat->length != (uint64_t)~0) {
		if (file->dir != NULL) {
			error = EINVAL;
			goto out;
		}

		if (truncate(file->name, (off_t)l9stat->length) != 0) {
			error = errno;
			goto out;
		}
	}

	if (req->lr_conn->lc_version >= L9P_2000U) {
		if (lchown(file->name, l9stat->n_uid, l9stat->n_gid) != 0) {
			error = errno;
			goto out;
		}
	}

	if (l9stat->mode != (uint32_t)~0) {
		if (chmod(file->name, l9stat->mode & 0777) != 0) {
			error = errno;
			goto out;
		}
	}

	if (strlen(l9stat->name) > 0) {
		char *dir;
		char *newname;
		char *tmp;

		/* Forbid renaming root fid. */
		if (strcmp(file->name, sc->fs_rootpath) == 0) {
			error = EINVAL;
			goto out;
		}
		dir = r_dirname(file->name, NULL, 0);
		if (dir == NULL) {
			error = errno;
			goto out;
		}
		if (asprintf(&newname, "%s/%s", dir, l9stat->name) < 0) {
			error = errno;
			free(dir);
			goto out;
		}
		if (rename(file->name, newname))
			error = errno;
		else {
			/* Successful rename, update file->name. */
			tmp = newname;
			newname = file->name;
			file->name = tmp;
		}
		free(newname);
		free(dir);
	}
out:
	return (error);
}

static int
fs_statfs(void *softc __unused, struct l9p_request *req)
{
	struct openfile *file;
	struct stat st;
	struct statfs f;
	long name_max;

	file = req->lr_fid->lo_aux;
	assert(file);

	if (lstat(file->name, &st) != 0)
		return (errno);

	if (!check_access(&st, file->uid, file->gid, L9P_OREAD))
		return (EPERM);

	if (statfs(file->name, &f) != 0)
		return (errno);

	name_max = pathconf(file->name, _PC_NAME_MAX);
	if (name_max == -1)
		return (errno);

	dostatfs(&req->lr_resp.rstatfs.statfs, &f, name_max);

	return (0);
}

static int
fs_lopen(void *softc, struct l9p_request *req)
{
	struct l9p_fid *fid = req->lr_fid;
	struct stat st;
	enum l9p_omode p9;
	int error, flags;

	error = fs_oflags_dotl(req->lr_req.tlopen.flags, &flags, &p9);
	if (error)
		return (error);

	error = fs_iopen(softc, fid, flags, p9, &st);
	if (error)
		return (error);

	generate_qid(&st, &req->lr_resp.rlopen.qid);
	req->lr_resp.rlopen.iounit = req->lr_conn->lc_max_io_size;
	return (0);
}

static int
fs_lcreate(void *softc, struct l9p_request *req)
{
	struct fs_softc *sc = softc;
	struct openfile *file;
	struct l9p_fid *dir;
	struct stat st;
	enum l9p_omode p9;
	char *name;
	char newname[MAXPATHLEN];
	int error, fd, flags;

	if (sc->fs_readonly)
		return (EROFS);

	dir = req->lr_fid;
	name = req->lr_req.tlcreate.name;

	error = fs_buildname(dir, name, newname, sizeof(newname));
	if (error)
		return (error);

	error = fs_oflags_dotl(req->lr_req.tlcreate.flags, &flags, &p9);
	if (error)
		return (error);

	/*
	 * XXX racy, see fs_create.
	 * Note, file->name is testing the containing dir,
	 * not the file itself.
	 */
	file = dir->lo_aux;
	if (lstat(file->name, &st) != 0)
		return (errno);
	if (!S_ISDIR(st.st_mode))
		return (ENOTDIR);
	if (!check_access(&st, file->uid, req->lr_req.tlcreate.gid, L9P_OWRITE))
		return (EPERM);
	fd = open(newname, flags | O_CREAT | O_EXCL, req->lr_req.tlcreate.mode);
	if (fd < 0)
		return (errno);
	file->fd = fd;
	if (fchown(fd, file->uid, req->lr_req.tlcreate.gid) != 0)
		return (errno);
	if (fstat(fd, &st) != 0)
		return (errno);

	generate_qid(&st, &req->lr_resp.rlcreate.qid);
	req->lr_resp.rlcreate.iounit = req->lr_conn->lc_max_io_size;
	return (0);
}

/*
 * Could use a bit more work to reduce code duplication with fs_create.
 */
static int
fs_symlink(void *softc, struct l9p_request *req)
{
	struct fs_softc *sc = softc;
	struct openfile *file;
	struct l9p_fid *dir;
	struct stat st;
	char *name;
	char newname[MAXPATHLEN];
	int error;

	if (sc->fs_readonly)
		return (EROFS);

	dir = req->lr_fid;
	name = req->lr_req.tsymlink.name;
	error = fs_buildname(dir, name, newname, sizeof(newname));
	if (error)
		return (error);

	file = dir->lo_aux;

	if (lstat(file->name, &st) != 0)
		return (errno);
	if (!check_access(&st, file->uid, file->gid, L9P_OWRITE))
		return (EPERM);

	error = internal_symlink(req->lr_req.tsymlink.symtgt, newname);
	if (error)
		return (error);

	if (lchown(newname, file->uid, req->lr_req.tsymlink.gid) != 0 ||
	    lstat(newname, &st) != 0)
		return (errno);

	generate_qid(&st, &req->lr_resp.rsymlink.qid);
	return (0);
}

/*
 * Could use a bit more work to reduce code duplication.
 */
static int
fs_mknod(void *softc, struct l9p_request *req)
{
	struct fs_softc *sc = softc;
	struct openfile *file;
	struct l9p_fid *dir;
	struct stat st;
	uint32_t mode, major, minor;
	char *name;
	char newname[MAXPATHLEN];
	int error;

	if (sc->fs_readonly)
		return (EROFS);

	dir = req->lr_fid;
	name = req->lr_req.tmknod.name;
	error = fs_buildname(dir, name, newname, sizeof(newname));
	if (error)
		return (error);

	file = dir->lo_aux;

	if (lstat(file->name, &st) != 0)
		return (errno);
	if (!check_access(&st, file->uid, file->gid, L9P_OWRITE))
		return (EPERM);

	mode = req->lr_req.tmknod.mode;
	major = req->lr_req.tmknod.major;
	minor = req->lr_req.tmknod.major;

	/*
	 * For now at least, limit to block and character devs only.
	 * Probably need to allow fifos eventually.
	 */
	switch (mode & S_IFMT) {
	case S_IFBLK:
	case S_IFCHR:
		mode = (mode & S_IFMT) | (mode & 0777);	/* ??? */
		if (mknod(newname, (mode_t)mode, makedev(major, minor)) != 0)
			return (errno);
		break;
	case S_IFSOCK:
		error = internal_mksocket(file, newname, name);
		if (error != 0)
			return (error);
		break;
	default:
		return (EINVAL);
	}
	if (lchown(newname, file->uid, req->lr_req.tmknod.gid) != 0 ||
	    lstat(newname, &st) != 0)
		return (errno);

	generate_qid(&st, &req->lr_resp.rmknod.qid);
	return (0);
}

static int
fs_rename(void *softc, struct l9p_request *req)
{
	struct fs_softc *sc = softc;
	struct openfile *file, *f2;
	struct stat st;
	char *olddirname = NULL, *newname = NULL, *swtmp;
	int error;

	/*
	 * Note: lr_fid represents the file that is to be renamed,
	 * so we must locate its parent directory and verify that
	 * both this parent directory and the new directory f2 are
	 * writable.
	 */
	file = req->lr_fid->lo_aux;
	f2 = req->lr_fid2->lo_aux;
	assert(file && f2);

	if (sc->fs_readonly)
		return (EROFS);

	/* Client probably should not attempt to rename root. */
	if (strcmp(file->name, sc->fs_rootpath) == 0) {
		error = EINVAL;
		goto out;
	}
	olddirname = r_dirname(file->name, NULL, 0);
	if (olddirname == NULL) {
		error = errno;
		goto out;
	}
	if (lstat(olddirname, &st) != 0) {
		error = errno;
		goto out;
	}
	if (!check_access(&st, file->uid, file->gid, L9P_OWRITE)) {
		error = EPERM;
		goto out;
	}
	if (strcmp(olddirname, f2->name) != 0) {
		if (lstat(f2->name, &st) != 0) {
			error = errno;
			goto out;
		}
		if (!check_access(&st, f2->uid, f2->gid, L9P_OWRITE)) {
			error = EPERM;
			goto out;
		}
	}
	if (asprintf(&newname, "%s/%s",
	    f2->name, req->lr_req.trename.name) < 0) {
		error = ENAMETOOLONG;
		goto out;
	}

	if (rename(file->name, newname) != 0) {
		error = errno;
		goto out;
	}
	/* file has been renamed but old fid is not clunked */
	swtmp = newname;
	newname = file->name;
	file->name = swtmp;
	error = 0;

out:
	free(newname);
	free(olddirname);
	return (error);
}

static int
fs_readlink(void *softc __unused, struct l9p_request *req)
{
	struct openfile *file;
	ssize_t linklen;
	char buf[MAXPATHLEN];
	int error = 0;

	file = req->lr_fid->lo_aux;
	assert(file);

	linklen = readlink(file->name, buf, sizeof(buf));
	if (linklen < 0)
		error = errno;
	else if ((size_t)linklen >= sizeof(buf))
		error = ENOMEM; /* todo: allocate dynamically */
	else if ((req->lr_resp.rreadlink.target = strndup(buf,
	    (size_t)linklen)) == NULL)
		error = ENOMEM;
	return (error);
}

static int
fs_getattr(void *softc __unused, struct l9p_request *req)
{
	uint64_t mask, valid;
	struct openfile *file;
	struct stat st;
	int error = 0;

	file = req->lr_fid->lo_aux;
	assert(file);

	valid = 0;
	if (lstat(file->name, &st)) {
		error = errno;
		goto out;
	}
	/* ?? Can we provide items not-requested? If so, can skip tests. */
	mask = req->lr_req.tgetattr.request_mask;
	if (mask & L9PL_GETATTR_MODE) {
		/* It is not clear if we need any translations. */
		req->lr_resp.rgetattr.mode = st.st_mode;
		valid |= L9PL_GETATTR_MODE;
	}
	if (mask & L9PL_GETATTR_NLINK) {
		req->lr_resp.rgetattr.nlink = st.st_nlink;
		valid |= L9PL_GETATTR_NLINK;
	}
	if (mask & L9PL_GETATTR_UID) {
		/* provide st_uid, or file->uid? */
		req->lr_resp.rgetattr.uid = st.st_uid;
		valid |= L9PL_GETATTR_UID;
	}
	if (mask & L9PL_GETATTR_GID) {
		/* provide st_gid, or file->gid? */
		req->lr_resp.rgetattr.gid = st.st_gid;
		valid |= L9PL_GETATTR_GID;
	}
	if (mask & L9PL_GETATTR_RDEV) {
		/* It is not clear if we need any translations. */
		req->lr_resp.rgetattr.rdev = (uint64_t)st.st_rdev;
		valid |= L9PL_GETATTR_RDEV;
	}
	if (mask & L9PL_GETATTR_ATIME) {
		req->lr_resp.rgetattr.atime_sec =
		    (uint64_t)st.st_atimespec.tv_sec;
		req->lr_resp.rgetattr.atime_nsec =
		    (uint64_t)st.st_atimespec.tv_nsec;
		valid |= L9PL_GETATTR_ATIME;
	}
	if (mask & L9PL_GETATTR_MTIME) {
		req->lr_resp.rgetattr.mtime_sec =
		    (uint64_t)st.st_mtimespec.tv_sec;
		req->lr_resp.rgetattr.mtime_nsec =
		    (uint64_t)st.st_mtimespec.tv_nsec;
		valid |= L9PL_GETATTR_MTIME;
	}
	if (mask & L9PL_GETATTR_CTIME) {
		req->lr_resp.rgetattr.ctime_sec =
		    (uint64_t)st.st_ctimespec.tv_sec;
		req->lr_resp.rgetattr.ctime_nsec =
		    (uint64_t)st.st_ctimespec.tv_nsec;
		valid |= L9PL_GETATTR_CTIME;
	}
	if (mask & L9PL_GETATTR_BTIME) {
#if defined(HAVE_BIRTHTIME)
		req->lr_resp.rgetattr.btime_sec =
		    (uint64_t)st.st_birthtim.tv_sec;
		req->lr_resp.rgetattr.btime_nsec =
		    (uint64_t)st.st_birthtim.tv_nsec;
#else
		req->lr_resp.rgetattr.btime_sec = 0;
		req->lr_resp.rgetattr.btime_nsec = 0;
#endif
		valid |= L9PL_GETATTR_BTIME;
	}
	if (mask & L9PL_GETATTR_INO)
		valid |= L9PL_GETATTR_INO;
	if (mask & L9PL_GETATTR_SIZE) {
		req->lr_resp.rgetattr.size = (uint64_t)st.st_size;
		valid |= L9PL_GETATTR_SIZE;
	}
	if (mask & L9PL_GETATTR_BLOCKS) {
		req->lr_resp.rgetattr.blksize = (uint64_t)st.st_blksize;
		req->lr_resp.rgetattr.blocks = (uint64_t)st.st_blocks;
		valid |= L9PL_GETATTR_BLOCKS;
	}
	if (mask & L9PL_GETATTR_GEN) {
		req->lr_resp.rgetattr.gen = st.st_gen;
		valid |= L9PL_GETATTR_GEN;
	}
	/* don't know what to do with data version yet */

	generate_qid(&st, &req->lr_resp.rgetattr.qid);
out:
	req->lr_resp.rgetattr.valid = valid;
	return (error);
}

/*
 * Should combine some of this with wstat code.
 */
static int
fs_setattr(void *softc, struct l9p_request *req)
{
	uint64_t mask;
	struct fs_softc *sc = softc;
	struct timeval tv[2];
	struct openfile *file;
	struct stat st;
	int error = 0;
	uid_t uid, gid;

	file = req->lr_fid->lo_aux;
	assert(file);

	if (sc->fs_readonly)
		return (EROFS);

	/*
	 * As with WSTAT we have atomicity issues.
	 */
	mask = req->lr_req.tsetattr.valid;

	if (lstat(file->name, &st)) {
		error = errno;
		goto out;
	}

	if ((mask & L9PL_SETATTR_SIZE) && S_ISDIR(st.st_mode)) {
		error = EISDIR;
		goto out;
	}

	if (mask & L9PL_SETATTR_MODE) {
		if (lchmod(file->name, req->lr_req.tsetattr.mode & 0777)) {
			error = errno;
			goto out;
		}
	}

	if (mask & (L9PL_SETATTR_UID | L9PL_SETATTR_GID)) {
		uid = mask & L9PL_SETATTR_UID ? req->lr_req.tsetattr.uid :
		    (uid_t)-1;
		gid = mask & L9PL_SETATTR_GID ? req->lr_req.tsetattr.gid :
		    (gid_t)-1;
		if (lchown(file->name, uid, gid)) {
			error = errno;
			goto out;
		}
	}

	if (mask & L9PL_SETATTR_SIZE) {
		/* Truncate follows symlinks, is this OK? */
		if (truncate(file->name, (off_t)req->lr_req.tsetattr.size)) {
			error = errno;
			goto out;
		}
	}

	if (mask & (L9PL_SETATTR_ATIME | L9PL_SETATTR_CTIME)) {
		tv[0].tv_sec = st.st_atimespec.tv_sec;
		tv[0].tv_usec = (int)st.st_atimespec.tv_nsec / 1000;
		tv[1].tv_sec = st.st_mtimespec.tv_sec;
		tv[1].tv_usec = (int)st.st_mtimespec.tv_nsec / 1000;

		if (mask & L9PL_SETATTR_ATIME) {
			if (mask & L9PL_SETATTR_ATIME_SET) {
				tv[0].tv_sec =
				    (long)req->lr_req.tsetattr.atime_sec;
				tv[0].tv_usec =
				    (int)req->lr_req.tsetattr.atime_nsec / 1000;
			} else {
				if (gettimeofday(&tv[0], NULL)) {
					error = errno;
					goto out;
				}
			}
		}
		if (mask & L9PL_SETATTR_MTIME) {
			if (mask & L9PL_SETATTR_MTIME_SET) {
				tv[1].tv_sec =
				    (long)req->lr_req.tsetattr.mtime_sec;
				tv[1].tv_usec =
				    (int)req->lr_req.tsetattr.mtime_nsec / 1000;
			} else {
				if (gettimeofday(&tv[1], NULL)) {
					error = errno;
					goto out;
				}
			}
		}
		if (lutimes(file->name, tv)) {
			error = errno;
			goto out;
		}
	}
out:
	return (error);
}

static int
fs_xattrwalk(void *softc __unused, struct l9p_request *req __unused)
{
	return (EOPNOTSUPP);
}

static int
fs_xattrcreate(void *softc __unused, struct l9p_request *req __unused)
{
	return (EOPNOTSUPP);
}

static int
fs_readdir(void *softc __unused, struct l9p_request *req)
{
	struct openfile *file;
	struct l9p_dirent de;
	struct l9p_message msg;
	struct dirent *dp;
	struct stat st;
	int error = 0;

	file = req->lr_fid->lo_aux;
	assert(file);

	if (file->dir == NULL)
		return (ENOTDIR);

	/*
	 * There is no getdirentries variant that accepts an
	 * offset, so once we are multithreaded, this will need
	 * a lock (which will cover the dirent structures as well).
	 *
	 * It's not clear whether we can use the same trick for
	 * discarding offsets here as we do in fs_read.  It
	 * probably should work, we'll have to see if some
	 * client(s) use the zero-offset thing to rescan without
	 * clunking the directory first.
	 */
	if (req->lr_req.io.offset == 0)
		rewinddir(file->dir);
	else
		seekdir(file->dir, (long)req->lr_req.io.offset);

	l9p_init_msg(&msg, req, L9P_PACK);
	while ((dp = readdir(file->dir)) != NULL) {
		/*
		 * Although "." is forbidden in naming and ".." is
		 * special cased, testing shows that we must transmit
		 * them through readdir.  (For ".." at root, we
		 * should perhaps alter the inode number, but not
		 * yet.)
		 */
#ifdef wrong
		if (dp->d_name[0] == '.' &&
		    (dp->d_namlen == 1 || strcmp(dp->d_name, "..") == 0))
			continue;
#endif

		/*
		 * TODO: we do a full lstat here; could use dp->d_*
		 * to construct the qid more efficiently, as long
		 * as dp->d_type != DT_UNKNOWN.
		 */
		if (fs_lstatat(file, dp->d_name, &st))
			continue;

		de.qid.type = 0;
		generate_qid(&st, &de.qid);
		de.offset = (uint64_t)telldir(file->dir);
		de.type = de.qid.type; /* or dp->d_type? */
		de.name = dp->d_name;

		if (l9p_pudirent(&msg, &de) < 0)
			break;
	}

	req->lr_resp.io.count = (uint32_t)msg.lm_size;
	return (error);
}

static int
fs_fsync(void *softc __unused, struct l9p_request *req)
{
	struct openfile *file;
	int error = 0;

	file = req->lr_fid->lo_aux;
	assert(file);
	if (fsync(file->fd))
		error = errno;
	return (error);
}

static int
fs_lock(void *softc __unused, struct l9p_request *req __unused)
{

	return (EOPNOTSUPP);
}

static int
fs_getlock(void *softc __unused, struct l9p_request *req __unused)
{

	return (EOPNOTSUPP);
}

static int
fs_link(void *softc, struct l9p_request *req)
{
	struct fs_softc *sc = softc;
	struct openfile *file;
	struct openfile *dirf;
	struct l9p_fid *dir;
	struct stat st;
	char *name;
	char newname[MAXPATHLEN];
	int error;

	if (sc->fs_readonly)
		return (EROFS);

	/* N.B.: lr_fid is the file to link, lr_fid2 is the target dir */
	dir = req->lr_fid2;
	name = req->lr_req.tlink.name;
	error = fs_buildname(dir, name, newname, sizeof(newname));
	if (error)
		return (error);

	dirf = dir->lo_aux;

	file = req->lr_fid->lo_aux;
	assert(file != NULL);

	/* Require write access to target directory. */
	if (lstat(dirf->name, &st))
		return (errno);
	if (!check_access(&st, file->uid, file->gid, L9P_OWRITE))
		return (EPERM);

	if (link(file->name, newname) != 0)
		error = errno;
	return (error);
}

static int
fs_mkdir(void *softc, struct l9p_request *req)
{
	struct fs_softc *sc = softc;
	struct openfile *file;
	struct l9p_fid *dir;
	struct stat st;
	char *name;
	char newname[MAXPATHLEN];
	int error;

	if (sc->fs_readonly)
		return (EROFS);

	dir = req->lr_fid;
	name = req->lr_req.tmkdir.name;
	error = fs_buildname(dir, name, newname, sizeof(newname));
	if (error)
		return (error);

	file = dir->lo_aux;

	/* Require write access to target directory. */
	if (lstat(file->name, &st))
		return (errno);
	if (!check_access(&st, file->uid, req->lr_req.tmkdir.gid, L9P_OWRITE))
		return (EPERM);

	error = internal_mkdir(newname, (mode_t)req->lr_req.tmkdir.mode, &st);
	if (error)
		return (error);

	if (lchown(newname, file->uid, req->lr_req.tmkdir.gid) != 0 ||
	    lstat(newname, &st) != 0)
		return (errno);

	generate_qid(&st, &req->lr_resp.rmkdir.qid);
	return (error);
}

static int
fs_renameat(void *softc, struct l9p_request *req)
{
	struct fs_softc *sc = softc;
	struct openfile *olddir, *newdir;
	struct stat st;
	char *oldname = NULL, *newname = NULL;
	int error;

	olddir = req->lr_fid->lo_aux;
	newdir = req->lr_fid2->lo_aux;
	assert(olddir && newdir);

	if (sc->fs_readonly)
		return (EROFS);

	/* Require write access to both source and target directory. */
	if (lstat(olddir->name, &st))
		return (errno);
	if (!check_access(&st, olddir->uid, olddir->gid, L9P_OWRITE))
		return (EPERM);

	if (olddir != newdir) {
		if (lstat(newdir->name, &st))
			return (errno);
		if (!check_access(&st, newdir->uid, newdir->gid, L9P_OWRITE))
			return (EPERM);
	}

	if (asprintf(&oldname, "%s/%s",
		    olddir->name, req->lr_req.trenameat.oldname) < 0 ||
	    asprintf(&newname, "%s/%s",
		    newdir->name, req->lr_req.trenameat.newname) < 0)
		error = ENAMETOOLONG;
	else
		error = rename(oldname, newname);
	free(newname);
	free(oldname);
	return (error);
}

/*
 * Unlink file in given directory, or remove directory in given
 * directory, based on flags.
 */
static int
fs_unlinkat(void *softc, struct l9p_request *req)
{
	struct fs_softc *sc = softc;
	struct openfile *file;
	struct l9p_fid *dir;
	struct stat st;
	char *name;
	char newname[MAXPATHLEN];
	int error;

	if (sc->fs_readonly)
		return (EROFS);

	dir = req->lr_fid;
	name = req->lr_req.tunlinkat.name;
	error = fs_buildname(dir, name, newname, sizeof(newname));
	if (error)
		return (error);

	file = dir->lo_aux;

	/* Require write access to directory. */
	if (lstat(file->name, &st))
		return (errno);
	if (!check_access(&st, file->uid, file->gid, L9P_OWRITE))
		return (EPERM);

	if (req->lr_req.tunlinkat.flags & L9PL_AT_REMOVEDIR) {
		if (rmdir(newname) != 0)
			error = errno;
	} else {
		if (unlink(newname) != 0)
			error = errno;
	}
	return (error);
}

static void
fs_freefid(void *softc __unused, struct l9p_fid *fid)
{
	struct openfile *f = fid->lo_aux;

	if (f == NULL) {
		/* Nothing to do here */
		return;
	}

	if (f->fd != -1)
		close(f->fd);

	if (f->dir)
		closedir(f->dir);

	free(f->name);
	free(f);
}

int
l9p_backend_fs_init(struct l9p_backend **backendp, const char *root)
{
	struct l9p_backend *backend;
	struct fs_softc *sc;
	const char *rroot;

	rroot = realpath(root, NULL);
	if (rroot == NULL)
		return (-1);
	backend = l9p_malloc(sizeof(*backend));
	backend->attach = fs_attach;
	backend->clunk = fs_clunk;
	backend->create = fs_create;
	backend->flush = fs_flush;
	backend->open = fs_open;
	backend->read = fs_read;
	backend->remove = fs_remove;
	backend->stat = fs_stat;
	backend->walk = fs_walk;
	backend->write = fs_write;
	backend->wstat = fs_wstat;
	backend->statfs = fs_statfs;
	backend->lopen = fs_lopen;
	backend->lcreate = fs_lcreate;
	backend->symlink = fs_symlink;
	backend->mknod = fs_mknod;
	backend->rename = fs_rename;
	backend->readlink = fs_readlink;
	backend->getattr = fs_getattr;
	backend->setattr = fs_setattr;
	backend->xattrwalk = fs_xattrwalk;
	backend->xattrcreate = fs_xattrcreate;
	backend->readdir = fs_readdir;
	backend->fsync = fs_fsync;
	backend->lock = fs_lock;
	backend->getlock = fs_getlock;
	backend->link = fs_link;
	backend->mkdir = fs_mkdir;
	backend->renameat = fs_renameat;
	backend->unlinkat = fs_unlinkat;
	backend->freefid = fs_freefid;

	sc = l9p_malloc(sizeof(*sc));
	sc->fs_rootpath = rroot;
	sc->fs_readonly = false;
	backend->softc = sc;

	setpassent(1);

	*backendp = backend;
	return (0);
}
