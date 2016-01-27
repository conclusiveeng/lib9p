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
#include <stdbool.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include "../lib9p.h"
#include "../log.h"

static void fs_attach(void *, struct l9p_request *);
static void fs_clunk(void *, struct l9p_request *);
static void fs_create(void *, struct l9p_request *);
static void fs_flush(void *, struct l9p_request *);
static void fs_open(void *, struct l9p_request *);
static void fs_read(void *, struct l9p_request *);
static void fs_remove(void *, struct l9p_request *);
static void fs_stat(void *, struct l9p_request *);
static void fs_walk(void *, struct l9p_request *);
static void fs_write(void *, struct l9p_request *);
static void fs_wstat(void *, struct l9p_request *);

struct fs_softc
{
	const char *fs_rootpath;
	bool fs_readonly;
};

struct openfile
{
	DIR *dir;
	int fd;
	char *name;
};

static struct openfile *
open_fid(const char *path)
{
	struct openfile *ret;

	ret = calloc(1, sizeof(*ret));
	ret->fd = -1;
	ret->name = strdup(path);
	return (ret);
}

static void
dostat(struct l9p_stat *s, char *name, struct stat *buf)
{
	char *user = getenv("USER");
	s->type = 0;
	s->dev = 0;
	s->qid.type = buf->st_mode&S_IFMT >> 8;
	s->qid.path = buf->st_ino;
	s->qid.version = 0;
	s->mode = buf->st_mode & 0777;
	if (S_ISDIR(buf->st_mode)) {
		s->mode |= P9_DMDIR;
		s->qid.type |= L9P_QTDIR;
	}
	s->atime = buf->st_atime;
	s->mtime = buf->st_mtime;
	s->length = buf->st_size;
	s->name =name;
	s->uid = user;
	s->gid = user;
	s->muid = user;
}

static void
fs_attach(void *softc, struct l9p_request *req)
{
	struct fs_softc *sc = (struct fs_softc *)softc;

	req->lr_fid->lo_qid.type = L9P_QTDIR;
	req->lr_fid->lo_qid.path = (uintptr_t)req->lr_fid;
	req->lr_fid->lo_aux = open_fid(sc->fs_rootpath);
	req->lr_resp.rattach.qid = req->lr_fid->lo_qid;

	l9p_respond(req, NULL);
}

static void
fs_clunk(void *softc, struct l9p_request *req)
{
	struct l9p_connection *conn = req->lr_conn;
	struct openfile *file;
	struct stat st;

	file = req->lr_fid->lo_aux;

	if (file->dir)
		closedir(file->dir);
	else {
		close(file->fd);
		file->fd = -1;
	}

	l9p_respond(req, NULL);
}

static void
fs_create(void *softc, struct l9p_request *req)
{

}

static void
fs_flush(void *softc, struct l9p_request *req)
{
	l9p_respond(req, NULL);
}

static void
fs_open(void *softc, struct l9p_request *req)
{
	struct l9p_connection *conn = req->lr_conn;
	struct openfile *file;
	struct stat st;

	file = req->lr_fid->lo_aux;

	stat(file->name, &st);

	if (S_ISDIR(st.st_mode)) {
		file->dir = opendir(file->name);
	} else {
		file->fd = open(file->name, O_RDONLY);
		if (file->fd < 0) {
			l9p_respond(req, "Permission denied");
			return;
		}
	}

	req->lr_resp.ropen.iounit = conn->lc_max_io_size;
	l9p_respond(req, NULL);
}

static void
fs_read(void *softc, struct l9p_request *req)
{
	struct openfile *file;
	struct l9p_connection *conn = req->lr_conn;
	struct l9p_stat l9stat;

	file = req->lr_fid->lo_aux;

	if (file->dir != NULL) {
		struct dirent *d;
		struct stat st;

		for (;;) {
			d = readdir(file->dir);
			if (d) {
				stat(d->d_name, &st);
				dostat(&l9stat, d->d_name, &st);
				if (l9p_pack_stat(req, &l9stat) != 0) {
					seekdir(file->dir, -1);
					break;
				}

				continue;
			}

			break;
		}
	} else {
		size_t niov = l9p_truncate_iov(req->lr_data_iov, req->lr_data_niov, req->lr_req.io.count);
		req->lr_resp.io.count = readv(file->fd, req->lr_data_iov, niov);
	}

	l9p_respond(req, NULL);
}

static void
fs_remove(void *softc, struct l9p_request *req)
{

}

static void
fs_stat(void *softc, struct l9p_request *req)
{
	struct openfile *file;
	struct stat st;
	struct l9p_stat l9stat;

	file = req->lr_fid->lo_aux;

	stat(file->name, &st);
	dostat(&req->lr_resp.rstat.stat, file->name, &st);

	l9p_respond(req, NULL);
}

static void
fs_walk(void *softc, struct l9p_request *req)
{
	int i;
	struct stat buf;
	struct openfile *file = (struct openfile *)req->lr_fid->lo_aux;
	char *name = malloc(1024);

	strcpy(name, file->name);

	/* build full path. Stat full path. Done */
	for (i = 0; i < req->lr_req.twalk.nwname; i++) {
		strcat(name, "/");
		strcat(name, req->lr_req.twalk.wname[i]);
		if (stat(name, &buf) < 0){
			l9p_respond(req, "No such file or directory");
			free(name);
			return;
		}
		req->lr_resp.rwalk.wqid[i].type = buf.st_mode&S_IFMT >> 8;
		req->lr_resp.rwalk.wqid[i].path = buf.st_ino;
	}

	req->lr_newfid->lo_aux = open_fid(name);
	req->lr_resp.rwalk.nwqid = i;
	free(name);
	l9p_respond(req, NULL);
}

static void
fs_write(void *softc, struct l9p_request *req)
{

}

static void
fs_wstat(void *softc, struct l9p_request *req)
{

}

int
l9p_backend_fs_init(struct l9p_backend **backendp, const char *root)
{
	struct l9p_backend *backend;
	struct fs_softc *sc;

	backend = malloc(sizeof(*backend));
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

	sc = malloc(sizeof(*sc));
	sc->fs_rootpath = strdup(root);
	backend->softc = sc;

	*backendp = backend;
	return (0);
}
