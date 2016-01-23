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
#include <dirent.h>
#include "../lib9p.h"

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

	ret = malloc(sizeof(*ret));
	ret->fd = -1;
	ret->name = strdup(path);
	return (ret);
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

}

static void
fs_create(void *softc, struct l9p_request *req)
{

}

static void
fs_flush(void *softc, struct l9p_request *req)
{

}

static void
fs_open(void *softc, struct l9p_request *req)
{

}

static void
fs_read(void *softc, struct l9p_request *req)
{

}

static void
fs_remove(void *softc, struct l9p_request *req)
{

}

static void
fs_stat(void *softc, struct l9p_request *req)
{

}

static void
fs_walk(void *softc, struct l9p_request *req)
{
	int i;
	char *name;

	for (i = 0; i < req->lr_req.twalk.nwname; i++) {
		strcat(name, "/");
		strcat(name, req->lr_req.twalk.wname[i]);

	}
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

	*backendp = backend;
	return (0);
}
