/*-
 * Copyright (c) 2015 Will Andrews.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS        
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED   
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR       
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS        
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR           
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF             
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS         
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN          
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)          
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE       
 * POSSIBILITY OF SUCH DAMAGE.                                                      
 */

/*
 * Plan9 filesystem (9P2000.u) node operations implementation.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/dirent.h>
#include <sys/namei.h>

#include "p9fs_proto.h"
#include "p9fs_subr.h"

struct vop_vector p9fs_vnops;
static MALLOC_DEFINE(M_P9NODE, "p9fs_node", "p9fs node structures");

/*
 * Get a p9node.  Nodes are represented by (fid, qid) tuples in 9P2000.
 * Fids are assigned by the client, while qids are assigned by the server.
 *
 * The caller is expected to have generated the FID via p9fs_getfid() and
 * obtained the QID from the server via p9fs_client_walk() and friends.
 */
int
p9fs_nget(struct p9fs_session *p9s, uint32_t fid, struct l9p_qid *qid,
    int lkflags, struct p9fs_node **npp)
{
	int error = 0;
	struct p9fs_node *np;
	struct vnode *vp, *nvp;
	struct vattr vattr = {};
	struct thread *td = curthread;

	*npp = NULL;
	error = vfs_hash_get(p9s->p9s_mount, fid, lkflags, td, &vp, NULL, NULL);
	if (error != 0)
		return (error);
	if (vp != NULL) {
		*npp = vp->v_data;
		return (0);
	}

	np = malloc(sizeof (struct p9fs_node), M_P9NODE, M_WAITOK | M_ZERO);
	getnewvnode_reserve(1);

	error = getnewvnode("p9fs", p9s->p9s_mount, &p9fs_vnops, &nvp);
	if (error != 0) {
		getnewvnode_drop_reserve();
		free(np, M_P9NODE);
		return (error);
	}
	vp = nvp;
	vn_lock(vp, LK_EXCLUSIVE);

	error = insmntque(nvp, p9s->p9s_mount);
	if (error != 0) {
		/* vp was vput()'d by insmntque() */
		free(np, M_P9NODE);
		return (error);
	}
	error = vfs_hash_insert(nvp, fid, lkflags, td, &nvp, NULL, NULL);
	if (error != 0) {
		free(np, M_P9NODE);
		return (error);
	}
	if (nvp != NULL) {
		free(np, M_P9NODE);
		*npp = nvp->v_data;
		/* vp was vput()'d by vfs_hash_insert() */
		return (0);
	}

	error = p9fs_client_stat(p9s, fid, &vattr);
	if (error != 0) {
		free(np, M_P9NODE);
		return (error);
	}

	/* Our vnode is the winner.  Set up the new p9node for it. */
	vp->v_type = vattr.va_type;
	vp->v_data = np;
	np->p9n_fid = fid;
	np->p9n_session = p9s;
	np->p9n_vnode = vp;
	bcopy(qid, &np->p9n_qid, sizeof (*qid));
	*npp = np;

	return (error);
}

static int
p9fs_lookup(struct vop_cachedlookup_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct p9fs_node *dnp = dvp->v_data;
	struct p9fs_session *p9s = dnp->p9n_session;
	struct l9p_client_connection *conn = &p9s->connection;
	struct p9fs_node *np = NULL;
	struct l9p_qid qid;
	uint32_t newfid;
	int error;

	*vpp = NULL;
	printf("%s(fid %u name '%.*s')\n", __func__, dnp->p9n_fid,
	    (int)cnp->cn_namelen, cnp->cn_nameptr);

	/* Special case: lookup a directory from itself. */
	if (cnp->cn_namelen == 1 && *cnp->cn_nameptr == '.') {
		*vpp = dvp;
		vref(*vpp);
		return (0);
	}

	newfid = conn->get_fid(conn);
	error = p9fs_client_walk(p9s, dnp->p9n_fid, newfid,
				 cnp->cn_namelen, cnp->cn_nameptr, &qid);
	if (error == 0) {
		int ltype = 0;

		if (cnp->cn_flags & ISDOTDOT) {
			ltype = VOP_ISLOCKED(dvp);
			VOP_UNLOCK(dvp, 0);
		}
		error = p9fs_nget(p9s, newfid, &qid,
		    cnp->cn_lkflags, &np);
		if (cnp->cn_flags & ISDOTDOT)
			vn_lock(dvp, ltype | LK_RETRY);

	}
	if (error == 0) {
		*vpp = np->p9n_vnode;
		vref(*vpp);
	} else
		conn->release_fid(conn, newfid);

	return (error);
}

#define	VNOP_UNIMPLEMENTED				\
	printf("%s: not implemented yet\n", __func__);	\
	return (EINVAL)

static int
p9fs_create(struct vop_create_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_mknod(struct vop_mknod_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_open(struct vop_open_args *ap)
{
	int error;
	struct p9fs_node *np = ap->a_vp->v_data;
	struct p9fs_session *p9s = np->p9n_session;
	struct l9p_client_connection *conn = &p9s->connection;
	struct vattr vattr;
	uint32_t fid = np->p9n_fid;

	printf("%s(fid %u)\n", __func__, np->p9n_fid);

	/*
	 * XXX XXX XXX
	 * XXX Each fid is associated with a particular open mode, so this
	 *     isn't good enough.  Need to map the mode to a particular fid.
	 *     Oh, but wait, we can't determine the correct fid for a given
	 *     client I/O call, because the filesystem can't store per file
	 *     descriptor state... sigh...
	 *
	 * diod's docs for 9P2000.L mention that each user gets its own
	 * attach fid on which to perform its operations.  That doesn't help
	 * with the per-fid open mode issue though... a given user can have
	 * multiple open modes.
	 *
	 * So perhaps p9fs would have to create a list of per-user open modes
	 * to fids?  Then read/write calls would lookup the appropriate one
	 * given the implied request mode?
	 *
	 * IO_APPEND is always included for VOP_WRITE() for fd's that were
	 * opened with O_APPEND.  So for each user we'd need at most three
	 * different fids: one each for reads, writes, and appends.  Each fid
	 * would have a refcount based on the number of times an open() call
	 * was issued with its bit set in the mode flag.  That way we could
	 * clunk fids only when they no longer have corresponding users.
	 *
	 * However, R/W modes are quite common, so perhaps we should try to
	 * always open R/W and let VFS do the per-fd restriction?  Ah, but
	 * that won't work because some files will only be openable read-only
	 * or write-only or append-only on the server end.
	 *
	 * Append presents another challenge: a given user can have multiple
	 * append fd's open on the same file at once.  Different appends can
	 * be at different offsets.  And some filesystems implement having
	 * append-only files.  However, looks like in that scenario the
	 * overlapping appends will always just get sent to the file's
	 * current size regardless.  This does mean we need an append fid.
	 *
	 * Finally, a p9fs_node should be indexed in the vfs hash by qid
	 * instead of by fid, since each vnode will be mappable to
	 * potentially many fids.  p9fs_nget() already takes a qid.  The
	 * main challenge is that vfs_hash_insert() only takes an u_int for
	 * the hash value, so we'll need to provide a comparator.
	 *
	 * Although, according to py9p, we can't clone an open fid, so
	 * perhaps we need a normal fid that is used just for cloning and
	 * metadata operations.
	 *
	 * NB: We likely also have to implement Tattach for every user, so
	 *     that the server has correct credentials for each fid and
	 *     tree of fids.  The initial attach would be defined by the
	 *     mount, but followup accesses by other users will require
	 *     their own attach.
	 */
	if (np->p9n_opens > 0) {
		np->p9n_opens++;
		return (0);
	}

	/* XXX Can this be cached in some reasonable fashion? */
	error = p9fs_client_stat(np->p9n_session, np->p9n_fid, &vattr);
	if (error != 0)
		return (error);

	/*
	 * XXX VFS calls VOP_OPEN() on a directory it's about to perform
	 *     VOP_READDIR() calls on.  However, 9P2000 Twalk requires that
	 *     the given fid not have been opened.  What should we do?
	 *
	 * For now, this call performs an internal Twalk to obtain a cloned
	 * fid that can be opened separately.  It will be clunk'd at the
	 * same time as the unopened fid.
	 */
	if (ap->a_vp->v_type == VDIR) {
		if (np->p9n_ofid == 0) {
			np->p9n_ofid = conn->get_fid(conn);

			error = p9fs_client_walk(np->p9n_session, np->p9n_fid,
						 np->p9n_ofid, 0, NULL, &np->p9n_qid);
			if (error != 0) {
				np->p9n_ofid = 0;
				return (error);
			}
		}
		fid = np->p9n_ofid;
	}

	error = p9fs_client_open(np->p9n_session, fid, ap->a_mode);
	if (error == 0) {
		np->p9n_opens = 1;
		vnode_create_vobject(ap->a_vp, vattr.va_bytes, ap->a_td);
	}

	return (error);
}

static int
p9fs_close(struct vop_close_args *ap)
{
	struct p9fs_node *np = ap->a_vp->v_data;

	printf("%s(fid %d ofid %d opens %d)\n", __func__,
	    np->p9n_fid, np->p9n_ofid, np->p9n_opens);
	np->p9n_opens--;
	if (np->p9n_opens == 0) {
		struct l9p_client_connection *conn = &np->p9n_session->connection;
		conn->release_fid(conn, np->p9n_ofid);
		np->p9n_ofid = 0;
	}

	/*
	 * In p9fs, the only close-time operation to do is Tclunk, but it's
	 * only appropriate to do that in VOP_RECLAIM, since we may reuse
	 * the vnode for a file for some time before its fid is guaranteed
	 * not to be used again.
	 */
	return (0);
}

static int
p9fs_access(struct vop_access_args *ap)
{
	struct p9fs_node *np = ap->a_vp->v_data;
	int accmode = ap->a_accmode;
	struct vattr vattr;
	int error;

	/* Read-only filesystem check. */
	if ((accmode & VMODIFY_PERMS) != 0 &&
	    (ap->a_vp->v_mount->mnt_flag & MNT_RDONLY) != 0) {
		switch (ap->a_vp->v_type) {
		case VDIR:
		case VLNK:
		case VREG:
			error = EROFS;
			goto out;
		default:
			break;
		}
	}

	error = vfs_unixify_accmode(&accmode);
	if (error != 0)
		goto out;

	if (accmode == 0)
		goto out;

	/*
	 * We have some access mode to check.
	 *
	 * XXX In cooperation with p9fs_{open,getattr}(), can this metadata
	 *     be cached in a reasonable fashion?
	 */
	error = p9fs_client_stat(np->p9n_session, np->p9n_fid, &vattr);
	if (error != 0)
		goto out;

	error = vaccess(ap->a_vp->v_type, vattr.va_mode, vattr.va_uid,
	    vattr.va_gid, accmode, ap->a_cred, NULL);

out:
	printf("%s(fid %d) ret %d\n", __func__, np->p9n_fid, error);
	return (error);
}

static int
p9fs_getattr(struct vop_getattr_args *ap)
{
	struct p9fs_node *np = ap->a_vp->v_data;
	int error = p9fs_client_stat(np->p9n_session, np->p9n_fid, ap->a_vap);

	printf("%s(fid %d) ret %d\n", __func__, np->p9n_fid, error);
	return (error);
}

static int
p9fs_setattr(struct vop_setattr_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_read(struct vop_read_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_write(struct vop_write_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_fsync(struct vop_fsync_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_remove(struct vop_remove_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_link(struct vop_link_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_rename(struct vop_rename_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_mkdir(struct vop_mkdir_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_rmdir(struct vop_rmdir_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_symlink(struct vop_symlink_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

struct p9fs_readdir_state {
	/*
	 * The uio for use by p9fs_client_read(); local to p9fs_readdir().
	 * Must be first entry so p9fs_client_read() can access it.
	 */
	struct uio rd_uio;

	/* readdir's caller metadata */
	struct vop_readdir_args *rd_ap;

	/* metadata used by p9fs_readdir_cb */
	u_long *rd_cookies;
	int rd_count;
	int rd_eof;
	int *rd_eofp;
};

static int
p9fs_readdir_cb(void *mp, uint32_t count, size_t *offp, struct uio *arg)
{
	struct l9p_client_rpc *msg = mp;
	struct p9fs_readdir_state *rd = (struct p9fs_readdir_state *)arg;
	struct vop_readdir_args *ap = rd->rd_ap;
	struct l9p_stat p9sbuf;
	struct dirent entry;
	int error;

	printf("%s(%p, %u, %p, %p)\n", __FUNCTION__, mp, count, offp, arg);
	if (count == 0) {
		*rd->rd_eofp = 1;
		return (EJUSTRETURN);
	}

	/*
	 * If this is the first run, pop off the stat[n] total byte header.
	 * XXX See comments in p9fs_client_stat() about compliance of this.
	 */
#if 0
	if (ap->a_uio->uio_offset == 0) {
		uint16_t *totsz;

		p9fs_msg_get(mp, offp, (void *)&totsz, sizeof (*totsz));
		printf("%s: got totsz %d\n", __func__, *totsz);
	}
#endif

	/*
	 * Parse p9fs_stat structures out of the message until there is no
	 * space left in the message or until our client's uio runs out.
	 */
	/*
	 * I want to use l9p_pustat on msg->response_data.
	 */
	while (l9p_pustat(&msg->response_data, &p9sbuf, msg->conn->lc_version) > 0) {
		entry.d_fileno = (uint32_t)(p9sbuf.qid.path >> 32);
		entry.d_reclen = offsetof(struct dirent, d_name);

		/* Determine the entry type from extension[s] if special. */
		switch (p9sbuf.qid.type) {
		case L9P_QTDIR:
			entry.d_type = DT_DIR;
			break;
		case L9P_QTSYMLINK:
			entry.d_type = DT_LNK;
			break;
		case L9P_QTFILE:
			entry.d_type = DT_REG;
			break;
		default:
			/* Try again from stat_mode's upper bits. */
			switch (p9sbuf.mode & L9P_DMDIR) {
			case L9P_DMDEVICE:
				entry.d_type = DT_BLK;
				break;
			case L9P_DMSYMLINK:
				entry.d_type = DT_LNK;
				break;
			case L9P_DMSOCKET:
				entry.d_type = DT_SOCK;
				break;
			case L9P_DMNAMEDPIPE:
				entry.d_type = DT_FIFO;
				break;
			default:
				/* XXX What should be done with other types? */
				entry.d_type = DT_UNKNOWN;
				break;
			}
			break;
		}

		entry.d_namlen = strlen(p9sbuf.name);
		if (entry.d_namlen > MAXNAMLEN) {
			error = ENAMETOOLONG;
			break;
		}
		entry.d_reclen += entry.d_namlen;
		if (entry.d_reclen > ap->a_uio->uio_resid) {
			error = EJUSTRETURN;
			break;
		}
		strcpy(p9sbuf.name, entry.d_name);

		/* All good, now send it to the caller. */
		error = uiomove((void *)&entry, entry.d_reclen, ap->a_uio);
		if (error != 0)
			break;
		rd->rd_count++;
		rd->rd_uio.uio_offset += count;
		/* Adjust caller's offset to match, due to smaller payloads. */
		ap->a_uio->uio_offset = rd->rd_uio.uio_offset;
		if (rd->rd_cookies != NULL) {
			KASSERT(rd->rd_count <= *ap->a_ncookies,
			    ("p9fs_readdir: cookies buffer too small"));
			*rd->rd_cookies++ = ap->a_uio->uio_offset;
		}
		printf("%s loop iter end off %zu\n", __func__, *offp);
	}
	printf("%s end of loop\n", __func__);

	return (error);
}

/*
 * Minimum length for a directory entry: size of fixed size section of
 * struct dirent plus a 1 byte C string for the name.
 */
#define	DIRENT_MIN_LEN	(offsetof(struct dirent, d_name) + 2)

static int
p9fs_readdir(struct vop_readdir_args *ap)
{
	struct p9fs_node *np = ap->a_vp->v_data;
	struct p9fs_readdir_state rd = {};
	struct iovec iov;
	int error = 0;

	if (ap->a_uio->uio_iov->iov_len <= 0)
		return (EINVAL);

	rd.rd_eofp = ap->a_eofflag != NULL ? ap->a_eofflag : &rd.rd_eof;
	if (ap->a_ncookies != NULL) {
		u_long ncookies = ap->a_uio->uio_resid / DIRENT_MIN_LEN + 1;
		*ap->a_cookies = malloc(ncookies * sizeof (*ap->a_cookies),
		    M_TEMP, M_WAITOK);
		rd.rd_cookies = *ap->a_cookies;
	}

	/*
	 * Plan9 doesn't have a vnode operation specific to reading
	 * directories; doing read()s on a directory is the equivalent.  For
	 * directories, this call returns a list of p9fs_stat structures for
	 * each entry.  Only when subsequent calls return nothing is the
	 * list completely fulfilled.  Set up the local uio before starting.
	 * This local uio tracks the offset from the server's point of view.
	 */
	iov.iov_base = malloc(P9_MSG_MAX, M_TEMP, M_WAITOK);
	rd.rd_uio.uio_iov = &iov;
	rd.rd_uio.uio_segflg = UIO_SYSSPACE;
	rd.rd_uio.uio_rw = UIO_READ;
	rd.rd_uio.uio_iovcnt = 1;
	rd.rd_uio.uio_td = curthread;
	rd.rd_ap = ap;

	for (;;) {
		ssize_t resid = ap->a_uio->uio_resid;

		rd.rd_uio.uio_resid = iov.iov_len = P9_MSG_MAX;
		/*
		 * XXX How to translate caller offset to internal offset?
		 *     VOP_READDIR() will get called again until no more
		 *     entries are found.  However, the caller's uio uses a
		 *     different scale.
		 *
		 *     In ZFS, offset is merely the object count.  In UFS,
		 *     it's the byte count; in that filesystem the entry
		 *     size is a fixed quantity, so it's effectively also an
		 *     object count.
		 *
		 *     However, on the plus side, what this means is that
		 *     the caller's uio_offset is internal state only.
		 *     Therefore, we can set it to whatever we want.
		 */
		rd.rd_uio.uio_offset = ap->a_uio->uio_offset;
		printf("%s(%d):  rd.uio_resid = %zd, uio_offset = %ld\n", __FUNCTION__, __LINE__, rd.rd_uio.uio_resid, rd.rd_uio.uio_offset);
		error = p9fs_client_read(np->p9n_session, np->p9n_ofid,
					 p9fs_readdir_cb, (struct uio *)&rd);
		/* Stop on error or if no more entries can be sent to caller. */
		if (error != 0 || ap->a_uio->uio_resid < DIRENT_MIN_LEN ||
		    ap->a_uio->uio_resid == resid)
			break;
	}

	/* See whether any entries made it into the return at all. */
	if (error == EJUSTRETURN)
		error = 0;
	if (error == 0 && rd.rd_count == 0)
		error = EINVAL;
	if (error == 0) {
		if (ap->a_ncookies != NULL)
			*ap->a_ncookies = rd.rd_count;
		ap->a_uio->uio_offset = rd.rd_uio.uio_offset;
	}

	/* Clean up as needed. */
	if (error != 0 && ap->a_ncookies != NULL) {
		free(*ap->a_cookies, M_TEMP);
		*ap->a_ncookies = 0;
		*ap->a_cookies = NULL;
	}
	free(iov.iov_base, M_TEMP);

	printf("%s(fid %d) ret %d\n", __func__, np->p9n_ofid, error);
	return (error);
}

static int
p9fs_readlink(struct vop_readlink_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_inactive(struct vop_inactive_args *ap)
{
	return (0);
}

static int
p9fs_reclaim(struct vop_reclaim_args *ap)
{
	struct p9fs_node *np = ap->a_vp->v_data;
	struct l9p_client_connection *conn = &np->p9n_session->connection;
	int error;

	/* Remove the p9fs_node from visibility. */
	vnode_destroy_vobject(ap->a_vp);
	vfs_hash_remove(ap->a_vp);
	VI_LOCK(ap->a_vp);
	ap->a_vp->v_data = NULL;
	VI_UNLOCK(ap->a_vp);

	error = p9fs_client_clunk(np->p9n_session, np->p9n_fid);
	if (error != 0) {
		/* Failure should never happen here! */
		printf("%s(%d): error %d\n", __func__, np->p9n_fid, error);
	}
	printf("%s(fid %d ofid %d)\n", __func__, np->p9n_fid, np->p9n_ofid);

	if (np->p9n_ofid != 0)
		conn->release_fid(conn, np->p9n_ofid);

	/* The root vnode has a special fid and backing for its np. */
	if (np->p9n_fid != ROOTFID) {
		conn->release_fid(conn, np->p9n_fid);
		free(np, M_P9NODE);
	}

	return (0);
}

static int
p9fs_print(struct vop_print_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_pathconf(struct vop_pathconf_args *ap)
{
	VNOP_UNIMPLEMENTED;
}

static int
p9fs_vptofh(struct vop_vptofh_args *ap)
{
	VNOP_UNIMPLEMENTED;
}


struct vop_vector p9fs_vnops = {
	.vop_default =		&default_vnodeops,
	.vop_lookup =		vfs_cache_lookup,
	.vop_cachedlookup =	p9fs_lookup,
	.vop_create =		p9fs_create,
	.vop_mknod =		p9fs_mknod,
	.vop_open =		p9fs_open,
	.vop_close =		p9fs_close,
	.vop_access =		p9fs_access,
	.vop_getattr =		p9fs_getattr,
	.vop_setattr =		p9fs_setattr,
	.vop_read =		p9fs_read,
	.vop_write =		p9fs_write,
	.vop_fsync =		p9fs_fsync,
	.vop_remove =		p9fs_remove,
	.vop_link =		p9fs_link,
	.vop_rename =		p9fs_rename,
	.vop_mkdir =		p9fs_mkdir,
	.vop_rmdir =		p9fs_rmdir,
	.vop_symlink =		p9fs_symlink,
	.vop_readdir =		p9fs_readdir,
	.vop_readlink =		p9fs_readlink,
	.vop_inactive =		p9fs_inactive,
	.vop_reclaim =		p9fs_reclaim,
	.vop_print =		p9fs_print,
	.vop_pathconf =		p9fs_pathconf,
	.vop_vptofh =		p9fs_vptofh,
#ifdef NOT_NEEDED
	.vop_bmap =		p9fs_bmap,
	.vop_bypass =		p9fs_bypass,
	.vop_islocked =		p9fs_islocked,
	.vop_whiteout =		p9fs_whiteout,
	.vop_accessx =		p9fs_accessx,
	.vop_markatime =	p9fs_markatime,
	.vop_poll =		p9fs_poll,
	.vop_kqfilter =		p9fs_kqfilter,
	.vop_revoke =		p9fs_revoke,
	.vop_lock1 =		p9fs_lock1,
	.vop_unlock =		p9fs_unlock,
	.vop_strategy =		p9fs_strategy,
	.vop_getwritemount =	p9fs_getwritemount,
	.vop_advlock =		p9fs_advlock,
	.vop_advlockasync =	p9fs_advlockasync,
	.vop_advlockpurge =	p9fs_advlockpurge,
	.vop_reallocblks =	p9fs_reallocblks,
	.vop_getpages =		p9fs_getpages,
	.vop_putpages =		p9fs_putpages,
	.vop_getacl =		p9fs_getacl,
	.vop_setacl =		p9fs_setacl,
	.vop_aclcheck =		p9fs_aclcheck,
	/*
	 * 9P2000.u specifically doesn't support extended attributes,
	 * although they could be as an extension.
	 */
	.vop_closeextattr =	p9fs_closeextattr,
	.vop_getextattr =	p9fs_getextattr,
	.vop_listextattr =	p9fs_listextattr,
	.vop_openextattr =	p9fs_openextattr,
	.vop_deleteextattr =	p9fs_deleteextattr,
	.vop_setextattr =	p9fs_setextattr,
	.vop_setlabel =		p9fs_setlabel,
	.vop_vptocnp =		p9fs_vptocnp,
	.vop_allocate =		p9fs_allocate,
	.vop_advise =		p9fs_advise,
	.vop_unp_bind =		p9fs_unp_bind,
	.vop_unp_connect =	p9fs_unp_connect,
	.vop_unp_detach =	p9fs_unp_detach,
	.vop_is_text =		p9fs_is_text,
	.vop_set_text =		p9fs_set_text,
	.vop_unset_text =	p9fs_unset_text,
	.vop_get_writecount =	p9fs_get_writecount,
	.vop_add_writecount =	p9fs_add_writecount,
#endif
};
