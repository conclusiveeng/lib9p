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
 * Plan9 filesystem (9P2000.u) client implementation.
 *
 * Functions intended to map to client handling of protocol operations are
 * to be defined as p9fs_client_<operation>.
 *
 * See p9fs_proto.h for more details on the protocol specification.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/stdint.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#include <sys/stat.h>

#include "p9fs_proto.h"
#include "p9fs_subr.h"
#include "../lib9p.h"

/*
 * version - negotiate protocol version
 *
 *   size[4] Tversion tag[2] msize[4] version[s]
 *   size[4] Rversion tag[2] msize[4] version[s]
 *
 ******** PROTOCOL NOTES
 * Tversion must be the first message sent on the 9P connection; the client
 * may not send any other requests until it is complete.
 *
 * tag[2]: Must always be NOTAG.
 *
 * Tmsize[4]: Suggested maximum size the client will ever generate/receive.
 * Rmsize[4]: Server value, which must be <= Tmsize.
 ********
 *
 * This implementation only handles 9P2000.u, so if any other version is
 * returned, the call will simply bail.
 */
int
p9fs_client_version(struct p9fs_session *p9s)
{
	struct l9p_client_rpc *msg = NULL;
	int error = 0;
	uint32_t max_size = P9_MSG_MAX;
	
	msg = l9p_calloc(1, sizeof(*msg));
	if (msg == NULL)
		return (ENOMEM);
	msg->conn = &p9s->connection;
	
retry:
	error = p9_msg(&p9s->connection, &msg->message, L9P_TVERSION, max_size, UN_VERS);
	if (error)
		goto done;
	
	error = p9_send_and_reply(msg);

	if (error == EMSGSIZE)
		goto retry;
	
	if (error)
		goto done;

	if (strcmp(msg->response.version.version, UN_VERS) != 0) {
		printf("Remote offered incompatible version '%s'\n",
		       msg->response.version.version);
		error = EINVAL;
	}

done:
	if (msg) {
		l9p_freefcall(&msg->response);
		l9p_free(msg);
	}
	
	return (error);
}

/*
 * attach, auth - messages to establish a connection
 *
 *   size[4] Tauth tag[2] afid[4] uname[s] aname[s]
 *   size[4] Rauth tag[2] aqid[13]
 *
 *   size[4] Tattach tag[2] fid[4] afid[4] uname[s] aname[s]
 *   size[4] Rattach tag[2] qid[13]
 *
 * 9P2000.u modifies, according to py9p but not the spec:
 *
 *   size[4] Tattach tag[2] fid[4] afid[4] uname[s] aname[s] uid[4]
 *
 ******** PROTOCOL NOTES
 * Tuname[s]: User identification
 * Taname[s]: File tree being attached
 ******** PROTOCOL NOTES (auth)
 * Tafid[4]: Proposed afid to be used for authentication.
 * Raqid[13]: File of type QTAUTH to execute an authentication protocol.
 *
 * XXX This needs more explanation.
 ******** PROTOCOL NOTES (attach)
 * Tafid[4]: Successful afid from auth, or NOFID if no auth required.
 ********
 *
 * This implementation only supports authentication-free connections for now.
 */
int
p9fs_client_auth(struct p9fs_session *p9s)
{
	return (EINVAL);
}

int
p9fs_client_attach(struct p9fs_session *p9s)
{
	struct l9p_client_rpc *msg = NULL;
	int error = 0;
	struct p9fs_node *np = &p9s->p9s_rootnp;
	
	msg = l9p_calloc(1, sizeof(*msg));
	if (msg == NULL)
		return (ENOMEM);
	msg->conn = &p9s->connection;

retry:
	error = p9_msg(&p9s->connection, &msg->message, L9P_TATTACH,
		       np->p9n_fid, p9s->p9s_afid,
		       p9s->p9s_uname,
		       p9s->p9s_path,
		       p9s->p9s_uid);
	if (error)
		goto done;
	
	error = p9_send_and_reply(msg);

	if (error == EMSGSIZE)
		goto retry;

done:
	if (error == 0) {
		bcopy(&msg->response.ropen.qid, &np->p9n_qid, sizeof(np->p9n_qid));
	}
	if (msg) {
		l9p_freefcall(&msg->response);
		l9p_free(msg);
	}

	return (error);
}

/*
 * clunk - forget about a fid
 *
 *   size[4] Tclunk tag[2] fid[4]
 *   size[4] Rclunk tag[2]
 *
 ******** PROTOCOL NOTES
 *
 ********
 *
 */
int
p9fs_client_clunk(struct p9fs_session *p9s, uint32_t fid)
{
	struct l9p_client_rpc *msg = NULL;
	int error = 0;

	msg = l9p_calloc(1, sizeof(*msg));
	if (msg == NULL)
		return (ENOMEM);
	msg->conn = &p9s->connection;
	
retry:
	error = p9_msg(&p9s->connection, &msg->message, L9P_TCLUNK, fid);
	if (error)
		goto done;
	
	error = p9_send_and_reply(msg);

	if (error == EMSGSIZE)
		goto retry;

done:
	if (msg) {
		l9p_freefcall(&msg->response);
		l9p_free(msg);
	}

	return (error);
}

#if 0
/*
 * error - return an error
 *
 *   size[4] Rerror tag[2] ename[s] errno[4]
 *
 ******** PROTOCOL NOTES
 *
 ********
 *
 * This is primarily used by other functions as a means of checking for
 * error conditions, so it also checks whether the expected R command is
 * being transmitted.
 *
 * Note that in order for the caller to receive a reply message from
 * p9fs_msg_send(), the reply must have had the correct tag to begin with.
 *
 * Return codes:
 * >0: Error return from the server.  May be EINVAL if the wrong R command
 *     was returned.
 *  0: No error; the expected R command was returned.
 *
 * NB: m is consumed if an error is returned, regardless of type.
 */
int
p9fs_client_error(struct p9fs_session *p9s, void **mp,
    enum p9fs_msg_type expected_type)
{
	void *m = *mp;
	size_t off = 0;
	struct p9fs_msg_hdr *hdr;
	int errcode = EINVAL;

	p9fs_msg_get(m, &off, (void **)&hdr, sizeof (*hdr));
	if (hdr->hdr_type == expected_type)
		return (0);

	if (hdr->hdr_type == Rerror) {
		struct p9fs_str p9str;
		uint32_t *proto_err;

		p9fs_msg_get_str(m, &off, &p9str);
		p9fs_msg_get(m, &off, (void *)&proto_err, sizeof (*proto_err));
		errcode = *proto_err;
		printf("%s: Rerror ret: errcode=%d err(%d)='%.*s'\n",
		    __func__, errcode, p9str.p9str_size,
		    p9str.p9str_size, p9str.p9str_str);
		if (errcode == -1)
			errcode = EIO;
	}
	p9fs_msg_destroy(p9s, m);
	*mp = NULL;
	return (errcode);
}
#endif

/*
 * flush - abort a message
 *
 *   size[4] Tflush tag[2] oldtag[2]
 *   size[4] Rflush tag[2]
 *
 ******** PROTOCOL NOTES
 *
 ********
 *
 */
int
p9fs_client_flush(void)
{
	return (EINVAL);
}

/*
 * open, create - prepare a fid for I/O on an existing or new file
 *
 *   size[4] Topen tag[2] fid[4] mode[1]
 *   size[4] Ropen tag[2] qid[13] iounit[4]
 *
 *   size[4] Tcreate tag[2] fid[4] name[s] perm[4] mode[1] extension[s]
 *   size[4] Rcreate tag[2] qid[13] iounit[4]
 *
 ******** PROTOCOL NOTES
 * Topen fid[4]: Existing fid opened via Twalk.
 * Tcreate fid[4]: ???
 ********
 *
 */
int
p9fs_client_open(struct p9fs_session *p9s, uint32_t fid, int mode)
{
	struct l9p_client_rpc *msg = NULL;
	int error = 0;
	uint8_t mode1;

	msg = l9p_calloc(1, sizeof(*msg));
	if (msg == NULL)
		return (ENOMEM);
	msg->conn = &p9s->connection;
	
retry:
	/* Convert VOP_OPEN() mode to 9P2000 mode[1]. */
	if ((mode & (FREAD|FWRITE)) == (FREAD|FWRITE))
		mode1 = L9P_ORDWR;
	else if (mode & FREAD)
		mode1 = L9P_OREAD;
	else if (mode & FWRITE)
		mode1 = L9P_OWRITE;
	if (mode & O_TRUNC)
		mode1 |= L9P_OTRUNC;
	/* There is no POSIX mode correlating to ORCLOSE. */

	error = p9_msg(&p9s->connection, &msg->message, L9P_TOPEN, fid, mode1);

	if (error)
		goto done;

	error = p9_send_and_reply(msg);
	
	if (error == EMSGSIZE)
		goto retry;
	
	if (error == 0) {
		struct l9p_qid qid;
		// Do we need to do anything with qid?
		bcopy(&msg->response.ropen.qid, &qid, sizeof(qid));
	}
done:
	if (msg) {
		l9p_freefcall(&msg->response);
		l9p_free(msg);
	}
	return (error);
}

int
p9fs_client_create(void)
{
	return (EINVAL);
}

/*
 * Common i/o callback for uio users.  This will be used by higher layers
 * that want to use read/write directly via uio, without custom translation.
 * Other callers have the choice to do additional processing.
 */
int
p9fs_client_uio_callback(void *mp, uint32_t count, size_t *offp __unused, struct uio *uio)
{
	int error = 0;

	if (uio->uio_rw == UIO_WRITE) {
		uio->uio_offset += count;
		uio->uio_resid -= count;
	} else {
		struct l9p_client_rpc *msg = mp;
		error = l9p_uio_io(&msg->response_data, uio, count);
	}

	return (error);
}

/*
 * read, write - transfer data to and from a file
 *
 *   size[4] Tread tag[2] fid[4] offset[8] count[4]
 *   size[4] Rread tag[2] count[4] data[count]
 *
 *   size[4] Twrite tag[2] fid[4] offset[8] count[4] data[count]
 *   size[4] Rwrite tag[2] count[4]
 *
 ******** PROTOCOL NOTES
 *
 ********
 *
 */
int
p9fs_client_read(struct p9fs_session *p9s, uint32_t fid,
		 io_callback iocb, struct uio *uio)
{
	struct l9p_client_rpc *msg = NULL;
	int error = 0;
	uint64_t off;
	uint32_t count;

	printf("%s(%p, %u, %p, uio = { %ld, %d }\n", __FUNCTION__, p9s, fid, iocb, uio ? uio->uio_offset : -1, uio ? uio->uio_rw : -1);

	if (iocb == NULL || uio->uio_offset < 0 || uio->uio_rw != UIO_READ)
		return (EINVAL);

	off = uio->uio_offset;
	CTASSERT(P9_MSG_MAX <= UINT32_MAX);
	count = MIN(P9_MSG_MAX, uio->uio_resid);
	if (count == 0) {
		printf("%s(%d):  count == 0\n", __FUNCTION__, __LINE__);
		return (0);
	}
	printf("%s(%d):  Made it here...\n", __FUNCTION__, __LINE__);
	msg = l9p_calloc(1, sizeof(*msg));
	if (msg == NULL)
		return (ENOMEM);
	msg->conn = &p9s->connection;
	
retry:
	error = p9_msg(&p9s->connection, &msg->message, L9P_TREAD, fid, off, count);
	if (error)
		goto done;
	
	error = p9_send_and_reply(msg);
	if (error == EMSGSIZE)
		goto retry;
	if (error == 0) {
		/*
		 * After p9_send_and_reply(), the data is in
		 * msg->response_data.
		 */
		error = iocb(msg, count, NULL, uio);
	}
	if (error) printf("%s(%d):  error = %d\n", __FUNCTION__, __LINE__, error);

done:
	if (msg) {
		l9p_freefcall(&msg->response);
		l9p_free(msg);
	}
	return (error);
}

int
p9fs_client_write(struct p9fs_session *p9s, uint32_t fid,
		  io_callback iocb, struct uio *uio)
{
	struct l9p_client_rpc *msg = NULL;
	int error = 0;
	uint64_t off;
	uint32_t count;
	
	if (iocb == NULL || uio->uio_offset < 0 || uio->uio_rw != UIO_WRITE)
		return (EINVAL);

	msg = l9p_calloc(1, sizeof(*msg));
	if (msg == NULL)
		return (ENOMEM);
	
	off = uio->uio_offset;
	CTASSERT(P9_MSG_MAX <= UINT32_MAX);
	count = MIN(P9_MSG_MAX, uio->uio_resid);
	if (count == 0)
		goto done;

retry:
	error = p9_msg(&p9s->connection, &msg->message, L9P_TWRITE, fid, off, count);
	if (error == 0) {
		size_t iov_indx = 0;

		do {
			error = l9p_msg_add_iovec(&msg->message_data, &uio->uio_iov[iov_indx]);
			// Is this correct?  Or do I need to use bcopy?
			if (error == 0)
				uio->uio_iov[iov_indx].iov_len = 0;
			iov_indx++;
		} while (error == 0 && iov_indx < uio->uio_iovcnt);
	}
	if (error)
		goto done;
	
	error = p9_send_and_reply(msg);
	if (error == EMSGSIZE)
		goto retry;

	if (error == 0) {
		uint32_t retcount = 0;

		retcount = msg->response.io.count;
		error = iocb(msg, retcount, &off, uio);
	}

done:
	if (msg) {
		l9p_freefcall(&msg->response);
		l9p_free(msg);
	}
	return (error);
}

/*
 * remove - remove a file from a server
 *
 *   size[4] Tremove tag[2] fid[4]
 *   size[4] Rremove tag[2]
 *
 ******** PROTOCOL NOTES
 *
 ********
 *
 */
int
p9fs_client_remove(void)
{
	return (EINVAL);
}

#if 0
/* Parse the 9P2000-only portion of Rstat from the message. */
void
p9fs_client_parse_std_stat(void *m, struct p9fs_stat_payload *pay, size_t *offp)
{
	size_t soff = *offp;

	p9fs_msg_get(m, offp, (void **)&pay->pay_stat, sizeof (*pay->pay_stat));
	{
		struct p9fs_stat *p9stat = pay->pay_stat;
		printf("p9stat: size=%u type=%u dev=%u qid=(%u,%u,%lu) "
		    "mode=%u atime=%u mtime=%u length=%lu\n",
		    p9stat->stat_size, p9stat->stat_type,
		    p9stat->stat_dev, p9stat->stat_qid.qid_mode,
		    p9stat->stat_qid.qid_version,
		    p9stat->stat_qid.qid_path, p9stat->stat_mode,
		    p9stat->stat_atime, p9stat->stat_mtime,
		    p9stat->stat_length);
	}
	p9fs_msg_get_str(m, offp, &pay->pay_name);
	p9fs_msg_get_str(m, offp, &pay->pay_uid);
	p9fs_msg_get_str(m, offp, &pay->pay_gid);
	p9fs_msg_get_str(m, offp, &pay->pay_muid);
	printf("p9stat: name='%.*s' uid='%.*s' gid='%.*s' muid='%.*s'\n",
	    pay->pay_name.p9str_size, pay->pay_name.p9str_str,
	    pay->pay_uid.p9str_size, pay->pay_uid.p9str_str,
	    pay->pay_gid.p9str_size, pay->pay_gid.p9str_str,
	    pay->pay_muid.p9str_size, pay->pay_muid.p9str_str);
	printf("p9stat: start off %zu end off %zu\n", soff, *offp);
}

/* Parse the 9P2000.u-only portion of Rstat from the message. */
void
p9fs_client_parse_u_stat(void *m, struct p9fs_stat_u_payload *pay, size_t *offp)
{
	size_t soff = *offp;

	p9fs_client_parse_std_stat(m, &pay->upay_std, offp);
	p9fs_msg_get_str(m, offp, &pay->upay_extension);
	p9fs_msg_get(m, offp, (void **)&pay->upay_footer,
	    sizeof (pay->upay_footer));

	printf("p9stat.u: ext='%.*s' uid=%d gid=%d muid=%d\n",
	    pay->upay_extension.p9str_size, pay->upay_extension.p9str_str,
	    pay->upay_footer->n_uid, pay->upay_footer->n_gid, pay->upay_footer->n_muid);
	printf("p9stat.u: start off %zu end off %zu\n", soff, *offp);
}
#endif

static void
print_vattr(struct vattr *vap, uint32_t fid)
{
	printf("vattr(fid=%u %p)={\n", fid, vap);
	printf("  atime=%ld mtime=%ld\n", vap->va_atime.tv_sec, vap->va_mtime.tv_sec);
	printf("  mode=%o bytes=%lu\n", vap->va_mode, vap->va_bytes);
	printf("  type=%d fileid=%lu\n", vap->va_type, vap->va_fileid);
	printf("}\n");
}

/*
 * stat, wstat - inquire or change file attributes
 *
 *   size[4] Tstat tag[2] fid[4]
 *   size[4] Rstat tag[2] stat[n]
 *
 *   size[4] Twstat tag[2] fid[4] stat[n]
 *   size[4] Rwstat tag[2]
 *
 ******** PROTOCOL NOTES
 * Tfid[4]: Fid to perform the stat call on.
 ********
 *
 * This is only used for p9fs_getattr(), so its call signature reflects that.
 */
int
p9fs_client_stat(struct p9fs_session *p9s, uint32_t fid, struct vattr *vap)
{
	struct l9p_client_rpc *msg = NULL;
	int error = 0;

	msg = l9p_calloc(1, sizeof(*msg));
	if (msg == NULL)
		return (ENOMEM);
	msg->conn = &p9s->connection;
	
retry:
	error = p9_msg(&p9s->connection, &msg->message, L9P_TSTAT, fid);

	if (error)
		goto done;
	
	error = p9_send_and_reply(msg);
	if (error == EMSGSIZE)
		goto retry;

	if (error)
		goto done;
	

	struct l9p_stat *statp = &msg->response.rstat.stat;
	vap->va_nlink = 1;
	vap->va_atime.tv_sec = statp->atime;
	vap->va_mtime.tv_sec = statp->mtime;
	vap->va_ctime.tv_sec = statp->mtime;
	vap->va_size = statp->length;
	vap->va_bytes = statp->length;
	vap->va_rdev = statp->dev;
	vap->va_filerev = statp->qid.version;
	vap->va_gen = statp->qid.version;
	vap->va_mode = statp->mode & ~L9P_DMDIR;
	vap->va_fileid = statp->qid.path;
	vap->va_blocksize = MAXPHYS;
	
	switch (statp->qid.type) {
	case L9P_QTDIR:
		vap->va_type = VDIR;
		vap->va_nlink++;
		break;
	case L9P_QTSYMLINK:
		vap->va_type = VLNK;
		break;
	case L9P_QTFILE:
		vap->va_type = VREG;
		break;
	default:
		/* Try again from stat_mode's upper bits. */
		switch (statp->mode & L9P_DMDIR) {
		case L9P_DMDEVICE:
			vap->va_type = VBLK;
			break;
		case L9P_DMSYMLINK:
			vap->va_type = VLNK;
			break;
		case L9P_DMSOCKET:
			vap->va_type = VSOCK;
			break;
		case L9P_DMNAMEDPIPE:
			vap->va_type = VFIFO;
			break;
		default:
			/* XXX What should be done with other types? */
			vap->va_type = VNON;
			break;
		}
		break;
	}
	vap->va_uid = statp->n_uid;
	vap->va_gid = statp->n_gid;

	print_vattr(vap, fid);

done:
	if (msg) {
		l9p_freefcall(&msg->response);
		l9p_free(msg);
	}
	return (error);
}

int
p9fs_client_wstat(struct p9fs_session *p9s, uint32_t fid, struct vattr *vap)
{
	struct l9p_client_rpc *msg = NULL;
	int error = 0;
	struct l9p_stat p9stat = { 0 };
	
	msg = l9p_calloc(1, sizeof(*msg));
	if (msg == NULL)
		return (ENOMEM);
	msg->conn = &p9s->connection;
	
	// Do some setup first
	p9stat.length = vap->va_size;
	p9stat.dev = vap->va_rdev;
	p9stat.mode = vap->va_mode & ~S_IFMT;
	p9stat.atime = vap->va_atime.tv_sec;
	p9stat.mtime = vap->va_mtime.tv_sec;
	p9stat.qid.version = vap->va_filerev;
	p9stat.qid.path = vap->va_fileid;
	switch (vap->va_type) {
	case VDIR:
		p9stat.qid.type = L9P_QTDIR;
		break;
	case VLNK:
		p9stat.qid.type = L9P_QTSYMLINK;
		p9stat.mode |= L9P_DMSYMLINK;
		break;
	case VREG:
		p9stat.qid.type = L9P_QTFILE;
		break;
	case VBLK:
		p9stat.mode |= L9P_DMDEVICE;
		break;
	case VSOCK:
		p9stat.mode |= L9P_DMSOCKET;
		break;
	case VFIFO:
		p9stat.mode |= L9P_DMNAMEDPIPE;
		break;
	default:
		break;
	}
	p9stat.n_uid = vap->va_uid;
	p9stat.n_gid = vap->va_gid;
	
retry:
	error = p9_msg(&p9s->connection, &msg->message, L9P_TWSTAT, fid, &p9stat);
	if (error != 0)
		goto done;

	error = p9_send_and_reply(msg);
	if (error == EMSGSIZE)
		goto retry;
done:
	if (msg) {
		l9p_freefcall(&msg->response);
		l9p_free(msg);
	}
	return (error);
}

/*
 * walk - descend a directory hierarchy
 *
 *   size[4] Twalk tag[2] fid[4] newfid[4] nwname[2] nwname*(wname[s])
 *   size[4] Rwalk tag[2] nwqid[2] nwqid*(qid[13])
 *
 ******** PROTOCOL NOTES
 * Tfid[4] must be a fid for a directory
 * Tnewfid[4] is the proposed fid for the thing being walked to.
 * Tnwname[2] is the number of things to walk down; newfid is for the last.
 * T*wname[s] are the names of those things.
 ********
 *
 * For the purposes of p9fs, this call will only ever be used for a single
 * walk at a time, due to the nature of POSIX VFS.
 *
 * Note that this call is used to open files in addition to directories.
 */
int
p9fs_client_walk(struct p9fs_session *p9s, uint32_t fid, uint32_t newfid,
		 size_t namelen, const char *namestr, struct l9p_qid *qidp)
{
	struct l9p_client_rpc *msg = NULL;
	int error = 0;

	msg = l9p_calloc(1, sizeof(*msg));
	if (msg == NULL)
		return (ENOMEM);
	msg->conn = &p9s->connection;
	
retry:
	error = p9_msg(&p9s->connection, &msg->message, L9P_TWALK, fid, newfid, namestr);
	if (error)
		goto done;
	
	error = p9_send_and_reply(msg);
	if (error == EMSGSIZE)
		goto retry;

	if (error == 0) {
		if (msg->response.rwalk.nwqid == 0) {
			error = ENOENT;	// Is that right?
		} else {
			bcopy(&msg->response.rwalk.wqid[0], qidp, sizeof(*qidp));
		}
	}

done:
	if (msg) {
		l9p_freefcall(&msg->response);
		l9p_free(msg);
	}
	return (error);
}
