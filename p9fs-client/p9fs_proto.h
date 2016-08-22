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
 * Plan9 filesystem (9P2000.u) protocol definitions.
 */

/**************************************************************************
 * Plan9 protocol documentation section
 **************************************************************************/

/*
 * 2 Introduction / 2.1 Messages
 *
 * - A client transmits requests (T-messages) to a server, which subsequently
 *   returns replies (R-messages) to the client.  The combined acts of
 *   transmitting (receiving) a request of a particular type, and receiving
 *   (transmitting) its reply is called a transaction of that type.
 *
 * - Each message consists of a sequence of bytes. Two-, four-, and
 *   eight-byte fields hold unsigned integers represented in little-endian
 *   order (least significant byte first).  Data items of larger or variable
 *   lengths are represented by a two-byte field specifying a count, n,
 *   followed by n bytes of data. Text strings are represented this way, with
 *   the text itself stored as a UTF-8 encoded sequence of Unicode characters.
 *   Text strings in 9P messages are not NUL-terminated: n counts the bytes
 *   of UTF-8 data, which include no final zero byte.  The NUL character is
 *   illegal in all text strings in 9P, and is therefore excluded from file
 *   names, user names, and so on.
 *
 * - Each 9P message begins with a four-byte size field specifying the length
 *   in bytes of the complete message including the four bytes of the size
 *   field itself.  The next byte is the message type, one of the constants
 *   in the enumeration in the include file fcall.h.  The next two bytes are
 *   an identifying tag, described below. The remaining bytes are parameters
 *   of different sizes. In the message descriptions, the number of bytes in a
 *   field is given in brackets after the field name.  The notation
 *   parameter[n] where n is not a constant represents a variable-length
 *   parameter: n[2] followed by n bytes of data forming the parameter.
 *   The notation string[s] (using a literal s character) is shorthand for
 *   s[2] followed by s bytes of UTF-8 text.  (Systems may choose to reduce
 *   the set of legal characters to reduce syntactic problems, for example
 *   to remove slashes from name components, but the protocol has no such
 *   restriction.  Plan 9 names may contain any printable character (that
 *   is, any character outside hexadecimal 00-1F and 80-9F) except slash.)
 *   Messages are transported in byte form to allow for machine independence;
 *   fcall(2) describes routines that convert to and from this form into a
 *   machine-dependent C structure.
 *
 * - Each T-message has a tag field, chosen and used by the client to
 *   identify the message.  The reply to the message will have the same tag.
 *   Clients must arrange that no two outstanding messages on the same
 *   connection have the same tag.  An exception is the tag NOTAG, defined
 *   as (ushort)~0 in fcall.h: the client can use it, when establishing a
 *   connection, to override tag matching in version messages.
 *
 * - The type of an R-message will either be one greater than the type of
 *   the corresponding T-message or Rerror, indicating that the request failed.
 *   In the latter case, the ename field contains a string describing the
 *   reason for failure.
 *
 * - The version message identifies the version of the protocol and indicates
 *   the maximum message size the system is prepared to handle.  It also
 *   initializes the connection and aborts all outstanding I/O on the
 *   connection.  The set of messages between version requests is called
 *   a session.
 *
 * - Most T-messages contain a fid, a 32-bit unsigned integer that the
 *   client uses to identify a ``current file'' on the server.  Fids are
 *   somewhat like file descriptors in a user process, but they are not
 *   restricted to files open for I/O: directories being examined, files
 *   being accessed by stat(2) calls, and so on -- all files being
 *   manipulated by the operating system -- are identified by fids.  Fids are
 *   chosen by the client.  All requests on a connection share the same fid
 *   space; when several clients share a connection, the agent managing the
 *   sharing must arrange that no two clients choose the same fid.
 *
 * - The fid supplied in an attach message will be taken by the server to
 *   refer to the root of the served file tree.  The attach identifies the
 *   user to the server and may specify a particular file tree served by the
 *   server (for those that supply more than one).
 *
 * - Permission to attach to the service is proven by providing a special
 *   fid, called afid, in the attach message.  This afid is established by
 *   exchanging auth messages and subsequently manipulated using read and
 *   write messages to exchange authentication information not defined
 *   explicitly by 9P [P9SEC].  Once the authentication protocol is
 *   complete, the afid is presented in the attach to permit the user to
 *   access the service.
 *
 * - A walk message causes the server to change the current file associated
 *   with a fid to be a file in the directory that is the old current file,
 *   or one of its subdirectories.  Walk returns a new fid that refers to
 *   the resulting file.  Usually, a client maintains a fid for the root,
 *   and navigates by walks from the root fid.
 *
 * - A client can send multiple T-messages without waiting for the
 *   corresponding R-messages, but all outstanding T-messages must specify
 *   different tags.  The server may delay the response to a request and
 *   respond to later ones; this is sometimes necessary, for example when
 *   the client reads from a file that the server synthesizes from external
 *   events such as keyboard characters.
 *
 * - Replies (R-messages) to auth, attach, walk, open, and create requests
 *   convey a qid field back to the client.  The qid represents the server's
 *   unique identification for the file being accessed: two files on the
 *   same server hierarchy are the same if and only if their qids are the
 *   same. (The client may have multiple fids pointing to a single file on
 *   a server and hence having a single qid.)  The thirteen-byte qid fields
 *   hold a one-byte type, specifying whether the file is a directory,
 *   append-only file, etc., and two unsigned integers: first the four-byte
 *   qid version, then the eight-byte qid path.  The path is an integer unique
 *   among all files in the hierarchy.  If a file is deleted and recreated
 *   with the same name in the same directory, the old and new path
 *   components of the qids should be different.  The version is a version
 *   number for a file; typically, it is incremented every time the file
 *   is modified.
 *
 * - An existing file can be opened, or a new file may be created in the
 *   current (directory) file.  I/O of a given number of bytes at a given
 *   offset on an open file is done by read and write.
 *
 * - A client should clunk any fid that is no longer needed. The remove
 *   transaction deletes files.
 *
 * - The stat transaction retrieves information about the file.  The stat
 *   field in the reply includes the file's name, access permissions (read,
 *   write and execute for owner, group and public), access and modification
 *   times, and owner and group identifications (see stat(2)).  The owner
 *   and group identifications are textual names.  The wstat transaction
 *   allows some of a file's properties to be changed.  A request can be
 *   aborted with a flush request.  When a server receives a Tflush, it
 *   should not reply to the message with tag oldtag (unless it has already
 *   replied), and it should immediately send an Rflush.  The client must
 *   wait until it gets the Rflush (even if the reply to the original message
 *   arrives in the interim), at which point oldtag may be reused.
 *
 * - Because the message size is negotiable and some elements of the
 *   protocol are variable length, it is possible (although unlikely) to
 *   have a situation where a valid message is too large to fit within the
 *   negotiated size.  For example, a very long file name may cause a Rstat
 *   of the file or Rread of its directory entry to be too large to send.
 *   In most such cases, the server should generate an error rather than
 *   modify the data to fit, such as by truncating the file name.  The
 *   exception is that a long error string in an Rerror message should be
 *   truncated if necessary, since the string is only advisory and in
 *   some sense arbitrary.
 *
 * - 
 */

/*
 * 2.2 Directories
 *
 * - Directories are created by create with DMDIR set in the permissions
 *   argument.  The members of a directory can be found with
 *   read(5).  All directories must support walks to the directory ..
 *   (dot-dot) meaning parent directory, although by convention directories
 *   contain no explicit entry for .. or . (dot).  The parent of the root
 *   directory of a server's tree is itself.
 *
 * - Each file server maintains a set of user and group names.  Each user
 *   can be a member of any number of groups.  Each group has a group leader
 *   who has special privileges.  Every file request has an implicit user id
 *   (copied from the original attach) and an implicit set of groups (every
 *   group of which the user is a member).
 */

/*
 * 2.3 Access Permissions
 *
 * - Each file has an associated owner and group id and three sets of
 *   permissions: those of the owner, those of the group, and those of
 *   ``other'' users.  When the owner attempts to do something to a file,
 *   the owner, group, and other permissions are consulted, and if any of
 *   them grant the requested permission, the operation is allowed.  For
 *   someone who is not the owner, but is a member of the file's group, the
 *   group and other permissions are consulted.  For everyone else, the
 *   other permissions are used.  Each set of permissions says whether
 *   reading is allowed, whether writing is allowed, and whether executing
 *   is allowed.  A walk in a directory is regarded as executing the
 *   directory, not reading it.  Permissions are kept in the low-order bits
 *   of the file mode: owner read/write/execute permission represented as
 *   1 in bits 8, 7, and 6 respectively (using 0 to number the low order).
 *   The group permissions are in bits 5, 4, and 3, and the other
 *   permissions are in bits 2, 1, and 0.
 *
 * - The file mode contains some additional attributes besides the
 *   permissions.  If bit 31 (DMDIR) is set, the file is a directory; if
 *   bit 30 (DMAPPEND) is set, the file is append-only (offset is ignored
 *   in writes); if bit 29 (DMEXCL) is set, the file is exclusive- use
 *   (only one client may have it open at a time); if bit 27 (DMAUTH) is set,
 *   the file is an authentication file established by auth messages; if
 *   bit 26 (DMTMP) is set, the contents of the file (or directory) are not
 *   included in nightly archives.  (Bit 28 is skipped for historical
 *   reasons.)  These bits are reproduced, from the top bit down, in the
 *   type byte of the Qid: QTDIR, QTAPPEND, QTEXCL, (skipping one bit)
 *   QTAUTH, and QTTMP.  The name QTFILE, defined to be zero, identifies
 *   the value of the type for a plain file.
 */

/**************************************************************************
 * Plan9 protocol definitions section
 **************************************************************************/

#include "../lib9p.h"
#include "../lib9p_impl.h"
#include "../client.h"

#ifndef	__P9FS_PROTO_H__
#define	__P9FS_PROTO_H__

/* This FID is not specified by the standard, but implemented here as such. */
#define	ROOTFID		(uint32_t)0

#define	P9_VERS		"9P2000"
#define	UN_VERS		P9_VERS ".u"
#define	P9_MSG_MAX	(1024 * 1024)	// 1mbyte max for now

/**************************************************************************
 * Plan9 session details section
 **************************************************************************/

struct p9fs_req {
	TAILQ_ENTRY(p9fs_req) req_link;
	uint16_t req_tag;
	struct mbuf *req_msg;
	int req_error;
};
TAILQ_HEAD(p9fs_req_list, p9fs_req);

struct p9fs_recv {
	uint32_t p9r_resid;
	uint32_t p9r_size;
	int p9r_error;
	int p9r_soupcalls;
	struct mbuf *p9r_msg;
	struct p9fs_req_list p9r_reqs;
};

enum p9s_type {
	P9S_UNKNOWN = 0,
	P9S_SOCKET,
	P9S_VIRTIO,
};

enum p9s_state {
	P9S_INIT,
	P9S_RUNNING,
	P9S_CLOSING,
	P9S_CLOSED,
};

struct p9fs_session;

struct p9fs_node_user {
	uint32_t p9nu_read_fid;
	uint16_t p9nu_read_refs;
	uint32_t p9nu_write_fid;
	uint16_t p9nu_write_refs;
	uint32_t p9nu_append_fid;
	uint16_t p9nu_append_refs;
};

/* A Plan9 node. */
struct p9fs_node {
	uint32_t p9n_fid;
	uint32_t p9n_ofid;
	uint32_t p9n_opens;
	struct l9p_qid p9n_qid;
	struct vnode *p9n_vnode;
	struct p9fs_session *p9n_session;
};

#define	MAXUNAMELEN	32
struct l9p_socket_context {
	int p9s_proto;
	int p9s_sockaddr_len;
	struct sockaddr p9s_sockaddr;
	struct socket *p9s_sock;
	int p9s_socktype;
};

struct p9fs_session {
	enum p9s_type p9s_type;
	enum p9s_state p9s_state;
	struct mtx p9s_lock;
	struct p9fs_recv p9s_recv;
	int p9s_threads;

	struct l9p_client_connection connection;
	uint32_t p9s_uid;
	char p9s_uname[MAXUNAMELEN];
	uint32_t p9s_afid;
	char p9s_path[MAXPATHLEN];

	struct mount *p9s_mount;
	struct p9fs_node p9s_rootnp;

};

typedef int (*io_callback)(void *, uint32_t, size_t *, struct uio *);

/* Primary 9P2000.u client API calls. */
int p9fs_client_version(struct p9fs_session *);
int p9fs_client_auth(struct p9fs_session *);
int p9fs_client_attach(struct p9fs_session *);
int p9fs_client_clunk(struct p9fs_session *, uint32_t);
int p9fs_client_flush(void);
int p9fs_client_open(struct p9fs_session *, uint32_t, int);
int p9fs_client_create(void);
int p9fs_client_read(struct p9fs_session *, uint32_t, io_callback, struct uio *);
int p9fs_client_write(struct p9fs_session *, uint32_t, io_callback, struct uio *);
int p9fs_client_remove(void);
int p9fs_client_stat(struct p9fs_session *, uint32_t, struct vattr *);
int p9fs_client_wstat(struct p9fs_session *, uint32_t, struct vattr *);
int p9fs_client_walk(struct p9fs_session *, uint32_t, uint32_t, size_t,
		     const char *, struct l9p_qid *);

/* Helpers for working with API data. */
int p9fs_client_uio_callback(void *, uint32_t, size_t *, struct uio *);
void p9fs_client_parse_std_stat(void *, struct l9p_stat *, size_t *);
void p9fs_client_parse_u_stat(void *, struct l9p_stat *, size_t *);

/* Wrapper API calls. */
int p9fs_nget(struct p9fs_session *, uint32_t, struct l9p_qid *,
    int, struct p9fs_node **);
int p9fs_client_getnode(struct p9fs_node *, char *, struct p9fs_node **);

/* Send and receive functions */
int p9fs_msg_send(struct l9p_client_rpc *);
int p9fs_msg_recv(struct l9p_client_rpc *);

#endif /* __P9FS_PROTO_H__ */
