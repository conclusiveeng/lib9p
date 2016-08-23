#ifndef _KERNEL
# include <stdio.h>
# include <stdlib.h>
# include <errno.h>
# include <stdarg.h>
# include <string.h>
# include <strings.h>
# include <err.h>
#else
# include <sys/libkern.h>
# include <sys/errno.h>
# include <machine/stdarg.h>
#endif
#include <sys/param.h>
#include <sys/uio.h>
#ifdef __APPLE__
# include "apple_endian.h"
#else
# include <sys/endian.h>
#endif
#if defined(__FreeBSD__)
# include <sys/sbuf.h>
#else
# include "sbuf/sbuf.h"
#endif

#include "client.h"
#include "lib9p_impl.h"
#include "fcall.h"

/*
 * Pack the fcall into msg.
 * This always packs msg->message to msg->message_data
 */
int
client_pack_message(struct l9p_client_rpc *msg)
{
	struct l9p_client_connection *client = msg->conn;
	int error;
	void *buffer;

	buffer = l9p_calloc(1, client->lc_max_io_size);
	if (buffer == NULL) {
		return (ENOMEM);
	}

	bzero(&msg->message_data, sizeof(msg->message_data));
	msg->message_data.lm_mode = L9P_PACK;
	msg->message_data.lm_iov[0].iov_base = buffer;
	msg->message_data.lm_iov[0].iov_len = client->lc_max_io_size;
	msg->message_data.lm_niov = 1;
	error = l9p_pufcall(&msg->message_data, &msg->message, client->lc_version);
	if (error) {
		l9p_free(buffer);
		bzero(&msg->message_data, sizeof(msg->message_data));
	} else {
		msg->message_data.lm_iov[0].iov_len = msg->message_data.lm_size;
	}
	return (error);
}

/*
 * Unpacks a message.
 * The message is in msg->response_data, and should have at least one iovec
 * structure filled out.  This is a much simpler function than it used to
 * be.  Any response with data (Rread{,dir}, maybe others?) will have the
 * data accessible using l9p_iov_io(msg->response_data, buffer, len).
 */
int
client_unpack_message(struct l9p_client_rpc *msg)
{
	int error = 0;

	bzero(&msg->response, sizeof(msg->response));
	msg->response_data.lm_mode = L9P_UNPACK;
	error = l9p_pufcall(&msg->response_data, &msg->response, msg->conn->lc_version);

	return (error);
		
}

/*
 * Send a p9 message, and get its reply.
 * Returns an error, and sets *response to NULL if
 * unable to send the message.  If the response is
 * an error message, then it returns the error, and *response
 * is not NULL.
 */
int
p9_send_and_reply(struct l9p_client_rpc *msg)
{
	struct sbuf *sb = sbuf_new_auto();
	union l9p_fcall *send, *recv;
	int error = 0;
	struct l9p_client_connection *conn = msg->conn;
	enum l9p_ftype expected;
	
	bzero(&msg->message_data, sizeof(msg->message_data));
	bzero(&msg->response, sizeof(msg->response));
	bzero(&msg->response_data, sizeof(msg->response_data));

	// All messages have a tag
	send = &msg->message;
	recv = &msg->response;

	msg->tag = send->hdr.tag;
	
	l9p_describe_fcall(send, conn->lc_version, sb);
	printf("%s\n", sbuf_data(sb));
	sbuf_clear(sb);

	expected = send->hdr.type + 1;
	error = client_pack_message(msg);
	if (error)
		goto done;

	error = conn->send_msg(msg);

	if (error == 0)
		error = conn->recv_msg(msg);

	if (error == 0) {
		struct l9p_message *response = &msg->response_data;
		error = client_unpack_message(msg);
	}
	if (error)
		goto done;

	if (msg->response.hdr.type == L9P_RERROR)
		error = (int)(msg->response.error.errnum);

	if (msg->response.hdr.type != expected) {
		error = EINVAL;
	}
done:
	if (sb)
		sbuf_delete(sb);
	return (error);
}

/*
 * Construct a l9p_message from the parameters.
 */
int
vp9_msg(struct l9p_client_connection *conn, union l9p_fcall *fcallp, enum l9p_ftype type, va_list ap)
{
	int error = 0;
	size_t indx = 0;
	char *twalk_name;
	uint32_t maxsize;
	char *version_string;

	bzero(fcallp, sizeof(*fcallp));
	/*
	 * Every T message except for TVERSION has <type, tag, fid>
	 * If I start supporting creating R messages, this will have to
	 * change.
	 */
	if (type != L9P_TVERSION) {
		fcallp->hdr.tag = conn->get_tag(conn);
		fcallp->hdr.type = type;
		fcallp->hdr.fid = va_arg(ap, uint32_t);
	}

	switch (type) {
	case L9P_TVERSION:
		maxsize = (uint32_t)va_arg(ap, int);
		version_string = va_arg(ap, char *);
		fcallp->hdr.type = fcallp->version.hdr.type = type;
		fcallp->version.hdr.tag = NOTAG;	// Override the normal case
		fcallp->version.msize = maxsize;
		fcallp->version.version = version_string;
		break;
	case L9P_TATTACH:
		fcallp->tattach.afid = va_arg(ap, uint32_t);
		fcallp->tattach.uname = va_arg(ap, char*);
		fcallp->tattach.aname = va_arg(ap, char*);
		if (conn->lc_version > L9P_2000)
			fcallp->tattach.n_uname = va_arg(ap, uint32_t);
		break;
	case L9P_TOPEN:
		fcallp->topen.mode = (uint8_t)va_arg(ap, unsigned int);
		fcallp->topen.name = NULL;
		break;
	case L9P_TCREATE:
		fcallp->topen.name = l9p_strdup(va_arg(ap, char*));
		fcallp->topen.perm = va_arg(ap, uint32_t);
		fcallp->topen.mode = (uint8_t)va_arg(ap, unsigned int);
		break;
	case L9P_TWALK:
		fcallp->twalk.newfid = va_arg(ap, uint32_t);
		error = 0;
		while ((twalk_name = va_arg(ap, char *)) != NULL) {
			char *tmp = l9p_strdup(twalk_name);

			if (tmp == NULL) {
				error = ENOMEM;
				break;
			}
			fcallp->twalk.wname[indx++] = tmp;

			if (indx >= L9P_MAX_WELEM) {
				error = ERANGE;
				break;
			}
		}
		if (error) {
			l9p_freefcall(fcallp);
		} else {
			fcallp->twalk.nwname = (uint16_t)indx;
		}
		break;
	case L9P_TCLUNK:
	case L9P_TREMOVE:
	case L9P_TSTAT:
		break;
	case L9P_TWSTAT:
		fcallp->twstat.stat = *va_arg(ap, struct l9p_stat *);
		break;
	case L9P_TFLUSH:
		fcallp->tflush.oldtag = (uint16_t)va_arg(ap, int);
		break;
	case L9P_TREAD:
		fcallp->io.offset = va_arg(ap, uint64_t);
		fcallp->io.count = va_arg(ap, uint32_t);
		break;
	case L9P_TWRITE:
		fcallp->io.offset = va_arg(ap, uint64_t);
		fcallp->io.count = va_arg(ap, uint32_t);
#if 0
		fcallp->io.data = l9p_calloc(1, fcallp->io.count);
		if (fcallp->io.data)
			bcopy(va_arg(ap, void*), fcallp->io.data, fcallp->io.count);
		else {
			l9p_freefcall(fcallp);
			error = ENOMEM;
		}
#else
		printf("%s(%d):  caller needs to add iovec\n", __FUNCTION__, __LINE__);
#endif
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error);
}

int
p9_msg(struct l9p_client_connection *conn, union l9p_fcall *fcallp, enum l9p_ftype type, ...)
{
	va_list ap;

	va_start(ap, type);
	return vp9_msg(conn, fcallp, type, ap);
}
