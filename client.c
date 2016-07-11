#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <stdarg.h>
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
 */
int
client_pack_message(struct l9p_client_connection *client, struct iovec *msg, union l9p_fcall *fcallp)
{
	int error;
	struct l9p_message packed_msg;
	void *buffer;

	buffer = l9p_calloc(1, client->lc_max_io_size);
	if (buffer == NULL) {
		return (ENOMEM);
	}

	bzero(&packed_msg, sizeof(packed_msg));
	packed_msg.lm_mode = L9P_PACK;
	packed_msg.lm_iov[0].iov_base = buffer;
	packed_msg.lm_iov[0].iov_len = client->lc_max_io_size;
	packed_msg.lm_niov = 1;

	error = l9p_pufcall(&packed_msg, fcallp, client->lc_version);
	if (error) {
		l9p_free(buffer);
		msg->iov_base = 0;
		msg->iov_len = 0;
	} else {
		msg->iov_base = buffer;
		msg->iov_len = packed_msg.lm_size;
	}
	return (error);
}

int
client_unpack_message(struct l9p_client_connection *client, struct iovec *msg, union l9p_fcall *fcallp)
{
	int error = 0;
	struct l9p_message packed_msg;

	bzero(&packed_msg, sizeof(packed_msg));
	packed_msg.lm_mode = L9P_UNPACK;
	packed_msg.lm_iov[0] = *msg;
	packed_msg.lm_niov = 1;

	error = l9p_pufcall(&packed_msg, fcallp, client->lc_version);

	return (error);
		
}

/*
 * Construct a l9p_message from the parameters.
 */
int
vp9_msg(struct l9p_client_connection *conn, union l9p_fcall *fcallp, enum l9p_ftype type, uint16_t *tagp, va_list ap)
{
	int error = 0;
	size_t indx = 0;
	char *twalk_name;
	uint32_t maxsize;
	char *version_string;

	/*
	 * Every T message except for TVERSION has <type, tag, fid>
	 * If I start supporting creating R messages, this will have to
	 * change.
	 */
	if (type != L9P_TVERSION) {
		*tagp = conn->get_tag(conn);
		fcallp->hdr.type = type;
		fcallp->hdr.tag = *tagp;
		fcallp->hdr.fid = va_arg(ap, uint32_t);
	}
#define STD(f, ty, ta, va) (void)0

	switch (type) {
	case L9P_TVERSION:
		maxsize = (uint32_t)va_arg(ap, int);
		version_string = va_arg(ap, char *);
		fcallp->version.hdr.type = type;
		fcallp->version.hdr.tag = *tagp = NOTAG;	// Override the normal case
		fcallp->version.msize = maxsize;
		fcallp->version.version = version_string;
		break;
	case L9P_TATTACH:
		STD(fcallp, type, *tagp, ap);
		fcallp->tattach.afid = va_arg(ap, uint32_t);
		fcallp->tattach.uname = va_arg(ap, char*);
		fcallp->tattach.aname = va_arg(ap, char*);
		if (conn->lc_version > L9P_2000)
			fcallp->tattach.n_uname = va_arg(ap, uint32_t);
		break;
	case L9P_TOPEN:
		STD(fcallp, type, *tagp, ap);
		fcallp->topen.mode = (uint8_t)va_arg(ap, unsigned int);
		fcallp->topen.name = NULL;
		break;
	case L9P_TCREATE:
		STD(fcallp, type, *tagp, ap);
		fcallp->topen.name = strdup(va_arg(ap, char*));
		fcallp->topen.perm = va_arg(ap, uint32_t);
		fcallp->topen.mode = (uint8_t)va_arg(ap, unsigned int);
		break;
	case L9P_TWALK:
		STD(fcallp, type, *tagp, ap);
		fcallp->twalk.newfid = va_arg(ap, uint32_t);
		error = 0;
		while ((twalk_name = va_arg(ap, char *)) != NULL) {
			char *tmp = strdup(twalk_name);

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
		STD(fcallp, type, *tagp, ap);
		break;
	case L9P_TWSTAT:
		STD(fcallp, type, *tagp, ap);
		fcallp->twstat.stat = *va_arg(ap, struct l9p_stat *);
		break;
	case L9P_TFLUSH:
		STD(fcallp, type, *tagp, ap);
		fcallp->tflush.oldtag = (uint16_t)va_arg(ap, int);
		break;
	case L9P_TREAD:
		STD(fcallp, type, *tagp, ap);
		fcallp->io.offset = va_arg(ap, uint64_t);
		fcallp->io.count = va_arg(ap, uint32_t);
		fcallp->io.data = NULL;
		break;
	case L9P_TWRITE:
		STD(fcallp, type, *tagp, ap);
		fcallp->io.offset = va_arg(ap, uint64_t);
		fcallp->io.count = va_arg(ap, uint32_t);
		fcallp->io.data = l9p_calloc(1, fcallp->io.count);
		if (fcallp->io.data)
			bcopy(va_arg(ap, void*), fcallp->io.data, fcallp->io.count);
		else {
			l9p_freefcall(fcallp);
			error = ENOMEM;
		}
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error);
}

int
p9_msg(struct l9p_client_connection *conn, union l9p_fcall *fcallp, enum l9p_ftype type, uint16_t *tagp, ...)
{
	va_list ap;

	va_start(ap, tagp);
	return vp9_msg(conn, fcallp, type, tagp, ap);
}

int
packed_p9_msg(struct l9p_client_connection *conn, struct iovec *iovc, enum l9p_ftype type, uint16_t *tagp, ...)
{
	va_list ap;
	union l9p_fcall fcall;
	int error = 0;

	va_start(ap, tagp);

	error = vp9_msg(conn, &fcall, type, tagp, ap);
	if (error == 0)
		error = client_pack_message(conn, iovc, &fcall);
	return (error);
}
