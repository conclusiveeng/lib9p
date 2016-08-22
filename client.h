#ifndef _9PCLIENT_H
# define _9PCLIENT_H

# ifdef _KERNEL
#  include <machine/stdarg.h>
# else
#  include <stdarg.h>
# endif

// May need to change this
# include "lib9p.h"
# include "fid.h"

# define NOTAG	((uint16_t)(~0))
# define NOFID	((uint32_t)(~0))

/*
 * This is used to send a message and get its response.
 * The context field is transport-specific.
 */
struct l9p_client_connection;

struct l9p_client_rpc {
	uint16_t	tag;
	union l9p_fcall		message;
	struct l9p_message	message_data;
	union l9p_fcall		response;
	struct l9p_message	response_data;
	struct l9p_client_connection	*conn;
	void		*client_context;
};

/*
 * Similar to l9p_connection, but without the server aspects.
 */
struct l9p_client_connection {
	enum l9p_version lc_version;
	uint32_t	root_fid;
	uint32_t lc_msize;
	uint32_t lc_max_io_size;
	void	*context;
	void	*fids;		// context to determine next fid
	void	*tags;		// context to determine next hash

	int	(*send_msg)(struct l9p_client_rpc *);
	int	(*recv_msg)(struct l9p_client_rpc *);
	uint16_t	(*get_tag)(struct l9p_client_connection *);
	uint32_t	(*get_fid)(struct l9p_client_connection *);
	void	(*release_tag)(struct l9p_client_connection *, uint16_t tag);
	void	(*release_fid)(struct l9p_client_connection *, uint32_t fid);
};

int client_pack_message(struct l9p_client_rpc *);
int client_unpack_message(struct l9p_client_rpc *);

/*
 * RPC functions
 */
void p9_init_rpc(struct l9p_client_connection *, struct l9p_client_rpc *);
int p9_send_and_reply(struct l9p_client_rpc *);

/*
 * Functions to create a p9 message.
 */
int vp9_msg(struct l9p_client_connection *, union l9p_fcall *msg, enum l9p_ftype type, va_list ap);
int p9_msg(struct l9p_client_connection *, union l9p_fcall *msg, enum l9p_ftype type, ...);

#endif /* _9PCLIENT_H */
