//
// Created by Jakub Klama on 28.12.2015.
//

#ifndef LIB9P_SOCKET_H
#define LIB9P_SOCKET_H

#include <sys/types.h>
#include <sys/socket.h>
#include "../lib9p.h"

int l9p_start_server(struct l9p_server *server, const char *host,
    const char *port);
void l9p_socket_accept(struct l9p_server *server, int conn_fd,
    struct sockaddr *client_addr, socklen_t client_addr_len);

#endif //LIB9P_SOCKET_H
