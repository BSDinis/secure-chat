/***
 * peer.h
 */

#pragma once

#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>

#include "buffer_queue.h"
#include "ssl_info.h"
#include "ssl_util.h"

#define MAX_MSG_SZ (1 << 11)

typedef struct peer_t
{
  int socket;
  struct sockaddr_in address;

  buffer_queue send_queue;

  uint8_t recv_buffer[MAX_MSG_SZ];
  ssize_t recv_buffer_sz;

  ssl_info_t info;
} peer_t;

static inline bool peer_valid(const peer_t *peer) { return peer->socket != -1; }
static inline bool peer_has_message_to_send(const peer_t *peer) { return !queue_empty(&peer->send_queue); }
static inline bool peer_has_message_recv(const peer_t *peer) { return peer->recv_buffer_sz > 0; }

int peer_create(peer_t *, SSL_CTX * ctx, bool server);
int peer_delete(peer_t *);

int peer_close(peer_t *);
int peer_connect(peer_t *, struct sockaddr_in *addr);
int peer_accept(peer_t *, int listen_socket);

int peer_recv(peer_t *, int (*message_handler)(peer_t *));
int peer_send(peer_t *);
int peer_prepare_send(peer_t *, uint8_t *blob, ssize_t sz);

const char * peer_get_addr(const peer_t *); // static mem
