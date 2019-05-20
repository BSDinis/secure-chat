/***
 * peer.c
 */

#include "peer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <errno.h>

#define MAX_RD_REP (3)
#define MAX_WR_REP (3)

#define BACKLOG (16)

#define print_error(msg) fprintf(stderr, "%s:%d > %s\n", __FILE__, __LINE__, msg)

/* ------------------------------------------------- */

int peer_create(peer_t * peer, SSL_CTX * ctx, bool server)
{
  peer->socket = -1;
  memset(&peer->address, 0, sizeof(struct sockaddr_in));

  if (server) {
    if (ssl_info_server_create(&peer->info, ctx) == -1) {
      print_error("failed to create ssl info");
      return -1;
    }
  }
  else if (ssl_info_client_create(&peer->info, ctx) == -1) {
    print_error("failed to create ssl info");
    return -1;
  }

  return 0;
}

int peer_delete(peer_t * peer)
{
  if (peer == NULL) return 0;

  int ret = 0;
  if (peer->socket != -1 && peer_close(peer) == -1) {
    print_error("failed to close peer connection");
    ret = -1;
  }

  if (ssl_info_destroy(&peer->info) == -1) {
    print_error("failed to delete ssl info");
    ret = -1;
  }

  return ret;
}

/* ------------------------------------------------- */

int peer_close(peer_t * peer)
{
  if (peer == NULL) return 0;

  if (peer->socket != -1) close(peer->socket);
  peer->socket = -1;

  return 0;
}

int peer_connect(peer_t * peer, struct sockaddr_in *addr)
{
  peer->socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (peer->socket < 0) {
    print_error("failed to open socket");
    perror("socket");
    return -1;
  }

  peer->address = *addr;
  errno = 0;
  while (
      connect(peer->socket, (struct sockaddr *) &(peer->address),
      sizeof(struct sockaddr)) == -1
      && errno == EINPROGRESS
      );
  if (errno != 0 && errno != EINPROGRESS) {
    print_error("failed to connect");
    perror("connect");
    return -1;
  }

  return 0;
}

// assumes to have been created first
int peer_accept(peer_t * peer, int listen_socket)
{
  socklen_t len = sizeof(struct sockaddr);
  peer->socket = accept(listen_socket, (struct sockaddr *) &peer->address, &len);
  if (peer->socket == -1) {
    print_error("failed to accept");
    perror("accept");
    return -1;
  }

  return 0;
}

/* ------------------------------------------------- */

int peer_recv(peer_t *peer, int (*handler)(peer_t *))
{
  uint8_t buf[MAX_MSG_SZ];
  ssize_t buf_sz = 0;
  int repeats = 0;

  ssize_t recvd_partial = 0;
  ssize_t recvd_total   = 0;

  do {
    repeats++;

    ssize_t len_to_recv = MAX_MSG_SZ - recvd_partial;
    if (len_to_recv <= 0) break;

    ssize_t recvd_partial = recv(
        peer->socket,
        (char*)&buf + recvd_total,
        len_to_recv,
        MSG_DONTWAIT
        );

    if (recvd_partial < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        print_error("peer would block");
        break;
      }
      else {
        print_error("error on receive");
        perror("recv");
        return -1;
      }
    }
    else if (recvd_partial == 0) {
      return -1; // shutdown
    }
    else {
      recvd_total += recvd_partial;
    }
  } while (recvd_partial > 0 && repeats < MAX_RD_REP);

  if (repeats >= MAX_RD_REP)
    return -1;

  buf_sz = recvd_total;

  if ( ssl_info_decrypt(&peer->info,
        buf, buf_sz) == -1 ) {

    print_error("failed to decrypt whatever was read\n");
    return -1;
  }

  return handler(peer);
}

int peer_send(peer_t *peer)
{
  if (!peer_has_message_to_send(peer)) return 0;

  uint8_t *buff = peer->info.encrypt_buf;

  ssize_t sent_partial = 0;
  ssize_t sent_total   = 0;
  int repeats = 0;

  fprintf(stderr, "sending %ld bytes: %s\n",
      peer->info.encrypt_sz,
      (char *) buff);
  return 0;

  do {
    sent_partial = send(peer->socket, buff + sent_total, peer->info.encrypt_sz, MSG_DONTWAIT);
    if (sent_partial == -1) {
      print_error("failed on send");
      perror("send");
      return -1;
    }
    sent_total  += sent_partial;
    peer->info.encrypt_sz     -= sent_partial;
  } while (peer->info.encrypt_sz > 0 && repeats < MAX_WR_REP);

  if (peer->info.encrypt_sz > 0) {
    print_error("couldn't send everything");
    return -1;
  }

  return 0;
}

int peer_prepare_send(peer_t *peer, uint8_t *blob, ssize_t sz)
{ return queue_unenc_bytes(&peer->info, blob, sz); }

/* ------------------------------------------------- */

const char * peer_get_addr(const peer_t * peer)
{
  static char __address_str[INET_ADDRSTRLEN + 16];
  char        __str_peer_ipv4[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &peer->address.sin_addr, __str_peer_ipv4, INET_ADDRSTRLEN);
  snprintf(__address_str, INET_ADDRSTRLEN + 15,
      "%s:%d", __str_peer_ipv4, ntohs(peer->address.sin_port));

  return __address_str;
}
