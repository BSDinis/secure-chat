/**
 * server_main.c
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "common/peer.h"
#include "common/network_wrappers.h"

#define  MAX_CLIENT  (10)
#define  SERVER_NAME "server"

/* ------------------------------------------------------- */

int listen_sock;
char *server = "127.0.0.1";
char *port   = "4123";
peer_t connection_list[MAX_CLIENT];
char read_buffer[1024];

/* ------------------------------------------------------- */

void shutdown_properly(int code);
void handle_signal_action(int sig_number);
int setup_signals();
int build_fd_sets(fd_set *read_fds, fd_set *write_fds, fd_set *except_fds);
int handle_new_connection();
int handle_read_from_stdin();
int handle_received_message(peer_t *);

/* ------------------------------------------------------- */

int main(int argc, char **argv)
{
  if (setup_signals() != 0)
    exit(EXIT_FAILURE);

  if (net_start_listen_socket(server, port, &listen_sock) != 0)
    exit(EXIT_FAILURE);

  /* Set nonblock for stdin. */
  int flag = fcntl(STDIN_FILENO, F_GETFL, 0);
  flag |= O_NONBLOCK;
  fcntl(STDIN_FILENO, F_SETFL, flag);

  for (int i = 0; i < MAX_CLIENT; ++i)
    peer_create(&connection_list[i]);

  fd_set read_fds;
  fd_set write_fds;
  fd_set except_fds;

  int high_sock = listen_sock;

  fprintf(stderr, "Waiting for incoming connections.\n");

  while (1) {
    build_fd_sets(&read_fds, &write_fds, &except_fds);

    high_sock = listen_sock;
    for (int i = 0; i < MAX_CLIENT; ++i) {
      if (connection_list[i].socket > high_sock)
        high_sock = connection_list[i].socket;
    }

    int activity = select(high_sock + 1, &read_fds, &write_fds, &except_fds, NULL);

    switch (activity) {
      case -1:
        perror("select");
        shutdown_properly(EXIT_FAILURE);

      case 0:
        // you should never get here
        fputs("select returns 0.\n", stderr);
        shutdown_properly(EXIT_FAILURE);

      default:
        /* All set fds should be checked. */
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
          if (handle_read_from_stdin() != 0)
            shutdown_properly(EXIT_FAILURE);
        }

        if (FD_ISSET(listen_sock, &read_fds)) {
          handle_new_connection();
        }

        if (FD_ISSET(STDIN_FILENO, &except_fds)) {
          fputs("except_fds for stdin.\n", stderr);
          shutdown_properly(EXIT_FAILURE);
        }

        if (FD_ISSET(listen_sock, &except_fds)) {
          fputs("exception listen socket fd.\n", stderr);
          shutdown_properly(EXIT_FAILURE);
        }

        for (int i = 0; i < MAX_CLIENT; ++i) {
          if (peer_valid(&connection_list[i]) && FD_ISSET(connection_list[i].socket, &read_fds)) {
            if (peer_recv(&connection_list[i], &handle_received_message) != 0) {
              peer_close(&connection_list[i]);
              continue;
            }
          }

          if (peer_valid(&connection_list[i]) && FD_ISSET(connection_list[i].socket, &write_fds)) {
            if (peer_send(&connection_list[i]) != 0) {
              peer_close(&connection_list[i]);
              continue;
            }
          }

          if (peer_valid(&connection_list[i]) && FD_ISSET(connection_list[i].socket, &except_fds)) {
            fputs("Exception client fd.\n", stderr);
            peer_close(&connection_list[i]);
            continue;
          }
        }
    }

    printf("And we are still waiting for clients' or stdin activity. You can type something to send:\n");
  }

  return 0;
}

/* ------------------------------------------------------- */

void shutdown_properly(int code)
{
  close(listen_sock);
  for (int i = 0; i < MAX_CLIENT; ++i)
    if (peer_valid(&connection_list[i]))
      peer_close(&connection_list[i]);

  fputs("Shutdown server properly.\n", stderr);
  exit(code);
}

/* ------------------------------------------------------- */

void handle_signal_action(int sig_number)
{
  if (sig_number == SIGINT) {
    printf("SIGINT was catched!\n");
    shutdown_properly(EXIT_SUCCESS);
  }
  else if (sig_number == SIGPIPE) {
    printf("SIGPIPE was catched!\n");
    shutdown_properly(EXIT_SUCCESS);
  }
}

/* ------------------------------------------------------- */

int setup_signals()
{
  struct sigaction sa;
  sa.sa_handler = handle_signal_action;
  if (sigaction(SIGINT, &sa, 0) != 0) {
    perror("sigaction()");
    return -1;
  }
  if (sigaction(SIGPIPE, &sa, 0) != 0) {
    perror("sigaction()");
    return -1;
  }

  return 0;
}

/* ------------------------------------------------------- */

int handle_new_connection()
{
  for (int i = 0; i < MAX_CLIENT; ++i) {
    if (peer_valid(&connection_list[i])) continue;

    if (peer_accept(&connection_list[i], listen_sock) != 0) {
      fputs("Failed to accept connection\n", stderr);
      return -1;
    }

    return 0;
  }

  fputs("There is too much connections, ignoring the new one\n", stderr);
  return -1;
}

/* ------------------------------------------------------- */

int handle_read_from_stdin()
{
  memset(read_buffer, 0, 1024);
  if (fgets(read_buffer, 1024, stdin) == NULL) {
    fputs("Failed to read from stdin\n", stderr);
    return -1;
  }

  for (int i = 0; i < MAX_CLIENT; ++i) {
    if (!peer_valid(&connection_list[i])) continue;
    if (peer_prepare_send(&connection_list[i], (uint8_t *)read_buffer, 1024) == -1) {
      fputs("Failed to prepare message to send\n", stderr);
      return -1;
    }
  }

  return 0;
}

/* ------------------------------------------------------- */

int handle_received_message(peer_t * peer)
{
  fprintf(stdout, "%s :: %s\n", peer_get_addr(peer), peer->recv_buffer);
  return 0;
}

/* ------------------------------------------------------- */

int build_fd_sets(fd_set *read_fds, fd_set *write_fds, fd_set *except_fds)
{
  FD_ZERO(read_fds);
  FD_SET(STDIN_FILENO, read_fds);
  FD_SET(listen_sock, read_fds);
  for (int i = 0; i < MAX_CLIENT; ++i)
    if (peer_valid(&connection_list[i]))
      FD_SET(connection_list[i].socket, read_fds);

  FD_ZERO(write_fds);
  for (int i = 0; i < MAX_CLIENT; ++i)
    if (peer_valid(&connection_list[i])
        && !queue_empty(&connection_list[i].send_queue))
      FD_SET(connection_list[i].socket, write_fds);

  FD_ZERO(except_fds);
  FD_SET(STDIN_FILENO, except_fds);
  FD_SET(listen_sock, except_fds);
  for (int i = 0; i < MAX_CLIENT; ++i)
    if (peer_valid(&connection_list[i]))
      FD_SET(connection_list[i].socket, except_fds);

  return 0;
}

