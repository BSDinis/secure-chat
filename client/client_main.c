#include <stdio.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "common/network_wrappers.h"
#include "common/peer.h"


char *server_addr_str = "127.0.0.1";
int port   = 3000;
peer_t server;
char read_buffer[1024];

/* ------------------------------------------------------- */

int setup_signals();
void shutdown_properly(int code);
int build_fd_sets(peer_t *server, fd_set *read_fds, fd_set *write_fds, fd_set *except_fds);
void handle_signal_action(int sig_number);
int handle_read_from_stdin(peer_t *server);
int handle_received_message(peer_t *peer);

/* ------------------------------------------------------- */

int main(int argc, char **argv)
{
  if (setup_signals() != 0)
    exit(EXIT_FAILURE);

  peer_create(&server);
  // set up addres
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(server_addr_str);
  server_addr.sin_port = htons(port);

  if (peer_connect(&server, &server_addr) != 0)
    shutdown_properly(EXIT_FAILURE);

  /* Set nonblock for stdin. */
  int flag = fcntl(STDIN_FILENO, F_GETFL, 0);
  flag |= O_NONBLOCK;
  fcntl(STDIN_FILENO, F_SETFL, flag);

  fd_set read_fds;
  fd_set write_fds;
  fd_set except_fds;

  fputs("Waiting for server message or stdin input. Please, type text to send:\n", stdout);

  while (1) {
    int maxfd = server.socket;
    build_fd_sets(&server, &read_fds, &write_fds, &except_fds);
    int activity = select(maxfd + 1, &read_fds, &write_fds, &except_fds, NULL);

    switch (activity) {
      case -1:
        perror("select");
        shutdown_properly(EXIT_FAILURE);

      case 0:
        fputs("select returns 0.\n", stderr);
        shutdown_properly(EXIT_FAILURE);

      default:
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
          if (handle_read_from_stdin(&server) != 0)
            shutdown_properly(EXIT_FAILURE);
        }

        if (FD_ISSET(STDIN_FILENO, &except_fds)) {
          fputs("except_fds for stdin.\n", stderr);
          shutdown_properly(EXIT_FAILURE);
        }

        if (FD_ISSET(server.socket, &read_fds)) {
          if (peer_recv(&server, &handle_received_message) != 0)
            shutdown_properly(EXIT_FAILURE);
        }

        if (FD_ISSET(server.socket, &write_fds)) {
          if (peer_send(&server) != 0)
            shutdown_properly(EXIT_FAILURE);
        }

        if (FD_ISSET(server.socket, &except_fds)) {
          fputs("except_fds for server.\n", stderr);
          shutdown_properly(EXIT_FAILURE);
        }
    }

    printf("And we are still waiting for server or stdin activity. You can type something to send:\n");
  }

  return 0;
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

int build_fd_sets(peer_t *server, fd_set *read_fds, fd_set *write_fds, fd_set *except_fds)
{
  FD_ZERO(read_fds);
  FD_SET(STDIN_FILENO, read_fds);
  FD_SET(server->socket, read_fds);

  FD_ZERO(write_fds);
  // there is smth to send, set up write_fd for server socket
  if (!queue_empty(&server->send_queue))
    FD_SET(server->socket, write_fds);

  FD_ZERO(except_fds);
  FD_SET(STDIN_FILENO, except_fds);
  FD_SET(server->socket, except_fds);

  return 0;
}

/* ------------------------------------------------------- */

int handle_read_from_stdin(peer_t *server)
{
  if (fgets(read_buffer, 1024, stdin) == NULL) {
    fputs("Failed to read from stdin\n", stderr);
    return -1;
  }

  // Create new message and enqueue it.
  if (peer_prepare_send(server, (uint8_t *)read_buffer, 1024) == -1) {
    fputs("Failed to prepare the message\n", stderr);
    return -1;
  }

  return 0;
}

/* ------------------------------------------------------- */

void shutdown_properly(int code)
{
  peer_delete(&server);
  fputs("Shutdown client properly.\n", stderr);
  exit(code);
}

/* ------------------------------------------------------- */

int handle_received_message(peer_t *peer)
{
  fprintf(stdout, "%s :: %s\n", peer_get_addr(peer), (char *) peer->recv_buffer);
  return 0;
}
