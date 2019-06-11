#include <stdio.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "network_wrappers.h"
#include "peer.h"
#include "ssl_util.h"

#define print_error(msg) { fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__, msg); }

/* ------------------------------------------------------- */

const char cert_file[] = "client.crt";
const char  key_file[] = "client.key";

char *server_addr_str = "127.0.0.1";
int port   = 3000;

SSL_CTX *client_ctx;
peer_t server;

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
  if (setup_signals() != 0) {
    print_error("failed to setup signals");
    exit(EXIT_FAILURE);
  }

  if (init_client_ssl_ctx(&client_ctx) == -1) {
    print_error("failed to setup client SSL ctx");
    exit(EXIT_FAILURE);
  }

  if (load_certificates(client_ctx, cert_file, key_file) == -1) {
    print_error("failed to load certificates");
    exit(EXIT_FAILURE);
  }

  /* Set nonblock for stdin. */
  int flag = fcntl(STDIN_FILENO, F_GETFL, 0);
  flag |= O_NONBLOCK;
  fcntl(STDIN_FILENO, F_SETFL, flag);

  peer_create(&server, client_ctx, false);

  // set up address
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(server_addr_str);
  server_addr.sin_port = htons(port);

  if (peer_connect(&server, &server_addr) == -1)
    shutdown_properly(EXIT_FAILURE);

  if (peer_do_handshake(&server) == -1)
    shutdown_properly(EXIT_FAILURE);

  fprintf(stdout, "Connected to server at %s\n", peer_get_addr(&server));

  fd_set read_fds;
  fd_set write_fds;
  fd_set except_fds;

  fputs("Waiting for server message or stdin input.\n", stdout);

  while (1) {
    if (peer_valid(&server)) {
      if (peer_want_read(&server)) {
        handle_received_message(&server);
      }
    }

    int high_sock = build_fd_sets(&server, &read_fds, &write_fds, &except_fds);
    int activity = select(high_sock + 1, &read_fds, &write_fds, &except_fds, NULL);

    switch (activity) {
      case -1:
        perror("select");
        shutdown_properly(EXIT_FAILURE);

      case 0:
        fputs("select returns 0.\n", stderr);
        shutdown_properly(EXIT_FAILURE);

      default:
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
          handle_read_from_stdin(&server);
        }
        if (FD_ISSET(STDIN_FILENO, &except_fds)) {
          fputs("except_fds for stdin.\n", stderr);
          shutdown_properly(EXIT_FAILURE);
        }

        if (peer_valid(&server)) {
          if (FD_ISSET(server.socket, &read_fds)) {
            if (peer_recv(&server) != 0)
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
    }
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
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_NODEFER;
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
  int high_sock = server->socket;
  FD_ZERO(read_fds);
  FD_SET(STDIN_FILENO, read_fds);
  FD_SET(server->socket, read_fds);

  FD_ZERO(write_fds);
  // there is smth to send, set up write_fd for server socket
  if (peer_want_write(server))
    FD_SET(server->socket, write_fds);

  FD_ZERO(except_fds);
  FD_SET(STDIN_FILENO, except_fds);
  FD_SET(server->socket, except_fds);

  return high_sock;
}

/* ------------------------------------------------------- */

int handle_read_from_stdin(peer_t *server)
{
  uint8_t read_buffer[1024];
  memset(read_buffer, 0, 1024);

  ssize_t len = read(STDIN_FILENO, read_buffer, sizeof(read_buffer));
  if (len > 0)
    return peer_prepare_message_to_send(server, read_buffer, len);
  else
    return -1;
}

/* ------------------------------------------------------- */

void shutdown_properly(int code)
{
  peer_delete(&server);
  fputs("Shutdown client properly.\n", stderr);
  close_ssl_ctx(client_ctx);
  exit(code);
}

/* ------------------------------------------------------- */

int handle_received_message(peer_t *peer)
{
  fprintf(stdout, "%lu: %.*s", peer_get_id(peer), (int)peer->process_sz, (char *) peer->process_buf);
  peer->process_sz = 0;
  return 0;
}


