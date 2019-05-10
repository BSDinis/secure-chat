/***
 * ssl_util.h
 *
 * utility wrappers for openssl
 */

#pragma once

#include <openssl/err.h>
#include <openssl/ssl.h>

static void __ssl_perror(const char * file, int lineno, const char * msg)
{
  fprintf(stderr, "%s:%d %s\n", file, lineno, msg);
  ERR_print_errors_fp(stderr);
}

static inline void ssl_perror(const char *msg)
{ __ssl_perror(__FILE__, __LINE__, msg); }

int init_client_ssl_ctx(SSL_CTX **);
int init_server_ssl_ctx(SSL_CTX **);

int close_ssl_ctx(SSL_CTX *);

int load_certificates(SSL_CTX *,
    const char * const cert,
    const char * const key);

void show_certificates(FILE *stream, SSL *ssl);
