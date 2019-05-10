/***
 * ssl_util.h
 *
 * utility wrappers for openssl
 */

#pragma once

#include <openssl/err.h>
#include <openssl/ssl.h>

static void ssl_perror(const char *msg);

int init_client_ssl_ctx(SSL_CTX **);
int init_server_ssl_ctx(SSL_CTX **);

int close_ssl_ctx(SSL_CTX *);

int load_certificates(SSL_CTX *,
    const char * const cert,
    const char * const key);

void show_certificates(FILE *stream, SSL *ssl);
