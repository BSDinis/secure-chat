/**
 * ssl_info.h
 *
 * helper struct for openssl
 */

#pragma once

#include <openssl/ssl.h>
#include <openssl/bio.h>


typedef struct ssl_info_t {
  BIO * in_bio;
  BIO * out_bio;
  SSL * ssl;
} ssl_info_t;

int ssl_info_server_create (ssl_info_t * info, SSL_CTX *ctx);
int ssl_info_client_create (ssl_info_t * info, SSL_CTX *ctx);
int ssl_info_destroy(ssl_info_t * info);

