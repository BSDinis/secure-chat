/**
 * ssl_info.c
 */

#include "ssl_info.h"

#define print_error(msg) fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__, msg)

static int ssl_info_create (ssl_info_t * info, SSL_CTX *ctx);

int ssl_info_server_create (ssl_info_t * info, SSL_CTX *ctx)
{
  int ret = ssl_info_create(info, ctx);
  SSL_set_accept_state(info->ssl);
  return ret;
}

int ssl_info_client_create (ssl_info_t * info, SSL_CTX *ctx)
{
  int ret = ssl_info_create(info, ctx);
  SSL_set_connect_state(info->ssl);
  return ret;
}

int ssl_info_destroy(ssl_info_t * info)
{
  if ( info->ssl ) {
    SSL_free(info->ssl);
    info->ssl = NULL;
  }

  return 0;
}

static int ssl_info_create (ssl_info_t * info, SSL_CTX *ctx)
{
  // ssl
  info->ssl = SSL_new(ctx);
  if ( !info->ssl ) {
    print_error("failed to create a new SSL");
    return -1;
  }

  // bio
  info->in_bio = BIO_new(BIO_s_mem());
  if ( !info->in_bio ) {
    print_error("failed to create a input BIO");
    SSL_free(info->ssl);
    return -1;
  }

  // returns -1 on no data
  BIO_set_mem_eof_return(info->in_bio, -1);

  // bio
  info->out_bio = BIO_new(BIO_s_mem());
  if ( !info->out_bio ) {
    print_error("failed to create a output BIO");
    BIO_free(info->in_bio);
    SSL_free(info->ssl);
    return -1;
  }

  // returns -1 on no data
  BIO_set_mem_eof_return(info->out_bio, -1);

  // set bios
  SSL_set_bio(info->ssl, info->in_bio, info->out_bio);

  return 0;
}

