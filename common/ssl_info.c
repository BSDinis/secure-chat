/**
 * ssl_info.c
 */

#include "ssl_info.h"
#include "ssl_util.h"
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define print_error(msg) fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__, msg)

// no good reason
#define DEF_BUF_SIZE (128)

/* --------------------------------- */
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

  // set to return -1 on no data
  BIO_set_mem_eof_return(info->in_bio, -1);
  // set nonblocking
  BIO_set_nbio(info->in_bio, 1);

  // bio
  info->out_bio = BIO_new(BIO_s_mem());
  if ( !info->out_bio ) {
    print_error("failed to create a output BIO");
    BIO_free(info->in_bio);
    SSL_free(info->ssl);
    return -1;
  }

  // set to return -1 on no data
  BIO_set_mem_eof_return(info->out_bio, -1);
  // set nonblocking
  BIO_set_nbio(info->out_bio, 1);

  // set bios
  SSL_set_bio(info->ssl, info->in_bio, info->out_bio);

  return 0;
}

/* --------------------------------- */

int ssl_info_get_ssl_err(ssl_info_t * info, int ret)
{
  return SSL_get_error(info->ssl, ret);
}

/* --------------------------------- */

int ssl_info_do_ssl_handshake(ssl_info_t * info)
{
  int ret = SSL_do_handshake(info->ssl);
  int err = ssl_info_get_ssl_err(info, ret);

  if (err == SSL_ERROR_WANT_READ) {
    uint8_t buf[DEF_BUF_SIZE];
    do {
      ret = BIO_read(info->out_bio, buf, DEF_BUF_SIZE);
      if (ret > 0) {
        fprintf(stderr, "%s:%d Dropping %d bytes because of handshake\n",
            __FILE__,  __LINE__, ret);
      }
      else if (!BIO_should_retry(info->out_bio)) {
        return -1;
      }
    } while (ret > 0);
  }
  else if (err != SSL_ERROR_NONE) {
    ssl_perror("Failed on Handshake");
  }

  return 0;
}

/* --------------------------------- */

int ssl_info_encrypt(ssl_info_t * info,
    uint8_t *clear_buf, ssize_t clear_sz,
    uint8_t **enc_buf, ssize_t *enc_sz
    )
{
  if (!SSL_is_init_finished(info->ssl))
    return 0;

  *enc_sz  = -1;
  *enc_buf = NULL;

  ssize_t tmp_cur = 0;
  ssize_t tmp_sz  = clear_sz;
  uint8_t *tmp_buf = malloc(tmp_sz * sizeof(uint8_t));
  if (!tmp_buf) {
    fprintf(stderr, "%s:%d malloc: %s\n", __FILE__, __LINE__, strerror(errno));
    return -1;
  }

  while ( clear_sz > 0) {
    ssize_t n = SSL_write(info->ssl, clear_buf, clear_sz);
    int err = ssl_info_get_ssl_err(info, n);

    if ( n > 0 ) {

      // adjust clear_buffer
      if ( n < clear_sz )
        clear_buf += n;
      clear_sz  -= n;

      do {
        // consume from bio and prepare to send
        n = BIO_read(info->out_bio, tmp_buf + tmp_cur, tmp_sz);
        if (n > 0) {
          tmp_cur += n;
          if (tmp_cur == tmp_sz) {
            tmp_sz *= 2; tmp_buf = realloc(tmp_buf, tmp_sz * sizeof(uint8_t));
            if (!tmp_buf) { fprintf(stderr, "%s:%d realloc: %s\n", __FILE__, __LINE__, strerror(errno)); return -1; }
          }
        }
        else if (!BIO_should_retry(info->out_bio)) {
          free(tmp_buf);
          ssl_perror("Failed to extract encrypted data from BIO");
          return -1;
        }
      } while (n > 0);
    }

    if (err != SSL_ERROR_NONE && err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      ssl_perror("Failed to extract encrypted data from BIO, because there was an error");
    }

    if (n == 0) break;
  }

  *enc_buf = tmp_buf;
  *enc_sz  = tmp_sz;
  return 0;
}
