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
static int queue_enc_bytes(ssl_info_t *, const uint8_t *, ssize_t sz);
static int queue_unenc_bytes(ssl_info_t *info, const uint8_t *buf, ssize_t sz);

int ssl_info_server_create (ssl_info_t * info, SSL_CTX *ctx)
{
  if (ssl_info_create(info, ctx) == -1) return -1;
  SSL_set_accept_state(info->ssl);
  return 0;
}

int ssl_info_client_create (ssl_info_t * info, SSL_CTX *ctx)
{
  if (ssl_info_create(info, ctx) == -1) return -1;
  SSL_set_connect_state(info->ssl);
  return 0;
}

int ssl_info_destroy(ssl_info_t * info)
{
  if ( info->ssl ) {
    SSL_free(info->ssl);
    info->ssl = NULL;
    free(info->clear_buf);
    free(info->encrypt_buf);
    info->clear_buf = info->encrypt_buf = NULL;
    info->clear_cap = info->encrypt_cap = -1;
    info->clear_sz  = info->encrypt_sz  = -1;
  }

  return 0;
}

static int ssl_info_create (ssl_info_t * info, SSL_CTX *ctx)
{
  if (!(info->clear_buf = malloc(INITIAL_BUFFER_SZ * sizeof(uint8_t)))) {
    print_error("malloc failed");
    return -1;
  }

  if (!(info->encrypt_buf = malloc(INITIAL_BUFFER_SZ * sizeof(uint8_t)))) {
    free(info->clear_buf);
    print_error("malloc failed");
    return -1;
  }

  // ssl
  info->ssl = SSL_new(ctx);
  if ( !info->ssl ) {
    print_error("failed to create a new SSL");
    free(info->clear_buf);
    free(info->encrypt_buf);
    return -1;
  }

  // bio
  info->in_bio = BIO_new(BIO_s_mem());
  if ( !info->in_bio ) {
    print_error("failed to create a input BIO");
    SSL_free(info->ssl);
    free(info->clear_buf);
    free(info->encrypt_buf);
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
    free(info->clear_buf);
    free(info->encrypt_buf);
    return -1;
  }

  info->clear_cap = info->encrypt_cap = INITIAL_BUFFER_SZ;
  info->clear_sz = info->encrypt_sz = 0;

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

int ssl_info_do_handshake(ssl_info_t * info)
{
  print_error("doing handshake");
  int ret = SSL_do_handshake(info->ssl);
  int err = ssl_info_get_ssl_err(info, ret);

  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
    uint8_t buf[DEF_BUF_SIZE];
    do {
      ret = BIO_read(info->out_bio, buf, DEF_BUF_SIZE);
      if (ret > 0)
        queue_enc_bytes(info, buf, ret);
      else if (!BIO_should_retry(info->out_bio)) {
        ssl_perror("Failed on Handshake");
        return -1;
      }
    } while (ret > 0);
  }
  else if (err != SSL_ERROR_NONE) {
    ssl_perror("Failed on Handshake");
    return -1;
  }

  return 0;
}

/* --------------------------------- */
/* --------------------------------- */

int ssl_info_encrypt(ssl_info_t * info,
    //uint8_t *clear_buf, ssize_t clear_sz,
    uint8_t *encrypt_buf, ssize_t encrypt_sz
    )
{
  if ( !SSL_is_init_finished(info->ssl) ) {
    return 0;
#if 0
    if (ssl_info_do_handshake(info) == -1
        || !SSL_is_init_finished(info->ssl) ) {
      print_error("ssl init is not yet finished");
      return  -1;
    }
#endif
  }

  uint8_t buf[DEF_BUF_SIZE];

  while ( encrypt_sz > 0) {
    ssize_t n = SSL_write(info->ssl, encrypt_buf, encrypt_sz);
    int err = ssl_info_get_ssl_err(info, n);

    if ( n > 0 ) {
      // adjust buffer
      if ( n < encrypt_sz )
        memmove(info->ssl, encrypt_buf + n , encrypt_sz - n);
      encrypt_sz -= n;

      do {
        // consume from bio and prepare to send
        n = BIO_read(info->out_bio, buf, DEF_BUF_SIZE);
        if (n > 0)
          queue_enc_bytes(info, buf, n);
        else if (!BIO_should_retry(info->out_bio)) {
          ssl_perror("Failed to extract encrypted data from BIO");
          return -1;
        }
      } while (n > 0);
    }

    if (err != SSL_ERROR_NONE && err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
      ssl_perror("Failed to extract encrypted data from BIO, because there was an error");
      return -1;
    }

    if (n == 0) break;
  }

  return 0;
}

/* --------------------------------- */

int ssl_info_decrypt(ssl_info_t * info,
    uint8_t *src, ssize_t sz)
{
  uint8_t buf[DEF_BUF_SIZE];

  while ( sz > 0) {
    ssize_t n = BIO_write(info->in_bio, src, sz);

    if ( n <= 0 )
      return -1; // BIO write is unrecoverable

    src += n;
    sz  -= n;

    if ( !SSL_is_init_finished(info->ssl) ) {
      if (ssl_info_do_handshake(info) == -1)
        return -1;

      if (!SSL_is_init_finished(info->ssl) )
        return  -1;
    }

    // consume data
    do {
      n = SSL_read(info->ssl, buf, DEF_BUF_SIZE);
      if (n > 0)
        queue_unenc_bytes(info, buf, n);
    } while (n > 0);

    int err = ssl_info_get_ssl_err(info, n);

    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      uint8_t buf[DEF_BUF_SIZE];
      int ret;
      do {
        ret = BIO_read(info->out_bio, buf, DEF_BUF_SIZE);
        if (ret > 0) {
          queue_enc_bytes(info, buf, ret);
        }
        else if (!BIO_should_retry(info->out_bio)) {
          ssl_perror("Failed on Handshake");
          return -1;
        }
      } while (ret > 0);
    }
    else if ( err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_NONE ) {
      ssl_perror("Failed to extract encrypted data from BIO, because there was an error");
      return -1;
    }
  }

  return 0;
}

/* --------------------------------- */
/* --------------------------------- */
/* --------------------------------- */
/* --------------------------------- */
/* --------------------------------- */
/* --------------------------------- */

static int __queue(
    uint8_t ** buf_ptr,
    ssize_t * cap_ptr,
    ssize_t * sz_ptr,
    const uint8_t *buf, ssize_t sz)
{
  if (*sz_ptr >= *cap_ptr) {
    *cap_ptr *= 2;
    void * tmp = realloc(*buf_ptr, *cap_ptr);
    if (!tmp) {
      print_error("failed to realloc");
      return -1;
    }
    *buf_ptr = tmp;
  }

  memcpy(*buf_ptr + *sz_ptr, buf, sz);
  *sz_ptr += sz;
  return 0;
}

static int queue_enc_bytes(ssl_info_t *info, const uint8_t *buf, ssize_t sz)
{
  return __queue(
      &info->clear_buf,
      &info->clear_cap,
      &info->clear_sz,
      buf,
      sz
      );
}

static int queue_unenc_bytes(ssl_info_t *info, const uint8_t *buf, ssize_t sz)
{
  return __queue(
      &info->encrypt_buf,
      &info->encrypt_cap,
      &info->encrypt_sz,
      buf,
      sz
      );
}
