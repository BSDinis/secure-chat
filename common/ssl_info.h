/**
 * ssl_info.h
 *
 * helper struct for openssl
 */

#pragma once

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <stddef.h>
#include <stdbool.h>


/*
 * this is the classical diagram
 * most sketches miss the socket
 */

/*            cleartext           | BIOs        |           ciphertext
 *                                | are         |
 *                                | buffers     |
 *  SSL_write  +-----+  BIO_write | +---------+ | BIO_read  +--------+  send  +---------+
 * ----------->|     |------------|>| out_bio |-|---------->|        |------->|         |
 *             |     |            | +---------+ |           |        |        |         |
 *             | SSL |            |             |           | socket |        | network |
 *   SSL_read  |     |  BIO_read  | +---------+ | BIO_write |        |  recv  |         |
 * <-----------|     |<-----------|-| in_bio  |<|-----------|        |<-------|         |
 *             +-----+            | +---------+ |           +--------+        +---------+
 *
 * SSL  writes in to out_bio and reads from in_bio
 * socket reads from out_bio and  writes to in_bio
 */

#define INITIAL_BUFFER_SZ (1<<10)
typedef struct ssl_info_t {
  BIO * in_bio;  // SSL reads from ; socket writes to
  BIO * out_bio; // SSL writes to  ; socket reads from
  SSL * ssl;

  // cleartext
  uint8_t *clear_buf;
  ssize_t  clear_cap;
  ssize_t  clear_sz;

  // ciphertext
  uint8_t *encrypt_buf;
  ssize_t  encrypt_cap;
  ssize_t  encrypt_sz;
} ssl_info_t;

int ssl_info_get_ssl_err(ssl_info_t * info, int ret);

int ssl_info_server_create(ssl_info_t * info, SSL_CTX *ctx);
int ssl_info_client_create(ssl_info_t * info, SSL_CTX *ctx);
int ssl_info_destroy(ssl_info_t * info);

int ssl_info_do_handshake(ssl_info_t * info);

int ssl_info_encrypt(ssl_info_t * info,
    //uint8_t *clear_buf, ssize_t clear_sz,
    uint8_t *encrypt_buf, ssize_t encrypt_sz
    );

int ssl_info_decrypt(ssl_info_t * info,
    uint8_t *src, ssize_t sz);


static inline bool ssl_info_has_message_to_send(const ssl_info_t * info)
{ return info->encrypt_sz > 0; }

static inline bool ssl_info_has_message_to_recv(const ssl_info_t * info)
{ return info->clear_sz > 0; }

int queue_unenc_bytes(ssl_info_t *info, const uint8_t *buf, ssize_t sz);
