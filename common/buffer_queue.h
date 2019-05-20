/**
 * buffer_queue.h
 *
 * implemented a buffer_queue, for requests
 */

#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct pair_t { uint8_t * buff; ssize_t sz; } pair_t;

typedef struct buffer_queue {
  pair_t *arr;

  ssize_t head, tail;
  ssize_t size;
} buffer_queue;

// queue dimensions are static
int queue_create(buffer_queue *, ssize_t size);

int queue_delete(buffer_queue *);

int queue_clear(buffer_queue *);

// return -1 on error (full queue)
// 0 on success
int queue_push(buffer_queue *, uint8_t *buffer, ssize_t size);

// return -1 on error (empty queue)
// 0 on success
int queue_pop(buffer_queue *, uint8_t **buffer, ssize_t *size);

static inline bool queue_empty(const buffer_queue * que) { return que->head == -1; }
static inline bool queue_full(const buffer_queue * que)
{
  return (que->head == 0 && que->tail == que->size - 1)
      || (que->tail == (que->head - 1) % que->size);
}
