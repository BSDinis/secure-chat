/**
 * buffer_queue.c
 *
 * implement
 */

#include "buffer_queue.h"
#include <stdio.h>
#include <errno.h>

int queue_create(buffer_queue *que, ssize_t size)
{
  que->head = que->tail = -1;

  que->buffer = calloc(size, sizeof(uint8_t *));
  if (!que->buffer) {
    perror("calloc");
    return -1;
  }

  que->buff_sz = calloc(size, sizeof(ssize_t));
  if (!que->buff_sz) {
    free(que->buffer);
    perror("calloc");
    return -1;
  }

  que->size = size;
  return 0;
}

int queue_delete(buffer_queue *que)
{
  free(que->buffer);
  free(que->buff_sz);
  que->buffer = NULL;
  que->buff_sz = NULL;
  que->size = 0;
  return 0;
}

int queue_clear(buffer_queue *que)
{
  uint8_t *buffer;
  ssize_t sz;
  while (queue_pop(que, &buffer, &sz) != -1)
    free(buffer);

  return 0;
}

int queue_push(buffer_queue *que, uint8_t *buffer, ssize_t size)
{
  if (queue_full(que)) return -1; // full queue

  que->tail++;
  que->tail %= que->size;
  if (que->head == -1)
    que->head = 0;

  que->buffer[que->tail] = buffer;
  que->buff_sz[que->tail] = size;

  return 0;
}


int queue_pop(buffer_queue *que, uint8_t **buffer, ssize_t *size)
{
  if (queue_empty(que)) return -1; // empty queue
  *buffer = que->buffer[que->head];
  *size = que->buff_sz[que->head];

  que->buffer[que->head] = NULL;
  que->buff_sz[que->head] = 0;

  if (que->head == que->tail)
    que->head = que->tail = -1;
  else {
    que->head++;
    que->head %= que->size;
  }

  return 0;
}

