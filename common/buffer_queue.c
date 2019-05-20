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

  que->arr = calloc(size, sizeof(pair_t));
  if (!que->arr) {
    perror("calloc");
    return -1;
  }

  que->size = size;
  return 0;
}

int queue_delete(buffer_queue *que)
{
  free(que->arr);
  que->arr = NULL;
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

  fprintf(stderr, "head at %ld;", que->head);
  fprintf(stderr, "tail at %ld\n", que->tail);

  que->tail++;
  que->tail %= que->size;
  if (que->head == -1)
    que->head = 0;

  pair_t p = { .buff = buffer, .sz = size };
  que->arr[que->tail] = p;
  return 0;
}


int queue_pop(buffer_queue *que, uint8_t **buffer, ssize_t *size)
{
  if (queue_empty(que)) return -1; // empty queue
  fprintf(stderr, "head at %ld;", que->head);
  fprintf(stderr, "tail at %ld\n", que->tail);

  pair_t p = que->arr[que->head];
  *buffer = p.buff;
  *size = p.sz;

  if (que->head == que->tail)
    que->head = que->tail = -1;
  else {
    que->head++;
    que->head %= que->size;
  }

  return 0;
}

