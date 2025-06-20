#ifndef __RRADIX_H__
#define __RRADIX_H__

/* An implementation of an 'optimized' radix tree where successive vertices with only 1 child
 * are compressed into 1 vertice
 * */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define RADIX_VERTEX_MAX_SIZE ((1 << 29) - 1)

typedef struct radix_vertex {
	uint32_t is_key:1;
	uint32_t is_null:1;
	uint32_t is_compressed:1;
	uint32_t size:29;
	uint8_t data[];
} radix_vertex;

typedef struct radix_tree {
	radix_vertex *head;
	uint64_t num_elements;
	uint64_t num_vertices;
} radix_tree;

/* stack used to walk the tree */
typedef struct radix_stack {
	void **stack; /* ptr to static_items or to heap-allocated array */
	size_t size;
	size_t capacity;
	void *static_items[32]; // to avoid heap allocations
	bool oom;
} radix_stack;

/* maybe some iterator stuff? Would be cool to try */

/* API */
radix_tree *radix_new(void);
void radix_free_callback(radix_tree *t, void (*free_callback)(void *)); // free a tree but with a callback to free auxiliary data
void radix_free(radix_tree *t);
int radix_insert(radix_tree *t, uint8_t *s, size_t len, void *data, void **old);
int radix_del(radix_tree *t, uint8_t *s, size_t len, void **old);
void *radix_find(radix_tree *t, uint8_t *s, size_t len);
void radix_print(radix_tree *t);

#endif // !__RRADIX_H__
