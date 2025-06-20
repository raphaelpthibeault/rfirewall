#include <rradix.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

/* Return the padding needed by vertex
 * The padding is needed to store the child pointers to aligned addresses
 * Add 4 to the vertex_size because a vertex has a 4-byte header */
#define radix_padding(vertex_size) ((sizeof(void*)-((vertex_size+4) % sizeof(void*))) & (sizeof(void*)-1))

/* Return the current total size of the vertex. 
 * The second line calculates the padding after the string, needed to save ptrs to aligned addresses */
#define radix_vertex_current_size(v) ( \
    sizeof(radix_vertex)+(v)->size+ \
    radix_padding((v)->size)+ \
    ((v)->is_compressed ? sizeof(radix_vertex *) : sizeof(radix_vertex *)*(v)->size)+ \
    (((v)->is_key && !(v)->is_null)*sizeof(void*)) \
)

/* Return the pointer to the last child pointer in a vertex
 * For a compressed vertex this is the only child pointer  */
#define radix_vertex_last_child_ptr(v) ((radix_vertex **) ( \
    ((uint8_t *)(v)) + \
    radix_vertex_current_size(v) - \
    sizeof(radix_vertex *) - \
    (((v)->is_key && !(v)->is_null) ? sizeof(void*) : 0) \
))

/* Return the pointer to the first child pointer in a vertex */
#define radix_vertex_first_child_ptr(v) ((radix_vertex **) ( \
    (v)->data + \
    (v)->size + \
    radix_padding((v)->size)))

#ifdef DEBUG
bool debug = true;
#else
bool debug = false;
#endif

#define debugf(...)                                         \
	if (debug) {																							\
	printf("%s:%s:%d:\t", __FILE__, __func__, __LINE__);			\
	printf(__VA_ARGS__);																			\
	fflush(stdout);                                           \
	}																													\

/* Used by debug_vertex() macro */
void 
debug_show_vertex(const char *msg, radix_vertex *v) 
{
    if (!debug) return;
    printf("%s: %p [%.*s] key:%d size:%d children:",
        msg, (void*)v, (int)v->size, (char*)v->data, v->is_key, v->size);
    int num_children = v->is_compressed ? 1 : v->size;
    radix_vertex **cp = radix_vertex_last_child_ptr(v) - (num_children - 1);
    while (num_children--) {
        radix_vertex *child;
        memcpy(&child, cp, sizeof(child));
        ++cp;
        printf("%p ", (void*)child);
    }
    printf("\n");
    fflush(stdout);
}

#define debug_vertex(msg,v) debug_show_vertex(msg,v)

static inline void
_stack_init(radix_stack *stack)
{
	stack->stack = stack->static_items;
	stack->size = 0;
	stack->capacity = 32;
	stack->oom = false;
}

static inline bool
_stack_push(radix_stack *stack, void *ptr)
{
	if (stack->size == stack->capacity)
	{
		if (stack->stack == stack->static_items)
		{
			stack->stack = malloc(sizeof(void *) * stack->capacity * 2);
			if (stack->stack == NULL)
			{
				stack->oom = true;
				stack->stack = stack->static_items;
				return false;
			}
			memcpy(stack->stack, stack->static_items, sizeof(void *) * stack->capacity);
		}
		else
		{
			void **new_allocation = realloc(stack->stack, sizeof(void *) * stack->capacity * 2);
			if (new_allocation == NULL)
			{
				stack->oom = true;
				return false;
			}
			stack->stack = new_allocation;
		}
		stack->capacity *= 2;
	}

	stack->stack[stack->size++] = ptr;
	return true;
}

static inline void *
_stack_pop(radix_stack *stack)
{
	if (stack->size == 0) return NULL;

	return stack->stack[--stack->size];
}

static inline void *
_stack_peek(radix_stack *stack)
{
	if (stack->size == 0) return NULL;

	return stack->stack[stack->size - 1];
}

static inline void
_stack_free(radix_stack *stack)
{
	if (stack->stack != stack->static_items)
		free(stack->stack);
}

static radix_vertex *
_new_vertex(size_t children, bool datafield)
{
	size_t size = sizeof(radix_vertex) + children + radix_padding(children) + sizeof(radix_vertex*) * children;
	if (datafield)
		size += sizeof(void *);

	radix_vertex *v = malloc(size);
	if (v == NULL) return NULL;

	v->is_key = false;
	v->is_null = false;
	v->is_compressed = 0;
	v->size = children;
	return v;
}

radix_tree *
radix_new(void)
{
	radix_tree *t = malloc(sizeof(*t));
	if (t == NULL) return NULL;

	t->num_elements = 0;
	t->num_vertices = 1;
	t->head = _new_vertex(0, false);
	
	if (t->head == NULL)
	{
		radix_free(t);
		return NULL;
	}

	return t;
}

static void *
radix_get_data(radix_vertex *v)
{
	if (v->is_null) return NULL;

	void **vdata = (void **)((uint8_t *)v + radix_vertex_current_size(v) - sizeof(void *));
	void *data;
	memcpy(&data, vdata, sizeof(data));
	return data;
}

static void
radix_set_data(radix_vertex *v, void *data)
{
	v->is_key = true;
	if (data != NULL)
	{
		v->is_null = false;
		void **vdata = (void **)((uint8_t *)v + radix_vertex_current_size(v) - sizeof(void *));
		memcpy(vdata, &data, sizeof(void *));
	}
	else
	{
		v->is_null = 1;
	}
}

static radix_vertex *
_radix_realloc_data(radix_vertex *v, void *data)
{
	if (data == NULL) // realloc unnecessary
		return v;

	size_t curr_size = radix_vertex_current_size(v);
	return realloc(v, curr_size + sizeof(void *));
}

static void
_radix_free(radix_tree *t, radix_vertex *v, void (*free_callback)(void *))
{
	debug_vertex("free traversing", v);
	int num_children = v->is_compressed ? 1 : v->size;	
	radix_vertex **cp = radix_vertex_last_child_ptr(v);

	while (num_children--)
	{
		radix_vertex *c;
		memcpy(&c, cp, sizeof(c));
		_radix_free(t, c, free_callback);
		--cp;
	}

	debug_vertex("free depth-first", v);
	
	if (free_callback && !v->is_null && v->is_key)
		free_callback(radix_get_data(v));

	free(v);
	--t->num_vertices;
}

void 
radix_free_callback(radix_tree *t, void (*free_callback)(void *))
{
	_radix_free(t, t->head, free_callback);
	assert(t->num_vertices == 0);
	free(t);
}

void 
radix_free(radix_tree *t)
{
	radix_free_callback(t, NULL);
}

static inline size_t 
_radix_walk(radix_tree *t, uint8_t *s, size_t len, radix_vertex **_stop_vertex, radix_vertex ***_parent_link, int *_split_pos, radix_stack *stack)
{
	radix_vertex *h = t->head;
	radix_vertex **parent_link = &t->head;

	size_t i = 0; /* pos in the string */
	size_t j = 0; /* position in the vertex children */

	while (h->size && i < len)
	{
		uint8_t *data = h->data;

		if (h->is_compressed)
		{
			for (j = 0; j < h->size && i < len; ++j, ++i)
			{
				if (data[j] != s[i]) 
					break;
			}
			if (j != h->size) 
				break;
		} 
		else
		{
			/* curiously, linear search in contiguous memory is comparable to binary search */
			for (j = 0; j < h->size; ++j)
			{
				if (data[j] == s[i])
					break;
			}
			if (j == h->size)
				break;
			++i;
		}

		if (stack)
		{
			_stack_push(stack, h);
		}

		radix_vertex **children = radix_vertex_first_child_ptr(h);
		if (h->is_compressed)
			j = 0;

		memcpy(&h, children + j, sizeof(h));
		parent_link = children + j;
		j = 0;
	}

	if (_stop_vertex)
		*_stop_vertex = h;

	if (_parent_link)
		*_parent_link = parent_link;

	if (_split_pos && h->is_compressed)
		*_split_pos = j;

	return i;
}

static radix_vertex *
_compress(radix_vertex *v, uint8_t *s, size_t len, radix_vertex **child)
{
	assert(v->size == 0 && !v->is_compressed);	

	void *data = NULL;
	size_t new_size;

	debugf("Compress vertice: '%.*s'\n", (int)len, s);

	*child = _new_vertex(0, 0);
	if (*child == NULL) return NULL;

	new_size = sizeof(radix_vertex) + len + radix_padding(len) + sizeof(radix_vertex *);
	
	if (v->is_key)
	{
		data = radix_get_data(v);
		if (!v->is_null)
			new_size += sizeof(void *);
	}

	radix_vertex *newv = realloc(v, new_size);
	if (newv == NULL)
	{
		free(*child);
		return NULL;
	}

	v = newv;
	v->is_compressed = true;
	v->size = len;
	memcpy(v->data, s, len);
	if (v->is_key)
		radix_set_data(v, data);

	radix_vertex **childfield = radix_vertex_last_child_ptr(v);
	memcpy(childfield, child, sizeof(*child));

	return v;
}

static radix_vertex *
_add_child(radix_vertex *v, uint8_t c, radix_vertex **childptr, radix_vertex ***parent_link)
{
	assert(!v->is_compressed);

	size_t curr_size = radix_vertex_current_size(v);
	++v->size;
	size_t new_size = radix_vertex_current_size(v);
	--v->size; // restore; update on success at the end

	radix_vertex *child = _new_vertex(0, 0); // allocate it
	if (child == NULL) return NULL;

	radix_vertex *newv = realloc(v, new_size);
	if (newv == NULL)
	{
		free(child);
		return NULL;
	}

	v = newv;
	
	int pos;
	for (pos = 0; pos < v->size; ++pos)
	{
		if (v->data[pos] > c) break;
	}

	uint8_t *dst, *src;
	if (!v->is_null && v->is_key)
	{
		dst = (uint8_t *)v + new_size - sizeof(void *);
		src = (uint8_t *)v + curr_size - sizeof(void *);
		memmove(dst, src, sizeof(void *));
	}

	size_t shift = new_size - curr_size - sizeof(void *);

	src = v->data + v->size + radix_padding(v->size) + sizeof(radix_vertex *) * pos;
	memmove(src + shift + sizeof(radix_vertex *), src, sizeof(radix_vertex *) * (v->size - pos));

	if (shift)
	{
		src = (uint8_t *)radix_vertex_first_child_ptr(v);
		memmove(src + shift, src, sizeof(radix_vertex *) * pos);
	}

	src = v->data + pos;
	memmove(src + 1, src, v->size - pos);

	v->data[pos] = c;
	++v->size;

	src = (uint8_t *)radix_vertex_first_child_ptr(v);
	radix_vertex **childfield = (radix_vertex **)(src + sizeof(radix_vertex *) * pos);
	memcpy(childfield, &child, sizeof(child));

	*childptr = child;
	*parent_link = childfield;

	return v;
}

/* returns 0 on no insert, returns 1 on insert */
static int
_radix_insert(radix_tree *t, uint8_t *s, size_t len, void *data, void **old, bool overwrite)
{
	size_t i;
	int j = 0; /* split position */
	radix_vertex *h, **parent_link;

	debugf("### Insert '%.*s' with value %p\n", (int)len, s, data);

	i = _radix_walk(t, s, len, &h, &parent_link, &j, NULL);

	if (i == len && (!h->is_compressed || j == 0)) // key vertex exists and it's not compressed
	{
		debugf("### Insert: vertice representing key exists\n");
		if (!h->is_key || (h->is_null && overwrite))
		{
			h = _radix_realloc_data(h, data);
			if (h)
				memcpy(parent_link, &h, sizeof(h));
		}
		if (h == NULL)
			return 0;

		// update key
		if (h->is_key)
		{
			if (old)
				*old = radix_get_data(h);

			if (overwrite)
				radix_set_data(h, data);

			return 0;
		}

		radix_set_data(h, data);
		++t->num_elements;
		return 1;
	}

	/* 
	 * uncompress the compressed vertex (if this is the case) 
	 * */

	if (i != len && h->is_compressed)
	{
		debugf("Algorithm 1: Stopped at compressed node '%.*s' (%p)\n",
				h->size, h->data, (void*)h);
		debugf("Still to insert: '%.*s'\n", (int)(len-i), s+i);
		debugf("Splitting at %d: '%c'\n", j, ((char*)h->data)[j]);
		debugf("Other (key) letter is '%c'\n", s[i]);

		/* Save next pointer */
		radix_vertex **childfield = radix_vertex_last_child_ptr(h);
		radix_vertex *next;
		memcpy(&next, childfield, sizeof(next));

		debugf("Next is %p\n", (void*)next);
		debugf("is_key %d\n", h->is_key);
		if (h->is_key) {
			debugf("key value is %p\n", radix_get_data(h));
		}

		size_t prefix_len = j;
		size_t postfix_len = h->size - j - 1;
		bool split_vertex_is_key = !prefix_len && !h->is_null && h->is_key;
		size_t vertex_size;

		/* Create un-compressed vertex */
		radix_vertex *split_vertex = _new_vertex(1, split_vertex_is_key); // 1 child
		radix_vertex *prefix = NULL;
		radix_vertex *postfix = NULL;

		if (prefix_len)
		{
			vertex_size = sizeof(radix_vertex) + prefix_len + radix_padding(prefix_len) + sizeof(radix_vertex *);
			if (!h->is_null && h->is_key)
				vertex_size += sizeof(void *);
			prefix = malloc(vertex_size);
		}

		if (postfix_len)
		{
			vertex_size = sizeof(radix_vertex) + postfix_len + radix_padding(postfix_len) + sizeof(radix_vertex *);
			postfix = malloc(vertex_size);
		}

		// abort on OOM
		if (split_vertex == NULL || (prefix_len && prefix == NULL) || (postfix_len && postfix == NULL))
		{
			free(split_vertex);
			free(prefix);
			free(postfix);
			return 0;
		}

		split_vertex->data[0] = h->data[j];

		/* Create prefix vertex */
		if (j == 0)
		{
			/* Replace old vertex with split vertex */
			if (h->is_key)
			{
				void *vdata = radix_get_data(h);
				radix_set_data(split_vertex, vdata);
			}
			memcpy(parent_link, &split_vertex, sizeof(split_vertex));
		}
		else
		{
			/* Trim the compressed vertex into prefix */
			prefix->size = prefix_len;
			memcpy(prefix->data, h->data, prefix_len);
			prefix->is_compressed = prefix_len > 1;
			prefix->is_key = h->is_key;
			prefix->is_null = h->is_null;
			if (!h->is_null && h->is_key)
			{
				void *vdata = radix_get_data(h);
				radix_set_data(prefix, vdata);
			}

			radix_vertex **cp = radix_vertex_last_child_ptr(prefix);
			memcpy(cp, &split_vertex, sizeof(split_vertex));
			memcpy(parent_link, &prefix, sizeof(prefix));
			parent_link = cp; // set parent link to split_vertex parent
			++t->num_vertices;
		}

		/* Create postfix vertex */
		if (postfix_len)
		{
			postfix->size = postfix_len;
			memcpy(postfix->data, h->data + prefix_len + 1, postfix_len);
			postfix->is_compressed = postfix_len > 1;
			postfix->is_key = false;
			postfix->is_null = false;

			radix_vertex **cp = radix_vertex_last_child_ptr(postfix);
			memcpy(cp, &next, sizeof(next));
			++t->num_vertices;
		}
		else
		{
			postfix = next;
		}

		/* Set split_vertex's last child as the postfix node */
		radix_vertex **split_child = radix_vertex_last_child_ptr(split_vertex);
		memcpy(split_child, &postfix, sizeof(postfix));
		
		/* Continue to fall-through (insertion) */
		free(h);
		h = split_vertex;
	}
	else if (i == len && h->is_compressed)
	{
		debugf("Algorithm 2: Stopped at compressed node '%.*s' (%p) j = %d\n",
				h->size, h->data, (void*)h, j);

		/* Save next pointer */
		radix_vertex **childfield = radix_vertex_last_child_ptr(h);
		radix_vertex *next;
		memcpy(&next, childfield, sizeof(next));

		size_t postfix_len = h->size - j;
		size_t vertex_size = sizeof(radix_vertex) + postfix_len + radix_padding(postfix_len) + sizeof(radix_vertex *);
		if (data != NULL)
			vertex_size += sizeof(void *);

		radix_vertex *postfix = malloc(vertex_size);

		vertex_size = sizeof(radix_vertex) + j + radix_padding(j) + sizeof(radix_vertex *);
		if (!h->is_null && h->is_key)
			vertex_size += sizeof(void *);

		radix_vertex *prefix = malloc(vertex_size);

		if (prefix == NULL || postfix == NULL)
		{
			free(prefix);
			free(postfix);
			return 0;
		}

		/* Create postfix vertex */
		postfix->size = postfix_len;
		memcpy(postfix->data, h->data + j, postfix_len);
		postfix->is_compressed = postfix_len > 1;
		postfix->is_key = true;
		postfix->is_null = false;
		radix_set_data(postfix, data);

		radix_vertex **cp = radix_vertex_last_child_ptr(postfix);
		memcpy(cp, &next, sizeof(next));
		++t->num_vertices;

		/* Trim compressed vertex */
		prefix->size = j;
		memcpy(prefix->data, h->data, j);
		prefix->is_compressed = j > 1;
		prefix->is_key = false;
		prefix->is_null = false;

		memcpy(parent_link, &prefix, sizeof(prefix));
		if (h->is_key)
		{
			void *vdata = radix_get_data(h);
			radix_set_data(prefix, vdata);
		}

		cp = radix_vertex_last_child_ptr(prefix);
		memcpy(cp, &postfix, sizeof(postfix));

		/* key is already inserted */

		++t->num_elements;
		free(h);
		return 1;
	}

	/* fall through, still got some chars left to go in string */
	while (i < len)
	{
		radix_vertex *child;	

		/* successive vertices with 1 children are compressed */
		if (h->size == 0 && len - i > 1)
		{
			debugf("Inserting compressed vertice\n");
			size_t compressed_size = len - i;
			if (compressed_size > RADIX_VERTEX_MAX_SIZE) 
				compressed_size = RADIX_VERTEX_MAX_SIZE;

			radix_vertex *newh = _compress(h, s+i, compressed_size, &child);
			if (newh == NULL)
				goto OOM;

			h = newh;
			memcpy(parent_link, &h, sizeof(h));
			parent_link = radix_vertex_last_child_ptr(h);
			i += compressed_size;
		}
		else // normal insert
		{
			debugf("Inserting normal vertice\n");
			radix_vertex **new_parent_link;	
			radix_vertex *newh = _add_child(h, s[i], &child, &new_parent_link);
			if (newh == NULL)
				goto OOM;

			h = newh;
			memcpy(parent_link, &h, sizeof(h));
			parent_link = new_parent_link;
			++i;
		}

		++t->num_vertices;
		h = child;
	}

	radix_vertex *newh = _radix_realloc_data(h, data);
	if (newh == NULL)
		goto OOM;
	
	h = newh;
	if (!h->is_key)
		++t->num_elements;

	radix_set_data(h, data);
	memcpy(parent_link, &h, sizeof(h));
	return 1;

OOM: // out of memory
	if (h->size == 0)
	{
		h->is_null = true;
		h->is_key = true;
		++t->num_elements; /* compensation for next removal */
		assert(radix_del(t, s, i, NULL) != 0);
	}

	return 0;
}

/* overwriting insert that updates the element if it exists */
int 
radix_insert(radix_tree *t, uint8_t *s, size_t len, void *data, void **old)
{
	return _radix_insert(t, s, len, data, old, 1);
}

static radix_vertex **
_radix_find_parent_link(radix_vertex *parent, radix_vertex *child)
{
	radix_vertex **cp = radix_vertex_first_child_ptr(parent);
	radix_vertex *c;

	while (1)
	{
		memcpy(&c, cp, sizeof(c));
		if (c == child) break;
		++cp;
	}

	return cp;
}

static radix_vertex *
_radix_del_child(radix_vertex *parent, radix_vertex *child)
{
	debug_vertex("_radix_del_child before", parent);

	if (parent->is_compressed)
	{
		void *data = NULL;
		if (parent->is_key)
			data = radix_get_data(parent);

		parent->is_null = false;
		parent->is_compressed = false;
		parent->size = 0;

		if (parent->is_key)
			radix_set_data(parent, data);

		debug_vertex("_radix_del_child after", parent);
		return parent;
	}

	/* if not compressed, find child pointer and move */

	radix_vertex **cp = radix_vertex_first_child_ptr(parent);
	radix_vertex **c = cp;
	uint8_t *edge = parent->data;

	while (1)
	{
		radix_vertex *v;
		memcpy(&v, c, sizeof(v));
		if (v == child) break;
		++c;
		++edge;
	}

	int tail_len = parent->size - (edge - parent->data) - 1;
	debugf("_radix_del_child tail len: %d\n", tail_len);
	memmove(edge, edge + 1, tail_len);

	size_t shift = ((parent->size + 4) % sizeof(void *)) == 1 ? sizeof(void *) : 0;
	if (shift)
		memmove(((uint8_t *)cp) - shift, cp, (parent->size - tail_len - 1) * sizeof(radix_vertex **));

	size_t value_len = (!parent->is_null && parent->is_key) ? sizeof(void *) : 0;
	memmove(((uint8_t *)c) - shift, c + 1, tail_len * sizeof(radix_vertex **) + value_len);

	--parent->size;

	/* frees data if overallocated; if it fails the old address is returned - which is valid */
	radix_vertex *newv = realloc(parent, radix_vertex_current_size(parent));
	if (newv)
		debug_vertex("_radix_del_child after", newv);

	return newv ? newv : parent;
}

int
radix_del(radix_tree *t, uint8_t *s, size_t len, void **old)
{
	radix_vertex *h;
	radix_stack stack;

	debugf("### Delete: %.*s\n", (int)len, s);

	_stack_init(&stack);
	int split_pos = 0;

	size_t i = _radix_walk(t, s, len, &h, NULL, &split_pos, &stack);
	if (i != len || (h->is_compressed && split_pos != 0) || !h->is_key)
	{
		_stack_free(&stack);
		return 0;
	}

	if (old)
		*old = radix_get_data(h);

	h->is_key = false;
	--t->num_elements;

	/* if node has no children, need to compress / cleanup */
	bool try_compress = false;
	if (h->size == 0)
	{
		debugf("Key deleted in vertex without children. Cleanup needed.\n");
		radix_vertex *child = NULL;

		while (h != t->head)
		{
			child = h;
			debugf("Freeing child %p [%.*s] key:%d\n", (void*)child, (int)child->size, (char*)child->data, child->is_key);
			free(child);
			--t->num_vertices;
			h = _stack_pop(&stack);
			// stop if vertex holds a key, or if it has more than 1 child
			if (h->is_key || (!h->is_compressed && h->size != 1))
				break;
		}
		if (child)
		{
			debugf("Unlinking child %p from parent %p\n", (void*)child, (void*)h);

			radix_vertex *new = _radix_del_child(h, child);
			if (new != h)
			{
				radix_vertex *parent = _stack_peek(&stack);
				radix_vertex **parent_link;

				if (parent == NULL)
				{
					parent_link = &t->head;
				}
				else
				{
					parent_link = _radix_find_parent_link(parent, h);
				}
				
				memcpy(parent_link, &new, sizeof(new));
			}

			if (new->size == 1 && !new->is_key)
			{
				try_compress = true;
				h = new;
			}
		}
	}
	else if (h->size == 1)
	{
		try_compress = true;
	}

	if (try_compress && stack.oom)
		try_compress = false;

	if (try_compress)
	{
		debugf("After removing %.*s:\n", (int)len, s);
		debug_vertex("Compression may be needed",h);
		debugf("Seek start node\n");

		radix_vertex *parent;
		while (1)
		{
			parent = _stack_pop(&stack);
			if (!parent || parent->is_key || (!parent->is_compressed && parent->size != 1)) break;
			h = parent;
			debug_vertex("Going up to",h);
		}

		radix_vertex *start = h;
		size_t compression_size = h->size;

		int vertices = 1;
		while (h->size != 0)
		{
			radix_vertex **cp = radix_vertex_last_child_ptr(h);
			memcpy(&h, cp, sizeof(h));
			if (h->is_key || (!h->is_compressed && h->size != 1)) break;
			if (compression_size + h->size > RADIX_VERTEX_MAX_SIZE) break;
			++vertices;
			compression_size += h->size;
		}
		if (vertices > 1)
		{
			size_t vertex_size = sizeof(radix_vertex) + compression_size + radix_padding(compression_size) + sizeof(radix_vertex *);	
			radix_vertex *new = malloc(vertex_size);

			// technically an OOM error here just means optimizing the node isn't possible, the tree should still be intact
			if (new == NULL)
			{
				_stack_free(&stack);
				return 1;
			}

			new->is_null = false;
			new->is_key = false;
			new->is_compressed = true;
			new->size = compression_size;
			++t->num_vertices;

			compression_size = 0;
			h = start;
			while (h->size != 0)
			{
				memcpy(new->data + compression_size, h->data, h->size);
				compression_size += h->size;
				radix_vertex **cp = radix_vertex_last_child_ptr(h);
				radix_vertex *to_free = h;
				memcpy(&h, cp, sizeof(h));
				free(to_free);
				--t->num_vertices;
				if (h->is_key || (!h->is_compressed && h->size != 1)) break;

			}
			debug_vertex("New vertex", new);

			// fix parent link, h should point to first vertex
			radix_vertex **cp = radix_vertex_last_child_ptr(new);
			memcpy(cp, &h, sizeof(h));

			if (parent)
			{
				radix_vertex **parent_link = _radix_find_parent_link(parent, start);
				memcpy(parent_link, &new, sizeof(new));
			}
			else
			{
				t->head = new;
			}

			debugf("Compressed %d vertices, %d total bytes\n", vertices, (int)compression_size);
		}
	}

	_stack_free(&stack);
	return 1;	
}

void *
radix_find(radix_tree *t, uint8_t *s, size_t len)
{
	radix_vertex *h;
	int split_pos = 0;

	debugf("### Lookup: '%.*s'\n", (int)len, s);

	size_t i = _radix_walk(t, s, len, &h, NULL, &split_pos, NULL);

	if (i != len || (h->is_compressed && split_pos != 0) || !h->is_key)
		return NULL;

	debugf("Found data: %p\n", radix_get_data(h));

	return radix_get_data(h);
}

void
_radix_print(radix_vertex *v, int level, int left_pad)
{
	char s = v->is_compressed ? '"' : '[';
	char e = v->is_compressed ? '"' : ']';

	int num_chars = printf("%c%.*s%c", s, v->size, v->data, e);
	if (v->is_key)
		num_chars += printf("=%p", radix_get_data(v));
	 
	int num_children = v->is_compressed ? 1 : v->size;

	if (level)
	{
		/* " `-(x) " has len 7 and " -> " has len 4 */
		left_pad += (num_children > 1) ? 7 : 4;
		if (num_children == 1) left_pad += num_chars;
	}

	radix_vertex **cp = radix_vertex_first_child_ptr(v);
	char *subtree = " `-(%c) ";
	for (int i = 0; i < num_children; ++i)
	{
		if (num_children > 1)
		{
			printf("\n");
			for (int j = 0; j < left_pad; ++j) putchar(' ');
			printf(subtree, v->data[i]);
		}
		else
		{
			printf(" -> ");
		}

		radix_vertex *child;
		memcpy(&child, cp, sizeof(child));
		_radix_print(child, level + 1, left_pad);
		++cp;
	}
}

void 
radix_print(radix_tree *t)
{
	_radix_print(t->head, 0, 0);	
	putchar('\n');
}
