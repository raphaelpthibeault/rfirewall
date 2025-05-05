#ifndef __MAPS_BPF_H__
#define __MAPS_BPF_H__

#include <bpf/bpf_helpers.h>
#include <asm-generic/errno.h>
#include <conn/tcpconn.h>

static __always_inline void *
bpf_map_lookup_elem_or_try_create(void *map, const void *key, const void *iv)
{
	void *elem;
	long err; // https://docs.ebpf.io/linux/helper-function/bpf_map_update_elem/

	elem = bpf_map_lookup_elem(map, key); // https://docs.ebpf.io/linux/helper-function/bpf_map_lookup_elem/

	if (elem != NULL) {
		return elem;
	}
	
	err = bpf_map_update_elem(map, key, iv, BPF_NOEXIST);

	/* funkiness for thread-safety
	 * race condition is possible so if the error is that the elem exists, lookup again
	 * */

	if (err < 0 && err != -EEXIST) {
		return 0;	
	}

	return bpf_map_lookup_elem(map, key);
}

#endif // !__MAPS_BPF_H__
