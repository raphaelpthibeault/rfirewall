#include <conn/conn.h>
#include <conn/tcpconn.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <time.h>

#include <rradix.h>

#include <fcntl.h>

radix_tree *connections = NULL;

static int
handle_event(void *ctx, void *data, size_t data_sz)
{
	(void)ctx;
	(void)data_sz;

	const struct ebpf_event *e = data;
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	union {
		struct in_addr x4;
		struct in6_addr x6;
	} s, d;
	static __u64 start_ts;

	if (e->af == AF_INET) 
	{
		s.x4.s_addr = e->saddr_v4;
		d.x4.s_addr = e->daddr_v4;
	} 
	else if (e->af == AF_INET6) 
	{
		memcpy(&s.x6.s6_addr, e->saddr_v6, sizeof(s.x6.s6_addr)); 		
		memcpy(&d.x6.s6_addr, e->daddr_v6, sizeof(d.x6.s6_addr)); 		
	} else 
	{
		fprintf(stderr, "Broken event: e->af=%d\n", e->af);
		return 1;
	}

	if (start_ts == 0)
		start_ts = e->ts_us;

	char type = '-';
	switch (e->type) 
	{
		case TCP_EVENT_CONNECT:
			type = 'C';
			break;
		case TCP_EVENT_ACCEPT:
			type = 'A';
			break;
		case TCP_EVENT_CLOSE: 
			type = 'X';
			break;
	}

	printf("%c %-9.3f %-6d %-6d %-12.12s %-2d %-16s %-16s %-4d\n",
			type,
			(e->ts_us - start_ts) / 1000000.0,
			e->uid,
			e->pid,
			e->task,
			e->af == AF_INET ? 4 : 6,
			inet_ntop(e->af, &s, src, sizeof(src)),
			inet_ntop(e->af, &d, dst, sizeof(dst)),
			ntohs(e->dport));

	conn_key_t key;
	key.protocol = e->protocol;
	key.af_family = e->af;
	if (e->af == AF_INET) 
	{
		key.saddr_v4 = e->saddr_v4;
		key.daddr_v4 = e->daddr_v4;
	} 
	else if (e->af == AF_INET6) 
	{
		memcpy(&key.saddr_v6, e->saddr_v6, sizeof(key.saddr_v6));
		memcpy(&key.daddr_v6, e->daddr_v6, sizeof(key.daddr_v6));
	}
	key.sport = ntohs(e->sport);
	key.dport = ntohs(e->dport);

	if (e->type == TCP_EVENT_CONNECT || e->type == TCP_EVENT_ACCEPT)
	{
		// insert 1 temporarily until connection data struct
		radix_insert(connections, (uint8_t *)&key, sizeof(key), (void *)(long)1, NULL);
	} else if (e->type == TCP_EVENT_CLOSE)
	{
		radix_del(connections, (uint8_t *)&key, sizeof(key), NULL);
	}

	return 0;
}

static inline __attribute__((always_inline)) void 
print_events_header() 
{
	printf("%s %-9s %-6s %-6s %-12s %-2s %-16s %-16s %-4s\n", 
			"T", "TIME(s)", "UID", "PID", "COMM", "IP", "SADDR", "DADDR", "DPORT");
}

extern volatile sig_atomic_t exiting; // definition in rfirewall.c TODO put in some io.h ?

void
read_bpf_ringbuf(int ringbuf_fd) 
{
	struct ring_buffer *rb;
	int err;

	rb = ring_buffer__new(ringbuf_fd, &handle_event, NULL, NULL);
	connections = radix_new();
	
	if (rb == NULL) {
		fprintf(stderr, "Error with ring_buffer__new() '%d', '%s'",
			errno, strerror(errno));
		err = -errno;
		goto cleanup;
	}

	print_events_header();

	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Error polling ring buffer '%d', '%s'", -err, strerror(-err));
			goto cleanup;
		}
		err = 0; /* reset err to return 0 if exiting */
	}

	
cleanup:
	ring_buffer__free(rb);
}

