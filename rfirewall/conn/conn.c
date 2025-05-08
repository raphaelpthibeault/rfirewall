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

#include <fcntl.h>

static void
handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	union {
		struct in_addr x4;
		struct in6_addr x6;
	} s, d;
	static __u64 start_ts;

	if (e->af == AF_INET) {
		s.x4.s_addr = e->saddr_v4;
		d.x4.s_addr = e->daddr_v4;
	} else if (e->af == AF_INET6) {
		memcpy(&s.x6.s6_addr, e->saddr_v6, sizeof(s.x6.s6_addr)); 		
		memcpy(&d.x6.s6_addr, e->daddr_v6, sizeof(d.x6.s6_addr)); 		
	} else {
		fprintf(stderr, "Broken event: e->af=%d\n", e->af);
		return;
	}

	if (start_ts == 0) {
		start_ts = e->ts_us;
	}

	char type = '-';
	switch (e->type) {
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

	// TODO: add to connection table

}

static void
handle_lost_event(void *ctx, int cpu, __u64 lost_count)
{
	fprintf(stderr, "Lost '%llu' events on CPU #%d\n", lost_count, cpu);	
}

static void 
print_events_header() 
{
	printf("%s %-9s %-6s %-6s %-12s %-2s %-16s %-16s %-4s\n", 
			"T", "TIME(s)", "UID", "PID", "COMM", "IP", "SADDR", "DADDR", "DPORT");
}

extern volatile sig_atomic_t exiting; // definition in rfirewall.c TODO put in some io.h ?

void
print_events(int perf_map_fd) 
{
	struct perf_buffer *pbuf;	
	int err;

	pbuf = perf_buffer__new(perf_map_fd, 128, handle_event, handle_lost_event, NULL, NULL);
	if (pbuf == NULL) {
		fprintf(stderr, "Error with perf_buffer__new() '%d', '%s'",
			errno, strerror(errno));
		err = -errno;
		goto cleanup;
	}

	print_events_header();

	while (!exiting) {
		err = perf_buffer__poll(pbuf, 100);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "Error polling perf buffer '%d', '%s'", -err, strerror(-err));
			goto cleanup;
		}
		err = 0; /* reset err to return 0 if exiting */
	}

	
cleanup:
	perf_buffer__free(pbuf);
}

