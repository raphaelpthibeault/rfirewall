#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/maps.bpf.h>
#include <stdbool.h>
#include <conn/tcpconn.h>

#define AF_INET 2
#define AF_INET6 10

char LICENSE[] SEC("license") = "GPL";

/* 
listen and accept sockets are different
https://stackoverflow.com/a/34073929
"""
The listen() function basically sets a flag in the internal socket structure marking the socket as a passive listening socket, one that you can call accept on. It opens the bound port so the socket can then start receiving connections from clients.
The accept() function asks a listening socket to accept the next incoming connection and return a socket descriptor for that connection. So, in a sense, accept() does create a socket, just not the one you use to listen() for incoming connections on.
"""

Idk if krpobe is necessary, since it'd be storing the listen socket
 */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct sock *);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} accepted_sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} accepted_events SEC(".maps");

static __always_inline void
trace_v4(struct pt_regs *ctx, pid_t pid, struct sock *sk, __u16 dport)
{
	struct event e = {};

	/* is this right?
	 * for the newsk, 
	 * server is destination
	 * client is source
	 * then what do we do with dport?
	 * */
	BPF_CORE_READ_INTO(&e.saddr_v4, sk, __sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&e.daddr_v4, sk, __sk_common.skc_rcv_saddr);

	bpf_get_current_comm(e.task, sizeof(e.task));
	e.ts_us = bpf_ktime_get_ns() / 1000;
	e.af = AF_INET;
	e.pid = pid;
	e.uid = bpf_get_current_uid_gid();
	e.dport = dport;

	bpf_perf_event_output(ctx, &accepted_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
}

static __always_inline void
trace_v6(struct pt_regs *ctx, pid_t pid, struct sock *sk, __u16 dport)
{
	struct event e = {};

	BPF_CORE_READ_INTO(&e.saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	BPF_CORE_READ_INTO(&e.daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);

	bpf_get_current_comm(e.task, sizeof(e.task));
	e.ts_us = bpf_ktime_get_ns() / 1000;
	e.af = AF_INET6;
	e.pid = pid;
	e.uid = bpf_get_current_uid_gid();
	e.dport = dport;

	bpf_perf_event_output(ctx, &accepted_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
}

static __always_inline int
exit_tcp_accept(struct pt_regs *ctx, struct sock *newsk)
{
	
	// TODO store in sockets

	__u64 pid_tgid;
	__u32 pid, tid;
	__u16 dport;
	sa_family_t family;

	pid_tgid = bpf_get_current_pid_tgid(); // https://docs.ebpf.io/linux/helper-function/bpf_get_current_pid_tgid/
	pid = pid_tgid >> 32;
	tid = pid_tgid;

	BPF_CORE_READ_INTO(&family, newsk, __sk_common.skc_family);
	BPF_CORE_READ_INTO(&dport, newsk, __sk_common.skc_dport);


	if (family == AF_INET) {
		trace_v4(ctx, pid, newsk,  dport);
	} else if (family == AF_INET6) {
		trace_v6(ctx, pid, newsk, dport);
	} else {
		// some error, drop pkt
		return 0;	
	}

	return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_ret, struct sock *newsk)
{
	return exit_tcp_accept(ctx, newsk);
}

