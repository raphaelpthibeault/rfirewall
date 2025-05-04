#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/maps.bpf.h>
#include <conn/tcpconnect.h>
#include <stdbool.h>

#define AF_INET 2
#define AF_INET6 10

char LICENSE[] SEC("license") = "GPL";

SEC(".rodata") const int filter_ports[MAX_PORTS]; // empty, for now
const volatile int filter_ports_len = 0;
const volatile pid_t filter_pid = 0;
const volatile uid_t filter_uid = -1;

/* track socket states */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct sock *);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline bool 
filter_port(__u16 port)
{
	int i;

	if (filter_ports_len == 0) {
		return false;
	}

	for (i = 0; i < filter_ports_len; ++i) {
		if (port == filter_ports[i]) {
			return false;
		}
	} 

	return true;
}

static __always_inline void
trace_v4(struct pt_regs *ctx, pid_t pid, struct sock *sk, __u16 dport)
{
	struct event e = {};

	BPF_CORE_READ_INTO(&e.saddr_v4, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&e.daddr_v4, sk, __sk_common.skc_daddr);

	bpf_get_current_comm(e.task, sizeof(e.task));
	e.ts_us = bpf_ktime_get_ns() / 1000;
	e.af = AF_INET;
	e.pid = pid;
	e.uid = bpf_get_current_uid_gid();
	e.dport = dport;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
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

}

static __always_inline int
enter_tcp_connect(struct pt_regs *ctx, struct sock *sk)
{
	__u64 pid_tgid;
	__u32 pid, tid, uid;

	pid_tgid = bpf_get_current_pid_tgid(); // https://docs.ebpf.io/linux/helper-function/bpf_get_current_pid_tgid/
	pid = pid_tgid >> 32;
	tid = pid_tgid;

	if (filter_pid && pid != filter_pid) {
		return 0;
	}

	uid = bpf_get_current_uid_gid(); // https://docs.ebpf.io/linux/helper-function/bpf_get_current_uid_gid/
	if (filter_uid != (uid_t)-1 && uid != filter_uid) {
		return 0;
	}

	/* key: traffic identifier, value: socket  ; I wonder, I could probably use pid_tgid as key */
	bpf_map_update_elem(&sockets, &tid, &sk, 0);
	return 0;
}

static __always_inline int
exit_tcp_connect(struct pt_regs *ctx, int ret, int ip_ver)
{
	__u64 pid_tgid;
	__u32 pid, tid;
	__u16 dport;
	struct sock *sk;
	struct sock **skpp;
	
	pid_tgid = bpf_get_current_pid_tgid(); // https://docs.ebpf.io/linux/helper-function/bpf_get_current_pid_tgid/
	pid = pid_tgid >> 32;
	tid = pid_tgid;

	skpp = bpf_map_lookup_elem(&sockets, &tid);
	if (skpp == NULL) {
		return 0;
	}

	if (ret) {
		goto end;
	}

	sk = *skpp;
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
	if (filter_port(dport)) {
		goto end;
	}

	if (ip_ver == 4) {
		trace_v4(ctx, pid, sk, dport);
	} else if (ip_ver == 6) {
		trace_v6(ctx, pid, sk, dport);	
	} else {
		// the fuck are you doing?
		goto end;
	}

end:
	bpf_map_delete_elem(&sockets, &tid);
	return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_ret, int ret)
{
	return exit_tcp_connect(ctx, ret, 4);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(tcp_v6_connect_ret, int ret)
{
	return exit_tcp_connect(ctx, ret, 6);
}


