#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/maps.bpf.h>
#include <conn/tcpconn.h>
#include <stdbool.h>

#define AF_INET 2
#define AF_INET6 10

char LICENSE[] SEC("license") = "GPL";

const volatile pid_t filter_pid = 0;
const volatile uid_t filter_uid = -1;

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

static __always_inline void
fill_event(struct event *e, struct sock *sk, __u16 family, pid_t pid, __u16 dport, __u8 type)
{
	if (family == AF_INET) {
		BPF_CORE_READ_INTO(&e->saddr_v4, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&e->daddr_v4, sk, __sk_common.skc_daddr);
	} else if (family == AF_INET6) {
		BPF_CORE_READ_INTO(&e->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&e->daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	bpf_get_current_comm(e->task, sizeof(e->task));
	e->ts_us = bpf_ktime_get_ns() / 1000;
	e->af = family;
	e->pid = pid;
	e->uid = bpf_get_current_uid_gid();
	e->dport = dport;
	e->type = type;
}

static __always_inline bool
filter_event(struct sock *sk, __u32 pid, __u32 uid)
{
	__u16 family;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);

	if (family != AF_INET && family != AF_INET6) {
		return true;
	}

	if (filter_pid && pid != filter_pid) {
		return true;
	}

	if (filter_uid != (uid_t)-1 && uid != filter_uid) {
		return true;
	}

	return false;
}

static __always_inline int
enter_tcp_connect(struct pt_regs *ctx, struct sock *sk)
{
	__u64 pid_tgid;
	__u32 pid, tid, uid;

	pid_tgid = bpf_get_current_pid_tgid(); // https://docs.ebpf.io/linux/helper-function/bpf_get_current_pid_tgid/
	pid = pid_tgid >> 32;
	tid = pid_tgid;

	uid = bpf_get_current_uid_gid(); // https://docs.ebpf.io/linux/helper-function/bpf_get_current_uid_gid/
	if (filter_event(sk, pid, uid)) {
		return 0; // drop pkt
	}

	/* key: traffic identifier, value: socket  ; I wonder, I could probably use pid_tgid as key */
	bpf_map_update_elem(&sockets, &tid, &sk, 0);
	return 0;
}

static __always_inline int
exit_tcp_connect(struct pt_regs *ctx, int ret, __u16 family)
{
	struct sock *sk;
	struct sock **skpp;
	struct event e = {};
	__u64 pid_tgid;
	__u32 pid, tid;
	__u16 dport;
	
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

	fill_event(&e, sk, family, pid, dport, TCP_EVENT_CONNECT);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

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
	return exit_tcp_connect(ctx, ret, AF_INET);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(tcp_v6_connect_ret, int ret)
{
	return exit_tcp_connect(ctx, ret, AF_INET6);
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_ret, struct sock *newsk)
{
	struct event e = {};
	__u64 pid_tgid;
	__u32 pid, tid;
	__u16 dport;
	sa_family_t family;

	pid_tgid = bpf_get_current_pid_tgid(); // https://docs.ebpf.io/linux/helper-function/bpf_get_current_pid_tgid/
	pid = pid_tgid >> 32;
	tid = pid_tgid;

	BPF_CORE_READ_INTO(&family, newsk, __sk_common.skc_family);
	BPF_CORE_READ_INTO(&dport, newsk, __sk_common.skc_dport);

	fill_event(&e, newsk, family, pid, dport, TCP_EVENT_ACCEPT);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

	return 0;
}

/* workaround for not having entry_trace_close*/
SEC("kprobe/tcp_close")
int kprobe__tcp_close(struct pt_regs *ctx)
{
	struct sock *sk;
	struct event e = {};
	__u64 pid_tgid, uid_gid;
	__u32 pid, uid;
	__u16 dport;
	sa_family_t family;
	__u8 oldstate;

	sk = (struct sock *)PT_REGS_PARM1(ctx);

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	uid_gid = bpf_get_current_uid_gid();
	uid = uid_gid;
	

	if (filter_event(sk, pid, uid)) {
		return 0;
	}

	/* do not generate close event for unestablished connections */
	oldstate = BPF_CORE_READ(sk, __sk_common.skc_num);
	if (oldstate == TCP_SYN_SENT || oldstate == TCP_SYN_RECV || oldstate == TCP_NEW_SYN_RECV) {
		return 0;
	}

	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

	fill_event(&e, sk, family, pid, dport, TCP_EVENT_CLOSE);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

	return 0;
}

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(enter_tcp_set_state, struct sock *sk, int state) 
{
	struct event e = {};
	sa_family_t family;
	__u64 pid_tgid, uid_gid;
	__u32 pid, uid;
	__u16 dport;

	if ((state != TCP_ESTABLISHED && state != TCP_CLOSE) || state == TCP_CLOSE) {
		return 0;
	}	

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	uid_gid = bpf_get_current_uid_gid();
	uid = uid_gid;

	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
	
	fill_event(&e, sk, family, pid, dport, TCP_EVENT_CONNECT);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

	return 0;
}

