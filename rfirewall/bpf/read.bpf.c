#include <stdint.h>
#include <sys/types.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct sys_read_state {
	unsigned int fd;
	size_t count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, uint32_t);
	__type(value, struct sys_read_state);
} sys_read_state_map SEC(".maps");

struct sys_enter_read_tp_ctx {
	uint8_t inaccessible[16];
	uint64_t fd;
	char * buf;
	uint64_t count;
};

SEC("tp/syscalls/sys_enter_read")
int
handle_sys_enter_read(struct sys_enter_read_tp_ctx *ctx) 
{
	struct sys_read_state state = {ctx->fd, ctx->count};
	uint32_t tid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&sys_read_state_map, &tid, &state, BPF_NOEXIST);
	return 0;
}

struct sys_exit_read_tp_ctx {
	uint8_t inaccessible[16];
	int64_t ret;
};

SEC("tp/syscalls/sys_exit_read")
int handle_sys_exit_read(struct sys_exit_read_tp_ctx *ctx)
{
	uint64_t tgid_pid = bpf_get_current_pid_tgid();
	uint32_t tid = tgid_pid;
	struct sys_read_state *read_state = bpf_map_lookup_elem(&sys_read_state_map, &tid);

	if (read_state) {
		uint32_t tgid = (int)(tgid_pid >> 32);
		char comm[16];
		bpf_get_current_comm(&comm, 16);

		{
			const char fmt[] = "Captured read() syscall: comm: %s, pid: %u, fd: %u, ";
			bpf_trace_printk((const char *)&fmt, sizeof(fmt), &comm, tgid, read_state->fd);
		}

		{
			const char fmt[] = "count: %u, ret: %li\n";
			bpf_trace_printk((const char *)&fmt, sizeof(fmt), read_state->count, ctx->ret);
		}

		bpf_map_delete_elem(&sys_read_state_map, &tid);
	}

	return 0;
}

