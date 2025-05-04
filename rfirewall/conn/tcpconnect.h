#ifndef __TCPCONNECT_H
#define __TCPCONNECT_H

#include <asm-generic/types.h>

#define MAX_ENTRIES 8192	/* max num of items in maps */
#define MAX_PORTS	64			/* max ports to filter */
#define TASK_COMM_LEN 16 // https://github.com/torvalds/linux/blob/master/include/linux/sched.h#L319

struct event {
	union {
		__u32 saddr_v4;
		__u8 saddr_v6[16]; // 128 bit addresses for v6
	};
	union {
		__u32 daddr_v4;
		__u8 daddr_v6[16];
	};
	char task[TASK_COMM_LEN];
	__u64 ts_us;
	__u32 af; // AF_INET or AF_INET6
	__u32 pid;
	__u32 uid;
	__u16 dport;
}/* __attribute__((packed)) */;

#endif // !__TCPCONNECT_H
