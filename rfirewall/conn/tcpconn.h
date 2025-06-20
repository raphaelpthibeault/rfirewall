#ifndef __TCPCONN_H__
#define __TCPCONN_H__

/* contains structs required by tcp*.bpf.c AND whatever files handle the tcp events
 * so keep this very minimal
 * */

#include <asm-generic/types.h>

#define MAX_ENTRIES 8192	/* max num of items in maps */
#define MAX_PORTS	64			/* max ports to filter */
#define TASK_COMM_LEN 16 // https://github.com/torvalds/linux/blob/master/include/linux/sched.h#L319

enum event_type 
{
	TCP_EVENT_CONNECT,
	TCP_EVENT_ACCEPT,
	TCP_EVENT_CLOSE,
};

struct ebpf_event 
{
	union 
	{
		__u32 saddr_v4;
		__u8 saddr_v6[16]; // 128 bit addresses for v6
	};
	union 
	{
		__u32 daddr_v4;
		__u8 daddr_v6[16];
	};
	__u16 sport;
	__u16 dport;
	char task[TASK_COMM_LEN];
	__u64 ts_us;
	__u32 af; // AF_INET or AF_INET6
	__u32 pid;
	__u32 uid;
	__u8 type;
	__u8 protocol;
};

// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
typedef enum
{
	HOPOPT    = 0,
	ICMP      = 1,
	IGMP      = 2,
	GGP       = 3,
	IPV4      = 4,
	ST        = 5,
	TCP       = 6,
	CBT       = 7,
	EGP       = 8,
	IGP       = 9,
	BBNRCCMON = 10,
	NVPII     = 11,
	PUP       = 12,
	ARGUS     = 13,
	EMCON     = 14,
	XNET      = 15,
	CHAOS     = 16,
	UDP       = 17
} ip_protocol_t;

#endif // !__TCPCONN_H__
