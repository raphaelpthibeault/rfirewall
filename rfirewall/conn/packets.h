#ifndef __PACKETS_H__
#define __PACKETS_H__

#include <stdint.h>
#include <stddef.h>

// https://www.nftables.org/projects/libmnl/doxygen/html/libmnl_8h_source.html
enum mnl_cb_result
{
	CB_ERROR = -1,
	CB_STOP = 0,
	CB_OK = 1,
};

struct nfq_event
{
	union 
	{
		uint32_t saddr_v4;
		uint8_t saddr_v6[16];
	};
	union 
	{
		uint32_t daddr_v4;
		uint8_t daddr_v6[16];
	};
	uint16_t sport;
	uint16_t dport;
	uint16_t ts_us;
	uint8_t protocol;

	uint32_t user_id;
	uint32_t group_id;
	uint32_t nfq_id;

	// TODO: missing queue
};

int setup_queue(int queue_num, uint16_t addr_family);

#endif // !__PACKETS_H__
