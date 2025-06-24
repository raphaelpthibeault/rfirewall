#ifndef __CONN_H__
#define __CONN_H__

#include <stddef.h>
#include <stdint.h>

typedef struct
{
	uint8_t protocol;
	uint8_t af_family;
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
} __attribute__((packed)) conn_key_t;

/* 
 * TODO: some connection data, e.g. process (process info struct?), last recently used ...
 * struct conn_data
 * {
 *	 ...
 * };
 */

int conn_init(int ringbuf_fd);
int conn_poll();
void conn_deinit();

#endif // !__CONN_H__
