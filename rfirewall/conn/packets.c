#include <conn/packets.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>

#include <arpa/inet.h>
 
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter/nfnetlink_conntrack.h> /* only for NFQA_CT, not needed otherwise: */

/* use mnl and nfq to get a pkt stream for:
 * INET, INET6, ICMP, ...
 *
 * reference: https://netfilter.org/projects/libnetfilter_queue/doxygen/html/nf-queue_8c_source.html
 * */

static struct mnl_socket *nl;
static unsigned int port_id;

static void
nfq_send_verdict(int queue_num, uint32_t id)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nlattr *nest;

	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);
	nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);

	/* example to set the connmark. First, start NFQA_CT section: */
	nest = mnl_attr_nest_start(nlh, NFQA_CT);

	/* then, add the connmark attribute: */
	mnl_attr_put_u32(nlh, CTA_MARK, htonl(42));
	/* more conntrack attributes, e.g. CTA_LABELS could be set here */

	/* end conntrack section */
	mnl_attr_nest_end(nlh, nest);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) 
	{
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}
}
	
static int
queue_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nfqnl_msg_packet_hdr *ph = NULL;
	struct nlattr *attr[NFQA_MAX+1] = {};
	uint32_t id = 0, skbinfo;
	struct nfgenmsg *nfg;
	uint16_t plen;

	if (nfq_nlmsg_parse(nlh, attr) < 0) 
	{
		perror("problems parsing");
		return MNL_CB_ERROR;
	}

	nfg = mnl_nlmsg_get_payload(nlh);

	if (attr[NFQA_PACKET_HDR] == NULL) 
	{
		fputs("metaheader not set\n", stderr);
		return MNL_CB_ERROR;
	}

	ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);

	plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
	/* void *payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]); */

	skbinfo = attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

	if (attr[NFQA_CAP_LEN]) 
	{
		uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
		if (orig_len != plen)
			printf("truncated ");
	}

	if (skbinfo & NFQA_SKB_GSO)
		printf("GSO ");

	id = ntohl(ph->packet_id);
	printf("packet received (id=%u hw=0x%04x hook=%u, payload len %u",
					id, ntohs(ph->hw_protocol), ph->hook, plen);

	/*
	* ip/tcp checksums are not yet valid, e.g. due to GRO/GSO.
	* The application should behave as if the checksums are correct.
	*
	* If these packets are later forwarded/sent out, the checksums will
	* be corrected by kernel/hardware.
	*/
	if (skbinfo & NFQA_SKB_CSUMNOTREADY)
		printf(", checksum not ready");
	puts(")");

	nfq_send_verdict(ntohs(nfg->res_id), id);

	return MNL_CB_OK;
}

/* 
 * -1: mnl_socket_open() failure
 * -2: mnl_socket_bind() failure
 * -3: malloc() failure
 * -4: nfq_nlmsg_put() failure
 * -5: mnl_socket_sendto() failure
 * -6: mnl_socket_recvfrom() failure
 * -7: mnl_cb_run() failure
 * */
int
setup_queue(int queue_num, uint16_t addr_family)
{
	char *buf;
	/* largest possible packet payload, plus netlink data overhead: */
	size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE / 2);
	struct nlmsghdr *nlh;
	int ret = 0;

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL)
		return -1;

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
		return -2;
	port_id = mnl_socket_get_portid(nl);

	buf = malloc(sizeof_buf);
	if (!buf)
		return -3;

	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
	if (nlh == NULL)
	{
		ret = -4;	
		goto cleanup;
	}

	nfq_nlmsg_cfg_put_cmd(nlh, addr_family, NFQNL_CFG_CMD_BIND);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
	{
		ret = -5;
		goto cleanup;
	}

	nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
	if (nlh == NULL)
	{
		ret = -4;	
		goto cleanup;
	}
	nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

	mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
	mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
	{
		ret = -5;
		goto cleanup;
	}

	/* TODO: move this to some function for a filter thread */

	printf("Setup Queue '%d' on IPV4, port '%u'... \n", queue_num, port_id);
	int err = 1;
	mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &err, sizeof(int));
	while (1)
	{
		err = mnl_socket_recvfrom(nl, buf, sizeof_buf);
		if (err == -1)
		{
			ret = -6;			
			goto cleanup;
		}

		err = mnl_cb_run(buf, err, 0, port_id, queue_cb, NULL);
		if (err < 0)
		{
			ret = -7;
			goto cleanup;
		}
	}

cleanup:
	if (buf != NULL)
		free(buf);

	mnl_socket_close(nl);
	return ret;	
}

