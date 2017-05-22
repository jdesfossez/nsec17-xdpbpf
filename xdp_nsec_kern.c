/* Copyright(c) 2017 Julien Desfossez <jdesfossez@efficios.com> */

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/if_vlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/ipv6.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include "bpf_helpers.h"

#include "xdp_nsec_common.h"

struct bpf_map_def SEC("maps") nsec = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = CMD_SIZE * sizeof(char), /* command */
	.max_entries = 1,
	.map_flags   = 0,
};

//#define DEBUG 1
#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

/* Parse Ethernet layer 2, extract network layer 3 offset and protocol
 *
 * Returns false on error and non-supported ether-type
 */
static __always_inline
bool parse_eth(struct ethhdr *eth, void *data_end,
	       u16 *eth_proto, u64 *l3_offset)
{
	u16 eth_type;
	u64 offset;

	offset = sizeof(*eth);
	if ((void *)eth + offset > data_end)
		return false;

	eth_type = eth->h_proto;

	/* Skip non 802.3 Ethertypes */
	if (unlikely(ntohs(eth_type) < ETH_P_802_3_MIN))
		return false;

	/* No VLAN suport */
	*eth_proto = ntohs(eth_type);
	*l3_offset = offset;
	return true;
}

u32 parse_port(struct xdp_md *ctx, u8 proto, void *hdr)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct udphdr *udph;
	u32 dport;
	char *cmd;
	unsigned long payload_offset;
	unsigned long payload_size;
	char *payload;
	u32 key = 0;

	if (proto != IPPROTO_UDP) {
		return XDP_PASS;
	}

	udph = hdr;
	if (udph + 1 > data_end) {
		return XDP_ABORTED;
	}

	payload_offset = sizeof(struct udphdr);
	payload_size = ntohs(udph->len) - sizeof(struct udphdr);

	dport = ntohs(udph->dest);
	if (dport == CMD_PORT + 1) {
		return XDP_DROP;
	}

	if (dport != CMD_PORT) {
		return XDP_PASS;
	}

	if ((hdr + payload_offset + CMD_SIZE) > data_end) {
		return XDP_ABORTED;
	}
	cmd = bpf_map_lookup_elem(&nsec, &key);
	if (!cmd) {
		return XDP_PASS;
	}
	memset(cmd, 0, CMD_SIZE);
	payload = &((char *) hdr)[payload_offset];
	cmd[0] = payload[0];
	cmd[1] = payload[1];
	cmd[2] = payload[2];
	cmd[3] = payload[3];
	cmd[4] = payload[4];
	cmd[5] = payload[5];
	cmd[6] = payload[6];
	cmd[7] = payload[7];
	cmd[8] = payload[8];
	cmd[9] = payload[9];
	cmd[10] = payload[10];
	cmd[11] = payload[11];
	cmd[12] = payload[12];
	cmd[13] = payload[13];
	cmd[14] = payload[14];
	cmd[15] = payload[15];

	return XDP_PASS;
}

static __always_inline
u32 parse_ipv4(struct xdp_md *ctx, u64 l3_offset)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct iphdr *iph = data + l3_offset;
	u64 *value;
	u32 ip_src; /* type need to match map */

	if (iph + 1 > data_end) {
		bpf_debug("Invalid IPv4 packet: L3off:%llu\n", l3_offset);
		return XDP_ABORTED;
	}

	return parse_port(ctx, iph->protocol, iph + 1);
}

static __always_inline
u32 parse_ipv6(struct xdp_md *ctx, u64 l3_offset)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct ipv6hdr *iph = data + l3_offset;

	if (iph + 1 > data_end) {
		bpf_debug("Invalid IPv4 packet: L3off:%llu\n", l3_offset);
		return XDP_ABORTED;
	}

	return parse_port(ctx, iph->nexthdr, iph + 1);
}

static __always_inline
u32 handle_eth_protocol(struct xdp_md *ctx, u16 eth_proto, u64 l3_offset)
{
	switch (eth_proto) {
	case ETH_P_IP:
		return parse_ipv4(ctx, l3_offset);
		break;
	case ETH_P_IPV6:
		return parse_ipv6(ctx, l3_offset);
	case ETH_P_ARP:  /* Let OS handle ARP */
		/* Fall-through */
	default:
		bpf_debug("Not handling eth_proto:0x%x\n", eth_proto);
		return XDP_PASS;
	}
	return XDP_PASS;
}

SEC("xdp_prog")
int  xdp_program(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	u16 eth_proto = 0;
	u64 l3_offset = 0;
	u32 action;

	if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset))) {
		return XDP_PASS; /* Skip */
	}

	action = handle_eth_protocol(ctx, eth_proto, l3_offset);
	return action;
}

char _license[] SEC("license") = "GPL";
