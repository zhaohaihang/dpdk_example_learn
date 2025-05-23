/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_flow.h>
#include <rte_flow_classify.h>
#include <rte_table_acl.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define MAX_NUM_CLASSIFY 30
#define FLOW_CLASSIFY_MAX_RULE_NUM 91
#define FLOW_CLASSIFY_MAX_PRIORITY 8
#define FLOW_CLASSIFIER_NAME_SIZE 64

#define COMMENT_LEAD_CHAR	('#')
#define OPTION_RULE_IPV4	"rule_ipv4"
#define RTE_LOGTYPE_FLOW_CLASSIFY	RTE_LOGTYPE_USER3
#define flow_classify_log(format, ...) \
		RTE_LOG(ERR, FLOW_CLASSIFY, format, ##__VA_ARGS__)

#define uint32_t_to_char(ip, a, b, c, d) do {\
		*a = (unsigned char)(ip >> 24 & 0xff);\
		*b = (unsigned char)(ip >> 16 & 0xff);\
		*c = (unsigned char)(ip >> 8 & 0xff);\
		*d = (unsigned char)(ip & 0xff);\
	} while (0)

enum {
	CB_FLD_SRC_ADDR,
	CB_FLD_DST_ADDR,
	CB_FLD_SRC_PORT,
	CB_FLD_SRC_PORT_DLM,
	CB_FLD_SRC_PORT_MASK,
	CB_FLD_DST_PORT,
	CB_FLD_DST_PORT_DLM,
	CB_FLD_DST_PORT_MASK,
	CB_FLD_PROTO,
	CB_FLD_PRIORITY,
	CB_FLD_NUM,
};

static struct{
	const char *rule_ipv4_name;
} parm_config;
const char cb_port_delim[] = ":";

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	},
};

struct flow_classifier {
	struct rte_flow_classifier *cls;
};

struct flow_classifier_acl {
	struct flow_classifier cls;
} __rte_cache_aligned;

/* ACL field definitions for IPv4 5 tuple rule */

enum {
	PROTO_FIELD_IPV4,
	SRC_FIELD_IPV4,
	DST_FIELD_IPV4,
	SRCP_FIELD_IPV4,
	DSTP_FIELD_IPV4,
	NUM_FIELDS_IPV4
};

enum {
	PROTO_INPUT_IPV4,
	SRC_INPUT_IPV4,
	DST_INPUT_IPV4,
	SRCP_DESTP_INPUT_IPV4
};

static struct rte_acl_field_def ipv4_defs[NUM_FIELDS_IPV4] = {
	/* first input field - always one byte long. */
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint8_t),
		.field_index = PROTO_FIELD_IPV4,
		.input_index = PROTO_INPUT_IPV4,
		.offset = sizeof(struct rte_ether_hdr) +
			offsetof(struct rte_ipv4_hdr, next_proto_id),
	},
	/* next input field (IPv4 source address) - 4 consecutive bytes. */
	{
		/* rte_flow uses a bit mask for IPv4 addresses */
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint32_t),
		.field_index = SRC_FIELD_IPV4,
		.input_index = SRC_INPUT_IPV4,
		.offset = sizeof(struct rte_ether_hdr) +
			offsetof(struct rte_ipv4_hdr, src_addr),
	},
	/* next input field (IPv4 destination address) - 4 consecutive bytes. */
	{
		/* rte_flow uses a bit mask for IPv4 addresses */
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint32_t),
		.field_index = DST_FIELD_IPV4,
		.input_index = DST_INPUT_IPV4,
		.offset = sizeof(struct rte_ether_hdr) +
			offsetof(struct rte_ipv4_hdr, dst_addr),
	},
	/*
	 * Next 2 fields (src & dst ports) form 4 consecutive bytes.
	 * They share the same input index.
	 */
	{
		/* rte_flow uses a bit mask for protocol ports */
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint16_t),
		.field_index = SRCP_FIELD_IPV4,
		.input_index = SRCP_DESTP_INPUT_IPV4,
		.offset = sizeof(struct rte_ether_hdr) +
			sizeof(struct rte_ipv4_hdr) +
			offsetof(struct rte_tcp_hdr, src_port),
	},
	{
		/* rte_flow uses a bit mask for protocol ports */
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint16_t),
		.field_index = DSTP_FIELD_IPV4,
		.input_index = SRCP_DESTP_INPUT_IPV4,
		.offset = sizeof(struct rte_ether_hdr) +
			sizeof(struct rte_ipv4_hdr) +
			offsetof(struct rte_tcp_hdr, dst_port),
	},
};

/* flow classify data */
static int num_classify_rules;
static struct rte_flow_classify_rule *rules[MAX_NUM_CLASSIFY];
static struct rte_flow_classify_ipv4_5tuple_stats ntuple_stats;
static struct rte_flow_classify_stats classify_stats = {
		.stats = (void **)&ntuple_stats
};

/* parameters for rte_flow_classify_validate and
 * rte_flow_classify_table_entry_add functions
 */

static struct rte_flow_item  eth_item = { RTE_FLOW_ITEM_TYPE_ETH,
	0, 0, 0 };
static struct rte_flow_item  end_item = { RTE_FLOW_ITEM_TYPE_END,
	0, 0, 0 };

/* sample actions:
 * "actions count / end"
 */
struct rte_flow_query_count count = {
	.reset = 1,
	.hits_set = 1,
	.bytes_set = 1,
	.hits = 0,
	.bytes = 0,
};
// 启用流量计数器
static struct rte_flow_action count_action = { RTE_FLOW_ACTION_TYPE_COUNT,
	&count};
static struct rte_flow_action end_action = { RTE_FLOW_ACTION_TYPE_END, 0};
// rte_flow_action 结构体数组(terminated by the END pattern item)，表示流规则的动作，比如QUEUE, DROP, END等等
// 这里的action有两个动作，分别是计数和结束
static struct rte_flow_action actions[2];

/* sample attributes */
static struct rte_flow_attr attr;// 代表的一条流规则属性

/* flow_classify.c: * Based on DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	struct rte_ether_addr addr;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	rte_eth_dev_info_get(port, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port classifying the packets and writing to an output port.
 */
static __attribute__((noreturn)) void
lcore_main(struct flow_classifier *cls_app)
{
	uint16_t port;
	int ret;
	int i = 0;

	ret = rte_flow_classify_table_entry_delete(cls_app->cls,
			rules[7]);
	if (ret)
		printf("table_entry_delete failed [7] %d\n\n", ret);
	else
		printf("table_entry_delete succeeded [7]\n\n");

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) > 0 &&
			rte_eth_dev_socket_id(port) != (int)rte_socket_id()) {
			printf("\n\n");
			printf("WARNING: port %u is on remote NUMA node\n",
			       port);
			printf("to polling thread.\n");
			printf("Performance will not be optimal.\n");
		}
	printf("\nCore %u forwarding packets. ", rte_lcore_id());
	printf("[Ctrl+C to quit]\n");

	/* Run until the application is quit or killed. */
	for (;;) {
		/*
		 * Receive packets on a port, classify them and forward them
		 * on the paired port.
		 * The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
		RTE_ETH_FOREACH_DEV(port) {
			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			for (i = 0; i < MAX_NUM_CLASSIFY; i++) {
				if (rules[i]) {
					ret = rte_flow_classifier_query(
						cls_app->cls,
						bufs, nb_rx, rules[i],
						&classify_stats);
					if (ret)
					;
						// printf(
							// "rule [%d] query failed ret [%d]\n\n",
							// i, ret);
					else {
						printf(
						"rule[%d] count=%"PRIu64"\n",
						i, ntuple_stats.counter1);

						printf("proto = %d\n",
						ntuple_stats.ipv4_5tuple.proto);
					}
				}
			}

			// /* Send burst of TX packets, to second port of pair. */
			// const uint16_t nb_tx = rte_eth_tx_burst(port ^ 1, 0,
			// 		bufs, nb_rx);
			// printf("port %d,nb_rx = %d\n\n",port, nb_rx);
			// /* Free any unsent packets. */
			// if (unlikely(nb_tx < nb_rx)) {
			// 	uint16_t buf;

			// 	for (buf = nb_tx; buf < nb_rx; buf++)
			// 		rte_pktmbuf_free(bufs[buf]);
			// }
			uint16_t buf;
			for (buf = 0; buf < nb_rx; buf++)
				rte_pktmbuf_free(bufs[buf]);
			
		}
	}
}

/*
 * Parse IPv4 5 tuple rules file, ipv4_rules_file.txt.
 * Expected format:
 * <src_ipv4_addr>'/'<masklen> <space> \
 * <dst_ipv4_addr>'/'<masklen> <space> \
 * <src_port> <space> ":" <src_port_mask> <space> \
 * <dst_port> <space> ":" <dst_port_mask> <space> \
 * <proto>'/'<proto_mask> <space> \
 * <priority>
 */

static int
get_cb_field(char **in, uint32_t *fd, int base, unsigned long lim,
		char dlm)
{
	unsigned long val;
	char *end;

	errno = 0;
	val = strtoul(*in, &end, base);
	if (errno != 0 || end[0] != dlm || val > lim)
		return -EINVAL;
	*fd = (uint32_t)val;
	*in = end + 1;
	return 0;
}

static int
parse_ipv4_net(char *in, uint32_t *addr, uint32_t *mask_len)  // 解析 ip mask
{
	uint32_t a, b, c, d, m;

	if (get_cb_field(&in, &a, 0, UINT8_MAX, '.'))
		return -EINVAL;
	if (get_cb_field(&in, &b, 0, UINT8_MAX, '.'))
		return -EINVAL;
	if (get_cb_field(&in, &c, 0, UINT8_MAX, '.'))
		return -EINVAL;
	if (get_cb_field(&in, &d, 0, UINT8_MAX, '/'))
		return -EINVAL;
	if (get_cb_field(&in, &m, 0, sizeof(uint32_t) * CHAR_BIT, 0))
		return -EINVAL;

	addr[0] = RTE_IPV4(a, b, c, d);
	mask_len[0] = m;
	return 0;
}

static int
parse_ipv4_5tuple_rule(char *str, struct rte_eth_ntuple_filter *ntuple_filter)  // 解析文本的规则
{
	int i, ret;
	char *s, *sp, *in[CB_FLD_NUM];
	static const char *dlm = " \t\n";
	int dim = CB_FLD_NUM;
	uint32_t temp;

	s = str;
	for (i = 0; i != dim; i++, s = NULL) {
		in[i] = strtok_r(s, dlm, &sp);
		if (in[i] == NULL)
			return -EINVAL;
	}

	ret = parse_ipv4_net(in[CB_FLD_SRC_ADDR],
			&ntuple_filter->src_ip,
			&ntuple_filter->src_ip_mask);
	if (ret != 0) {
		flow_classify_log("failed to read source address/mask: %s\n",
			in[CB_FLD_SRC_ADDR]);
		return ret;
	}

	ret = parse_ipv4_net(in[CB_FLD_DST_ADDR],
			&ntuple_filter->dst_ip,
			&ntuple_filter->dst_ip_mask);
	if (ret != 0) {
		flow_classify_log("failed to read source address/mask: %s\n",
			in[CB_FLD_DST_ADDR]);
		return ret;
	}

	if (get_cb_field(&in[CB_FLD_SRC_PORT], &temp, 0, UINT16_MAX, 0))
		return -EINVAL;
	ntuple_filter->src_port = (uint16_t)temp;

	if (strncmp(in[CB_FLD_SRC_PORT_DLM], cb_port_delim,
			sizeof(cb_port_delim)) != 0)
		return -EINVAL;

	if (get_cb_field(&in[CB_FLD_SRC_PORT_MASK], &temp, 0, UINT16_MAX, 0))
		return -EINVAL;
	ntuple_filter->src_port_mask = (uint16_t)temp;

	if (get_cb_field(&in[CB_FLD_DST_PORT], &temp, 0, UINT16_MAX, 0))
		return -EINVAL;
	ntuple_filter->dst_port = (uint16_t)temp;

	if (strncmp(in[CB_FLD_DST_PORT_DLM], cb_port_delim,
			sizeof(cb_port_delim)) != 0)
		return -EINVAL;

	if (get_cb_field(&in[CB_FLD_DST_PORT_MASK], &temp, 0, UINT16_MAX, 0))
		return -EINVAL;
	ntuple_filter->dst_port_mask = (uint16_t)temp;

	if (get_cb_field(&in[CB_FLD_PROTO], &temp, 0, UINT8_MAX, '/'))
		return -EINVAL;
	ntuple_filter->proto = (uint8_t)temp;

	if (get_cb_field(&in[CB_FLD_PROTO], &temp, 0, UINT8_MAX, 0))
		return -EINVAL;
	ntuple_filter->proto_mask = (uint8_t)temp;

	if (get_cb_field(&in[CB_FLD_PRIORITY], &temp, 0, UINT16_MAX, 0))
		return -EINVAL;
	ntuple_filter->priority = (uint16_t)temp;
	if (ntuple_filter->priority > FLOW_CLASSIFY_MAX_PRIORITY)
		ret = -EINVAL;

	return ret;
}

/* Bypass comment and empty lines */
static inline int
is_bypass_line(char *buff)
{
	int i = 0;

	/* comment line */
	if (buff[0] == COMMENT_LEAD_CHAR)
		return 1;
	/* empty line */
	while (buff[i] != '\0') {
		if (!isspace(buff[i]))
			return 0;
		i++;
	}
	return 1;
}

static uint32_t
convert_depth_to_bitmask(uint32_t depth_val)
{
	uint32_t bitmask = 0;
	int i, j;

	for (i = depth_val, j = 0; i > 0; i--, j++)
		bitmask |= (1 << (31 - j));
	return bitmask;
}

static int
add_classify_rule(struct rte_eth_ntuple_filter *ntuple_filter,
		struct flow_classifier *cls_app)
{
	int ret = -1;
	int key_found;
	/* rte_flow_item： ACL 规则的详细内容。
    会从最低协议层开始堆叠flow_item来形成一个匹配模式。必须由 end_item 结尾。
    */
	struct rte_flow_error error;
	struct rte_flow_item_ipv4 ipv4_spec;
	struct rte_flow_item_ipv4 ipv4_mask;
	struct rte_flow_item ipv4_udp_item;
	struct rte_flow_item ipv4_tcp_item;
	struct rte_flow_item ipv4_sctp_item;
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	struct rte_flow_item udp_item;
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	struct rte_flow_item tcp_item;
	struct rte_flow_item_sctp sctp_spec;
	struct rte_flow_item_sctp sctp_mask;
	struct rte_flow_item sctp_item;
	struct rte_flow_item pattern_ipv4_5tuple[4];
	struct rte_flow_classify_rule *rule;
	uint8_t ipv4_proto;

	if (num_classify_rules >= MAX_NUM_CLASSIFY) {
		printf(
			"\nINFO:  classify rule capacity %d reached\n",
			num_classify_rules);
		return ret;
	}

	/* set up parameters for validate and add */
	// 填充ip头部协议字段(上层协议)
	memset(&ipv4_spec, 0, sizeof(ipv4_spec));
	ipv4_spec.hdr.next_proto_id = ntuple_filter->proto;
	ipv4_spec.hdr.src_addr = ntuple_filter->src_ip;
	ipv4_spec.hdr.dst_addr = ntuple_filter->dst_ip;
	ipv4_proto = ipv4_spec.hdr.next_proto_id;

	memset(&ipv4_mask, 0, sizeof(ipv4_mask));
	ipv4_mask.hdr.next_proto_id = ntuple_filter->proto_mask;
	ipv4_mask.hdr.src_addr = ntuple_filter->src_ip_mask;
	ipv4_mask.hdr.src_addr =
		convert_depth_to_bitmask(ipv4_mask.hdr.src_addr); //转化为掩码
	ipv4_mask.hdr.dst_addr = ntuple_filter->dst_ip_mask;
	ipv4_mask.hdr.dst_addr =
		convert_depth_to_bitmask(ipv4_mask.hdr.dst_addr);

	switch (ipv4_proto) {
	case IPPROTO_UDP:	// 如果是UDP
		// 匹配IPV4
		ipv4_udp_item.type = RTE_FLOW_ITEM_TYPE_IPV4;
		ipv4_udp_item.spec = &ipv4_spec;
		ipv4_udp_item.mask = &ipv4_mask;
		ipv4_udp_item.last = NULL;

		// 填充UDP头部
		udp_spec.hdr.src_port = ntuple_filter->src_port;
		udp_spec.hdr.dst_port = ntuple_filter->dst_port;
		udp_spec.hdr.dgram_len = 0;
		udp_spec.hdr.dgram_cksum = 0;

		// 填充udp的掩码
		udp_mask.hdr.src_port = ntuple_filter->src_port_mask;
		udp_mask.hdr.dst_port = ntuple_filter->dst_port_mask;
		udp_mask.hdr.dgram_len = 0;
		udp_mask.hdr.dgram_cksum = 0;

		// 匹配UDP
		udp_item.type = RTE_FLOW_ITEM_TYPE_UDP;
		udp_item.spec = &udp_spec;
		udp_item.mask = &udp_mask;
		udp_item.last = NULL;

		attr.priority = ntuple_filter->priority; // 设置组内规则优先级属性
		pattern_ipv4_5tuple[1] = ipv4_udp_item; // 将每个规则添加到规则数组中
		pattern_ipv4_5tuple[2] = udp_item;
		break;
	case IPPROTO_TCP:
		ipv4_tcp_item.type = RTE_FLOW_ITEM_TYPE_IPV4;
		ipv4_tcp_item.spec = &ipv4_spec;
		ipv4_tcp_item.mask = &ipv4_mask;
		ipv4_tcp_item.last = NULL;

		memset(&tcp_spec, 0, sizeof(tcp_spec));
		tcp_spec.hdr.src_port = ntuple_filter->src_port;
		tcp_spec.hdr.dst_port = ntuple_filter->dst_port;

		memset(&tcp_mask, 0, sizeof(tcp_mask));
		tcp_mask.hdr.src_port = ntuple_filter->src_port_mask;
		tcp_mask.hdr.dst_port = ntuple_filter->dst_port_mask;

		tcp_item.type = RTE_FLOW_ITEM_TYPE_TCP;
		tcp_item.spec = &tcp_spec;
		tcp_item.mask = &tcp_mask;
		tcp_item.last = NULL;

		attr.priority = ntuple_filter->priority;
		pattern_ipv4_5tuple[1] = ipv4_tcp_item;
		pattern_ipv4_5tuple[2] = tcp_item;
		break;
	case IPPROTO_SCTP:
		ipv4_sctp_item.type = RTE_FLOW_ITEM_TYPE_IPV4;
		ipv4_sctp_item.spec = &ipv4_spec;
		ipv4_sctp_item.mask = &ipv4_mask;
		ipv4_sctp_item.last = NULL;

		sctp_spec.hdr.src_port = ntuple_filter->src_port;
		sctp_spec.hdr.dst_port = ntuple_filter->dst_port;
		sctp_spec.hdr.cksum = 0;
		sctp_spec.hdr.tag = 0;

		sctp_mask.hdr.src_port = ntuple_filter->src_port_mask;
		sctp_mask.hdr.dst_port = ntuple_filter->dst_port_mask;
		sctp_mask.hdr.cksum = 0;
		sctp_mask.hdr.tag = 0;

		sctp_item.type = RTE_FLOW_ITEM_TYPE_SCTP;
		sctp_item.spec = &sctp_spec;
		sctp_item.mask = &sctp_mask;
		sctp_item.last = NULL;

		attr.priority = ntuple_filter->priority;
		pattern_ipv4_5tuple[1] = ipv4_sctp_item;
		pattern_ipv4_5tuple[2] = sctp_item;
		break;
	default:
		return ret;
	}

	attr.ingress = 1; // 规则适用于入口流量
	pattern_ipv4_5tuple[0] = eth_item; // 匹配二层数据报文
	pattern_ipv4_5tuple[3] = end_item; // 结束匹配
	actions[0] = count_action; // 指定action
	actions[1] = end_action;

	/* Validate and add rule */
	/*
		流分类验证
		cls_app->cls: 流分类器实例
		attr： 流规则属性
		pattern_ipv4_5tuple: 模式指定（列表由END模式项终止）
		actions： 关联动作（列表由END模式项终止）
		error： 如果不为NULL，则执行详细的错误报告。仅在发生错误的情况下初始化结构
	*/
	ret = rte_flow_classify_validate(cls_app->cls, &attr,
			pattern_ipv4_5tuple, actions, &error);
	if (ret) {
		printf("table entry validate failed ipv4_proto = %u\n",
			ipv4_proto);
		return ret;
	}

	/*
		将流分类规则添加到flow_classifier表中
		cls_app->cls: 流分类器实例
		attr： 流规则属性
		pattern_ipv4_5tuple: 模式指定（列表由END模式项终止）
		actions： 关联动作（列表由END模式项终止）
		key_found: 如果规则已经存在，则返回1，否则返回0
		error： 如果不为NULL，则执行详细的错误报告。仅在发生错误的情况下初始化结构

		成功时返回有效句柄rule
	*/
	rule = rte_flow_classify_table_entry_add(
			cls_app->cls, &attr, pattern_ipv4_5tuple,
			actions, &key_found, &error);
	if (rule == NULL) {
		printf("table entry add failed ipv4_proto = %u\n",
			ipv4_proto);
		ret = -1;
		return ret;
	}

	// 将句柄存放在rules数组中
	rules[num_classify_rules] = rule;
	num_classify_rules++;
	return 0;
}

static int
add_rules(const char *rule_path, struct flow_classifier *cls_app)
{
	FILE *fh;
	char buff[LINE_MAX];
	unsigned int i = 0;
	unsigned int total_num = 0;
	struct rte_eth_ntuple_filter ntuple_filter;
	int ret;

	fh = fopen(rule_path, "rb");
	if (fh == NULL)
		rte_exit(EXIT_FAILURE, "%s: fopen %s failed\n", __func__,
			rule_path);

	ret = fseek(fh, 0, SEEK_SET);
	if (ret)
		rte_exit(EXIT_FAILURE, "%s: fseek %d failed\n", __func__,
			ret);

	i = 0;
	while (fgets(buff, LINE_MAX, fh) != NULL) {
		i++;

		if (is_bypass_line(buff))  // 跳过空行，或者#开头的行
			continue;

		if (total_num >= FLOW_CLASSIFY_MAX_RULE_NUM - 1) {
			printf("\nINFO: classify rule capacity %d reached\n",
				total_num);
			break;
		}

		if (parse_ipv4_5tuple_rule(buff, &ntuple_filter) != 0)  // 解析文本中的规则
			rte_exit(EXIT_FAILURE,
				"%s Line %u: parse rules error\n",
				rule_path, i);

		if (add_classify_rule(&ntuple_filter, cls_app) != 0)  // 添加规则
			rte_exit(EXIT_FAILURE, "add rule error\n");

		total_num++;
	}

	fclose(fh);
	return 0;
}

/* display usage */
static void
print_usage(const char *prgname)
{
	printf("%s usage:\n", prgname);
	printf("[EAL options] --  --"OPTION_RULE_IPV4"=FILE: ");
	printf("specify the ipv4 rules file.\n");
	printf("Each rule occupies one line in the file.\n");
}

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{OPTION_RULE_IPV4, 1, 0, 0},
		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "",
				lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* long options */
		case 0:
			if (!strncmp(lgopts[option_index].name,
					OPTION_RULE_IPV4,
					sizeof(OPTION_RULE_IPV4)))
				parm_config.rule_ipv4_name = optarg;  // 解析txt文件的名字
			break;
		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

/*
 * The main function, which does initialization and calls the lcore_main
 * function.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	uint16_t nb_ports;
	uint16_t portid;
	int ret;
	int socket_id;
	struct rte_table_acl_params table_acl_params; // ACL(访问控制列表)参数
	struct rte_flow_classify_table_params cls_table_params; // 创建ACL table表参数
	struct flow_classifier *cls_app; 
	struct rte_flow_classifier_params cls_params; // 流分类器创建参数
	uint32_t size;

	/* Initialize the Environment Abstraction Layer (EAL). */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid flow_classify parameters\n");

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	socket_id = rte_eth_dev_socket_id(0);

	// 分为4大步骤
	//1.分配内存
	//2.创建分类器
	//3.创建ACL表
	//4.添加规则

	/* Memory allocation */
	// 分配一块内存，用来存放flow_classifier结构体，用来存放ACL表和分类器
	size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct flow_classifier_acl));
	cls_app = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);  // // 分配一个struct flow_classifier_acl大小的缓存
	if (cls_app == NULL)
		rte_exit(EXIT_FAILURE, "Cannot allocate classifier memory\n");

	cls_params.name = "flow_classifier"; // 流分类器参数初始化
	cls_params.socket_id = socket_id;

	cls_app->cls = rte_flow_classifier_create(&cls_params); // 根据流分类器参数创建流分类器
	if (cls_app->cls == NULL) {
		rte_free(cls_app);
		rte_exit(EXIT_FAILURE, "Cannot create classifier\n");
	}

	/* initialise ACL table params */
	table_acl_params.name = "table_acl_ipv4_5tuple";  //设置表的ACL的name字段
	table_acl_params.n_rules = FLOW_CLASSIFY_MAX_RULE_NUM; // 表的ACL表中的最大规则数，这里的91条
	table_acl_params.n_rule_fields = RTE_DIM(ipv4_defs); // 表的ACL表中的字段数
	memcpy(table_acl_params.field_format, ipv4_defs, sizeof(ipv4_defs));

	/* initialise table create params */
	cls_table_params.ops = &rte_table_acl_ops;  // 设置流分类表的参数
	cls_table_params.arg_create = &table_acl_params;
	cls_table_params.type = RTE_FLOW_CLASSIFY_TABLE_ACL_IP4_5TUPLE;

	ret = rte_flow_classify_table_create(cls_app->cls, &cls_table_params); //创建流分类表
	if (ret) {
		rte_flow_classifier_free(cls_app->cls);
		rte_free(cls_app);
		rte_exit(EXIT_FAILURE, "Failed to create classifier table\n");
	}

	/* read file of IPv4 5 tuple rules and initialize parameters
	 * for rte_flow_classify_validate and rte_flow_classify_table_entry_add
	 * API's.
	 */
	if (add_rules(parm_config.rule_ipv4_name, cls_app)) {  // 添加规则
		rte_flow_classifier_free(cls_app->cls);
		rte_free(cls_app);
		rte_exit(EXIT_FAILURE, "Failed to add rules\n");
	}

	/* Call lcore_main on the master core only. */
	lcore_main(cls_app);

	return 0;
}
