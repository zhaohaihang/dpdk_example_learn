#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ENABLE_SEND		1
#define ENABLE_ARP		1
#define NUM_MBUFS (4096-1)
#define BURST_SIZE	32

#if ENABLE_SEND
static uint32_t gSrcIp; //
static uint32_t gDstIp;

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];

static uint16_t gSrcPort;
static uint16_t gDstPort;
#endif

int gDpdkPortId = 0;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

static void ng_init_port(struct rte_mempool *mbuf_pool) {
	uint16_t nb_sys_ports = rte_eth_dev_count_avail(); //
	if (nb_sys_ports == 0) {
		rte_exit(EXIT_FAILURE, "No Supported eth found\n");
	}

	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(gDpdkPortId, &dev_info); //

	const int num_rx_queues = 1;
	const int num_tx_queues = 1;  // 设置tx队列
	struct rte_eth_conf port_conf = port_conf_default;
	rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);  // 配置网口的整体

	if (rte_eth_rx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool) < 0) {  // 配置网口的RX
		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
	}

	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.rxmode.offloads; // 负载，是指一次性能发送多少  
	if (rte_eth_tx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0) {  // 配置网口的TX
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
	}

	if (rte_eth_dev_start(gDpdkPortId) < 0) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}
}

static int ng_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len) {  // 
	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN); // 设置srcmac
	rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN); // 设置dstmac
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	// 2 iphdr 
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_UDP;
	ip->src_addr = gSrcIp;
	ip->dst_addr = gDstIp;
	ip->hdr_checksum = 0; // 一定先置为0，否则影响sum的计算
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 udphdr 
	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	udp->src_port = gSrcPort;
	udp->dst_port = gDstPort;
	uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	udp->dgram_len = htons(udplen);
	rte_memcpy((uint8_t *)(udp + 1), data, udplen); // 将要发送的内容，拷贝至udp头部后面的位置
	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp); // 计算校验和

	struct in_addr addr;
	addr.s_addr = gSrcIp;
	printf("send package src: %s:%d, ", inet_ntoa(addr), ntohs(gSrcPort));

	addr.s_addr = gDstIp;
	printf("send package dst: %s:%d\n", inet_ntoa(addr), ntohs(gDstPort));

	return 0;
}

static struct rte_mbuf *ng_send(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length) {
	const unsigned total_len = length + 42; // 总长度=数据长度+以太网头部+ip头部+udp头部

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool); // 从mbuf pool中，取出一段内存，作为mbuf
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len; // 设置mbuf的字段，包的总长度，两者可以设置相同的，这里不是属于数据包的一部分，仅仅是mbuf的一部分
	mbuf->data_len = total_len; // 设置mbuf的数据长度

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t *); // 获取mbuf结构体里面.用于存放数据的内存的起始位置

	ng_encode_udp_pkt(pktdata, data, total_len); // 构建数据包

	return mbuf;
}


int main(int argc, char *argv[]) {
	if (rte_eal_init(argc, argv) < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL init\n");
	}

	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
		0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
	}

	ng_init_port(mbuf_pool); // 初始化网口

	rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac); // 根据网口的ID，获取绑定的dpdk网口的MAC地址，作为源MAC

	while (1) {
		struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE); // 从某一个网口的某一个队列接收多个数据包，放入mbufs
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}
		if (num_recvd != 0) {
			printf("receving %d packages\n", num_recvd);
		}

		unsigned i = 0;
		for (i = 0;i < num_recvd;i++) { // 循环处理每一个数据包
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);  // 解析以太网头部,rte_pktmbuf_mtod用于获得mbuf中数据帧的起始地址
			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) { // 判断ipV4
				continue;
			}
			rte_memcpy(gDstMac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN); // 接收的包中的源mac，作为发送包中的目的mac

			struct rte_ipv4_hdr *iphdr = (struct rte_ipv4_hdr *)(ehdr + 1); 
			// struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr)); // 解析IP头部
			if (iphdr->next_proto_id != IPPROTO_UDP) { // 判断UDP
				continue;
			}
			rte_memcpy(&gSrcIp, &iphdr->dst_addr, sizeof(uint32_t)); // 接收的包中的源ip，作为发送包中的目的ip                  
			rte_memcpy(&gDstIp, &iphdr->src_addr, sizeof(uint32_t));

			struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1); // 解析UDP头部
			// struct rte_udp_hdr *udphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_udp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
			rte_memcpy(&gSrcPort, &udphdr->dst_port, sizeof(uint16_t));// 接收的包中的源port，作为发送包中的目的port
			rte_memcpy(&gDstPort, &udphdr->src_port, sizeof(uint16_t));

			uint16_t length = ntohs(udphdr->dgram_len);
			*((char *)udphdr + length) = '\0';

			struct in_addr addr;
			addr.s_addr = iphdr->src_addr;
			printf("received package src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));

			addr.s_addr = iphdr->dst_addr;
			printf("received package dst: %s:%d, %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port), (char *)(udphdr + 1));

			struct rte_mbuf *txbuf = ng_send(mbuf_pool, (uint8_t *)(udphdr + 1), length); // 构建返回的报文，放在txbuf
			rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1); // 发送
			rte_pktmbuf_free(txbuf);

			rte_pktmbuf_free(mbufs[i]);
		}
	}
}