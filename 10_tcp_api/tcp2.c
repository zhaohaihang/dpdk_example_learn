#include <stdio.h>
#include <stdlib.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_timer.h>
#include "arp.h"

#define NUM_MBUFS (4096-1)
#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
#define RING_SIZE	1024
#define BURST_SIZE	32
#define TIMER_RESOLUTION_CYCLES 120000000000ULL // 10ms * 1000 = 10s * 6 

static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 3, 100);
static uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static int gDpDkPortId = 0;

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
// static struct rte_ether_addr gSrcMac;

struct inout_ring {
	struct rte_ring *in;
	struct rte_ring *out;
};
static struct inout_ring *rInst = NULL;
static struct inout_ring *ringInstance() {
	if (rInst == NULL) {
		rInst = rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
		memset(rInst, 0, sizeof(struct inout_ring));
	}
	return rInst;
}


static void ng_init_port(struct rte_mempool *mbuf_pool) {
	uint16_t nb_sys_ports = rte_eth_dev_count_avail();
	if (nb_sys_ports == 0) {
		rte_exit(EXIT_FAILURE, "No Supported eth found\n");
	}

	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(gDpDkPortId, &dev_info);

	const int num_rx_queues = 1;
	const int num_tx_queues = 1;

	static const struct rte_eth_conf port_conf_default = {
		.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
	};

	// struct rte_eth_conf port_conf = port_conf_default;
	rte_eth_dev_configure(gDpDkPortId, num_rx_queues, num_tx_queues, &port_conf_default);

	if (rte_eth_rx_queue_setup(gDpDkPortId, 0, 1024, ret_eht_dev_socket_id(gDpDkPortId), NULL, mbuf_pool) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
	}

	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf_default.rxmode.offloads;
	if (rte_eth_tx_queue_setup(gDpDkPortId, 0, 1024, rte_eth_dev_socket_id(gDpDkPortId), &txq_conf) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
	}

	if (rte_eth_dev_start(gDpDkPortId) < 0) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}
}

static int ng_encode_arp_pkt(uint8_t *msg, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	if (!strncmp((const char *)dst_mac, (const char *)gDefaultArpMac, RTE_ETHER_ADDR_LEN)) { // 如果目的mac是全f，说明目的mac是未知的，所以在以太网层的目的mac是全0
		uint8_t mac[RTE_ETHER_ADDR_LEN] = { 0x0 };
		rte_memcpy(eth->d_addr.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
	}
	else {
		rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	}
	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

	// 2 arp
	struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
	arp->arp_hardware = htons(1);
	arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp->arp_hlen = RTE_ETHER_ADDR_LEN;
	arp->arp_plen = sizeof(uint32_t);
	arp->arp_opcode = htons(opcode);
	rte_memcpy(arp->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	arp->arp_data.arp_sip = sip;
	rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	arp->arp_data.arp_tip = dip;
	return 0;
}

static struct ret_mbuf *ng_send_arp(struct ret_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "ng_send_arp rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;
	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	ng_encode_arp_pkt(pkt_data, opcode, dst_mac, sip, dip);
	return mbuf;
}

static void arp_request_timer_cb(struct rte_timer *tim, void *arg) {
	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	struct  inout_ring *ring = ringInstance();
	int i = 0;
	for (i = 1;i < 255;i++) {
		uint32_t dstip = (gLocalIp & 0x00FFFFFF) | (0xFF000000 & (i << 24));
		uint8_t *dstmac = ng_get_dst_macaddr(dstip);

		struct rte_mbuf *arpbuf = NULL;
		if (dstmac == NULL) {
			arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, gLocalIp, dstip);
		}
		else {
			arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, dstmac, gLocalIp, dstip);
		}
		rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);
	}
}


static uint16_t ng_checksum(uint16_t *addr, int count) {
	register long sum = 0;
	while (count > 1) {
		sum += *(unsigned short *)addr++;
		count -= 2;
	}
	if (count > 0) {
		sum += *(unsigned char *)addr;
	}
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return ~sum;
}

static int ng_encode_icmp_pkt(uint8 *msg, uint8_t *dst_mac, uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {
	struct rte_ether_mbuf *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->totla_legnth = htons(sizeof(struct ret_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64;
	ip->next_proto_id = IPPROTO_ICMP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(ip + 1);
	icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
	icmp->icmp_code = 0;
	icmp->icmp_ident = id;
	icmp->icmp_seq_nb = seqnb;
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = ng_checksum((uint16_t *)icmp, sizeof(struct rte_icmp_hdr));
}

static struct rte_mbuf *ng_send_icmp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac, uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {
	const unsigned total_length = sizewof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "ng_send_icmp rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;
	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	ng_encode_icmp_pkt(pkt_data, dst_mac, sip, dip, id, seqnb);
	return mbuf;
}


static int pkt_process(void *arg) {
	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	struct inout_ring *ring = ringInstance();
	while (1) {
		struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recvd = rte_ring_mc_dequeue_burst(ring->in, (void **)mbufs, BURST_SIZE, NULL);
		unsigned i = 0;
		for (i = 0;i < num_recvd;i++) {
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
			if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
				struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
				if (ahdr->arp_data.arp_tip == gLocalIp) {
					if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
						struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REPLY, ahdr->arp_data.arp_sha.addr_bytes, ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);
						rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);
						// TODO 
						rte_pktmbuf_free(mbufs[i]);
					}
					else if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
						struct arp_table *table = arp_tables_instance();
						uint8_t *hwaddr = ng_get_dst_macaddr(ahdr->arp_data.arp_sip); // 通过arp源ip，查询对应的mac
						if (hwaddr == NULL) {
							struct arp_entry *entry = rte_malloc("arp_entry", sizeof(struct arp_entry), 0);
							if (entry) {  // 如果没有找到对应的mac，则创建一个新的arp_entry存入arp表
								memset(entry, 0, sizeof(struct arp_entry));
								entry->ip = ahdr->arp_data.arp_sip;
								rte_memcpy(entry->hwaddr, ahdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
								entry->type = 0;
								LL_ADD(entry, table->entries);
								table->count++;
							}
						}
						rte_pktmbuf_free(mbufs[i]);
					}
				}
			}
			else if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
				// icmp
				if (iphdr->next_proto_id == IPPROTO_ICMP) {
					struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);
					if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
						struct rte_mbuf *icmpbuf = ng_send_icmp(mbuf_pool, ehdr->s_addr.addr_bytes, iphdr->dst_addr, iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);
						rte_ring_mp_enqueue_burst(ring->out, (void **)&icmpbuf, 1, NULL);
						rte_pktmbuf_free(mbufs[i]);
					}
				}
				else if (iphdr->next_proto_id == IPPROTO_UDP) {
					ng_udp_process(mbufs[i]); // udp
				}
				else if (iphdr->next_proto_id == IPPROTO_TCP) {
					ng_tcp_process(mbufs[i]); // tcp
				}
			}
		}
		ng_udp_out(mbuf_pool);
		ng_tcp_out(mbuf_pool);
	}
	return 0;
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

	ng_init_port(mbuf_pool);
	rte_eth_macaddr_get(gDpDkPortId, (struct rte_ether_hdr *)gSrcMac);

	rte_timer_subsystem_init();
	struct rte_timer arp_timer;
	rte_timer_init(&arp_timer);
	uint64_t hz = rte_get_timer_hz();
	unsigned lcore_id = rte_lcore_id();
	rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mbuf_pool);

	struct inout_ring *ring = ringInstance();
	if (ring == NULL) {
		rte_exit(EXIT_FAILURE, "ring buffer init failed\n");
	}
	if (ring->in == NULL) {
		ring->in = rte_ring_create("in ring", RING_SIZE, rete_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}
	if (ring->out == NULL) {
		ring->out = rte_ring_create("out ring", RING_SIZE, rete_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}

	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(pkt_process, mbuf_pool, lcore_id);

	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(udp_server_entry, mbuf_pool, lcore_id);

	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(tcp_server_entry, mbuf_pool, lcore_id);

	while (1) {
		// rx
		struct rte_mbuf *rx_pkts[BURST_SIZE];
		unsigned num_recvd = rte_eth_rx_burst(gDpDkPortId, 0, rx_pkts, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {  // 接收的包数量，不能比BURST_SIZE大
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}
		else if (num_recvd > 0) {
			rte_ring_sp_enqueue_burst(ring->in, (void **)rx_pkts, num_recvd, NULL);
		}

		// tx
		struct rte_mbuf *tx[BURST_SIZE];
		unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void **)tx, BURST_SIZE, NULL);
		if (nb_tx > 0) {
			rte_eth_tx_burst(gDpDkPortId, 0, tx, nb_tx);
			unsigned i = 0;
			for (i = 0;i < nb_tx;i++) {
				rte_pktmbuf_free(tx[i]);
			}
		}

		static uint64_t prev_tsc = 0, cur_tsc;
		prev_tsc = 0;
		cur_tsc = rte_rdtsc();
		uint64_t diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
	}
}
