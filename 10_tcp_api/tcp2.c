#include <stdio.h>
#include <stdlib.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_timer.h>

#define NUM_MBUFS (4096-1)
#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 3, 100);
static uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static int gDpDkPortId = 0;

// static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static struct rte_ether_addr gSrcMac;

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

static struct ret_mbuf *ng_send_arp(struct ret_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr)
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
	rte_eth_macaddr_get(gDpDkPortId, &gSrcMac);

	rte_timer_subsystem_init();
	struct rte_timer arp_timer;
	rte_timer_init(&arp_timer);
	uint64_t hz = rte_get_timer_hz();
	unsigned lcore_id = rte_lcore_id();
	rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mbuf_pool);


}
