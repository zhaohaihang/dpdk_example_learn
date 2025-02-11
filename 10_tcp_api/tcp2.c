#include <stdio.h>
#include <stdlib.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_timer.h>

#define NUM_MBUFS (4096-1)


int gDpDkPortId = 0;


static void ng_init_port(struct rte_mempool *mbuf_pool) {
	uint16_t nb_sys_ports = rte_eth_dev_count_avail();
	if (nb_sys_ports == 0) {
		rte_exit(EXIT_FAILURE,"No Supported eth found\n");
	}

	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(gDpDkPortId,&dev_info);

	const int num_rx_queues = 1;
	const int num_tx_queues = 1;

	static const struct rte_eth_conf port_conf_default = {
		.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
	};
	
	// struct rte_eth_conf port_conf = port_conf_default;
	rte_eth_dev_configure(gDpDkPortId,num_rx_queues,num_tx_queues,&port_conf_default);

	if (rte_eth_rx_queue_setup(gDpDkPortId,0,1024,ret_eht_dev_socket_id(gDpDkPortId),NULL,mbuf_pool) < 0) {
		rte_exit(EXIT_FAILURE,"Could not setup RX queue\n");
	}



}

int main(int argc ,char *argv[]){
	if (rte_eal_init(argc,argv) < 0 ) {
		rte_exit(EXIT_FAILURE,"Error with EAL init\n");
	}

	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool",NUM_MBUFS,
		0,0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE,"Could not create mbuf pool\n");
	}

	ng_init_port(mbuf_pool);
}
