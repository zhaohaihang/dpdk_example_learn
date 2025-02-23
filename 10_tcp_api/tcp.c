#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_timer.h>

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "arp.h"

#define NUM_MBUFS (4096-1)
#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
#define RING_SIZE	1024
#define BURST_SIZE	32
#define TIMER_RESOLUTION_CYCLES 120000000000ULL // 10ms * 1000 = 10s * 6 
#define UDP_APP_RECV_BUFFER_SIZE	128

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
static struct inout_ring *ringInstance(void) {
	if (rInst == NULL) {
		rInst = rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
		memset(rInst, 0, sizeof(struct inout_ring));
	}
	return rInst;
}


struct offload {
	uint32_t sip;
	uint32_t dip;

	uint16_t sport;
	uint16_t dport;

	int protocol;
	unsigned char *data;
	uint16_t length;
};


struct localhost {
	int fd;

	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint32_t localip;
	uint16_t localport;
	uint8_t protocol;

	struct rte_ring *rcvbuf;
	struct rte_ring *sndbuf;

	struct localhost *prev;
	struct localhost *next;

	pthread_cond_t cond;
	pthread_mutex_t mutex;
};

static struct localhost *lhost = NULL;

static struct localhost *get_hostinfo_from_ip_port(uint32_t ip, uint16_t port, uint8_t protocol) {
	struct localhost *host ;
	for (host = lhost ;host != NULL;host = host->next) {
		if (host->localip == ip && host->localport == port && host->protocol == protocol) {
			return host;
		}
	}
	return NULL;
}

static void *get_hostinfo_from_fd(int sockfd) {
	struct localhost *host;
	for (host = lhost; host != NULL;host = host->next) {
		if (sockfd == host->fd) {
			return host;
		}
	}

	// struct ng_tcp_stream *stream = NULL;
	// struct ng_tcp_table *table = tcpInstance();
	// for (stream = table->tcb_set;stream != NULL;stream = stream->next) {
	// 	if (sockfd == stream->fd) {
	// 		return stream;
	// 	}
	// }
	return NULL;
}


#define DEFAULT_FD_NUM	3
#define MAX_FD_COUNT	1024
static unsigned char fd_table[MAX_FD_COUNT] = { 0 };

static int get_fd_from_bitmap(void) { // 通过bitmap获取可用的fd
	int fd = DEFAULT_FD_NUM;
	for (;fd < MAX_FD_COUNT;fd++) {
		if ((fd_table[fd / 8] & (0x1 << (fd % 8))) == 0) {
			fd_table[fd / 8] |= (0x1 << (fd % 8));
			return fd;
		}
	}
	return -1;
}

static int set_fd_from_bitmap(int fd) {
	if (fd >= MAX_FD_COUNT) return -1;
	fd_table[fd / 8] &= ~(0x1 << (fd % 8));
	return 0;
}


static int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused))  int protocol) {
	int fd = get_fd_from_bitmap();
	if (type == SOCK_DGRAM) {
		struct localhost *host = rte_malloc("localhost", sizeof(struct localhost), 0);
		if (host == NULL) {
			return -1;
		}
		memset(host, 0, sizeof(struct localhost));
		host->fd = fd;
		host->protocol = IPPROTO_UDP;
		host->rcvbuf = rte_ring_create("recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (host->rcvbuf == NULL) {
			rte_free(host);
			return -1;
		}
		host->sndbuf = rte_ring_create("send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (host->sndbuf == NULL) {
			rte_ring_free(host->rcvbuf);
			rte_free(host);
			return -1;
		}
		pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
		rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));
		pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
		rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));
		
		LL_ADD(host, lhost);
	}
	else if (type == SOCK_STREAM) {
		
	}
	return fd;
}

static int nbind(int sockfd, const struct sockaddr *addr,__attribute__((unused))  socklen_t addrlen) {
	void *hostinfo = get_hostinfo_from_fd(sockfd);
	if (hostinfo == NULL) {
		return -1;
	}

	struct localhost *host = (struct localhost *)hostinfo;  // 强制转换
	if (host->protocol == IPPROTO_UDP) {
		const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
		host->localport = laddr->sin_port;
		rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(host->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);
	}
	else if (host->protocol == IPPROTO_TCP) {
		
	}

	return 0;
}

static ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))  int flags,struct sockaddr *src_addr, __attribute__((unused))  socklen_t *addrlen) {

	struct localhost *host = get_hostinfo_from_fd(sockfd); // 通过fd获取host
	if (host == NULL) return -1;

	struct offload *ol = NULL;
	unsigned char *ptr = NULL;
	struct sockaddr_in *saddr = (struct sockaddr_in *)src_addr;// 强转，sockaddr_in 和 sockaddr 一样，仅仅是差一些字段
	int nb = -1;

	pthread_mutex_lock(&host->mutex);
	while ((nb = rte_ring_mc_dequeue(host->rcvbuf, (void **)&ol)) < 0) {  // 一直从 recv buffer 出队列到 ol中
		pthread_cond_wait(&host->cond, &host->mutex);  // 阻塞等待， recv buffer 中有数据
	}
	pthread_mutex_unlock(&host->mutex);
	saddr->sin_port = ol->sport; // 设置源端口
	rte_memcpy(&saddr->sin_addr.s_addr, &ol->sip, sizeof(uint32_t));// 设置源ip

	if (len < ol->length) { // 如果ol的数据长度，大于buf的长度，则先取出一部分数据，剩下的再次入队列，下次再取
		rte_memcpy(buf, ol->data, len); // 1.先取出一部分数据
		ptr = rte_malloc("unsigned char *", ol->length - len, 0); //2 申请新内存，并将剩余数据放在新内存
		rte_memcpy(ptr, ol->data + len, ol->length - len);
		ol->length -= len;
		rte_free(ol->data); // 3.释放原来的内存
		ol->data = ptr; // 4.将剩余数据放在新内存
		rte_ring_mp_enqueue(host->rcvbuf, ol); // 重新入队列
		return len;
	}
	else {  // 如果buf完全接受数据，则正常处理
		rte_memcpy(buf, ol->data, ol->length);
		rte_free(ol->data);
		rte_free(ol);
		return ol->length;
	}
}

static ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused))  int flags,const struct sockaddr *dest_addr, __attribute__((unused))  socklen_t addrlen) {

	struct localhost *host = get_hostinfo_from_fd(sockfd); // 通过fd获取host
	if (host == NULL) return -1;
	const struct sockaddr_in *daddr = (const struct sockaddr_in *)dest_addr;

	// 填充offload数据，并入sndbuf队列
	struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
	if (ol == NULL) return -1;
	ol->dip = daddr->sin_addr.s_addr;
	ol->dport = daddr->sin_port;
	ol->sip = host->localip;
	ol->sport = host->localport;
	ol->length = len;
	ol->data = rte_malloc("unsigned char *", len, 0);
	if (ol->data == NULL) {
		rte_free(ol);
		return -1;
	}
	rte_memcpy(ol->data, buf, len);

	rte_ring_mp_enqueue(host->sndbuf, ol);
	return len;
}

static int nclose(int fd) {
	void *hostinfo = get_hostinfo_from_fd(fd);
	if (hostinfo == NULL) return -1;
	struct localhost *host = (struct localhost *)hostinfo;
	if (host->protocol == IPPROTO_UDP) {
		LL_REMOVE(host, lhost);
		if (host->rcvbuf) {
			rte_ring_free(host->rcvbuf);
		}
		if (host->sndbuf) {
			rte_ring_free(host->sndbuf);
		}
		rte_free(host);
		set_fd_from_bitmap(fd);
	}
	else if (host->protocol == IPPROTO_TCP) {
	
	}
	return 0;
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

	if (rte_eth_rx_queue_setup(gDpDkPortId, 0, 1024, rte_eth_dev_socket_id(gDpDkPortId), NULL, mbuf_pool) < 0) {
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

static struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
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

static void arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim, void *arg) {
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


static uint16_t ng_icmp_checksum(uint16_t *addr, int count) {
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

static int ng_encode_icmp_pkt(uint8_t *msg, uint8_t *dst_mac, uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
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
	icmp->icmp_cksum = ng_icmp_checksum((uint16_t *)icmp, sizeof(struct rte_icmp_hdr));

	return 0;
}

static struct rte_mbuf *ng_send_icmp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac, uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {
	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);
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


static int ng_udp_process(struct rte_mbuf *udpmbuf) {
	struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(udpmbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

	struct localhost *host = get_hostinfo_from_ip_port(iphdr->dst_addr,udphdr->dst_port,iphdr->next_proto_id);
	if (host == NULL) {
		rte_pktmbuf_free(udpmbuf);
		return -3;
	}

	struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
	if (ol == NULL) {
		rte_pktmbuf_free(udpmbuf);
		return -1;
	}
	ol->dip = iphdr->dst_addr;
	ol->sip = iphdr->src_addr;
	ol->sport = udphdr->src_port;
	ol->dport = udphdr->dst_port;
	ol->protocol = IPPROTO_UDP;
	ol->length = ntohs(udphdr->dgram_len);
	ol->data = rte_malloc("unsigned char", ol->length - sizeof(struct rte_udp_hdr), 0);
	if (ol->data == NULL) {
		rte_pktmbuf_free(udpmbuf);
		rte_free(ol);
		return -2;
	}
	rte_memcpy(ol->data, (unsigned char *)(udphdr + 1), ol->length - sizeof(struct rte_udp_hdr));

	rte_ring_mp_enqueue(host->rcvbuf, ol);

	pthread_mutex_lock(&host->mutex);
	pthread_cond_signal(&host->cond);
	pthread_mutex_unlock(&host->mutex);

	rte_pktmbuf_free(udpmbuf);
	return 0;
}

static int udp_server_entry(__attribute__((unused))  void *arg) {
	int connfd = nsocket(AF_INET, SOCK_DGRAM, 0);
	if (connfd < 0) {
		printf("sockfd failed\n");
		return -1;
	}

	struct sockaddr_in localaddr;
	memset(&localaddr, 0, sizeof(struct sockaddr_in));
	localaddr.sin_family = AF_INET;
	localaddr.sin_addr.s_addr = inet_addr("192.168.3.100");
	localaddr.sin_port = htons(8080);

	nbind(connfd, (struct sockaddr *)&localaddr, sizeof(localaddr));

	struct sockaddr_in  clientaddr;
	char buffer[UDP_APP_RECV_BUFFER_SIZE] = { 0 };
	socklen_t addrlen = sizeof(clientaddr);
	while (1) {
		// 循环从fd相关的 recv buffer 环形队列中，读取数据到buffer，并获取clientaddr
		if (nrecvfrom(connfd, buffer, UDP_APP_RECV_BUFFER_SIZE, 0, (struct sockaddr *)&clientaddr, &addrlen) < 0) {
			continue;
		}
		else {
			printf("recv from %s:%d, data:%s\n", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port), buffer); // 处理数据
			nsendto(connfd, buffer, strlen(buffer), 0, (struct sockaddr *)&clientaddr, sizeof(clientaddr)); // 发送回复报文
		}
	}
	nclose(connfd);
}

static int ng_encode_udp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac, unsigned char *data, uint16_t total_len) {
	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
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
	ip->src_addr = sip;
	ip->dst_addr = dip;
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);
	// 3 udphdr 
	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	udp->src_port = sport;
	udp->dst_port = dport;
	uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	udp->dgram_len = htons(udplen);
	rte_memcpy((uint8_t *)(udp + 1), data, udplen);
	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);
	return 0;
}

static struct rte_mbuf *ng_udp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac, uint8_t *data, uint16_t length) {
	// mempool --> mbuf
	const unsigned total_len = length + 42;
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "ng_udp_pkt rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;
	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t *);
	ng_encode_udp_apppkt(pktdata, sip, dip, sport, dport, srcmac, dstmac, data, total_len);
	return mbuf;
}

static int ng_udp_out(struct rte_mempool *mbuf_pool) {
	struct localhost *host;
	for (host = lhost; host != NULL; host = host->next) { //遍历每一个host，从sendbuf取出数据，构建udp包
		struct offload *ol;
		int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void **)&ol);
		if (nb_snd < 0) {
			continue;
		}

		uint8_t *dstmac = ng_get_dst_macaddr(ol->dip);
		if (dstmac == NULL) { // 如果dstmac为空，则发送arp请求，并且将offload重新放入sndbuf
			struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, ol->sip, ol->dip);
			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);
			rte_ring_mp_enqueue(host->sndbuf, ol);
		}
		else {
			struct rte_mbuf *udpbuf = ng_udp_pkt(mbuf_pool, ol->sip, ol->dip, ol->sport, ol->dport, host->localmac, dstmac, ol->data, ol->length);
			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&udpbuf, 1, NULL); // 将udpbuf放入out环形队列
		}
	}
	return 0;
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
						struct arp_table *table = arp_table_instance();
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
				// else if (iphdr->next_proto_id == IPPROTO_TCP) {
				// 	ng_tcp_process(mbufs[i]); // tcp
				// }
			}
		}
		ng_udp_out(mbuf_pool);
		// ng_tcp_out(mbuf_pool);
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
	rte_eth_macaddr_get(gDpDkPortId, (struct rte_ether_addr *)gSrcMac);

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
		ring->in = rte_ring_create("in ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}
	if (ring->out == NULL) {
		ring->out = rte_ring_create("out ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}

	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(pkt_process, mbuf_pool, lcore_id);

	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(udp_server_entry, mbuf_pool, lcore_id);

	// lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	// rte_eal_remote_launch(tcp_server_entry, mbuf_pool, lcore_id);

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
