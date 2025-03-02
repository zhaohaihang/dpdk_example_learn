#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_timer.h>
#include <rte_log.h>
#include <rte_kni.h>

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
#define BUFFER_SIZE	1024
#define DEFAULT_FD_NUM	3
#define MAX_FD_COUNT	1024
#define TCP_OPTION_LENGTH	10
#define TCP_MAX_SEQ		4294967295
#define TCP_INITIAL_WINDOW  14600
#define MAX_PACKET_SIZE		2048

static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 3, 100);
static uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static int gDpdkPortId = 0;

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
// static struct rte_ether_addr gSrcMac;

static unsigned char fd_table[MAX_FD_COUNT] = { 0 };
struct rte_kni *global_kni = NULL;

struct inout_ring {
	struct rte_ring *in;
	struct rte_ring *out;
};

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

typedef enum _NG_TCP_STATUS {
	NG_TCP_STATUS_CLOSED = 0,
	NG_TCP_STATUS_LISTEN,
	NG_TCP_STATUS_SYN_SENT,
	NG_TCP_STATUS_SYN_RCVD,
	NG_TCP_STATUS_ESTABLISHED,

	NG_TCP_STATUS_FIN_WAIT_1,
	NG_TCP_STATUS_FIN_WAIT_2,
	NG_TCP_STATUS_CLOSING,
	NG_TCP_STATUS_TIME_WAIT,

	NG_TCP_STATUS_CLOSE_WAIT,
	NG_TCP_STATUS_LAST_ACK
} NG_TCP_STATUS;

struct ng_tcp_fragment {
	uint16_t sport;
	uint16_t dport;
	uint32_t seqnum;
	uint32_t acknum;
	uint8_t  hdrlen_off;
	uint8_t  tcp_flags;
	uint16_t windows;
	uint16_t cksum;
	uint16_t tcp_urp;

	int optlen;
	uint32_t option[TCP_OPTION_LENGTH];

	unsigned char *data;
	uint32_t length;
};

struct ng_tcp_stream {
	int fd;
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint32_t dip;
	uint16_t dport;
	uint8_t protocol;

	uint32_t sip;
	uint16_t sport;

	uint32_t snd_nxt;
	uint32_t rcv_nxt;

	NG_TCP_STATUS status;

	struct rte_ring *sndbuf;
	struct rte_ring *rcvbuf;

	struct ng_tcp_stream *next;
	struct ng_tcp_stream *prev;

	pthread_cond_t cond;
	pthread_mutex_t mutex;
};

struct ng_tcp_table {
	int count;
	struct ng_tcp_stream *tcb_set;
};

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




static struct inout_ring *rInst = NULL;

static struct inout_ring *ringInstance(void) {
	if (rInst == NULL) {
		rInst = rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
		memset(rInst, 0, sizeof(struct inout_ring));
	}
	return rInst;
}

static struct ng_tcp_table *tInst = NULL;

static struct ng_tcp_table *tcpInstance(void) {
	if (tInst == NULL) {
		tInst = rte_malloc("ng_tcp_table", sizeof(struct ng_tcp_table), 0);
		memset(tInst, 0, sizeof(struct ng_tcp_table));
	}
	return tInst;
}

static struct ng_tcp_stream *get_accept_tcb(uint16_t dport) {
	struct ng_tcp_stream *apt;
	struct ng_tcp_table *table = tcpInstance();
	for (apt = table->tcb_set;apt != NULL;apt = apt->next) {
		if (dport == apt->dport && apt->fd == -1) {
			return apt;
		}
	}
	return NULL;
}

static struct localhost *lhost = NULL;

static struct localhost *get_hostinfo_from_ip_port(uint32_t ip, uint16_t port, uint8_t protocol) {
	struct localhost *host;
	for (host = lhost;host != NULL;host = host->next) {
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

	struct ng_tcp_stream *stream = NULL;
	struct ng_tcp_table *table = tcpInstance();
	for (stream = table->tcb_set;stream != NULL;stream = stream->next) {
		if (sockfd == stream->fd) {
			return stream;
		}
	}
	return NULL;
}


static struct ng_tcp_stream *ng_tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) { // proto
	struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
	if (stream == NULL) {
		return NULL;
	}

	stream->sip = sip;
	stream->dip = dip;
	stream->sport = sport;
	stream->dport = dport;
	stream->protocol = IPPROTO_TCP;
	stream->fd = -1; //unused
	stream->status = NG_TCP_STATUS_LISTEN;
	stream->sndbuf = rte_ring_create("sndbuf", RING_SIZE, rte_socket_id(), 0);
	stream->rcvbuf = rte_ring_create("rcvbuf", RING_SIZE, rte_socket_id(), 0);

	uint32_t next_seed = time(NULL);
	stream->snd_nxt = rand_r(&next_seed) % TCP_MAX_SEQ;
	rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

	pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
	rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

	return stream;
}

static struct ng_tcp_stream *ng_tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
	struct ng_tcp_table *table = tcpInstance();

	struct ng_tcp_stream *iter;
	for (iter = table->tcb_set;iter != NULL;iter = iter->next) {
		if (iter->sip == sip && iter->dip == dip && iter->sport == sport && iter->dport == dport) {
			return iter;
		}
	}

	for (iter = table->tcb_set;iter != NULL; iter = iter->next) {
		if (iter->dport == dport && iter->status == NG_TCP_STATUS_LISTEN) { // listen
			return iter;
		}
	}
	return NULL;
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
		struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
		if (stream == NULL) {
			return -1;
		}
		memset(stream, 0, sizeof(struct ng_tcp_stream));

		stream->fd = fd;
		stream->protocol = IPPROTO_TCP;
		stream->next = stream->prev = NULL;
		stream->rcvbuf = rte_ring_create("tcp recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (stream->rcvbuf == NULL) {
			rte_free(stream);
			return -1;
		}
		stream->sndbuf = rte_ring_create("tcp send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (stream->sndbuf == NULL) {
			rte_ring_free(stream->rcvbuf);
			rte_free(stream);
			return -1;
		}

		pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
		rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

		pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
		rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

		struct ng_tcp_table *table = tcpInstance();
		LL_ADD(stream, table->tcb_set);
	}
	return fd;
}

static int nbind(int sockfd, const struct sockaddr *addr, __attribute__((unused))  socklen_t addrlen) {
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
		struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
		const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
		stream->dport = laddr->sin_port;
		rte_memcpy(&stream->dip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);
		stream->status = NG_TCP_STATUS_CLOSED;
	}

	return 0;
}

static int nlisten(int sockfd, __attribute__((unused)) int backlog) { //
	void *hostinfo = get_hostinfo_from_fd(sockfd);
	if (hostinfo == NULL) {
		return -1;
	}
	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->protocol == IPPROTO_TCP) {
		stream->status = NG_TCP_STATUS_LISTEN;
	}
	return 0;
}

static int naccept(int sockfd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addrlen) {
	void *hostinfo = get_hostinfo_from_fd(sockfd);
	if (hostinfo == NULL) {
		return -1;
	}
	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->protocol == IPPROTO_TCP) {
		struct ng_tcp_stream *apt = NULL;
		pthread_mutex_lock(&stream->mutex);
		while ((apt = get_accept_tcb(stream->dport)) == NULL) {
			pthread_cond_wait(&stream->cond, &stream->mutex);
		}
		pthread_mutex_unlock(&stream->mutex);
		apt->fd = get_fd_from_bitmap();
		struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
		saddr->sin_port = apt->sport;
		rte_memcpy(&saddr->sin_addr.s_addr, &apt->sip, sizeof(uint32_t));
		return apt->fd;
	}
	return -1;
}

static ssize_t nsend(int sockfd, const void *buf, size_t len, __attribute__((unused)) int flags) {
	ssize_t length = 0;
	void *hostinfo = get_hostinfo_from_fd(sockfd);
	if (hostinfo == NULL) {
		return -1;
	}
	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->protocol == IPPROTO_TCP) {
		struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
		if (fragment == NULL) {
			return -2;
		}

		memset(fragment, 0, sizeof(struct ng_tcp_fragment));
		fragment->dport = stream->sport;
		fragment->sport = stream->dport;
		fragment->acknum = stream->rcv_nxt;
		fragment->seqnum = stream->snd_nxt;
		fragment->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
		fragment->windows = TCP_INITIAL_WINDOW;
		fragment->hdrlen_off = 0x50;
		fragment->data = rte_malloc("unsigned char *", len + 1, 0);
		if (fragment->data == NULL) {
			rte_free(fragment);
			return -1;
		}
		memset(fragment->data, 0, len + 1);
		rte_memcpy(fragment->data, buf, len);
		fragment->length = len;
		length = fragment->length;
		rte_ring_mp_enqueue(stream->sndbuf, fragment);
	}
	return length;
}

static ssize_t nrecv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags) {
	ssize_t length = 0;
	void *hostinfo = get_hostinfo_from_fd(sockfd);
	if (hostinfo == NULL) {
		return -1;
	}

	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->protocol == IPPROTO_TCP) {
		struct ng_tcp_fragment *fragment = NULL;
		int nb_rcv = 0;

		pthread_mutex_lock(&stream->mutex);
		while ((nb_rcv = rte_ring_mc_dequeue(stream->rcvbuf, (void **)&fragment)) < 0) {
			pthread_cond_wait(&stream->cond, &stream->mutex);
		}
		pthread_mutex_unlock(&stream->mutex);
		if (fragment->length > len) {
			rte_memcpy(buf, fragment->data, len);
			uint32_t i = 0;
			for (i = 0;i < fragment->length - len;i++) {
				fragment->data[i] = fragment->data[len + i];
			}
			fragment->length = fragment->length - len;
			length = fragment->length;
			rte_ring_mp_enqueue(stream->rcvbuf, fragment);
		}
		else if (fragment->length == 0) {
			rte_free(fragment);
			return 0;
		}
		else {
			rte_memcpy(buf, fragment->data, fragment->length);
			length = fragment->length;
			rte_free(fragment->data);
			fragment->data = NULL;
			rte_free(fragment);
		}
	}

	return length;
}

static ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))  int flags, struct sockaddr *src_addr, __attribute__((unused))  socklen_t *addrlen) {

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

static ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused))  int flags, const struct sockaddr *dest_addr, __attribute__((unused))  socklen_t addrlen) {

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
		struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
		if (stream->status != NG_TCP_STATUS_LISTEN) {
			struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
			if (fragment == NULL) {
				return -1;
			}
			fragment->data = NULL;
			fragment->length = 0;
			fragment->sport = stream->dport;
			fragment->dport = stream->sport;
			fragment->seqnum = stream->snd_nxt;
			fragment->acknum = stream->rcv_nxt;
			fragment->tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
			fragment->windows = TCP_INITIAL_WINDOW;
			fragment->hdrlen_off = 0x50;
			rte_ring_mp_enqueue(stream->sndbuf, fragment);
			stream->status = NG_TCP_STATUS_LAST_ACK;
			set_fd_from_bitmap(fd);
		}
		else { // nsocket
			struct ng_tcp_table *table = tcpInstance();
			LL_REMOVE(stream, table->tcb_set);
			rte_free(stream);
		}
	}
	return 0;
}



static void ng_init_port(struct rte_mempool *mbuf_pool) {
	uint16_t nb_sys_ports = rte_eth_dev_count_avail();
	if (nb_sys_ports == 0) {
		rte_exit(EXIT_FAILURE, "No Supported eth found\n");
	}

	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(gDpdkPortId, &dev_info);

	const int num_rx_queues = 1;
	const int num_tx_queues = 1;

	static const struct rte_eth_conf port_conf_default = {
		.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
	};

	// struct rte_eth_conf port_conf = port_conf_default;
	rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf_default);

	if (rte_eth_rx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
	}

	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf_default.rxmode.offloads;
	if (rte_eth_tx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
	}

	if (rte_eth_dev_start(gDpdkPortId) < 0) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}
	rte_eth_promiscuous_enable(gDpdkPortId);
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

static int ng_arp_entry_insert(uint32_t ip, uint8_t *mac) {
	struct arp_table *table = arp_table_instance();
	uint8_t *hwaddr = ng_get_dst_macaddr(ip);
	if (hwaddr == NULL) {
		struct arp_entry *entry = rte_malloc("arp_entry",sizeof(struct arp_entry), 0);
		if (entry) {
			memset(entry, 0, sizeof(struct arp_entry));
			entry->ip = ip;
			rte_memcpy(entry->hwaddr, mac, RTE_ETHER_ADDR_LEN);
			entry->type = 0;
			pthread_spin_lock(&table->spinlock);
			LL_ADD(entry, table->entries);
			table->count ++;
			pthread_spin_unlock(&table->spinlock);
		}
		return 1;
	}
	return 0;
}



// static uint16_t ng_icmp_checksum(uint16_t *addr, int count) {
// 	register long sum = 0;
// 	while (count > 1) {
// 		sum += *(unsigned short *)addr++;
// 		count -= 2;
// 	}
// 	if (count > 0) {
// 		sum += *(unsigned char *)addr;
// 	}
// 	while (sum >> 16) {
// 		sum = (sum & 0xffff) + (sum >> 16);
// 	}
// 	return ~sum;
// }

// static int ng_encode_icmp_pkt(uint8_t *msg, uint8_t *dst_mac, uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {
// 	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
// 	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
// 	rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
// 	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

// 	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
// 	ip->version_ihl = 0x45;
// 	ip->type_of_service = 0;
// 	ip->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
// 	ip->packet_id = 0;
// 	ip->fragment_offset = 0;
// 	ip->time_to_live = 64;
// 	ip->next_proto_id = IPPROTO_ICMP;
// 	ip->src_addr = sip;
// 	ip->dst_addr = dip;
// 	ip->hdr_checksum = 0;
// 	ip->hdr_checksum = rte_ipv4_cksum(ip);

// 	struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(ip + 1);
// 	icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
// 	icmp->icmp_code = 0;
// 	icmp->icmp_ident = id;
// 	icmp->icmp_seq_nb = seqnb;
// 	icmp->icmp_cksum = 0;
// 	icmp->icmp_cksum = ng_icmp_checksum((uint16_t *)icmp, sizeof(struct rte_icmp_hdr));

// 	return 0;
// }

// static struct rte_mbuf *ng_send_icmp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac, uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {
// 	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);
// 	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
// 	if (!mbuf) {
// 		rte_exit(EXIT_FAILURE, "ng_send_icmp rte_pktmbuf_alloc\n");
// 	}
// 	mbuf->pkt_len = total_length;
// 	mbuf->data_len = total_length;
// 	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
// 	ng_encode_icmp_pkt(pkt_data, dst_mac, sip, dip, id, seqnb);
// 	return mbuf;
// }




static int ng_udp_process(struct rte_mbuf *udpmbuf) {
	struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(udpmbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

	struct localhost *host = get_hostinfo_from_ip_port(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id);
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




static int ng_tcp_enqueue_recvbuffer(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen) {
	struct ng_tcp_fragment *rfragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
	if (rfragment == NULL) {
		return -1;
	}
	memset(rfragment, 0, sizeof(struct ng_tcp_fragment));
	rfragment->dport = ntohs(tcphdr->dst_port);
	rfragment->sport = ntohs(tcphdr->src_port);
	uint8_t hdrlen = tcphdr->data_off >> 4;
	int payloadlen = tcplen - hdrlen * 4; //
	if (payloadlen > 0) {
		uint8_t *payload = (uint8_t *)tcphdr + hdrlen * 4;
		rfragment->data = rte_malloc("unsigned char *", payloadlen + 1, 0);
		if (rfragment->data == NULL) {
			rte_free(rfragment);
			return -1;
		}
		memset(rfragment->data, 0, payloadlen + 1);
		rte_memcpy(rfragment->data, payload, payloadlen);
		rfragment->length = payloadlen;
	}
	else if (payloadlen == 0) {
		rfragment->length = 0;
		rfragment->data = NULL;
	}
	rte_ring_mp_enqueue(stream->rcvbuf, rfragment);

	pthread_mutex_lock(&stream->mutex);
	pthread_cond_signal(&stream->cond);
	pthread_mutex_unlock(&stream->mutex);

	return 0;
}

static int ng_tcp_send_ackpkt(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {
	struct ng_tcp_fragment *ackfrag = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
	if (ackfrag == NULL) {
		return -1;
	}
	memset(ackfrag, 0, sizeof(struct ng_tcp_fragment));
	ackfrag->dport = tcphdr->src_port;
	ackfrag->sport = tcphdr->dst_port;
	ackfrag->acknum = stream->rcv_nxt;
	ackfrag->seqnum = stream->snd_nxt;
	ackfrag->tcp_flags = RTE_TCP_ACK_FLAG;
	ackfrag->windows = TCP_INITIAL_WINDOW;
	ackfrag->hdrlen_off = 0x50;
	ackfrag->data = NULL;
	ackfrag->length = 0;
	rte_ring_mp_enqueue(stream->sndbuf, ackfrag);
	return 0;
}

static int ng_tcp_handle_close_wait(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {
	if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) { //
		if (stream->status == NG_TCP_STATUS_CLOSE_WAIT) {
		}
	}
	return 0;
}

static int ng_tcp_handle_last_ack(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {
	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {
		if (stream->status == NG_TCP_STATUS_LAST_ACK) {
			stream->status = NG_TCP_STATUS_CLOSED;
			struct ng_tcp_table *table = tcpInstance();
			LL_REMOVE(stream, table->tcb_set);
			rte_ring_free(stream->sndbuf);
			rte_ring_free(stream->rcvbuf);
			rte_free(stream);
		}
	}
	return 0;
}

static int ng_tcp_handle_listen(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, struct rte_ipv4_hdr *iphdr) {
	if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {
		
		if (stream->status == NG_TCP_STATUS_LISTEN) {
			
			struct ng_tcp_table *table = tcpInstance();
			struct ng_tcp_stream *syn = ng_tcp_stream_create(iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port);
			LL_ADD(syn, table->tcb_set);

			struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
			if (fragment == NULL) {
				return -1;
			}
			memset(fragment, 0, sizeof(struct ng_tcp_fragment));

			fragment->sport = tcphdr->dst_port;
			fragment->dport = tcphdr->src_port;
			fragment->seqnum = syn->snd_nxt;
			fragment->acknum = ntohl(tcphdr->sent_seq) + 1;
			syn->rcv_nxt = fragment->acknum;

			fragment->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
			fragment->windows = TCP_INITIAL_WINDOW;
			fragment->hdrlen_off = 0x50;
			fragment->data = NULL;
			fragment->length = 0;

			rte_ring_mp_enqueue(syn->sndbuf, fragment);
			syn->status = NG_TCP_STATUS_SYN_RCVD;			
		}
	}
	return 0;
}

static int ng_tcp_handle_established(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen) {
	if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {
		//
	}

	if (tcphdr->tcp_flags & RTE_TCP_PSH_FLAG) {
		ng_tcp_enqueue_recvbuffer(stream, tcphdr, tcplen);
		uint8_t hdrlen = tcphdr->data_off >> 4;
		int payloadlen = tcplen - hdrlen * 4;
		stream->rcv_nxt = stream->rcv_nxt + payloadlen;
		stream->snd_nxt = ntohl(tcphdr->recv_ack);
		ng_tcp_send_ackpkt(stream, tcphdr);
	}

	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

	}

	if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {
		stream->status = NG_TCP_STATUS_CLOSE_WAIT;
		ng_tcp_enqueue_recvbuffer(stream, tcphdr, tcphdr->data_off >> 4);
		stream->rcv_nxt = stream->rcv_nxt + 1;
		stream->snd_nxt = ntohl(tcphdr->recv_ack);
		ng_tcp_send_ackpkt(stream, tcphdr);
	}
	return 0;
}

static int ng_tcp_handle_syn_rcvd(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {
	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {
		if (stream->status == NG_TCP_STATUS_SYN_RCVD) {  // 考虑到重传的情况
			uint32_t acksum = ntohl(tcphdr->recv_ack);
			if (acksum == stream->snd_nxt + 1) {
				//
			}
			stream->status = NG_TCP_STATUS_ESTABLISHED;

			struct ng_tcp_stream *listener = ng_tcp_stream_search(0, 0, 0, stream->dport);
			if (listener == NULL) {
				rte_exit(EXIT_FAILURE, "listener is NULL\n");
			}
			pthread_mutex_lock(&listener->mutex);
			pthread_cond_signal(&listener->cond);
			pthread_mutex_unlock(&listener->mutex);
		}
	}
	return 0;
}

static int ng_tcp_process(struct rte_mbuf *tcpmbuf) {
	struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(tcpmbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(iphdr + 1);

	uint16_t tcpcksum = tcphdr->cksum;
	tcphdr->cksum = 0;
	uint16_t cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);
	if (cksum != tcpcksum) {
		rte_pktmbuf_free(tcpmbuf);
		return -1;
	}

	struct ng_tcp_stream *stream = ng_tcp_stream_search(iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port);
	if (stream == NULL) {
		return -2;
	}

	switch (stream->status) {
	case NG_TCP_STATUS_CLOSED: //client 
		break;
	case NG_TCP_STATUS_LISTEN: // server
		ng_tcp_handle_listen(stream, tcphdr, iphdr);
		break;
	case NG_TCP_STATUS_SYN_RCVD: // server
		ng_tcp_handle_syn_rcvd(stream, tcphdr);
		break;
	case NG_TCP_STATUS_SYN_SENT: // client
		break;
	case NG_TCP_STATUS_ESTABLISHED: { // server | client
		int tcplen = ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr);
		ng_tcp_handle_established(stream, tcphdr, tcplen);
		break;
	}
	case NG_TCP_STATUS_FIN_WAIT_1: //  ~client
		break;
	case NG_TCP_STATUS_FIN_WAIT_2: // ~client
		break;
	case NG_TCP_STATUS_CLOSING: // ~client
		break;
	case NG_TCP_STATUS_TIME_WAIT: // ~client
		break;
	case NG_TCP_STATUS_CLOSE_WAIT: // ~server
		ng_tcp_handle_close_wait(stream, tcphdr);
		break;
	case NG_TCP_STATUS_LAST_ACK:  // ~server
		ng_tcp_handle_last_ack(stream, tcphdr);
		break;
	}
	rte_pktmbuf_free(tcpmbuf);

	return 0;
}

static int tcp_server_entry(__attribute__((unused))  void *arg) {
	int listenfd = nsocket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1) {
		return -1;
	}

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(struct sockaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(9999);
	nbind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
	nlisten(listenfd, 10);

	while (1) {
		struct sockaddr_in client;
		socklen_t len = sizeof(client);
		int connfd = naccept(listenfd, (struct sockaddr *)&client, &len);
		char buff[BUFFER_SIZE] = { 0 };
		while (1) {
			int n = nrecv(connfd, buff, BUFFER_SIZE, 0); //block
			if (n > 0) {
				printf("recv: %s\n", buff);
				nsend(connfd, buff, n, 0);
			}
			else if (n == 0) {
				nclose(connfd);
				break;
			}
			else { //nonblock

			}
		}
	}
	nclose(listenfd);
}

static int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip, uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment) {
	// encode 
	const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
		sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) +
		fragment->optlen * sizeof(uint32_t);

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
	ip->next_proto_id = IPPROTO_TCP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 udphdr 
	struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	tcp->src_port = fragment->sport;
	tcp->dst_port = fragment->dport;
	tcp->sent_seq = htonl(fragment->seqnum);
	tcp->recv_ack = htonl(fragment->acknum);
	tcp->data_off = fragment->hdrlen_off;
	tcp->rx_win = fragment->windows;
	tcp->tcp_urp = fragment->tcp_urp;
	tcp->tcp_flags = fragment->tcp_flags;
	if (fragment->data != NULL) {
		uint8_t *payload = (uint8_t *)(tcp + 1) + fragment->optlen * sizeof(uint32_t);
		rte_memcpy(payload, fragment->data, fragment->length);
	}

	tcp->cksum = 0;
	tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

	return 0;
}

static struct rte_mbuf *ng_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip, uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment) {
	// mempool --> mbuf
	const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
		sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) +
		fragment->optlen * sizeof(uint32_t);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "ng_tcp_pkt rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;
	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t *);
	ng_encode_tcp_apppkt(pktdata, sip, dip, srcmac, dstmac, fragment);
	return mbuf;
}

static int ng_tcp_out(struct rte_mempool *mbuf_pool) {
	struct ng_tcp_table *table = tcpInstance();
	struct ng_tcp_stream *stream;
	for (stream = table->tcb_set;stream != NULL;stream = stream->next) {
		if (stream->sndbuf == NULL) continue; // listener
		struct ng_tcp_fragment *fragment = NULL;
		int nb_snd = rte_ring_mc_dequeue(stream->sndbuf, (void **)&fragment);
		if (nb_snd < 0) continue;
		uint8_t *dstmac = ng_get_dst_macaddr(stream->sip); // 
		if (dstmac == NULL) {
			struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, stream->dip, stream->sip);
			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);
			rte_ring_mp_enqueue(stream->sndbuf, fragment);
		}
		else {
			struct rte_mbuf *tcpbuf = ng_tcp_pkt(mbuf_pool, stream->dip, stream->sip, stream->localmac, dstmac, fragment);
			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&tcpbuf, 1, NULL);
			if (fragment->data != NULL) {
				rte_free(fragment->data);
			}
			rte_free(fragment);
		}
	}
	return 0;
}



static int ng_config_network_if(uint16_t port_id, uint8_t if_up) {
	if (!rte_eth_dev_is_valid_port(port_id)) {
		return -EINVAL;
	}
	int ret = 0;
	if (if_up) {
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
	} else {
		rte_eth_dev_stop(port_id);
	}
	if (ret < 0) {
		printf("Failed to start port : %d\n", port_id);
	}
	return 0;
}

static struct rte_kni *ng_alloc_kni(struct rte_mempool *mbuf_pool) {
	struct rte_kni *kni_hanlder = NULL;
	struct rte_kni_conf conf;
	memset(&conf, 0, sizeof(conf));
	snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", gDpdkPortId);
	conf.group_id = gDpdkPortId;
	conf.mbuf_size = MAX_PACKET_SIZE;
	rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)conf.mac_addr);
	rte_eth_dev_get_mtu(gDpdkPortId, &conf.mtu);
	// print_ethaddr("ng_alloc_kni: ", (struct rte_ether_addr *)conf.mac_addr);
	struct rte_kni_ops ops;
	memset(&ops, 0, sizeof(ops));

	ops.port_id = gDpdkPortId;
	ops.config_network_if = ng_config_network_if;
	
	kni_hanlder = rte_kni_alloc(mbuf_pool, &conf, &ops);	
	if (!kni_hanlder) {
		rte_exit(EXIT_FAILURE, "Failed to create kni for port : %d\n", gDpdkPortId);
	}
	return kni_hanlder;
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
			// if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
			// 	struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
			// 	if (ahdr->arp_data.arp_tip == gLocalIp) {
			// 		if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
			// 			struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REPLY, ahdr->arp_data.arp_sha.addr_bytes, ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);
			// 			rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);
			// 			rte_pktmbuf_free(mbufs[i]);
			// 		}
			// 		else if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
			// 			struct arp_table *table = arp_table_instance();
			// 			uint8_t *hwaddr = ng_get_dst_macaddr(ahdr->arp_data.arp_sip); // 通过arp源ip，查询对应的mac
			// 			if (hwaddr == NULL) {
			// 				struct arp_entry *entry = rte_malloc("arp_entry", sizeof(struct arp_entry), 0);
			// 				if (entry) {  // 如果没有找到对应的mac，则创建一个新的arp_entry存入arp表
			// 					memset(entry, 0, sizeof(struct arp_entry));
			// 					entry->ip = ahdr->arp_data.arp_sip;
			// 					rte_memcpy(entry->hwaddr, ahdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
			// 					entry->type = 0;
			// 					LL_ADD(entry, table->entries);
			// 					table->count++;
			// 				}
			// 			}
			// 			rte_pktmbuf_free(mbufs[i]);
			// 		}
			// 	}
			// }
			// else if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
			// 	struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
			// 	// icmp
			// 	if (iphdr->next_proto_id == IPPROTO_ICMP) {
			// 		struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);
			// 		if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
			// 			struct rte_mbuf *icmpbuf = ng_send_icmp(mbuf_pool, ehdr->s_addr.addr_bytes, iphdr->dst_addr, iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);
			// 			rte_ring_mp_enqueue_burst(ring->out, (void **)&icmpbuf, 1, NULL);
			// 			rte_pktmbuf_free(mbufs[i]);
			// 		}
			// 	}
			// 	else if (iphdr->next_proto_id == IPPROTO_UDP) {
			// 		ng_udp_process(mbufs[i]); // udp
			// 	}
			// 	else if (iphdr->next_proto_id == IPPROTO_TCP) {
			// 		ng_tcp_process(mbufs[i]); // tcp
			// 	}
			// }

			if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
				ng_arp_entry_insert(iphdr->src_addr, ehdr->s_addr.addr_bytes);
			
				if (iphdr->next_proto_id == IPPROTO_UDP) {
					ng_udp_process(mbufs[i]);
				} else if (iphdr->next_proto_id == IPPROTO_TCP) {
					ng_tcp_process(mbufs[i]);
				} else {
					rte_kni_tx_burst(global_kni, mbufs, num_recvd);
					printf("tcp/udp --> rte_kni_handle_request\n");
				}
			} else {
				rte_kni_tx_burst(global_kni, mbufs, num_recvd);
				printf("ip --> rte_kni_handle_request\n");
			}
		}
		rte_kni_handle_request(global_kni);
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

	if (-1 == rte_kni_init(gDpdkPortId)) {
		rte_exit(EXIT_FAILURE, "kni init failed\n");
	}
	ng_init_port(mbuf_pool);
	// kni_alloc
	global_kni = ng_alloc_kni(mbuf_pool);


	rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);

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

	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(tcp_server_entry, mbuf_pool, lcore_id);

	while (1) {
		// rx
		struct rte_mbuf *rx_pkts[BURST_SIZE];
		unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, rx_pkts, BURST_SIZE);
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
			rte_eth_tx_burst(gDpdkPortId, 0, tx, nb_tx);
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
