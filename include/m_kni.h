#ifndef __M_KNI_H
#define __M_KNI_H


/* Structure type for recording kni interface specific stats */
struct kni_interface_stats {
	/* number of pkts received from NIC, and sent to KNI */
	uint64_t rx_packets;

	/* number of pkts received from NIC, but failed to send to KNI */
	uint64_t rx_dropped;

	/* number of pkts received from KNI, and sent to NIC */
	uint64_t tx_packets;

	/* number of pkts received from KNI, but failed to send to NIC */
	uint64_t tx_dropped;
};

//extern volatile int kni_term;

extern struct kni_interface_stats kni_stats[MAX_DEV];

extern struct rte_kni *kni_alloc(uint8_t port_id,struct rte_mempool *pktmbuf_pool);
extern void init_kni(int num_of_kni_ports);
extern int kni_free_kni(uint8_t port_id,struct rte_kni *kni);

#endif
