#include "all.h"

#ifdef __MAIN_LOOP_KNI__

#define kni_link_up	1
#define kni_link_down 0

struct kni_interface_stats kni_stats[MAX_DEV];
int kni_link[MAX_DEV];

void
kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
	unsigned i;

	if (pkts == NULL)
		return;

	for (i = 0; i < num; i++) {
		rte_pktmbuf_free(pkts[i]);
		pkts[i] = NULL;
	}
}

/* Callback for request of changing MTU */
static int
kni_change_mtu(uint8_t port_id, unsigned new_mtu)
{
	return 0;
}

/* Callback for request of configuring network interface up/down */
static int
kni_config_network_interface(uint8_t port_id, uint8_t if_up)
{
	int ret = 0;

	if (port_id >= rte_eth_dev_count() || port_id >= RTE_MAX_ETHPORTS) {
		RUNNING_LOG_ERROR("Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RUNNING_LOG_INFO("Configure network interface of %d %s\n",
					port_id, if_up ? "up" : "down");

	if (if_up != 0) { /* Configure network interface up */
//		rte_eth_dev_stop(port_id);
//		ret = rte_eth_dev_start(port_id);
		kni_link[port_id]=kni_link_up;
	} else { /* Configure network interface down */
//		rte_eth_dev_stop(port_id);
		kni_link[port_id]=kni_link_down;
	}

	if (ret < 0)
		RUNNING_LOG_ERROR("Failed to start port %d\n", port_id);

	return ret;
}

struct rte_kni *kni_alloc(uint8_t port_id,struct rte_mempool *pktmbuf_pool)
{
	uint8_t i, socketid;
	struct rte_kni *kni;
	struct rte_kni_conf conf;

	if (port_id >= RTE_MAX_ETHPORTS)
		return NULL;

	socketid = rte_eth_dev_socket_id(port_id);
	if (socketid >= MAX_SOCKET) {
		RUNNING_LOG_WARN("WARN: error socketid for port %d, socketid=%d\n", port_id, socketid);
		socketid = 0;
	}

	RUNNING_LOG_INFO("%s: portid=%d, socketid=%d\n", __FUNCTION__, port_id, socketid);

	/* Clear conf at first */
	memset(&conf, 0, sizeof(conf));
	snprintf(conf.name, RTE_KNI_NAMESIZE,
			"vEth%u", port_id);
	conf.core_id = 0;
	conf.force_bind = 0;
	conf.group_id = (uint16_t)port_id;
	conf.mbuf_size = MAX_PACKET_SZ;
	/*
	 * The first KNI device associated to a port
	 * is the master, for multiple kernel thread
	 * environment.
	 */
	struct rte_kni_ops ops;
	struct rte_eth_dev_info dev_info;

	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(port_id, &dev_info);
	conf.addr = dev_info.pci_dev->addr;
	conf.id = dev_info.pci_dev->id;

	memset(&ops, 0, sizeof(ops));
	ops.port_id = port_id;
	ops.change_mtu = kni_change_mtu;
	ops.config_network_if = kni_config_network_interface;

	kni = rte_kni_alloc(pktmbuf_pool, &conf, &ops);
	return kni;
}

int kni_free_kni(uint8_t port_id,struct rte_kni *kni)
{
	if (port_id >= RTE_MAX_ETHPORTS)
		return -1;

	rte_kni_release(kni);
//	sleep(1);
	rte_eth_dev_stop(port_id);

	kni_link[port_id]=kni_link_down;

	return 0;
}


/* Initialize KNI subsystem */
void
init_kni(int num_of_kni_ports)
{
	int i;

	for(i=0;i<MAX_DEV;i++)
		kni_link[i]=kni_link_down;

	/* Invoke rte KNI init to preallocate the ports */
	rte_kni_init(num_of_kni_ports);


}

int main_loop_kni(void)
{
	uint64_t cur_tsc, prev_tsc,diff_tsc,start,end;
	int i,j,k;
	int my_lcore;
	struct lcore_info_s *local;
	struct rte_mbuf *pkts_burst[BURST_SZ];
	struct rte_kni *kni_array[MAX_DEV];
	struct rte_ring *ring_input[MAX_DEV];
	int queue_id[MAX_DEV];
	int nb_rx,nb_tx;
	int port_cnt=me.port_cnt;
	struct rte_mbuf tmp_pkts[BURST_SZ];
	struct rte_mbuf *p_pkts[BURST_SZ];

	my_lcore=rte_lcore_id();
	local=&lcore[my_lcore];
	rte_memcpy(kni_array,local->kni.kni_array,sizeof(struct rte_kni *)*MAX_DEV);
	rte_memcpy(ring_input,local->kni.ring_input,sizeof(struct rte_ring *)*MAX_DEV);
	rte_memcpy(queue_id,local->kni.queue_id,sizeof(int)*MAX_DEV);

//	RUNNING_LOG_INFO("core %d :kni process init\n",my_lcore);
//	kni_term=0;
//	while(init_step<=STEP_IF_INITED)
//		{
//		for(i=0;i<port_cnt;i++)
//			{
//			if(kni_term)
//				{
//				RUNNING_LOG_INFO("core %d :kni get term signal,exit now\n",my_lcore);
//				kni_term=2;
//				return;
//				}
//			rte_kni_handle_request(kni_array[i]);
//			}
//		}

	RUNNING_LOG_INFO("core %d :kni start\n",my_lcore);

	while(1)
		{
		//check some bug
//		if(term_pending)
//			continue;


		for(i=0;i<port_cnt;i++)
		{
			rte_kni_handle_request(kni_array[i]);

			nb_rx = rte_ring_sc_dequeue_burst(ring_input[i],(void **)pkts_burst, BURST_SZ);
			if(nb_rx)
			{
				RUNNING_LOG_DEBUG("%s: core<%d> port %d dequeue %d pkt to kni\n",__FUNCTION__,
					rte_lcore_id(),i,nb_rx);

				if(kni_link[i]==kni_link_down)
				{
					kni_burst_free_mbufs(pkts_burst, nb_rx);
					kni_stats[i].rx_dropped += nb_rx;

					RUNNING_LOG_DEBUG("%s: core<%d> port %d link down ,drop %d pkt\n",__FUNCTION__,
						rte_lcore_id(),i,nb_rx);
				}
				else
				{
//					for(j=0;j<nb_rx;j++)
//					{
//						rte_pktmbuf_dump(running_log_fp,pkts_burst[j],pkts_burst[j]->data_len);
//					}

					/* Burst tx to kni */

//#ifdef WF_NAT
//#ifdef BOND_2DIR
//					if(i<=1){
//						nb_tx = rte_kni_tx_burst(kni_array[0], pkts_burst, nb_rx);
//						rte_kni_handle_request(kni_array[0]);
//					}
//					else{
//						nb_tx = rte_kni_tx_burst(kni_array[2], pkts_burst, nb_rx);
//						rte_kni_handle_request(kni_array[2]);
//					}
//#else
//					nb_tx = rte_kni_tx_burst(kni_array[0], pkts_burst, nb_rx);
//					rte_kni_handle_request(kni_array[0]);
//#endif
//#else

//					for(j=0;j<nb_rx;j++)
//					{
//						p_pkts[j] = &tmp_pkts[j];
//						rte_memcpy(p_pkts[j],pkts_burst[j],sizeof(struct rte_mbuf));
//					}
					nb_tx = rte_kni_tx_burst(kni_array[i], pkts_burst, nb_rx);

//					nb_tx = rte_kni_tx_burst(kni_array[0], p_pkts, nb_rx);
//					rte_kni_handle_request(kni_array[0]);
//#endif
					kni_stats[i].rx_packets += nb_tx;

					if (unlikely(nb_tx < nb_rx))
					{
						RUNNING_LOG_DEBUG("%s: core<%d> port %d tx %d pkt to kni drop %d\n",
							__FUNCTION__,rte_lcore_id(),i,nb_rx,nb_rx-nb_tx);
						/* Free mbufs not tx to kni interface */
						kni_burst_free_mbufs(&pkts_burst[nb_tx], nb_rx - nb_tx);
						kni_stats[i].rx_dropped += nb_rx - nb_tx;
					}
				}
			}
		}

		for(i=0;i<port_cnt;i++)
		{
			/* Burst rx from kni */
			nb_rx = rte_kni_rx_burst(kni_array[i], pkts_burst, BURST_SZ);
			if(nb_rx)
			{
				RUNNING_LOG_DEBUG("%s: core<%d> port %d tx %d pkt from kni, queue=%d\n",
						__FUNCTION__,rte_lcore_id(),i,nb_rx,queue_id[i]);

//				for(j=0;j<nb_rx;j++)
//				{
//					rte_pktmbuf_dump(running_log_fp,pkts_burst[j],pkts_burst[j]->data_len);
//				}

				if(kni_link[i]==kni_link_down)
				{
					kni_burst_free_mbufs(pkts_burst, nb_rx);
					kni_stats[i].tx_dropped += nb_rx;

					RUNNING_LOG_DEBUG("%s: core<%d> port %d link down ,drop tx %d pkt\n",__FUNCTION__,
						rte_lcore_id(),i,nb_rx);
				}
				else
				{

					/* Burst tx to eth */
//					for(j=0;j<nb_rx;j++)
//					{
//						p_pkts[j] = &tmp_pkts[j];
//						rte_memcpy(p_pkts[j],pkts_burst[j],sizeof(struct rte_mbuf));
//					}

//					for(j=0;j<port_cnt;j++)
//					{
//						nb_tx = rte_eth_tx_burst(j, 0, p_pkts, (uint16_t)nb_rx);
//					}
//
//					rte_pktmbuf_dump(running_log_fp,p_pkts[0],(pkts_burst[0])->data_len);
//					rte_pktmbuf_dump(running_log_fp,pkts_burst[0],(pkts_burst[0])->data_len);
					nb_tx = rte_eth_tx_burst(i, queue_id[i], pkts_burst, (uint16_t)nb_rx);
					kni_stats[i].tx_packets += nb_tx;
					if (unlikely(nb_tx < nb_rx))
					{
						RUNNING_LOG_DEBUG("%s: core<%d> port %d tx %d pkt some drop %d\n",
							__FUNCTION__,rte_lcore_id(),i,nb_rx,nb_rx-nb_tx);
						/* Free mbufs not tx to NIC */
						kni_burst_free_mbufs(&pkts_burst[nb_tx], nb_rx - nb_tx);
						kni_stats[i].tx_dropped += nb_rx - nb_tx;
					}
				}
			}
		}

		usleep(10000);
	}
}
#endif /* #ifndef __MAIN_LOOP_KNI__ */
