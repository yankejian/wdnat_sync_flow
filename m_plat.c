#include "all.h"

//#define RTC_MODE

struct mmb mm_plat={
	.name="m_plat",
	.preinit=m_plat_preinit,
	.init=m_plat_init,
	.deinit=m_plat_deinit,
};

pthread_t mon_thread_id;
pthread_t vif_init_thread_id;
struct list_head port_list;
struct lcore_info_s lcore[MAX_CPU] = {0};
//struct port_all_s2 all[MAX_DEV];

static uint8_t rss_intel_key[40] = {
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A };


static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = rss_intel_key,
			.rss_hf = ETH_RSS_IP | ETH_RSS_UDP |
				ETH_RSS_TCP | ETH_RSS_SCTP,/*ETH_RSS_IP,*/
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

static int
pci_get_kernel_driver_by_path(const char *filename, char *dri_name)
{
	int count;
	char path[PATH_MAX];
	char *name;

	if (!filename || !dri_name)
		return MM_FAIL;

	count = readlink(filename, path, PATH_MAX);
	if (count >= PATH_MAX)
		return MM_FAIL;

	/* For device does not have a driver */
	if (count < 0)
		return 1;

	path[count] = '\0';

	name = strrchr(path, '/');
	if (name) {
		strncpy(dri_name, name + 1, strlen(name + 1) + 1);
		return MM_SUCCESS;
	}

	return MM_FAIL;
}


static int pci_unbind_kernel_driver(char *dev)
{
	FILE *f;
	char filename[PATH_MAX];

	/* open /sys/bus/pci/devices/AAAA:BB:CC.D/driver */
	sprintf(filename,SYSFS_PCI_DEVICES"/%s/driver/unbind",dev);

	f = fopen(filename, "w");
	if (f == NULL) /* device was not bound */
		return MM_SUCCESS;

	if (fwrite(dev, strlen(dev), 1, f) == 0) {
		RUNNING_LOG_ERROR("%s: could not write to %s\n", __FUNCTION__,filename);
		goto error;
	}

	fclose(f);
	return MM_SUCCESS;

error:
	fclose(f);
	return MM_FAIL;
}

static int pci_bind_kernel_driver(char *dev,char *driver)
{
	FILE *f;
	char filename[PATH_MAX];

	/* open /sys/bus/pci/devices/AAAA:BB:CC.D/driver */
	sprintf(filename,"%s/bind",driver);

	f = fopen(filename, "w");
	if (f == NULL) /* device was not bound */
		return MM_SUCCESS;

	if (fwrite(dev, strlen(dev), 1, f) == 0) {
		RUNNING_LOG_ERROR("%s: could not write to %s\n", __FUNCTION__,driver);
		goto error;
	}

	fclose(f);
	return MM_SUCCESS;

error:
	fclose(f);
	return MM_FAIL;
}

static int pci_bind_uio_driver(char *dev)
{
	unsigned long vendor,dev_id;
	char cbuf[PATH_MAX];
	FILE *fp;

	sprintf(cbuf,"%s/%s/vendor",SYSFS_PCI_DEVICES,dev);
	if(eal_parse_sysfs_value(cbuf,&vendor)==MM_FAIL)
		{
		RUNNING_LOG_ERROR("%s : read vendor fail %s\n",__FUNCTION__,cbuf);
		return MM_FAIL;
		}

	sprintf(cbuf,"%s/%s/device",SYSFS_PCI_DEVICES,dev);
	if(eal_parse_sysfs_value(cbuf,&dev_id)==MM_FAIL)
		{
		RUNNING_LOG_ERROR("%s : read device fail %s\n",__FUNCTION__,cbuf);
		return MM_FAIL;
		}


	sprintf(cbuf,"/sys/bus/pci/drivers/igb_uio/new_id",dev,SYSFS_PCI_DEVICES);

	if((fp = fopen(cbuf, "w")) == NULL) {
		RUNNING_LOG_ERROR("%s : open file fail %s\n",__FUNCTION__,cbuf);
		return MM_FAIL;
	}

	sprintf(cbuf,"%x %x",vendor,dev_id);
	RUNNING_LOG_DEBUG("%s : vendor = %llx device = %llx %s\n",__FUNCTION__,vendor,dev_id,cbuf);

	fwrite(cbuf,strlen(cbuf),1,fp);
	fclose(fp);

	sprintf(cbuf,"/sys/bus/pci/drivers/igb_uio/bind",dev,SYSFS_PCI_DEVICES);

	if((fp = fopen(cbuf, "w")) == NULL) {
		RUNNING_LOG_ERROR("%s : open file fail %s\n",__FUNCTION__,cbuf);
		return MM_FAIL;
	}

	fwrite(dev,strlen(dev),1,fp);
	fclose(fp);

	return MM_SUCCESS;
}

static int pci_unbind_uio_driver(char *dev)
{
	FILE *f;

	f = fopen("/sys/bus/pci/drivers/igb_uio/unbind", "w");
	if (f == NULL) /* device was not bound */
		return MM_SUCCESS;

	if (fwrite(dev, strlen(dev), 1, f) == 0) {
		RUNNING_LOG_ERROR("%s: could not write to %s\n", __FUNCTION__,
				"/sys/bus/pci/drivers/igb_uio/unbind");
		goto error;
	}

	fclose(f);
	return MM_SUCCESS;

error:
	fclose(f);
	return MM_FAIL;
}

static int32_t
addr_to_socket(void * addr)
{
	const struct rte_memseg *ms = rte_eal_get_physmem_layout();
	unsigned i;

	for (i = 0; i < RTE_MAX_MEMSEG; i++) {
		if ((ms[i].addr <= addr) &&
				((uintptr_t)addr <
				((uintptr_t)ms[i].addr + (uintptr_t)ms[i].len)))
			return ms[i].socket_id;
	}
	return -1;
}

static uint16_t
add_timestamps(uint8_t port __rte_unused, uint16_t qidx __rte_unused,
		struct rte_mbuf **pkts, uint16_t nb_pkts,
		uint16_t max_pkts __rte_unused, void *_ __rte_unused)
{
	unsigned i;
	uint64_t now = rte_rdtsc();

	for (i = 0; i < nb_pkts; i++)
		pkts[i]->udata64 = now;
	return nb_pkts;
}

static const struct rte_memzone *
memzone_reserve(const char *name, size_t len, int socket_id,
						unsigned flags)
{
	const struct rte_memzone *mz = rte_memzone_lookup(name);

	if (mz == NULL)
		mz = rte_memzone_reserve(name, len, socket_id, flags);

	return mz;
}

/*
void *create_fifo(char *name,uint64_t size,unsigned cz,int socket,struct fifo **fo)
{
	struct rte_memzone *mz;
	struct fifo *f;
	uint64_t sz=size * cz + sizeof(struct fifo);

	mz = memzone_reserve(name, sz,socket, 0);
	if(mz==NULL)
		return NULL;

	*fo=mz->addr;
	fifo_init(*fo, size,cz);

	return mz->addr;
}
*/

/*
void fifo_test()
{
	#define TEST_SZ	(1<<30)
	struct rte_memzone *mz;
	struct fifo *fo;
	int i;
	void *burst = NULL;

#define RX_FIFO_SIZE          (TEST_SZ * sizeof(void *) + sizeof(struct fifo))

	mz = memzone_reserve("test", RX_FIFO_SIZE,0, 0);
	if(mz==NULL)
		RUNNING_LOG_DEBUG("%s fail\n",__FUNCTION__);
	fo=mz->addr;
	fifo_init(fo, TEST_SZ);

	const uint64_t mc_start = rte_rdtsc();
	for (i = 0; i < TEST_SZ; i++) {
		fifo_put(fo,&burst,1);
	}
	const uint64_t mc_end = rte_rdtsc();
	for (i = 0; i < TEST_SZ; i++) {
		fifo_get(fo,&burst,1);
	}
	const uint64_t mc_endx = rte_rdtsc();

		RUNNING_LOG_ERROR("fifo_test: %llu %llu %"PRIu64"\n",
			mc_start,mc_end,(mc_end-mc_start) / TEST_SZ);
		RUNNING_LOG_ERROR("fifo_test2: %llu %llu %"PRIu64"\n",
			mc_end,mc_endx,(mc_endx-mc_end) / TEST_SZ);

}
*/

static void
pkt_info_obj_init(struct rte_mempool *mp, __attribute__((unused)) void *arg,
	    void *obj, unsigned i)
{
	uint32_t *objnum = obj;
	memset(obj, 0, mp->elt_size);
	*objnum = i;
}

static void
pkt_info_init(struct rte_mempool *mp,
		 __attribute__((unused)) void *opaque_arg,
		 void *_m,
		 __attribute__((unused)) unsigned i)
{
	struct pkt_info *m = _m;

	memset(m, 0, mp->elt_size);
	INIT_LIST_HEAD(&m->list);
	m->mp = mp;
}



int prepare_setup()
{
	int i,j,k,y,z;
	int cpu_cnt=0;
	int port_cnt=0;
	struct port_info_s port[MAX_DEV];
	struct rte_mempool *socket_pool[MAX_SOCKET]={NULL};
	struct rte_mempool *socket_io_mp[MAX_SOCKET]={NULL};
	struct rte_mempool *socket_sum_mp[MAX_SOCKET]={NULL};
	char s[64];
	uint64_t mask,mask2,mask3;
	struct rte_malloc_socket_stats sock_stats;
	uint64_t core_cnt[MAX_SOCKET]={0};
	uint64_t c_cnt[MAX_SOCKET]={0};

	RUNNING_LOG_DEBUG("%s ip_g_s2=%d ip_sum_b=%d port_struct=%d\n",
		__FUNCTION__,sizeof(struct ip_g_s2),sizeof(struct ip_sum_b),sizeof(struct port_info_sum));

	memset(port,0,sizeof(port[0])*MAX_DEV);
//	memset(port_stat_per,0,sizeof(port_stat_per[0])*MAX_DEV);
//	memset(port_stat_total,0,sizeof(port_stat_total[0])*MAX_DEV);

#ifdef MBUF_POOL_PERPORT
	for(i=0;i<MAX_DEV;i++)
		{
			snprintf(s, sizeof(s), "pkt_pool_%d",i);
			socket_pool[i]=rte_mempool_create(s, NB_MBUF,
					   MBUF_SIZE, 32,
					   sizeof(struct rte_pktmbuf_pool_private),
					   rte_pktmbuf_pool_init, NULL,
					   rte_pktmbuf_init, NULL,
					   rte_eth_dev_socket_id(i),0);

			if (socket_pool[i] == NULL)
				{
				RUNNING_LOG_ERROR("%s: could not create pkt pool for port %d socket %d\n",
					__FUNCTION__,i,rte_eth_dev_socket_id(i));
				return MM_FAIL;
				}
			else
				{
				RUNNING_LOG_DEBUG("%s: create pkt pool for port %d socket %d NB=%d\n",
					__FUNCTION__,i,rte_eth_dev_socket_id(i),NB_MBUF);
				}

		}
#endif

	rte_malloc_dump_stats(running_log_fp,NULL);

#if 0
	mon_ip_arr.arr=(uint32_t *)rte_zmalloc(NULL, sizeof(uint32_t)*mon_ip_arr.max, 8);
	if(mon_ip_arr.arr==NULL)
		{
		RUNNING_LOG_ERROR("%s: alloc mon_ip_arr fail\n",__FUNCTION__);
		return MM_FAIL;
		}
	mon_ip_arr.curr=0;

	mon_netport_arr.arr=(uint32_t *)rte_zmalloc(NULL, sizeof(uint32_t)*mon_netport_arr.max, 8);
	if(mon_netport_arr.arr==NULL)
		{
		RUNNING_LOG_ERROR("%s: alloc mon_netport_arr fail\n",__FUNCTION__);
		return MM_FAIL;
		}
	mon_netport_arr.curr=0;

	//mon_netport
	mon_netport_core.arr=(uint32_t *)rte_zmalloc(NULL, sizeof(uint32_t)*mon_netport_arr.max, 8);
	if(mon_netport_core.arr==NULL)
		{
		RUNNING_LOG_ERROR("%s: alloc mon netport fail\n",__FUNCTION__);
		return MM_FAIL;
		}
	mon_netport_core.curr=0;
	mon_netport_sig=0;
#endif
#ifdef __MAIN_LOOP_KNI__
	//kni ring
	for(i=0;i<me.port_cnt;i++)
		{
		snprintf(s, sizeof(s), "kni_input_%d",i);
		lcore[me.kni_no].kni.ring_input[i]=rte_ring_create(s,KNI_RING_SZ,
					rte_eth_dev_socket_id(i), RING_F_SC_DEQ);
		if(lcore[me.kni_no].kni.ring_input[i]==NULL)
			{
			RUNNING_LOG_ERROR("%s: alloc linux ring %d fail\n",__FUNCTION__,i);
			return MM_FAIL;
			}
		}

	mask=me.io_in_mask;
#ifdef WF_NAT
	mask=me.io_in_mask |me.io_out_mask;
#ifdef WF_NAT_DIST
	mask=me.distribute_mask;
#endif
#endif
	do
	{
		i=__builtin_ffsll(mask)-1;
		mask &= ~(1ULL<<i);
		for(j=0;j<lcore[i].port_cnt;j++)
		{
			k=lcore[i].port_id[j];//port id
			lcore[i].distribute.kni_ring[j]=lcore[me.kni_no].kni.ring_input[k];
		}
	}while(mask);
#endif	/* #ifdef __MAIN_LOOP_KNI__ */

#ifdef WF_NAT_DIST
	//distribute ring
	mask=me.io_in_mask |me.io_out_mask;

	do
	{
		i=__builtin_ffsll(mask)-1;
		mask &= ~(1ULL<<i);

		for(j=0;j<me.port_cnt;j++)
		{
			//int id=lcore[i].port_id[j];//port id

			snprintf(s, sizeof(s), "main_distribute%d_%d", i,j);
			lcore[i].io_in.ring_input[j]=rte_ring_create(s,me.dist_ring_cnt,
						rte_eth_dev_socket_id(j), RING_F_SC_DEQ);
			if(lcore[i].io_in.ring_input[j]==NULL)
			{
				RUNNING_LOG_ERROR("%s: core %d alloc main distribute ring fail\n",__FUNCTION__,i);
				return MM_FAIL;
			}
		}
	}while(mask);

#endif

	mask=me.sum_mask;
	k=0;
	do
		{
			mask2=me.io_in_mask;
#ifdef WF_NAT
			mask2=me.io_in_mask | me.io_out_mask;
#endif
			int qq=0;

			i=__builtin_ffsll(mask)-1;
			mask &= ~(1ULL<<i);
			do
				{
					j=__builtin_ffsll(mask2)-1;
					mask2 &= ~(1ULL<<j);
					lcore[i].sum.sum_ip_sum2io_burst[qq]=&lcore[j].io_in.ip_sum2io_burst[k];
					lcore[i].sum.sum_ip_io2sum_burst[qq]=&lcore[j].io_in.ip_io2sum_burst[k];

					lcore[i].sum.sum_netport_sum2io_burst[qq]=&lcore[j].io_in.netport_sum2io_burst[k];
					lcore[i].sum.sum_dn1_sum2io_burst[qq]=&lcore[j].io_in.dn1_sum2io_burst[k];

					RUNNING_LOG_DEBUG("%s(%d): sum %d io %d summask=%x iomask=%x qq=%d k=%d "
					" ip_sum2io_burst=%p ip_io2sum_burst=%p netport_sum2io_burst=%p dn1_sum2io_burst=%p\n",
					__FUNCTION__,__LINE__,
						i,j,mask,mask2,qq,k,
						&lcore[j].io_in.ip_sum2io_burst[k],&lcore[j].io_in.ip_io2sum_burst[k],
						&lcore[j].io_in.netport_sum2io_burst[k],&lcore[j].io_in.dn1_sum2io_burst[k]);

					qq++;
				}while(mask2);
			k++;
		}while(mask);


	mask=me.sum_src_mask;
	k=0;
	do
		{
			mask2=me.io_in_mask;
#ifdef WF_NAT
			mask2=me.io_in_mask | me.io_out_mask;
#endif
			int qq=0;

			i=__builtin_ffsll(mask)-1;
			mask &= ~(1ULL<<i);
			do
				{
					j=__builtin_ffsll(mask2)-1;
					mask2 &= ~(1ULL<<j);
					lcore[i].sumsrc.sum_src_s2io_burst[qq]=&lcore[j].io_in.ip_sumsrc2io_burst[k];
					lcore[i].sumsrc.sum_src_io2s_burst[qq]=&lcore[j].io_in.ip_io2sumsrc_burst[k];

					RUNNING_LOG_DEBUG("%s(%d): sumsrc %d io %d summask=%x iomask=%x qq=%d k=%d "
						" ip_sumsrc2io_burst=%p ip_io2sumsrc_burst=%p\n",
						__FUNCTION__,__LINE__,
						i,j,mask,mask2,qq,k,
						&lcore[j].io_in.ip_sumsrc2io_burst[k],&lcore[j].io_in.ip_io2sumsrc_burst[k]);

					qq++;
				}while(mask2);
			k++;
		}while(mask);

	//
#ifdef __SYNC_FLOW_TABLE__
	/* map the flow_nat_sync msg between this nat core and the others */
	{
		int io_cnt;
		int x=0, yy=0;

		mask=me.io_in_mask;
#ifdef WF_NAT
		mask=me.io_in_mask | me.io_out_mask;
#endif

		do
			{
			i=__builtin_ffsll(mask)-1;
			mask &= ~(1ULL<<i);
		}while(mask);
		x=i;

		mask=me.io_in_mask;
#ifdef WF_NAT
		mask=me.io_in_mask | me.io_out_mask;
#endif

		io_cnt = __builtin_popcountll(mask);
		k=0;
		z=0;

		/* the last nat core will catch the msg from miss msg before */
		mask &= ~(1ULL<<x);
		do
			{
				mask2=me.io_in_mask;
#ifdef WF_NAT
				mask2=me.io_in_mask | me.io_out_mask;
#endif
				y=0;
//				x=0;

				i=__builtin_ffsll(mask)-1;
				mask &= ~(1ULL<<i);
				do
					{
						j=__builtin_ffsll(mask2)-1;

						if (i==j)
						{
							mask2 &= ~(1ULL<<j);

							lcore[x].io_in.flow_nat_sync_rcv[yy]=&lcore[j].io_in.flow_nat_sync_snd[y];
							lcore[x].io_in.flow_nat_sync_rcv_back[yy]=&lcore[j].io_in.flow_nat_sync_snd_back[y];

//							RUNNING_LOG_DEBUG("%s(%d): io_rcv(%u).nat_flow_sync_rcv[%u] io_snd(%u).nat_flow_sync_snd[%u] mask=%#x mask2=%#x\n"
//								" flow_nat_sync_snd=%p(%u) flow_nat_sync_snd_back=%p(%u)\n",
//								__FUNCTION__,__LINE__,
//								x,yy,j,y,mask,mask2,
//								&lcore[j].io_in.flow_nat_sync_snd[k],lcore[j].io_in.flow_nat_sync_snd[y].load,
//								&lcore[j].io_in.flow_nat_sync_snd_back[k],lcore[j].io_in.flow_nat_sync_snd_back[y].load);

							yy++;
							continue;
						}

						mask2 &= ~(1ULL<<j);

						/* ignore the core itself */
						z=(k)%(io_cnt-1);

						lcore[i].io_in.flow_nat_sync_rcv[y]=&lcore[j].io_in.flow_nat_sync_snd[z];
						lcore[i].io_in.flow_nat_sync_rcv_back[y]=&lcore[j].io_in.flow_nat_sync_snd_back[z];

//						RUNNING_LOG_DEBUG("%s(%d): io_rcv(%u).nat_flow_sync_rcv[%u] io_snd(%u).nat_flow_sync_snd[%u] mask=%#x mask2=%#x\n"
//							" flow_nat_sync_snd=%p(%u) flow_nat_sync_snd_back=%p(%u)\n",
//							__FUNCTION__,__LINE__,
//							i,y,j,z,mask,mask2,
//							&lcore[j].io_in.flow_nat_sync_snd[k],lcore[j].io_in.flow_nat_sync_snd[z].load,
//							&lcore[j].io_in.flow_nat_sync_snd_back[k],lcore[j].io_in.flow_nat_sync_snd_back[z].load);

						y++;
						/* As ignore the self core, the last array is useless */
//						if (++y==io_cnt-1)
//							break;
					}while(mask2);
				k++;
//				if (k==io_cnt-1)
//					break;
			}while(mask);
	}
#endif

	//msg src2io
	mask=me.io_in_mask;
#ifdef WF_NAT
	mask=me.io_in_mask | me.io_out_mask;
#endif
	k=0;
	do
		{
			mask2=me.sum_src_mask;
			int qq=0;

			i=__builtin_ffsll(mask)-1;
			mask &= ~(1ULL<<i);
			do
				{
					j=__builtin_ffsll(mask2)-1;
					mask2 &= ~(1ULL<<j);

					lcore[i].io_in.msg_sumsrc2io_send[qq]=&lcore[j].sumsrc.msg_sumsrc2io_send[k];
					lcore[i].io_in.msg_sumsrc2io_back[qq]=&lcore[j].sumsrc.msg_sumsrc2io_back[k];

					RUNNING_LOG_INFO("%s(%d): sum %d io %d summask=%x iomask=%x qq=%d k=%d "
						" msg_bwl_def_send=%p msg_bwl_def_back=%p\n",
						__FUNCTION__,__LINE__,
						i,j,mask,mask2,qq,k,
						&lcore[j].sumsrc.msg_sumsrc2io_send[k],&lcore[j].sumsrc.msg_sumsrc2io_back[k]);

					qq++;
				}while(mask2);
			k++;
		}while(mask);

/*
	mask=me.pcap_mask;
	k=0;
	do
		{
			mask2=me.io_in_mask;
#ifdef WF_NAT
			mask2|= me.io_out_mask;
#endif
			int qq=0;

			i=__builtin_ffsll(mask)-1;
			mask &= ~(1ULL<<i);
			do
				{
					j=__builtin_ffsll(mask2)-1;
					mask2 &= ~(1ULL<<j);
					lcore[i].pcap.pcap_io2pcap_burst[qq]=&lcore[j].io_in.io2pcap_burst[k];
					lcore[i].pcap.pcap_io2pcap_back[qq]=&lcore[j].io_in.pcap2io_burst[k];


//					EARLY_LOG_DEBUG("%s(%d): pcap %d io %d pcapmask=%x iomask=%x qq=%d k=%d "
//					" ip_pcap2io_burst=%p ip_io2pcap_burst=%p\n",
//					__FUNCTION__,__LINE__,
//						i,j,mask,mask2,qq,k,
//						&lcore[j].io_in.io2pcap_burst[k],&lcore[j].io_in.pcap2io_burst[k]);

					qq++;
				}while(mask2);
			k++;
		}while(mask);
*/
#ifdef PIPE_OUT_LIST_MODE
{
		int a,b,g,w,h,x;

		mask=me.io_out_mask;
		do
			{
			j=__builtin_ffsll(mask)-1;
			mask &= ~(1ULL<<j);

			for(i=0;i<lcore[j].port_cnt;i++)
				{
				mask2=me.port2core_mask_in[lcore[j].port_id[i]];

				do
					{
					k=__builtin_ffsll(mask2)-1;
					mask2 &= ~(1ULL<<k);

					for(y=0;y<lcore[k].port_cnt;y++)//search out port idx
						{
						if(lcore[j].port_id[i]==lcore[k].port_id[y])
							break;
						}

					if(unlikely(lcore[j].port_id[i]!=lcore[k].port_id[y]))
						{
						RUNNING_LOG_ERROR("error out port map\n");
						return MM_FAIL;
						}

//					lcore[j].io_out.port_do_pop[i].port_id=lcore[j].port_id[i];
//					lcore[k].io_in.port_do_push[y].port_id=lcore[j].port_id[i];



					a=lcore[j].io_out.port_do_pop[i].count;
					b=lcore[k].io_in.port_do_push[y].count;
					lcore[j].io_out.port_do_pop[i].remote_submit_list[a]=
						&lcore[k].io_in.port_do_push[y].submit_list[b];
					lcore[j].io_out.port_do_pop[i].remote_back_list[a]=
						&lcore[k].io_in.port_do_push[y].back_list[b];

					lcore[j].io_out.port_do_pop[i].count++;
					lcore[k].io_in.port_do_push[y].count++;
					}while(mask2);
				}

			}while(mask);


}

#if 1//debug
{
			mask=me.io_in_mask;
			do
				{
					j=__builtin_ffsll(mask)-1;
					mask &= ~(1ULL<<j);

					for(i=0;i<lcore[j].port_cnt;i++)
						{
						RUNNING_LOG_INFO("core in<%d>: portidx=%d port_cnt=%d count%d portid=%d\n",
							j,i,lcore[j].port_cnt,lcore[j].io_in.port_do_push[i].count,lcore[j].port_id[i]);

						for(k=0;k<lcore[j].io_in.port_do_push[i].count;k++)
							{
							RUNNING_LOG_INFO(">>>> no %d id %d sub %p back %p\n",
								k,lcore[j].io_in.port_do_push[i].port_id,
								&lcore[j].io_in.port_do_push[i].submit_list[k],
								&lcore[j].io_in.port_do_push[i].back_list[k]);
							}
						}

				}while(mask);


			mask=me.io_out_mask;
			do
				{
					j=__builtin_ffsll(mask)-1;
					mask &= ~(1ULL<<j);

					for(i=0;i<lcore[j].port_cnt;i++)
						{
						RUNNING_LOG_INFO("core out<%d>: portidx=%d port_cnt=%d count%d portid=%d\n",
							j,i,lcore[j].port_cnt,lcore[j].io_out.port_do_pop[i].count,lcore[j].port_id[i]);

						for(k=0;k<lcore[j].io_out.port_do_pop[i].count;k++)
							{
							RUNNING_LOG_INFO(">>>> no %d id %d rsub %p rback %p\n",
								k,lcore[j].io_out.port_do_pop[i].port_id,
								lcore[j].io_out.port_do_pop[i].remote_submit_list[k],
								lcore[j].io_out.port_do_pop[i].remote_back_list[k]);
							}

						for(k=0;k<lcore[j].io_out.port_do_pop[i].port_queue_arr_sz;k++)
							{
							RUNNING_LOG_INFO("[%d]=%d \n",
								k,lcore[j].io_out.port_do_pop[i].port_queue_arr[k]);
							}

						}

				}while(mask);
}
#endif

#endif

	for(i=0;i<MAX_CPU;i++)
		{
		int o=rte_lcore_to_socket_id(i);
		lcore[i].core_id = (uint8_t)i;


		if(lcore[i].type==FUN_IO_IN || lcore[i].type==FUN_IO_OUT)
			{
			int a;
			struct hash_array *p;
			struct ip_g_s2 *ip;
			struct l4_port_g_s2 *netport;
			struct flow_s *flow;
			struct flow_tag *flowtag;
			struct flow_nat *flownat;
			struct out_burst_cell *out_cell;
			struct dnat_config *dnatconfig;
			struct snat_ip *snatip;
            struct toa_vip *toaip;
			struct src_sum *ss;
//			struct msg_io2dis_rsp_flow *msg_io2dis;
			struct hash_array *ptimer;
#ifdef __SRC_SUM__
			struct io_src_policy *srcip_policy;
#endif
#ifdef	__SYNC_FLOW_TABLE__
			struct flow_nat_msg *flow_msg_snd;
#endif

//			memset(lcore[i].io_in.port_do_push,0,sizeof(lcore[i].io_in.port_do_push[0])*MAX_DEV);
#ifdef PIPE_OUT_LIST_MODE
				{
				for(k=0;k<MAX_DEV;k++)
					{
					for(j=0;j<MAX_CPU;j++)
						{
						INIT_LIST_HEAD(&lcore[i].io_in.port_do_push[k].back_list[j].header);
//						INIT_LIST_HEAD(&lcore[i].io_in.port_do_push[k].pending_list[j].header);
						INIT_LIST_HEAD(&lcore[i].io_in.port_do_push[k].submit_list[j].header);
						}
					}

				//out pool
				out_cell=(struct out_burst_cell *)rte_zmalloc_socket(NULL, sizeof(struct out_burst_cell)*me.io_output_pool_cnt, 8,o);
				if(out_cell==NULL)
					{
					RUNNING_LOG_ERROR("%s: alloc core %d out_cell pool %d fail\n",__FUNCTION__,i,me.io_output_pool_cnt);
					return MM_FAIL;
					}
				INIT_LIST_HEAD(&lcore[i].io_in.out_pool.header);
				for(k=0;k<me.io_output_pool_cnt;k++,out_cell++)
					{
					INIT_LIST_HEAD(&out_cell->alloc_list);
					list_add_tail(&out_cell->alloc_list,&lcore[i].io_in.out_pool.header);
					}
				lcore[i].io_in.out_pool.load=me.io_output_pool_cnt;
				}
#endif

			//netport pool
			netport=(struct l4_port_g_s2 *)rte_zmalloc_socket(NULL, sizeof(struct l4_port_g_s2)*me.io_netport_pool_cnt, 8,o);
			if(netport==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d netport pool %d fail\n",__FUNCTION__,i,me.io_netport_pool_cnt);
				return MM_FAIL;
				}
			INIT_LIST_HEAD(&lcore[i].io_in.netport_pool.header);
			for(k=0;k<me.io_netport_pool_cnt;k++,netport++)
				{
				INIT_LIST_HEAD(&netport->alloc_list);
				list_add_tail(&netport->alloc_list,&lcore[i].io_in.netport_pool.header);
				}
			lcore[i].io_in.netport_pool.load=me.io_netport_pool_cnt;

			//ip hash
			lcore[i].io_in.io_in_hash=(struct hash_array *)rte_zmalloc_socket(NULL, sizeof(struct hash_array)*IP_HASH_ARRAY_SZ, 8,o);
			if(lcore[i].io_in.io_in_hash==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d ip_hash_sub fail\n",__FUNCTION__,i);
				return MM_FAIL;
				}

			for(a=0,p=lcore[i].io_in.io_in_hash;a<IP_HASH_ARRAY_SZ;a++,p++)
			   INIT_LIST_HEAD(&p->header);

			//ip pool
			ip=(struct ip_g_s2 *)rte_zmalloc_socket(NULL, sizeof(struct ip_g_s2)*me.io_ip_pool_cnt, 8,o);
			if(ip==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d ip pool %d fail\n",__FUNCTION__,i,me.io_ip_pool_cnt);
				return MM_FAIL;
				}

			// srcip sum pool
			ss=(struct src_sum *)rte_zmalloc_socket(NULL, sizeof(struct src_sum)*me.io_srcsum_pool_cnt, 8,o);
			if(ss==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d src cell pool fail\n",__FUNCTION__,i);
				return MM_FAIL;
				}

			INIT_LIST_HEAD(&lcore[i].io_in.srcsum_pool.header);
			for(k=0;k<me.io_srcsum_pool_cnt;k++,ss++)
				{
				INIT_LIST_HEAD(&ss->pending_list);
				INIT_LIST_HEAD(&ss->list);
				list_add_tail(&ss->pending_list,&lcore[i].io_in.srcsum_pool.header);
				}
			lcore[i].io_in.srcsum_pool.load=me.io_srcsum_pool_cnt;

//			lcore[i].io_in.ip_pool.load=0;
			INIT_LIST_HEAD(&lcore[i].io_in.ip_pool.header);
			for(k=0;k<me.io_ip_pool_cnt;k++,ip++)
				{
				INIT_LIST_HEAD(&ip->list);
				INIT_LIST_HEAD(&ip->pending_list);
				list_add_tail(&ip->list,&lcore[i].io_in.ip_pool.header);
				}
			lcore[i].io_in.ip_pool.load=me.io_ip_pool_cnt;

			//pcap pool
//			struct pcap_ship *pcap=(struct pcap_ship *)rte_zmalloc_socket(NULL, sizeof(struct pcap_ship)*me.pcap_pool_cnt, 8,o);
//			if(pcap==NULL)
//				{
//				RUNNING_LOG_ERROR("%s: alloc core %d pcap pool %d fail\n",__FUNCTION__,i,me.pcap_pool_cnt);
//				return MM_FAIL;
//				}

//			INIT_LIST_HEAD(&lcore[i].io_in.pcap_pool.header);
//			for(k=0;k<me.pcap_pool_cnt;k++,pcap++)
//				{
//				INIT_LIST_HEAD(&pcap->list);
//				list_add_tail(&pcap->list,&lcore[i].io_in.pcap_pool.header);
//				}
//			lcore[i].io_in.pcap_pool.load=me.pcap_pool_cnt;

#ifdef __SYNC_FLOW_TABLE__


			// srcip sum pool
			flow_msg_snd=(struct flow_nat_msg *)rte_zmalloc_socket(NULL, sizeof(struct flow_nat_msg)*me.io_flow_nat_sync_msg_cnt, 8,o);
			if(flow_msg_snd==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d sync flow cell pool fail\n",__FUNCTION__,i);
				return MM_FAIL;
				}

			INIT_LIST_HEAD(&lcore[i].io_in.flow_nat_sync_pool.header);
			for(k=0;k<me.io_flow_nat_sync_msg_cnt;k++,flow_msg_snd++)
				{
				INIT_LIST_HEAD(&flow_msg_snd->list);
				list_add_tail(&flow_msg_snd->list,&lcore[i].io_in.flow_nat_sync_pool.header);
				}
			lcore[i].io_in.flow_nat_sync_pool.load=me.io_flow_nat_sync_msg_cnt;


#endif

#if 0
			//flow hash
			lcore[i].io_in.io_flow_hash=(struct hash_array *)rte_zmalloc_socket(NULL, sizeof(struct hash_array)*FLOW_HASH_ARRAY_SZ, 8,o);
			if(lcore[i].io_in.io_flow_hash==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d flow_hash_sub fail\n",__FUNCTION__,i);
				return MM_FAIL;
				}

			for(a=0;a<FLOW_HASH_ARRAY_SZ;a++)
			   INIT_LIST_HEAD(&lcore[i].io_in.io_flow_hash[a].header);

			//flow pool
			flow=(struct flow_s *)rte_zmalloc_socket(NULL, sizeof(struct flow_s)*me.io_flow_pool_cnt, 8,o);
			if(flow==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d flow pool %d fail\n",__FUNCTION__,i,me.io_flow_pool_cnt);
				return MM_FAIL;
				}

			INIT_LIST_HEAD(&lcore[i].io_in.flow_pool.header);
			for(k=0;k<me.io_flow_pool_cnt;k++,flow++)
				{
				INIT_LIST_HEAD(&flow->alloc_list);
				INIT_LIST_HEAD(&flow->tbl_list);
				flow->type=TYPE_FLOW_STRUCT;
				list_add_tail(&flow->alloc_list,&lcore[i].io_in.flow_pool.header);
				}
			lcore[i].io_in.flow_pool.load=me.io_flow_pool_cnt;

			//flowtag pool
			flowtag=(struct flow_tag *)rte_zmalloc_socket(NULL, sizeof(struct flow_tag)*me.io_flowtag_pool_cnt, 8,o);
			if(flowtag==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d flowtag pool %d fail\n",__FUNCTION__,i,me.io_flowtag_pool_cnt);
				return MM_FAIL;
				}

			INIT_LIST_HEAD(&lcore[i].io_in.flowtag_pool.header);
			for(k=0;k<me.io_flowtag_pool_cnt;k++,flowtag++)
				{
				INIT_LIST_HEAD(&flowtag->alloc_list);
				INIT_LIST_HEAD(&flowtag->tbl_list);
				flowtag->type=TYPE_FLOW_TAG;
				list_add_tail(&flowtag->alloc_list,&lcore[i].io_in.flowtag_pool.header);
				}
			lcore[i].io_in.flowtag_pool.load=me.io_flowtag_pool_cnt;
#endif

#ifdef WF_NAT
			//flownat hash
			lcore[i].io_in.io_flownat_hash=(struct hash_array *)rte_zmalloc_socket(NULL, sizeof(struct hash_array)*FLOWNAT_HASH_ARRAY_SZ, 8,o);
			if(lcore[i].io_in.io_flownat_hash == NULL)
			{
				RUNNING_LOG_ERROR("%s: alloc core %d io_natflow_hash fail\n", __FUNCTION__,i);
				return MM_FAIL;
			}

			for(a=0; a<FLOWNAT_HASH_ARRAY_SZ; a++)
			{
				INIT_LIST_HEAD(&lcore[i].io_in.io_flownat_hash[a].header);
			}

			//flownat pool
			flownat=(struct flow_nat *)rte_zmalloc_socket(NULL, sizeof(struct flow_nat)*me.io_flownat_pool_cnt, 8, o);
			if(flownat==NULL)
			{
				RUNNING_LOG_ERROR("%s: alloc core %d flownat pool %d 	fail\n",__FUNCTION__,i,me.io_flownat_pool_cnt);
				return MM_FAIL;
			}

			INIT_LIST_HEAD(&lcore[i].io_in.flownat_pool.header);
			for(k=0; k < me.io_flownat_pool_cnt; k++, flownat++)
			{
				INIT_LIST_HEAD(&flownat->alloc_list);
				INIT_LIST_HEAD(&flownat->nat_tuplehash[0].listnode);
				INIT_LIST_HEAD(&flownat->nat_tuplehash[1].listnode);
				INIT_LIST_HEAD(&flownat->nat_tuplehash[0].src_list);
				INIT_LIST_HEAD(&flownat->nat_tuplehash[1].src_list);
				list_add_tail(&flownat->alloc_list, &lcore[i].io_in.flownat_pool.header);
			}
			lcore[i].io_in.flownat_pool.load=me.io_flownat_pool_cnt;

			//dnat_config_hash
			lcore[i].io_in.dnat_config_hash=(struct hash_array *)rte_zmalloc_socket(NULL, sizeof(struct hash_array)*DNAT_CONFIG_HASH_ARRAY_SZ, 8, o);
			if(lcore[i].io_in.dnat_config_hash == NULL)
			{
				RUNNING_LOG_ERROR("%s: alloc core %d dnat_config_hash fail\n", __FUNCTION__,i);
				return MM_FAIL;
			}

			for(a=0; a<DNAT_CONFIG_HASH_ARRAY_SZ; a++)
			{
				INIT_LIST_HEAD(&lcore[i].io_in.dnat_config_hash[a].header);
			}

			//dnat_config pool
			dnatconfig=(struct dnat_config *)rte_zmalloc_socket(NULL, sizeof(struct dnat_config)*DNAT_CONFIG_HASH_ARRAY_SZ, 8, o);
			if(dnatconfig==NULL)
			{
				RUNNING_LOG_ERROR("%s: alloc core %d dnat_config pool fail,cnt=%d\n",__FUNCTION__,i,DNAT_CONFIG_HASH_ARRAY_SZ);
				return MM_FAIL;
			}

			INIT_LIST_HEAD(&lcore[i].io_in.dnatconfig_pool.header);
			for(k=0; k < DNAT_CONFIG_HASH_ARRAY_SZ; k++, dnatconfig++)
			{
				INIT_LIST_HEAD(&dnatconfig->tbl_list);
				INIT_LIST_HEAD(&dnatconfig->alloc_list);
				list_add_tail(&dnatconfig->alloc_list, &lcore[i].io_in.dnatconfig_pool.header);
			}
			lcore[i].io_in.dnatconfig_pool.load=DNAT_CONFIG_HASH_ARRAY_SZ;


			//snat_ip hash
			lcore[i].io_in.io_srcip_hash=(struct hash_array *)rte_zmalloc_socket(NULL, sizeof(struct hash_array)*IP_HASH_ARRAY_SZ, 8,o);
			if(lcore[i].io_in.io_srcip_hash == NULL)
			{
				RUNNING_LOG_ERROR("%s: alloc core %d io_srcip_hash fail\n", __FUNCTION__,i);
				return MM_FAIL;
			}

			for(k=0; k<IP_HASH_ARRAY_SZ; k++)
			{
				INIT_LIST_HEAD(&lcore[i].io_in.io_srcip_hash[k].header);
			}

			//snat_ip pool
			snatip=(struct snat_ip *)rte_zmalloc_socket(NULL, sizeof(struct snat_ip)*IP_HASH_ARRAY_SZ, 8, o);
			if(snatip==NULL)
			{
				RUNNING_LOG_ERROR("%s: alloc core %d srcipnat pool %d fail\n",__FUNCTION__,i,IP_HASH_ARRAY_SZ);
				return MM_FAIL;
			}

			INIT_LIST_HEAD(&lcore[i].io_in.srcipnat_pool.header);
			for(k=0; k < IP_HASH_ARRAY_SZ; k++, snatip++)
			{
				INIT_LIST_HEAD(&snatip->alloc_list);
				list_add_tail(&snatip->alloc_list, &lcore[i].io_in.srcipnat_pool.header);
			}
			lcore[i].io_in.srcipnat_pool.load=IP_HASH_ARRAY_SZ;

            	        //toa_vip hash
			lcore[i].io_in.io_viptoa_hash=(struct hash_array *)rte_zmalloc_socket(NULL, sizeof(struct hash_array)*TOA_IP_HASH_ARRAY_SZ, 8,o);
			if(lcore[i].io_in.io_viptoa_hash == NULL)
			{
				RUNNING_LOG_ERROR("%s: alloc core %d io_viptoa_hash fail\n", __FUNCTION__,i);
				return MM_FAIL;
			}

			for(k=0; k<TOA_IP_HASH_ARRAY_SZ; k++)
			{
				INIT_LIST_HEAD(&lcore[i].io_in.io_viptoa_hash[k].header);
			}

#ifdef __SRC_SUM__
			//sum srcip hash
			lcore[i].io_in.sumsrc_srcip_hash=(struct hash_array *)rte_zmalloc_socket(NULL, sizeof(struct hash_array)*IP_HASH_ARRAY_SZ, 8,o);
			if(lcore[i].io_in.sumsrc_srcip_hash == NULL)
			{
				RUNNING_LOG_ERROR("%s: alloc core %d sumsrc_srcip_hash fail\n", __FUNCTION__,i);
				return MM_FAIL;
			}

			for(k=0; k<IP_HASH_ARRAY_SZ; k++)
			{
				INIT_LIST_HEAD(&lcore[i].io_in.sumsrc_srcip_hash[k].header);
			}

			srcip_policy=(struct io_src_policy *)rte_zmalloc_socket(NULL, sizeof(struct io_src_policy)*me.io_srcip_policy_pool_cnt, 8,o);
			if(srcip_policy==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d io src policy pool %d fail\n",__FUNCTION__,i,me.io_srcip_policy_pool_cnt);
				return MM_FAIL;
				}

			lcore[i].io_in.srcip_policy_pool.load=0;
			INIT_LIST_HEAD(&lcore[i].io_in.srcip_policy_pool.header);
			for(k=0;k<me.io_srcip_policy_pool_cnt;k++,srcip_policy++)
				{
				INIT_LIST_HEAD(&srcip_policy->list);
				list_add_tail(&srcip_policy->list,&lcore[i].io_in.srcip_policy_pool.header);
				lcore[i].io_in.srcip_policy_pool.load++;
				}

			//policy hash
			lcore[i].io_in.srcip_policy_hash=(struct hash_array *)rte_zmalloc_socket(NULL, sizeof(struct hash_array)*IP_HASH_ARRAY_SZ, 8,o);
			if(lcore[i].io_in.srcip_policy_hash==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d srcip_policy_hash fail\n",__FUNCTION__,i);
				return MM_FAIL;
				}

			for(a=0,p=lcore[i].io_in.srcip_policy_hash;a<IP_HASH_ARRAY_SZ;a++,p++)
			   INIT_LIST_HEAD(&p->header);
#endif
			//toa_vip pool
			toaip=(struct toa_vip *)rte_zmalloc_socket(NULL, sizeof(struct toa_vip)*TOA_IP_HASH_ARRAY_SZ, 8, o);
			if(toaip==NULL)
			{
				RUNNING_LOG_ERROR("%s: alloc core %d toaip pool %d fail\n",__FUNCTION__,i,TOA_IP_HASH_ARRAY_SZ);
				return MM_FAIL;
			}

			INIT_LIST_HEAD(&lcore[i].io_in.viptoa_pool.header);
			for(k=0; k < TOA_IP_HASH_ARRAY_SZ; k++, toaip++)
			{
				INIT_LIST_HEAD(&toaip->alloc_list);
				list_add_tail(&toaip->alloc_list, &lcore[i].io_in.viptoa_pool.header);
			}
			lcore[i].io_in.viptoa_pool.load=TOA_IP_HASH_ARRAY_SZ;

			//flowtimer
			lcore[i].io_in.flowtimer=(struct hash_array *)rte_zmalloc_socket(NULL, sizeof(struct hash_array)*TIMER_LOOP_SZ, 8,o);
			if(lcore[i].io_in.flowtimer==NULL)
			{
				RUNNING_LOG_ERROR("%s: alloc core %d flowtimer fail\n",__FUNCTION__,i);
				return MM_FAIL;
			}
			for(k=0,ptimer=lcore[i].io_in.flowtimer; k<TIMER_LOOP_SZ; k++,ptimer++)
			   INIT_LIST_HEAD(&ptimer->header);
#endif

			for(k=0;k<MAX_CPU;k++)
				{
				INIT_LIST_HEAD(&lcore[i].io_in.ip_io2sum_pending[k].header);
				INIT_LIST_HEAD(&lcore[i].io_in.ip_io2sum_burst[k].header);
				INIT_LIST_HEAD(&lcore[i].io_in.ip_sum2io_burst[k].header);
				INIT_LIST_HEAD(&lcore[i].io_in.ip_io2sumsrc_burst[k].header);
				INIT_LIST_HEAD(&lcore[i].io_in.ip_sumsrc2io_burst[k].header);

#ifdef	__SYNC_FLOW_TABLE__
				INIT_LIST_HEAD(&lcore[i].io_in.flow_nat_sync_snd[k].header);
				INIT_LIST_HEAD(&lcore[i].io_in.flow_nat_sync_snd_back[k].header);
#endif
//				INIT_LIST_HEAD(&lcore[i].io_in.io2pcap_burst[k].header);
//				INIT_LIST_HEAD(&lcore[i].io_in.pcap2io_burst[k].header);
//				INIT_LIST_HEAD(&lcore[i].io_in.netport_sum2io_burst[k].header);
//				INIT_LIST_HEAD(&lcore[i].io_in.dn1_sum2io_burst[k].header);
				}

			//timer
			lcore[i].localtimer.queue_sz=IN_TIMER_ROUND_SZ;
			lcore[i].localtimer.pointer=0;
			lcore[i].localtimer.handler=in_timer_handler;
			lcore[i].localtimer.event=(struct hash_array *)rte_malloc_socket(NULL,
				sizeof(struct hash_array)*lcore[i].localtimer.queue_sz, 8,o);
			if(lcore[i].localtimer.event==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d localtimer fail %d\n",__FUNCTION__,i,lcore[i].localtimer.queue_sz);
				return MM_FAIL;
				}

			for(j=0;j<lcore[i].localtimer.queue_sz;j++)
				{
				lcore[i].localtimer.event[j].load=0;
				INIT_LIST_HEAD(&lcore[i].localtimer.event[j].header);
				}

#ifdef WF_NAT
			lcore[i].localtimer.natlist = (struct hash_array *)rte_malloc_socket(NULL, sizeof(struct hash_array)*lcore[i].localtimer.queue_sz, 8,o);
			if(lcore[i].localtimer.natlist==NULL)
			{
				RUNNING_LOG_ERROR("%s: alloc core %d localtimer natlist fail \n",__FUNCTION__,i);
				return MM_FAIL;
			}
			for(j=0;j<lcore[i].localtimer.queue_sz;j++)
			{
				lcore[i].localtimer.natlist[j].load=0;
				INIT_LIST_HEAD(&lcore[i].localtimer.natlist[j].header);
			}
#endif

#ifndef WF_NAT_DIST
			//port setup
			for(k=0;k<lcore[i].port_cnt;k++)
				{
				if(port[lcore[i].port_id[k]].flag==0)
					{
					port[lcore[i].port_id[k]].socket=rte_eth_dev_socket_id(lcore[i].port_id[k]);
					port[lcore[i].port_id[k]].flag=1;
					port_cnt++;

					if(port[lcore[i].port_id[k]].socket==0xff)
						port[lcore[i].port_id[k]].socket=0;

					if(socket_pool[port[lcore[i].port_id[k]].socket]==NULL)
						{
						snprintf(s, sizeof(s), "pkt_pool_%d",port[lcore[i].port_id[k]].socket);
						socket_pool[port[lcore[i].port_id[k]].socket]=rte_mempool_create(s, NB_MBUF,
								   MBUF_SIZE, 32,
								   sizeof(struct rte_pktmbuf_pool_private),
								   rte_pktmbuf_pool_init, NULL,
								   rte_pktmbuf_init, NULL,
								   port[lcore[i].port_id[k]].socket, 0);

						if (socket_pool[port[lcore[i].port_id[k]].socket] == NULL)
							{
							RUNNING_LOG_ERROR("%s: could not create pkt pool for socket %d\n",
								__FUNCTION__,port[lcore[i].port_id[k]].socket);
							return MM_FAIL;
							}
						else
							{
							RUNNING_LOG_DEBUG("%s: create pkt pool for socket %d NB=%d\n",
								__FUNCTION__,port[lcore[i].port_id[k]].socket,NB_MBUF);
							}
						}
					}
				RUNNING_LOG_DEBUG("%s: check port %d rxq=%d core %d queue %d k=%d\n",
					__FUNCTION__,lcore[i].port_id[k],port[lcore[i].port_id[k]].rx_queue_cnt,
					i,lcore[i].queue_id[k],k);

				if(port[lcore[i].port_id[k]].rx_queue_cnt<lcore[i].queue_id[k])
					port[lcore[i].port_id[k]].rx_queue_cnt=lcore[i].queue_id[k];
				}
#endif

			}
		else if(lcore[i].type==FUN_SUM)
			{
			int a;
			struct hash_array *p;
			struct ip_sum_b *ip;
			struct l4_port_sum_b *netport;
			struct l4_port_g_b *netport_tbl;
			struct dn1_sum_b *dn1;
			struct dn1_pending *dn1_hash;

			//mon_ip
			lcore[i].sum.mon_ip_core[0].arr=(uint32_t *)rte_zmalloc_socket(NULL, sizeof(uint32_t)*mon_ip_arr.max, 8,o);
			if(lcore[i].sum.mon_ip_core[0].arr==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc mon ip 0 fail\n",__FUNCTION__,i);
				return MM_FAIL;
				}
			lcore[i].sum.mon_ip_core[0].curr=0;

			lcore[i].sum.mon_ip_core[1].arr=(uint32_t *)rte_zmalloc_socket(NULL, sizeof(uint32_t)*mon_ip_arr.max, 8,o);
			if(lcore[i].sum.mon_ip_core[1].arr==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc mon ip 1 fail\n",__FUNCTION__,i);
				return MM_FAIL;
				}
			lcore[i].sum.mon_ip_core[1].curr=0;

			lcore[i].sum.mon_ip_burst=(struct ip_sum_b **)rte_zmalloc_socket(NULL, sizeof(struct ip_sum_b *)*mon_ip_arr.max, 8,o);
			if(lcore[i].sum.mon_ip_burst==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc mon ip burst fail\n",__FUNCTION__,i);
				return MM_FAIL;
				}

			lcore[i].sum.mon_ip_idx=0;
			lcore[i].sum.mon_ip_switch=0;


			//netport pool
			netport_tbl=(struct l4_port_g_b*)rte_zmalloc_socket(NULL, sizeof(struct l4_port_g_b)*65536*2, 8,o);
			if(netport_tbl==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d netport_tbl fail\n",__FUNCTION__,i);
				return MM_FAIL;
				}

			lcore[i].sum.netport_tbl[0]=netport_tbl;
			lcore[i].sum.netport_tbl[1]=&netport_tbl[65536];
			for(k=0;k<65536;k++)
				{
				INIT_LIST_HEAD(&netport_tbl[k].chain.header);
				INIT_LIST_HEAD(&netport_tbl[k+65536].chain.header);
				netport_tbl[k].no=k;
				netport_tbl[k+65536].no=k;
				}

			netport=(struct l4_port_sum_b *)rte_zmalloc_socket(NULL, sizeof(struct l4_port_sum_b)*me.sum_netport_pool_cnt, 8,o);
			if(netport==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d netport sum pool %d fail\n",__FUNCTION__,i,me.sum_netport_pool_cnt);
				return MM_FAIL;
				}
			INIT_LIST_HEAD(&lcore[i].sum.netport_sum_pool.header);
			for(k=0;k<me.sum_netport_pool_cnt;k++,netport++)
				{
				INIT_LIST_HEAD(&netport->list_tbl);
				INIT_LIST_HEAD(&netport->alloc_list);
				INIT_LIST_HEAD(&netport->list_ip);
				list_add_tail(&netport->alloc_list,&lcore[i].sum.netport_sum_pool.header);
				}
			lcore[i].sum.netport_sum_pool.load=me.sum_netport_pool_cnt;

			//ip pool
			ip=(struct ip_sum_b *)rte_zmalloc_socket(NULL, sizeof(struct ip_sum_b)*me.sum_ip_pool_cnt, 8,o);
			if(ip==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d sum ip pool %d fail\n",__FUNCTION__,i,me.sum_ip_pool_cnt);
				return MM_FAIL;
				}

			lcore[i].sum.ip_sum_pool.load=0;
			INIT_LIST_HEAD(&lcore[i].sum.ip_sum_pool.header);
			for(k=0;k<me.sum_ip_pool_cnt;k++,ip++)
				{
				INIT_LIST_HEAD(&ip->list);
				INIT_LIST_HEAD(&ip->alloc_list);
//				INIT_LIST_HEAD(&ip->submit_list);
				list_add_tail(&ip->alloc_list,&lcore[i].sum.ip_sum_pool.header);
				lcore[i].sum.ip_sum_pool.load++;
				}
//			lcore[i].sum.ip_sum_pool.load=me.sum_ip_pool_cnt;

			for(k=0;k<MAX_CPU;k++)
				{
				INIT_LIST_HEAD(&lcore[i].sum.sum_sum2io_pending[k].header);
				INIT_LIST_HEAD(&lcore[i].sum.sum_netport_sum2io_pending[k].header);
				INIT_LIST_HEAD(&lcore[i].sum.sum_dn1_sum2io_pending[k].header);
				}

			//ip hash
			lcore[i].sum.sum_hash=(struct hash_array *)rte_zmalloc_socket(NULL, sizeof(struct hash_array)*IP_HASH_ARRAY_SZ, 8,o);
			if(lcore[i].sum.sum_hash==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d sum_hash_sub fail\n",__FUNCTION__,i);
				return MM_FAIL;
				}

			for(a=0,p=lcore[i].sum.sum_hash;a<IP_HASH_ARRAY_SZ;a++,p++)
			   INIT_LIST_HEAD(&p->header);

			//wd
			wd_register(lcore[i].sum.wd,lcore[i].sum.wd_valid_cnt,WD_PPS_DST,&ip_pps_dst_ops);
			lcore[i].sum.wd_valid_cnt++;
			wd_register(lcore[i].sum.wd,lcore[i].sum.wd_valid_cnt,WD_BPS_DST,&ip_bps_dst_ops);
			lcore[i].sum.wd_valid_cnt++;
			wd_register(lcore[i].sum.wd,lcore[i].sum.wd_valid_cnt,WD_PPS_SRC,&ip_pps_src_ops);
			lcore[i].sum.wd_valid_cnt++;
			}
		else if(lcore[i].type==FUN_SUM_SRC)
			{
#ifdef __SRC_SUM__
			struct src_sum_pack *srcip_sum;
			struct hash_array *ptimer;
			struct srcsum_dst_policy *pl;

			//dstip policy
			pl=(struct srcsum_dst_policy *)rte_zmalloc_socket(NULL, sizeof(struct srcsum_dst_policy)*me.sumsrc_dst_policy_pool_cnt, 8,o);
			if(pl==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d sumsrc dstip pl pool %d fail\n",__FUNCTION__,i,me.sumsrc_dst_policy_pool_cnt);
				return MM_FAIL;
				}

			lcore[i].sumsrc.dstip_policy_pool.load=0;
			INIT_LIST_HEAD(&lcore[i].sumsrc.dstip_policy_pool.header);
			for(k=0;k<me.sumsrc_dst_policy_pool_cnt;k++,pl++)
				{
				INIT_LIST_HEAD(&pl->tbl_list);
				INIT_LIST_HEAD(&pl->alloc_list);
				list_add_tail(&pl->alloc_list,&lcore[i].sumsrc.dstip_policy_pool.header);
				lcore[i].sumsrc.dstip_policy_pool.load++;
				}

			//dstip pl hash
			lcore[i].sumsrc.dstip_policy_hash=(struct hash_array *)rte_zmalloc_socket(NULL, sizeof(struct hash_array)*IP_HASH_ARRAY_SZ, 8,o);
			if(lcore[i].sumsrc.dstip_policy_hash==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d srcsum dstip_pl_hash fail\n",__FUNCTION__,i);
				return MM_FAIL;
				}

			for(k=0;k<IP_HASH_ARRAY_SZ;k++)
			   INIT_LIST_HEAD(&lcore[i].sumsrc.dstip_policy_hash[k].header);
#endif
			//msg pool
			struct sum_msg *s=(struct sum_msg *)rte_zmalloc_socket(NULL, sizeof(struct sum_msg)*me.msg_srcsum2io_pool_cnt, 8,o);
			if(s==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d msg src2io bwl pool %d fail\n",__FUNCTION__,i,me.msg_srcsum2io_pool_cnt);
				return MM_FAIL;
				}

			lcore[i].sumsrc.msg_io_pool.load=0;
			INIT_LIST_HEAD(&lcore[i].sumsrc.msg_io_pool.header);
			for(k=0;k<me.msg_srcsum2io_pool_cnt;k++,s++)
				{
				INIT_LIST_HEAD(&s->list);
				list_add_tail(&s->list,&lcore[i].sumsrc.msg_io_pool.header);
				lcore[i].sumsrc.msg_io_pool.load++;
				}

			//msg init
			for(k=0;k<MAX_CPU;k++)
				{
				INIT_LIST_HEAD(&lcore[i].sumsrc.msg_sumsrc2io_send[k].header);
				lcore[i].sumsrc.msg_sumsrc2io_send[k].load=0;

				INIT_LIST_HEAD(&lcore[i].sumsrc.msg_sumsrc2io_back[k].header);
				lcore[i].sumsrc.msg_sumsrc2io_back[k].load=0;
				}
#ifdef __SRC_SUM__
			//sum
			srcip_sum=(struct src_sum_pack *)rte_zmalloc_socket(NULL, sizeof(struct src_sum_pack)*me.sum_srcip_pool_cnt, 8,o);
			if(srcip_sum==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d sumsrc ip_sum_pool %d fail\n",__FUNCTION__,i,me.sum_srcip_pool_cnt);
				return MM_FAIL;
				}

			lcore[i].sumsrc.ip_sum_src_pool.load=0;
			INIT_LIST_HEAD(&lcore[i].sumsrc.ip_sum_src_pool.header);
			for(k=0;k<me.sum_srcip_pool_cnt;k++,srcip_sum++)
				{
				INIT_LIST_HEAD(&srcip_sum->tbl_list);
				INIT_LIST_HEAD(&srcip_sum->alloc_list);
				list_add_tail(&srcip_sum->alloc_list,&lcore[i].sumsrc.ip_sum_src_pool.header);
				lcore[i].sumsrc.ip_sum_src_pool.load++;
				}

			//srcsum hash
			lcore[i].sumsrc.ip_sum_src_hash=(struct hash_array *)rte_zmalloc_socket(NULL, sizeof(struct hash_array)*IP_HASH_ARRAY_SZ, 8,o);
			if(lcore[i].sumsrc.ip_sum_src_hash==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d sum_hash fail\n",__FUNCTION__,i);
				return MM_FAIL;
				}

			for(k=0;k<IP_HASH_ARRAY_SZ;k++)
			   INIT_LIST_HEAD(&lcore[i].sumsrc.ip_sum_src_hash[k].header);

			//timer
			lcore[i].sumsrc.ltimer=(struct hash_array *)rte_zmalloc_socket(NULL, sizeof(struct hash_array)*TIMER_LOOP_SZ, 8,o);
			if(lcore[i].sumsrc.ltimer==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d timer fail\n",__FUNCTION__,i);
				return MM_FAIL;
				}
			for(k=0,ptimer=lcore[i].sumsrc.ltimer;k<TIMER_LOOP_SZ;k++,ptimer++)
			   INIT_LIST_HEAD(&ptimer->header);
#endif



			}
		else if(lcore[i].type==FUN_TIMER)
			{
			int mask=lcore[i].timer.timer_map;
			struct l4_port_g_b *netport_tbl;
			struct dn1_ti_b *dn;

			do
				{
					j=__builtin_ffsll(mask)-1;
					mask &= ~(1ULL<<j);
					lcore[i].timer.timer_triger[lcore[i].timer.timer_cnt]=&lcore[j].timer_flag;
					lcore[i].timer.timer_idle[lcore[i].timer.timer_cnt]=&lcore[j].timer_idle;
					lcore[i].timer.timer_cnt++;
				}while(mask);

//			mask=me.sum_mask;
//			k=0;
//			do
//				{
//					j=__builtin_ffsll(mask)-1;
//					mask &= ~(1ULL<<j);
//					lcore[i].timer.timer_l4_idx[k++]=&lcore[j].sum.l4_tlb_idx;
//				}while(mask);


			//netport pool
			netport_tbl=(struct l4_port_g_b *)rte_zmalloc_socket(NULL, sizeof(struct l4_port_g_b)*65536, 8,o);
			if(netport_tbl==NULL)
				{
				RUNNING_LOG_ERROR("%s: alloc core %d netport_sum_tbl fail\n",__FUNCTION__,i);
				return MM_FAIL;
				}

			lcore[i].timer.netport_tbl=netport_tbl;
			for(k=0;k<65536;k++)
				{
				INIT_LIST_HEAD(&netport_tbl[k].chain.header);
				netport_tbl[k].no=k;
				}

			//wd
			wd_register(lcore[i].timer.wd,lcore[i].timer.wd_valid_cnt,WD_PPS_DST,&ip_pps_dst_ops);
			lcore[i].timer.wd_valid_cnt++;
			wd_register(lcore[i].timer.wd,lcore[i].timer.wd_valid_cnt,WD_BPS_DST,&ip_bps_dst_ops);
			lcore[i].timer.wd_valid_cnt++;
			wd_register(lcore[i].timer.wd,lcore[i].timer.wd_valid_cnt,WD_PPS_SRC,&ip_pps_src_ops);
			lcore[i].timer.wd_valid_cnt++;

			//wdl4
			wd_register(lcore[i].timer.wdl4_g,lcore[i].timer.wdl4_g_valid_cnt,WDL4_ALL_DST,&l4_all_dst_ops);
			lcore[i].timer.wdl4_g_valid_cnt++;
			wd_register(lcore[i].timer.wdl4_g,lcore[i].timer.wdl4_g_valid_cnt,WDL4_ALL_SRC,&l4_all_src_ops);
			lcore[i].timer.wdl4_g_valid_cnt++;
			wd_register(lcore[i].timer.wdl4_g,lcore[i].timer.wdl4_g_valid_cnt,WDL4_TCP_DST,&l4_tcp_dst_ops);
			lcore[i].timer.wdl4_g_valid_cnt++;
			wd_register(lcore[i].timer.wdl4_g,lcore[i].timer.wdl4_g_valid_cnt,WDL4_TCP_SRC,&l4_tcp_src_ops);
			lcore[i].timer.wdl4_g_valid_cnt++;
			wd_register(lcore[i].timer.wdl4_g,lcore[i].timer.wdl4_g_valid_cnt,WDL4_UDP_DST,&l4_udp_dst_ops);
			lcore[i].timer.wdl4_g_valid_cnt++;
			wd_register(lcore[i].timer.wdl4_g,lcore[i].timer.wdl4_g_valid_cnt,WDL4_UDP_SRC,&l4_udp_src_ops);
			lcore[i].timer.wdl4_g_valid_cnt++;

			}
#ifdef PIPE_OUT_LIST_MODE
		else if(lcore[i].type==FUN_IO_OUT)
			{
			for(k=0;k<MAX_DEV;k++)
				{
				for(j=0;j<MAX_CPU;j++)
					{
					INIT_LIST_HEAD(&lcore[i].io_out.port_do_pop[k].tmp_back_list[j].header);
					INIT_LIST_HEAD(&lcore[i].io_out.port_do_pop[k].tmp_send_list[j].header);
					}
				}
			}
#endif
#ifdef WF_NAT_DIST
		else if(lcore[i].type==FUN_DISTRIBUTE)
		{
			struct srcip_nat *srcipnat;
			//port setup
			for(k=0;k<lcore[i].port_cnt;k++)
			{
				if(port[lcore[i].port_id[k]].flag==0)
				{
					port[lcore[i].port_id[k]].socket=rte_eth_dev_socket_id(lcore[i].port_id[k]);
					port[lcore[i].port_id[k]].flag=1;
					port_cnt++;

					if(port[lcore[i].port_id[k]].socket==0xff)
						port[lcore[i].port_id[k]].socket=0;

					if(socket_pool[port[lcore[i].port_id[k]].socket]==NULL)
						{
						snprintf(s, sizeof(s), "pkt_pool_%d",port[lcore[i].port_id[k]].socket);
						socket_pool[port[lcore[i].port_id[k]].socket]=rte_mempool_create(s, NB_MBUF,
								   MBUF_SIZE, 32,
								   sizeof(struct rte_pktmbuf_pool_private),
								   rte_pktmbuf_pool_init, NULL,
								   rte_pktmbuf_init, NULL,
								   port[lcore[i].port_id[k]].socket, 0);

						if (socket_pool[port[lcore[i].port_id[k]].socket] == NULL)
							{
							RUNNING_LOG_ERROR("%s: could not create pkt pool for socket %d\n",
								__FUNCTION__,port[lcore[i].port_id[k]].socket);
							return MM_FAIL;
							}
						else
							{
							RUNNING_LOG_DEBUG("%s: create pkt pool for socket %d NB=%d\n",
								__FUNCTION__,port[lcore[i].port_id[k]].socket,NB_MBUF);
							}
						}
				}
				RUNNING_LOG_DEBUG("%s: check port %d rxq=%d core %d queue %d k=%d\n",
					__FUNCTION__,lcore[i].port_id[k],port[lcore[i].port_id[k]].rx_queue_cnt,
					i,lcore[i].queue_id[k],k);

				if(port[lcore[i].port_id[k]].rx_queue_cnt<lcore[i].queue_id[k])
					port[lcore[i].port_id[k]].rx_queue_cnt=lcore[i].queue_id[k];
			}

#ifndef __MAIN_LOOP_KNI__
			lcore[i].distribute.io_buf = socket_pool[lcore[i].socket_id];
#endif
			//srcip hash
			lcore[i].distribute.io_srcip_hash=(struct hash_array *)rte_zmalloc_socket(NULL, sizeof(struct hash_array)*IP_HASH_ARRAY_SZ, 8,o);
			if(lcore[i].distribute.io_srcip_hash == NULL)
			{
				RUNNING_LOG_ERROR("%s: alloc core %d io_srcip_hash fail\n", __FUNCTION__,i);
				return MM_FAIL;
			}

			for(k=0; k<IP_HASH_ARRAY_SZ; k++)
			{
				INIT_LIST_HEAD(&lcore[i].distribute.io_srcip_hash[k].header);
			}

			//srcip pool
			srcipnat=(struct srcip_nat *)rte_zmalloc_socket(NULL, sizeof(struct srcip_nat)*IP_HASH_ARRAY_SZ, 8, o);
			if(srcipnat==NULL)
			{
				RUNNING_LOG_ERROR("%s: alloc core %d srcipnat pool %d fail\n",__FUNCTION__,i,IP_HASH_ARRAY_SZ);
				return MM_FAIL;
			}

			INIT_LIST_HEAD(&lcore[i].distribute.srcipnat_pool.header);
			for(k=0; k < IP_HASH_ARRAY_SZ; k++, srcipnat++)
			{
				INIT_LIST_HEAD(&srcipnat->alloc_list);
				list_add_tail(&srcipnat->alloc_list, &lcore[i].distribute.srcipnat_pool.header);
			}
			lcore[i].distribute.srcipnat_pool.load=IP_HASH_ARRAY_SZ;

		}
#endif
	}

	rte_malloc_dump_stats(running_log_fp,NULL);

#if 1//debug
{
					int kk,xx,yy;

					RUNNING_LOG_DEBUG("io_in_mask=%llx sum_mask=%llx out=%llx\n",
						me.io_in_mask,me.sum_mask,me.io_out_mask);


					for(kk=0;kk<MAX_CPU;kk++)
						{
						if(lcore[kk].type==FUN_IO_OUT)
							{
							}
						else if(lcore[kk].type==FUN_IO_IN)
							{
							}

						else if(lcore[kk].type==FUN_SUM)
							{
							for(xx=0;xx<8;xx++)
								{
								RUNNING_LOG_DEBUG("sum lcore[%d] %p\n",
									kk,lcore[kk].sum.sum_ip_sum2io_burst[xx]);
								}

//							RUNNING_LOG_DEBUG("sum lcore[%d] sum_timer2sum_pending=%p\n",
//								kk,	&lcore[kk].sum.sum_timer2sum_pending);
							}

						else if(lcore[kk].type==FUN_TIMER)
							{
							RUNNING_LOG_DEBUG("timer lcore[%d] mask=%llx\n",kk,lcore[kk].timer.timer_map);
							for(xx=0;xx<__builtin_popcountll(lcore[kk].timer.timer_map);xx++)
								RUNNING_LOG_DEBUG("timer lcore[%d] %p\n",
									kk,lcore[kk].timer.timer_triger[xx]);

//							for(xx=0;xx<__builtin_popcountll(me.sum_mask);xx++)
//								RUNNING_LOG_DEBUG("timer lcore[%d] timer_ip_timer2sum=%p\n",
//									kk,lcore[kk].timer.timer_ip_timer2sum[xx]);

							}

						}
}
#endif

#ifdef __MAIN_LOOP_KNI__
	init_kni(me.port_cnt);
#endif

	//port init
	for(i=0;i<port_cnt;i++)
		{
		int ret;

		if(rte_eth_devices[i].attached)
			{
//			struct rte_eth_dev_info info;

//			rte_eth_dev_info_get(i, &info);
//			info.default_rxconf.rx_drop_en = 1;
			port[i].rx_queue_cnt++;

//			if(me.type==TYPE_SJ)
				port[i].tx_queue_cnt=16;//lcore[me.kni_no].kni.queue_id[i]+1;//MAX_TX_QUEUE;//port[i].rx_queue_cnt+1;

			RUNNING_LOG_DEBUG("%s: configure port %d rxq %d txq %d\n",
									__FUNCTION__,i,port[i].rx_queue_cnt,port[i].tx_queue_cnt);

			ret = rte_eth_dev_configure(i, port[i].rx_queue_cnt, port[i].tx_queue_cnt, &port_conf);
			if (ret < 0)
				{
				RUNNING_LOG_ERROR("%s: Can not configure port: err=%d, port=%u\n",__FUNCTION__, ret, (unsigned) i);
				return MM_FAIL;
				}

			/* init one RX queue */
//			fflush(stdout);
			for(j=0;j<port[i].rx_queue_cnt;j++)
				{

				RUNNING_LOG_DEBUG("%s: set up port %d rxq %d pool=%d\n",__FUNCTION__,i,j,i);
#ifdef MBUF_POOL_PERPORT
				ret = rte_eth_rx_queue_setup(i, j, RX_RING_SIZE,
								 port[i].socket,
								 NULL,
								 socket_pool[i]);
#else
				ret = rte_eth_rx_queue_setup(i, j, RX_RING_SIZE,
								 port[i].socket,
								 NULL,
								 socket_pool[port[i].socket]);
#endif
				if (ret < 0)
					{
					RUNNING_LOG_ERROR("%s : rxq setup fail err=%d, port=%u queue %d\n",
						  __FUNCTION__,ret, (unsigned) i,j);
					return MM_FAIL;
					}

				rte_eth_add_rx_callback(i, j, add_timestamps, NULL);
				}

			/* init one TX queue on each port */
//			fflush(stdout);
			for(j=0;j<port[i].tx_queue_cnt;j++)
				{

				RUNNING_LOG_DEBUG("%s: set up port %d txq %d\n",__FUNCTION__,i,j);
				ret = rte_eth_tx_queue_setup(i, j, TX_RING_SIZE,
								 port[i].socket,
								 NULL);
				if (ret < 0)
					{
					RUNNING_LOG_ERROR("%s : txq setup fail err=%d, port=%u queue %d\n",
						  __FUNCTION__,ret, (unsigned) i,j);
					return MM_FAIL;
					}
				}

			/* Start device */
			ret = rte_eth_dev_start(i);
			if (ret < 0)
				{
				RUNNING_LOG_ERROR("%s : start port %u fail, err=%d\n",__FUNCTION__,(unsigned)i,ret);
				return MM_FAIL;
				}
#ifdef __MAIN_LOOP_KNI__
			lcore[me.kni_no].kni.kni_array[i]=kni_alloc(i,socket_pool[port[i].socket]);
			if(lcore[me.kni_no].kni.kni_array[i] == NULL)
				{
				RUNNING_LOG_ERROR("%s : start port %u kni fail, err=%d\n",__FUNCTION__,(unsigned)i,ret);
				return MM_FAIL;
				}
#endif
			rte_eth_promiscuous_enable(i);
		}
		else
			{
			RUNNING_LOG_ERROR("%s: port %d is not attached\n", __FUNCTION__,i);

			return MM_FAIL;
			}
		}


	RUNNING_LOG_INFO("%s: ports setup OK\n", __FUNCTION__);
	return MM_SUCCESS;
//return MM_FAIL;
}

extern uint64_t core_stat[MAX_CPU];
extern uint64_t core_prev[MAX_CPU];
extern int abcdef[MAX_CPU];
extern uint64_t timer_perform_aver[MAX_CPU];
extern uint64_t timer_perform_min[MAX_CPU];
extern uint64_t timer_perform_max[MAX_CPU];

extern uint61_t aaa_min[MAX_CPU], aaa_max[MAX_CPU], ddd_min[MAX_CPU], ddd_max[MAX_CPU];

//extern uint64_t tmr1,tmr2;

void print_core_stats(void)
{
	int i,j;

	for(i=0;i<MAX_CPU;i++)
		{
		if(lcore[i].type==FUN_IO_IN ||lcore[i].type==FUN_IO_OUT)
			{
			MON_LOG("$$$ io %02d : total=%010llu, pps=%llu, dstip_pool=%d flownatpool=%d, miss=%d miss2=%d aver=%llu max=%llu min=%llu\n",
				i,core_stat[i],core_stat[i]-core_prev[i],
				lcore[i].io_in.ip_pool.load,lcore[i].io_in.flownat_pool.load,
				lcore[i].io_in.miss_alloced,lcore[i].io_in.miss_alloced_flownat,
				timer_perform_aver[i],timer_perform_max[i],timer_perform_min[i]);
			MON_LOG("$$$  io %d : aaa_min %llu aaa_max=%llu ddd_min=%llu ddd_max=%llu\n"
				i,aaa_min[i],aaa_max[i],ddd_min[i],ddd_max[i]);
//			for(j=0;j<__builtin_popcountll(me.sum_mask);j++)
//				{
//				MON_LOG("io %d : <%d> ip_io2sum_burst=%d ip_io2sum_pending=%d ip_sum2io_burst=%d\n",
//					i,j,lcore[i].io_in.ip_io2sum_burst[j].load,
//					lcore[i].io_in.ip_io2sum_pending[j].load,
//					lcore[i].io_in.ip_sum2io_burst[j].load);
//				}

			core_prev[i]=core_stat[i];
			}

		if(lcore[i].type==FUN_SUM)
			{
			MON_LOG(">>> sum %d : ip_pool=%d port_pool=%d dpool=%d miss=%d miss2=%d miss3=%d"
				" aver=%llu max=%llu min=%llu\n",
				i,lcore[i].sum.ip_sum_pool.load,lcore[i].sum.netport_sum_pool.load,lcore[i].sum.dn1_sum_pool.load,
				lcore[i].sum.miss_alloced,lcore[i].sum.miss_alloced_netport,lcore[i].sum.miss_alloced_dn1,
				timer_perform_aver[i],timer_perform_max[i],timer_perform_min[i]);

//			for(j=0;j<__builtin_popcountll(me.io_in_mask);j++)
//				{
//				MON_LOG("sum %d : <%d> sum_sum2io_pending=%d\n",
//					i,j,lcore[i].sum.sum_sum2io_pending[j].load);
//				}

//			MON_LOG("mmmmmmmmmmmin :%llu   max: %llu\n", tmr1, tmr2);
			}

//		if(lcore[i].type==FUN_TIMER)
//			{
//			MON_LOG("core %d : pool=%d miss=%d timer aver=%llu max=%llu min=%llu\n",
//				i,lcore[i].timer.dn1_timer_pool.load,lcore[i].timer.miss_alloced_dn1,
//				timer_perform_aver[i],timer_perform_max[i],timer_perform_min[i]);
//			}

		}
}


#if 0


void port_sum_calc(int idx)
{
	int i,j,k;
//	struct port_all_s all[MAX_DEV];
	struct port_sum_s *curr,*pp;

	for(i=0;i<MAX_CPU;i++)
		{
		if((lcore[i].type==FUN_MODE_0)||(lcore[i].type==FUN_MODE_1))
			{
			curr=lcore[i].port_stat_arr+idx*MAX_DEV;

			for(j=0;j<lcore[i].port_cnt;j++)
				{
				pp=curr+j;
				k=lcore[i].port_id[j];
				all[k].all.in_pkts+=pp->in_pkts;
				all[k].all.in_bytes+=pp->in_bytes;
				all[k].all.bad_ipv4_pkts+=pp->bad_ipv4_pkts;
				all[k].all.tcp_flagerr_pkts+=pp->tcp_flagerr_pkts;
				all[k].all.tcp_pkts+=pp->tcp_pkts;
				all[k].all.tcp_bytes+=pp->tcp_bytes;
				all[k].all.tcp_syn_pkts+=pp->tcp_syn_pkts;
				all[k].all.tcp_syn_bytes+=pp->tcp_syn_bytes;
				all[k].all.tcp_synack_pkts+=pp->tcp_synack_pkts;
				all[k].all.tcp_synack_bytes+=pp->tcp_synack_bytes;
				all[k].all.tcp_ack_pkts+=pp->tcp_ack_pkts;
				all[k].all.tcp_ack_bytes+=pp->tcp_ack_bytes;
				all[k].all.tcp_rst_pkts+=pp->tcp_rst_pkts;
				all[k].all.tcp_rst_bytes+=pp->tcp_rst_bytes;
				all[k].all.tcp_fin_pkts+=pp->tcp_fin_pkts;
				all[k].all.tcp_fin_bytes+=pp->tcp_fin_bytes;
				all[k].all.udp_pkts+=pp->udp_pkts;
				all[k].all.udp_bytes+=pp->udp_bytes;
				all[k].all.icmp_pkts+=pp->icmp_pkts;
				all[k].all.icmp_bytes+=pp->icmp_bytes;
				all[k].all.igmp_pkts+=pp->igmp_pkts;
				all[k].all.igmp_bytes+=pp->igmp_bytes;
				all[k].all.land_pkts+=pp->land_pkts;
				all[k].all.land_bytes+=pp->land_bytes;
				all[k].all.smurf_pkts+=pp->smurf_pkts;
				all[k].all.smurf_bytes+=pp->smurf_bytes;
				all[k].all.ssdp_pkts+=pp->ssdp_pkts;
				all[k].all.ssdp_bytes+=pp->ssdp_bytes;
				all[k].all.ntp_pkts+=pp->ntp_pkts;
				all[k].all.ntp_bytes+=pp->ntp_bytes;
				all[k].all.dns_pkts+=pp->dns_pkts;
				all[k].all.dns_bytes+=pp->dns_bytes;
				all[k].all.snmp_pkts+=pp->snmp_pkts;
				all[k].all.snmp_bytes+=pp->snmp_bytes;
				all[k].all.chargen_pkts+=pp->chargen_pkts;
				all[k].all.chargen_bytes+=pp->chargen_bytes;
				all[k].all.fraggle_pkts+=pp->fraggle_pkts;
				all[k].all.fraggle_bytes+=pp->fraggle_bytes;
				all[k].all.frag_pkts+=pp->frag_pkts;
				all[k].all.frag_bytes+=pp->frag_bytes;
				all[k].all.frag_err_pkts+=pp->frag_err_pkts;
				all[k].all.frag_err_bytes+=pp->frag_err_bytes;
				all[k].all.nuker_pkts+=pp->nuker_pkts;
				all[k].all.nuker_bytes+=pp->nuker_bytes;
				all[k].all.ip_option_pkts+=pp->ip_option_pkts;
				all[k].all.ip_option_bytes+=pp->ip_option_bytes;
				all[k].all.tracert_pkts+=pp->tracert_pkts;
				all[k].all.tracert_bytes+=pp->tracert_bytes;
				all[k].all.ipv4_pkts+=pp->ipv4_pkts;
				all[k].all.ipv4_bytes+=pp->ipv4_bytes;
				all[k].all.ipv6_pkts+=pp->ipv6_pkts;
				all[k].all.ipv6_bytes+=pp->ipv6_bytes;

				all[k].in_pps=pp->in_pkts;
				all[k].in_bps=pp->in_bytes;
				all[k].tcp_pps=pp->tcp_pkts;
				all[k].tcp_bps=pp->tcp_bytes;
				all[k].tcp_syn_pps=pp->tcp_syn_pkts;
				all[k].tcp_syn_bps=pp->tcp_syn_bytes;
				all[k].tcp_synack_pps=pp->tcp_synack_pkts;
				all[k].tcp_synack_bps=pp->tcp_synack_bytes;
				all[k].tcp_ack_pps=pp->tcp_ack_pkts;
				all[k].tcp_ack_bps=pp->tcp_ack_bytes;
				all[k].tcp_rst_pps=pp->tcp_rst_pkts;
				all[k].tcp_rst_bps=pp->tcp_rst_bytes;
				all[k].tcp_fin_pps=pp->tcp_fin_pkts;
				all[k].tcp_fin_bps=pp->tcp_fin_bytes;
				all[k].udp_pps=pp->udp_pkts;
				all[k].udp_bps=pp->udp_bytes;
				all[k].icmp_pps=pp->icmp_pkts;
				all[k].icmp_bps=pp->icmp_bytes;
				all[k].igmp_pps=pp->igmp_pkts;
				all[k].igmp_bps=pp->igmp_bytes;
				all[k].land_pps=pp->land_pkts;
				all[k].land_bps=pp->land_bytes;
				all[k].smurf_pps=pp->smurf_pkts;
				all[k].smurf_bps=pp->smurf_bytes;
				all[k].ssdp_pps=pp->ssdp_pkts;
				all[k].ssdp_bps=pp->ssdp_bytes;
				all[k].ntp_pps=pp->ntp_pkts;
				all[k].ntp_bps=pp->ntp_bytes;
				all[k].dns_pps=pp->dns_pkts;
				all[k].dns_bps=pp->dns_bytes;
				all[k].snmp_pps=pp->snmp_pkts;
				all[k].snmp_bps=pp->snmp_bytes;
				all[k].chargen_pps=pp->chargen_pkts;
				all[k].chargen_bps=pp->chargen_bytes;
				all[k].fraggle_pps=pp->fraggle_pkts;
				all[k].fraggle_bps=pp->fraggle_bytes;
				all[k].frag_pps=pp->frag_pkts;
				all[k].frag_bps=pp->frag_bytes;
				all[k].nuker_pps=pp->nuker_pkts;
				all[k].nuker_bps=pp->nuker_bytes;
				all[k].ip_option_pps=pp->ip_option_pkts;
				all[k].ip_option_bps=pp->ip_option_bytes;
				all[k].tracert_pps=pp->tracert_pkts;
				all[k].tracert_bps=pp->tracert_bytes;
				all[k].ipv4_pps=pp->ipv4_pkts;
				all[k].ipv4_bps=pp->ipv4_bytes;
				all[k].ipv6_pps=pp->ipv6_pkts;
				all[k].ipv6_bps=pp->ipv6_bytes;

				memset(pp,0,sizeof(struct port_sum_s));
				}
			}
		}

	for(i=0;i<MAX_CPU;i++)
		{
		if((lcore[i].type==FUN_MODE_0)||(lcore[i].type==FUN_MODE_1))
			{
			curr=lcore[i].port_stat_arr;
			for(j=0;j<4;j++)
				{
				struct port_sum_s *p0,*p1;

				p0=curr+j;
				p1=curr+MAX_DEV+j;
				MON_LOG("core %d : j=%d %llu %llu\n",i,j,
					   p0->in_pkts,p1->in_pkts);
				}
			}
		}
}

#endif

int run_cmd(char *cmd)
{
    pid_t status;

    status = system(cmd);

    if (-1 != status)
    {
        if (WIFEXITED(status))
        {
            if (0 == WEXITSTATUS(status))
            {
		RUNNING_LOG_DEBUG("running cmd %s success\n",cmd);
                return MM_SUCCESS;
            }
        }
    }

	RUNNING_LOG_INFO("running cmd %s fail\n",cmd);
	return MM_FAIL;
}


/* Check the link status of all ports in up to 9s, and print them finally */
static int
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 30 /* 3s (30 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	RUNNING_LOG_INFO("Checking data link status\n");
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					RUNNING_LOG_INFO("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					RUNNING_LOG_INFO("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN)
				{
				all_ports_up = 0;
				link_status_map&=(~(1ULL<<portid));
				break;
				}
			else
				{
				link_status_map|=(1ULL<<portid);
				}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
//			RUNNING_LOG_INFO(".");
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			RUNNING_LOG_INFO("done all_ports_up(%#x) check_counter(%u)\n", all_ports_up, count);
		}
	}

	return all_ports_up;
}

void print_port_stats(void)
{
	int port_id;
	struct rte_eth_stats stats;
	static struct rte_eth_stats prev[MAX_DEV];
	uint64_t pps,bps;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

	MON_LOG("%%s",clr, topLeft);

	for(port_id=0;port_id<me.port_cnt;port_id++)
		{
		rte_eth_link_get_nowait(port_id, &me.link[port_id]);
		if(me.link[port_id].link_status)
			{
			MON_LOG("Port %d Link Up - speed %u "
					"Mbps - %s\n", (uint8_t)port_id,
					(unsigned)me.link[port_id].link_speed,
			(me.link[port_id].link_duplex == ETH_LINK_FULL_DUPLEX) ?
				("full-duplex") : ("half-duplex\n"));
			}
		else
			{
			MON_LOG("Port %d Link Down\n",port_id);
			}

		rte_eth_stats_get(port_id, &stats);
		pps=stats.ipackets-prev[port_id].ipackets;
		bps=stats.ibytes-prev[port_id].ibytes;
		prev[port_id]=stats;
		//memcpy(prev,stats,sizeof(struct rte_eth_stats));
		MON_LOG("\n RX-packets:  %10"PRIu64" RX-missed: %10"PRIu64
			   " RX-bytes: %10"PRIu64" PPS: %10"PRIu64"	BPS: %10"PRIu64"\n",
			   stats.ipackets, stats.imissed, stats.ibytes,pps,bps);
		MON_LOG(" RX-badcrc: %10"PRIu64" RX-badlen: %10"PRIu64
			   " RX-errors:  %10"PRIu64"\n",
			   stats.ibadcrc, stats.ibadlen, stats.ierrors);
		MON_LOG("RX-nombuf:  %10"PRIu64"\n",
			   stats.rx_nombuf);
		MON_LOG("TX-packets: %10"PRIu64" TX-errors: %10"PRIu64
			   " TX-bytes: %10"PRIu64"\n",
			   stats.opackets, stats.oerrors, stats.obytes);
			   /*
		MON_LOG("in_pps: %10"PRIu64" in_bps: %10"PRIu64
			   " udp_pps: %10"PRIu64" udp_bps: %10"PRIu64"\n",
			   all[port_id].in_pps,all[port_id].in_bps,
			   all[port_id].udp_pps,all[port_id].udp_bps);
			   */

		}
}

int get_if_status(char *ifname,int *status)
{
	char name[256];
	char buffer[512];
	FILE *fd;
	char *endptr;

	sprintf(name,"/sys/class/net/%s/flags",ifname);
	if((fd = fopen(name, "r")) == NULL)
		return MM_FAIL;

	if(fgets(buffer, sizeof(buffer), fd)==NULL)
	{
		fclose(fd);
		return MM_FAIL;
	}

	*status=strtoul(buffer, &endptr, 16);

	fclose(fd);

	return MM_SUCCESS;
}

#ifdef VLAN_ON
void check_l2_state(
	struct settle_mode_gw_bonding_in_out_vlan *p)
{
	static int t_cnt=0;
	char cbuf[1024];
	char name[512];
	FILE *fd;
	int i,j;
	char *t,*str;
	char tmp_mac[6];
	char *token;
	char ipaddr[64];
	char type[64];
	char flag[64];
	uint32_t flags;
	char mac[64];
	char mask[64];
	char dev[64];
	char in_devname[64];
	char out_devname[64];
	int in_devname_len;
	int out_devname_len;
	uint64_t io_mask=me.io_in_mask;

	sprintf(in_devname,"%s.%d",BOND_IF_NAME,p->in_vlanid);
	sprintf(out_devname,"%s.%d",BOND_IF_NAME,p->out_vlanid);
	in_devname_len=strlen(in_devname);
	out_devname_len=strlen(out_devname);

	//adress
	sprintf(name,"/sys/class/net/%s.%d/address",BOND_IF_NAME,p->in_vlanid);
	if((fd=fopen(name,"r"))!=NULL)
		{
		cbuf[0]=0;
		while (!feof(fd))
			{
				fgets(cbuf, sizeof(cbuf), fd);
				break;
			}

		if(cbuf[0])
			{
			t=&cbuf[0];
			for(i=0;i<6;i++,t+=3)
				{
				*(t+2)=0;
				j=(int)strtol(t, &str, 16);
				tmp_mac[i]=j;
				}

			}

		fclose(fd);

		if((p->out_flag & FLAG(L2_SELF_MAC_VAILD))==0)
			{
			memcpy(p->out_mac,tmp_mac,6);
			p->out_flag |= (FLAG(L2_SELF_MAC_VAILD)|FLAG(L2_STATE_UPDATE));
			}
		else
			{
			if(memcmp(tmp_mac,p->out_mac,6)!=0)
				{
				memcpy(p->out_mac,tmp_mac,6);
				p->out_flag |= FLAG(L2_STATE_UPDATE);
				}
			}
		}

	//neigh address
	if((fd=fopen("/proc/net/arp","r"))!=NULL)
		{
		cbuf[0]=0;
		fgets(cbuf, sizeof(cbuf), fd);
		while (!feof(fd))
			{
				fgets(cbuf, sizeof(cbuf), fd);
				sscanf(cbuf,"%s%*[ ]%s%*[ ]%s%*[ ]%s%*[ ]%s%*[ ]%s",
					ipaddr,type,flag,mac,mask,dev);
				if(strncmp(in_devname,dev,in_devname_len)==0)
					{
						t=&mac[0];
						for(i=0;i<6;i++,t+=3)
							{
							*(t+2)=0;
							j=(int)strtol(t, &str, 16);
							tmp_mac[i]=j;
							}

						flags=(uint32_t)strtol(flag, &str, 16);
						if((flags & 0x2)==0)
							break;

						if((p->out_flag & FLAG(L2_NEIGH_MAC_VAILD))==0)
							{
							memcpy(p->out_neigh_mac,tmp_mac,6);
							p->out_flag |= (FLAG(L2_NEIGH_MAC_VAILD)|FLAG(L2_STATE_UPDATE));
							}
						else
							{
							if(memcmp(tmp_mac,p->out_neigh_mac,6)!=0)
								{
								memcpy(p->out_neigh_mac,tmp_mac,6);
								p->out_flag |= FLAG(L2_STATE_UPDATE);
								}
							}

						break;
					}
			}
		fclose(fd);

		}

	if((p->out_flag & (FLAG(L2_NEIGH_MAC_VAILD)|FLAG(L2_SELF_MAC_VAILD)
		|FLAG(L2_STATE_UPDATE)))==(FLAG(L2_NEIGH_MAC_VAILD)|FLAG(L2_SELF_MAC_VAILD)
		|FLAG(L2_STATE_UPDATE)))
		{

		memcpy(&p->l2_out_pending[0],p->out_neigh_mac,6);
		memcpy(&p->l2_out_pending[6],p->out_mac,6);
		p->l2_out_pending[12]=0x81;
		p->l2_out_pending[13]=0;
		p->l2_out_pending[14]=(char)(p->out_vlanid>>8);
		p->l2_out_pending[15]=(char)(p->out_vlanid);
		p->out_flag &= (~FLAG(L2_STATE_UPDATE));

		RUNNING_LOG_INFO("get neigh %x:%x:%x:%x:%x:%x <- %x:%x:%x:%x:%x:%x type=%x%x vlan=%d\n",
			p->l2_out_pending[0],p->l2_out_pending[1],p->l2_out_pending[2],
			p->l2_out_pending[3],p->l2_out_pending[4],p->l2_out_pending[5],
			p->l2_out_pending[6],p->l2_out_pending[7],p->l2_out_pending[8],
			p->l2_out_pending[9],p->l2_out_pending[10],p->l2_out_pending[11],
			p->l2_out_pending[12],p->l2_out_pending[13],p->l2_out_pending[14]<<8+p->l2_out_pending[15]);



		do{
			i=__builtin_ffsll(io_mask)-1;
			io_mask &= ~(1ULL<<i);

			memcpy(lcore[i].io_in.l2_data,p->l2_out_pending,16);
			rte_wmb();
			lcore[i].io_in.l2_sig=1;
			rte_wmb();
		}while(io_mask);

		}

}
#endif

#ifdef WF_NAT
void check_l2_state(
	struct settle_mode_gw_bonding_in_out_vlan *p)
{
	static int t_cnt=0;
	char cbuf[1024];
	char name[512];
	FILE *fd;
	int i,j;
	char *t,*str;
	char tmp_mac[6];
	char *token;
	char ipaddr[64];
	char type[64];
	char flag[64];
	uint32_t flags;
	char mac[64];
	char mask[64];
	char dev[64];
	char in_devname[64];
	char out_devname[64];
	int in_devname_len;
	int out_devname_len;
	struct in_addr inp;
	uint64_t io_mask=me.io_in_mask | me.io_out_mask;

	uint64_t io_out_mask=me.io_in_mask | me.io_out_mask;

#ifdef BOND_2DIR_VLAN
	sprintf(in_devname,"%s.%d",BOND_IF_NAME,p->in_vlanid);
	sprintf(out_devname,"%s.%d",BOND1_IF_NAME,p->out_vlanid);
#else
	sprintf(in_devname,"%s", ip2str(ipaddr, p->in_gw_ip));
	sprintf(out_devname,"%s",  ip2str(ipaddr, p->out_gw_ip));
#endif
	in_devname_len=strlen(in_devname);
	out_devname_len=strlen(out_devname);
	//RUNNING_LOG_DEBUG("%s in_devname=%s,out_devname=%s\n",__FUNCTION__, in_devname, out_devname);

	//adress
#ifdef BOND_2DIR_VLAN
	sprintf(name,"/sys/class/net/%s.%d/address",BOND_IF_NAME,p->in_vlanid);
#else
	sprintf(name,"/sys/class/net/%s/address",BOND_IF_NAME);
#endif
	if((fd=fopen(name,"r"))!=NULL)
	{
		cbuf[0]=0;
		while (!feof(fd))
		{
			fgets(cbuf, sizeof(cbuf), fd);
			break;
		}

		if(cbuf[0])
		{
			t=&cbuf[0];
			for(i=0;i<6;i++,t+=3)
			{
				*(t+2)=0;
				j=(int)strtol(t, &str, 16);
				tmp_mac[i]=(char)j;
			}

		}

		fclose(fd);

		if((p->in_flag & FLAG(L2_SELF_MAC_VAILD))==0)
		{
			memcpy(p->in_mac, tmp_mac, 6);
			p->in_flag |= (FLAG(L2_SELF_MAC_VAILD)|FLAG(L2_STATE_UPDATE));
		}
		else
		{
			if(memcmp(tmp_mac,p->in_mac,6)!=0)
			{
				memcpy(p->in_mac,tmp_mac,6);
				p->in_flag |= FLAG(L2_STATE_UPDATE);
			}
		}
	}

#ifdef BOND_2DIR
#ifdef BOND_2DIR_VLAN
	sprintf(name,"/sys/class/net/%s.%d/address",BOND1_IF_NAME,p->out_vlanid);
#else	/* #ifdef BOND_2DIR_VLAN */
	sprintf(name,"/sys/class/net/%s/address", BOND1_IF_NAME);
#endif	/* #ifdef BOND_2DIR_VLAN */
	if((fd=fopen(name,"r"))!=NULL)
	{
		cbuf[0]=0;
		while (!feof(fd))
		{
			fgets(cbuf, sizeof(cbuf), fd);
			break;
		}

		if(cbuf[0])
		{
			t=&cbuf[0];
			for(i=0;i<6;i++,t+=3)
			{
				*(t+2)=0;
				j=(int)strtol(t, &str, 16);
				tmp_mac[i]=(char)j;
			}

		}

		fclose(fd);

		if((p->out_flag & FLAG(L2_SELF_MAC_VAILD))==0)
		{
			memcpy(p->out_mac,tmp_mac,6);
			p->out_flag |= (FLAG(L2_SELF_MAC_VAILD)|FLAG(L2_STATE_UPDATE));
#ifdef BOND_2DIR_VLAN
#else	/* #ifdef BOND_2DIR_VLAN */
/*
				memcpy(&p->l2_out_pending[0],p->out_neigh_mac,6);
        		memcpy(&p->l2_out_pending[6],p->out_mac,6);
        		p->l2_out_pending[12]=0x08;
        		p->l2_out_pending[13]=0;

		do{
			i=__builtin_ffsll(io_mask)-1;
			io_mask &= ~(1ULL<<i);

			memcpy(lcore[i].io_in.l2_data_out,p->l2_out_pending,14);
			rte_wmb();
		}while(io_mask);
*/
#endif	/* #ifdef BOND_2DIR_VLAN */
		}
		else
		{
			if(memcmp(tmp_mac,p->out_mac,6)!=0)
			{
				memcpy(p->out_mac,tmp_mac,6);
				p->out_flag |= FLAG(L2_STATE_UPDATE);
			}
		}
	}
#endif	/* #ifdef BOND_2DIR */

	//neigh address
	if((fd=fopen("/proc/net/arp","r"))!=NULL)
	{
		cbuf[0]=0;
		fgets(cbuf, sizeof(cbuf), fd);
		while (!feof(fd))
		{
			fgets(cbuf, sizeof(cbuf), fd);
			cbuf[1023]=0;

//			RUNNING_LOG_INFO("%s cbuf=%s\n",__FUNCTION__, cbuf);

			sscanf(cbuf,"%s%*[ ]%s%*[ ]%s%*[ ]%s%*[ ]%s%*[ ]%s",
				ipaddr,type,flag,mac,mask,dev);

			inet_aton(ipaddr,&inp);
//			RUNNING_LOG_INFO("%s %#x inip:%#x\n", ipaddr, inp.s_addr,p->in_gw_ip);

			if((strncmp(in_devname, ipaddr, in_devname_len)==0)&&(inp.s_addr==p->in_gw_ip))
			{
				t=&mac[0];
				for(i=0;i<6;i++,t+=3)
				{
					*(t+2)=0;
					j=(int)strtol(t, &str, 16);
					tmp_mac[i]=j;
				}

				flags=(uint32_t)strtol(flag, &str, 16);
				if((flags & 0x2)==0)
					break;

				if((p->in_flag & FLAG(L2_NEIGH_MAC_VAILD))==0)
				{
					memcpy(p->in_neigh_mac,tmp_mac,6);
					p->in_flag |= (FLAG(L2_NEIGH_MAC_VAILD)|FLAG(L2_STATE_UPDATE));
				}
				else
				{
					if(memcmp(tmp_mac,p->in_neigh_mac,6)!=0)
					{
						memcpy(p->in_neigh_mac,tmp_mac,6);
						p->in_flag |= FLAG(L2_STATE_UPDATE);
					}
				}
			}
#ifdef BOND_2DIR
			else if((strncmp(out_devname,ipaddr,out_devname_len)==0)&&(inp.s_addr==p->out_gw_ip))
			{
				t=&mac[0];
				for(i=0;i<6;i++,t+=3)
				{
					*(t+2)=0;
					j=(int)strtol(t, &str, 16);
					tmp_mac[i]=j;
				}

				flags=(uint32_t)strtol(flag, &str, 16);
				if((flags & 0x2)==0)
					break;

				if((p->out_flag & FLAG(L2_NEIGH_MAC_VAILD))==0)
				{
					memcpy(p->out_neigh_mac,tmp_mac,6);
					p->out_flag |= (FLAG(L2_NEIGH_MAC_VAILD)|FLAG(L2_STATE_UPDATE));
				}
				else
				{
					if(memcmp(tmp_mac,p->out_neigh_mac,6)!=0)
					{
						memcpy(p->out_neigh_mac,tmp_mac,6);
						p->out_flag |= FLAG(L2_STATE_UPDATE);
					}
				}

			}
#endif

		}
		fclose(fd);

	}

	if((p->in_flag & (FLAG(L2_NEIGH_MAC_VAILD)|FLAG(L2_SELF_MAC_VAILD)
		|FLAG(L2_STATE_UPDATE)))==(FLAG(L2_NEIGH_MAC_VAILD)|FLAG(L2_SELF_MAC_VAILD)
		|FLAG(L2_STATE_UPDATE)))
	{

		memcpy(&p->l2_in_pending[0],p->in_neigh_mac,6);
		memcpy(&p->l2_in_pending[6],p->in_mac,6);
		p->l2_in_pending[12]=0x08;
		p->l2_in_pending[13]=0;
		p->in_flag &= (~FLAG(L2_STATE_UPDATE));
#ifdef BOND_2DIR_VLAN
		p->l2_in_pending[12]=0x81;
		p->l2_in_pending[13]=0;
		p->l2_in_pending[14]=(char)(p->in_vlanid>>8);
		p->l2_in_pending[15]=(char)(p->in_vlanid);
#endif
		RUNNING_LOG_INFO("get in_neigh %x:%x:%x:%x:%x:%x <- %x:%x:%x:%x:%x:%x type=%02x%02x\n",
			(uint8_t)p->l2_in_pending[0], (uint8_t)p->l2_in_pending[1], (uint8_t)p->l2_in_pending[2],
			(uint8_t)p->l2_in_pending[3], (uint8_t)p->l2_in_pending[4], (uint8_t)p->l2_in_pending[5],
			(uint8_t)p->l2_in_pending[6], (uint8_t)p->l2_in_pending[7], (uint8_t)p->l2_in_pending[8],
			(uint8_t)p->l2_in_pending[9], (uint8_t)p->l2_in_pending[10], (uint8_t)p->l2_in_pending[11],
			p->l2_in_pending[12],p->l2_in_pending[13]);

#ifdef BOND_2DIR_VLAN
		do{
			i=__builtin_ffsll(io_out_mask)-1;
			io_out_mask &= ~(1ULL<<i);

			memcpy(lcore[i].io_in.l2_data_in,p->l2_in_pending,16);
			rte_wmb();
			lcore[i].io_in.l2_sig=1;
			rte_wmb();
		}while(io_out_mask);
#else
		do{
			i=__builtin_ffsll(io_out_mask)-1;
			io_out_mask &= ~(1ULL<<i);

			memcpy(lcore[i].io_in.l2_data_in,p->l2_in_pending,14);
			rte_wmb();
			lcore[i].io_in.l2_sig=1;
			rte_wmb();
		}while(io_out_mask);
#endif
	}

#ifdef BOND_2DIR
	if((p->out_flag & (FLAG(L2_NEIGH_MAC_VAILD)|FLAG(L2_SELF_MAC_VAILD)
		|FLAG(L2_STATE_UPDATE)))==(FLAG(L2_NEIGH_MAC_VAILD)|FLAG(L2_SELF_MAC_VAILD)
		|FLAG(L2_STATE_UPDATE)))
	{

		memcpy(&p->l2_out_pending[0],p->out_neigh_mac,6);
		memcpy(&p->l2_out_pending[6],p->out_mac,6);
		p->l2_out_pending[12]=0x08;
		p->l2_out_pending[13]=0;
		p->out_flag &= (~FLAG(L2_STATE_UPDATE));

#ifdef BOND_2DIR_VLAN
		p->l2_out_pending[12]=0x81;
		p->l2_out_pending[13]=0;
		p->l2_out_pending[14]=(char)(p->out_vlanid>>8);
		p->l2_out_pending[15]=(char)(p->out_vlanid);
#endif

		RUNNING_LOG_INFO("get out_neigh %x:%x:%x:%x:%x:%x <- %x:%x:%x:%x:%x:%x type=%02x%02x\n",
			(uint8_t)p->l2_out_pending[0], (uint8_t)p->l2_out_pending[1], (uint8_t)p->l2_out_pending[2],
			(uint8_t)p->l2_out_pending[3], (uint8_t)p->l2_out_pending[4], (uint8_t)p->l2_out_pending[5],
			(uint8_t)p->l2_out_pending[6], (uint8_t)p->l2_out_pending[7], (uint8_t)p->l2_out_pending[8],
			(uint8_t)p->l2_out_pending[9], (uint8_t)p->l2_out_pending[10], (uint8_t)p->l2_out_pending[11],
			p->l2_out_pending[12],p->l2_out_pending[13]);

#ifdef BOND_2DIR_VLAN
		do{
			i=__builtin_ffsll(io_out_mask)-1;
			io_out_mask &= ~(1ULL<<i);

			memcpy(lcore[i].io_in.l2_data_out,p->l2_out_pending,16);
			rte_wmb();
			lcore[i].io_in.l2_sig_out=1;
			rte_wmb();
		}while(io_out_mask);
#else
		do{
			i=__builtin_ffsll(io_mask)-1;
			io_mask &= ~(1ULL<<i);

			memcpy(lcore[i].io_in.l2_data_out,p->l2_out_pending,14);
			rte_wmb();
			lcore[i].io_in.l2_sig_out=1;
			rte_wmb();
		}while(io_mask);
#endif
	}
#endif	/* #ifdef BOND_2DIR */

}

#endif

uint32_t link_status_map;

int link_mon()
{
	int i;
	struct rte_eth_link link;
	uint32_t link_map_curr=0;
	int r=0;

	for(i=0;i<me.port_cnt;i++)
		{
		rte_eth_link_get_nowait(i, &link);
		if (link.link_status == ETH_LINK_DOWN)
			link_map_curr&=(~(1ULL<<i));
		else
			link_map_curr|=(1ULL<<i);
		}

	if(link_map_curr!=link_status_map)
		{
		RUNNING_LOG_INFO("link status change from %x to %x\n",link_status_map,link_map_curr);
		link_status_map=link_map_curr;
		r=1;
		}

	return r;
}

void *mon_thread(void *args)
{
	int i,j,cnt,retry;
	char cmd[256];
	char name1[256];
	char name2[256];
	char buffer[512];
	int linkstatus[MAX_DEV]={0};
	int link_ok_cnt;
	int term=0;
	FILE *fd;
	struct stat buf;

	#define RETRY_TIMES	3

	RUNNING_LOG_DEBUG("%s\n",__FUNCTION__);


#ifdef VLAN_ON

	if(init_step<=STEP_IF_INITED)
	{
		link_ok_cnt=0;
		//bring up vif
		for(retry=0;retry<RETRY_TIMES;retry++)
			{
			for(i=0;i<me.port_cnt;i++)
				{
				if(linkstatus[i]&1)
					continue;

				sprintf(cmd,"ifconfig vEth%d 0.0.0.0 up",i);
				if(run_cmd(cmd)==MM_FAIL)
				{
					RUNNING_LOG_ERROR("bringup vif vEth%d fail,try=%d\n",i,retry);
					break;
				}

				sprintf(cmd,"vEth%d",i);
				if(get_if_status(cmd,&linkstatus[i])==MM_FAIL)
				{
					RUNNING_LOG_ERROR("get vif vEth%d status fail,try=%d\n",i,retry);
					break;
				}

				if(linkstatus[i]&1)
					link_ok_cnt++;
			}

			if(link_ok_cnt==me.port_cnt)
				{
				RUNNING_LOG_INFO("vif link all up,port cnt=%d retry=%d\n",i,retry);
				break;
			}
		}

		if(link_ok_cnt!=me.port_cnt)
		{
			RUNNING_LOG_INFO("vif link fail,retry=%d,term process now!!!\n",retry);
			term=1;
			goto term_check;
		}

		//ifconfig bond0 up
		sprintf(cmd,"ifconfig %s 0.0.0.0 up",BOND_IF_NAME);
		for(i=0;i<RETRY_TIMES;i++)
		{
			if(run_cmd(cmd)==MM_SUCCESS)
				break;
		}
		if(i==RETRY_TIMES)
		{
			RUNNING_LOG_INFO("running %s fail!\n", cmd);
			term=1;
			goto term_check;
			}

		//ifenslave master slvae1 slave2 ...
		for(i=0;i<me.port_cnt;i++)
		{
			int found=0;

			for(j=0;j<RETRY_TIMES;j++)
			{
				sprintf(cmd,"ifenslave %s vEth%d",BOND_IF_NAME,i);
				run_cmd(cmd);

				sprintf(cmd,"/sys/class/net/%s/bonding/slaves",BOND_IF_NAME);
				if((fd = fopen(cmd, "r")) == NULL)
					{
					RUNNING_LOG_ERROR("open %s fail,retry %d\n",cmd,j);
					continue;
					}

				sprintf(cmd,"vEth%d",i);
				while(fgets(buffer, sizeof(buffer), fd)){
					 if(strstr(buffer,cmd))
						{
						found=1;
						RUNNING_LOG_INFO("found if %s\n",cmd);
						break;
						}
				}

				fclose(fd);
				if(!found)
					{
					RUNNING_LOG_ERROR("cannot found %s\n", cmd);
					continue;
					}
				else
					{
					RUNNING_LOG_INFO("ifenslave if %s ok\n",cmd);
					break;
					}
			}


			if(j==RETRY_TIMES)
			{
				RUNNING_LOG_INFO("ifenslave vEth%d fail\n",i);
				term=1;
				goto term_check;
			}
		}

		//vconfig add bond0 invlanid
		for(i=0;i<RETRY_TIMES;i++)
			{
			sprintf(cmd,"vconfig add %s %d",BOND_IF_NAME,me.settle_setting.gw_bonding_inoutvlan.in_vlanid);
			run_cmd(cmd);

			sprintf(cmd,"/sys/class/net/%s.%d",BOND_IF_NAME,me.settle_setting.gw_bonding_inoutvlan.in_vlanid);
			j=stat(cmd, &buf);
			if(j)
				{
				RUNNING_LOG_ERROR("%s:stat file %s fail\n",__FUNCTION__,cmd);
				continue;
				}

			sprintf(cmd,"ifconfig %s.%d %s netmask %s up",BOND_IF_NAME,
				me.settle_setting.gw_bonding_inoutvlan.in_vlanid,
				ip2str(name1,me.settle_setting.gw_bonding_inoutvlan.in_ip),
				ip2str(name2,me.settle_setting.gw_bonding_inoutvlan.in_ipmask));
			if(run_cmd(cmd)==MM_SUCCESS)
				break;
			}

		if(i==RETRY_TIMES)
			{
			RUNNING_LOG_INFO("in vlan config fail\n",i);
			term=1;
			goto term_check;
			}

		for(i=0;i<RETRY_TIMES;i++)
			{
			sprintf(cmd,"vconfig add %s %d",BOND_IF_NAME,me.settle_setting.gw_bonding_inoutvlan.out_vlanid);
			run_cmd(cmd);

			sprintf(cmd,"/sys/class/net/%s.%d",BOND_IF_NAME,me.settle_setting.gw_bonding_inoutvlan.out_vlanid);
			j=stat(cmd, &buf);
			if(j)
				{
				RUNNING_LOG_ERROR("%s:stat file %s fail\n",__FUNCTION__,cmd);
				continue;
				}


			sprintf(cmd,"ifconfig %s.%d %s netmask %s up",BOND_IF_NAME,
				me.settle_setting.gw_bonding_inoutvlan.out_vlanid,
				ip2str(name1,me.settle_setting.gw_bonding_inoutvlan.out_ip),
				ip2str(name2,me.settle_setting.gw_bonding_inoutvlan.out_ipmask));
			if(run_cmd(cmd)==MM_SUCCESS)
				break;
			}

		if(i==RETRY_TIMES)
			{
			RUNNING_LOG_INFO("out vlan config fail\n",i);
			term=1;
			goto term_check;
			}
		}

//	kni_term=1;
//	while(kni_term==1);
//	kill(myapp_pid,SIGQUIT);
//	init_step=STEP_FAIL;
//	return;

term_check:
	if(term)
		{
//		raise(SIGTERM);
		init_step=STEP_FAIL;
		return;
		}

	init_step=STEP_OK;
	rte_smp_wmb();
	RUNNING_LOG_INFO("%s(%d) : finish init process\n",__FUNCTION__,__LINE__);
#endif

	cnt = 0;
	while(!term_pending)
	{
#ifdef WF_NAT
		if (cnt%10 == 0)
		{
			cnt = 0;
			check_l2_state(&me.settle_setting.gw_bonding_inoutvlan);
		}
		cnt++;
#endif
#ifdef __MAIN_LOOP_KNI__
		link_mon();
#endif
		if(!mon_log_off)
			{
			print_port_stats();
			print_core_stats();
			}

		sleep(1);
	}

	RUNNING_LOG_INFO("%s(%d) : mon thread exit now\n",__FUNCTION__,__LINE__);
}

int dev_mon_init(void)
{
	int rc;
	char buf[1024];

	RUNNING_LOG_INFO("mon thread start\n");

        sprintf(buf,"%s/%s",me.root_dir, DEFAULT_MON_LOG);
	mon_log_fp = fopen(buf, "a+");
	if (!mon_log_fp) {
		RUNNING_LOG_ERROR("Failed to open %s for mon!\n");
		return MM_FAIL;
	}

	rc = pthread_create(&mon_thread_id, NULL,	&mon_thread, NULL);
	if (rc != 0) {
		RUNNING_LOG_ERROR("Failed to create mon thread, err=%s\n", strerror(errno));
		return MM_FAIL;
	}

	RUNNING_LOG_INFO("mon thread setup OK\n");

	return MM_SUCCESS;
}

static int get_ipaddr(const char *dev,uint32_t *addr)
{
    int sfd, saved_errno, ret;
	int r=MM_SUCCESS;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    sfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sfd==-1)
		{
		RUNNING_LOG_ERROR("%s : socket fail %s\n", __FUNCTION__,dev);
		return MM_FAIL;
		}

//    errno = saved_errno;
    ret = ioctl(sfd, SIOCGIFADDR, &ifr);
    if (ret == -1) {
        if (errno == 19) {
            RUNNING_LOG_ERROR("Interface %s : No such device.\n", dev);
        }
        else if (errno == 99) {
            RUNNING_LOG_ERROR("Interface %s : No IPv4 address assigned.\n", dev);
        }

		r=MM_FAIL;
    }
	else
		{
		*addr=((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
		}
//    saved_errno = errno;

//    inet_ntop(AF_INET, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), ipaddr, INET_ADDRSTRLEN);

    close(sfd);

    return r;
}

static int get_if_flags(const char *dev,int *flag)
{
    int sfd, ret, saved_errno;
    short if_flags;
	int r=MM_SUCCESS;
    struct ifreq ifr={0};

    sfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sfd==-1)
		{
		RUNNING_LOG_ERROR("%s : socket fail %s\n", __FUNCTION__,dev);
		return MM_FAIL;
		}

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

//    saved_errno = errno;
    ret = ioctl(sfd, SIOCGIFFLAGS, &ifr);
    if (ret == -1 /*&& errno == 19*/)
		{
        RUNNING_LOG_ERROR("Interface %s : No such device %d\n", ifr.ifr_name,errno);
//        exit(EXIT_FAILURE);
		r=MM_FAIL;
    	}
	else
		{
		*flag = ifr.ifr_flags;
		}
//    errno = saved_errno;

	close(sfd);
    return r;
}

void *vif_init_thread(void *args)
{
	uint32_t i,j,k,l,cnt,retry;
	char cmd[1024];
	char cbuf[1024];
	char buffer[256];
	char name1[256];
	char name2[256];
	char ipaddr[64];
	char type[64];
	char flag[64];
	char mac[64];
	char mask[64];
	char dev[64];
	int linkstatus;
	int link_ok_cnt;
	FILE *fd;
	int init_state=0;
	int found;
	int err;
	int flags;
	char *t,*str;
	char tmp_mac[6];
	uint64_t ok_mask=0;
	uint64_t tmp_mask;
	uint64_t io_mask=me.io_in_mask;
	uint32_t link_ok_mask;
	struct rte_eth_link link;


	RUNNING_LOG_INFO("%s\n",__FUNCTION__);

	link_ok_mask=(1ULL<<me.port_cnt)-1;
	ping_thread_start=0;

	while(!term_pending)
	{
		switch(init_state)
			{
			case 0:
				run_cmd("modprobe -r bonding");

				sleep(2);

				if(check_module("bonding","bonding",1)==MM_FAIL)
					{
					RUNNING_LOG_ERROR("Missing module bonding\n");
					sleep(10);
					}
				else
					init_state=1;
				break;

			case 1:
				err=0;
#ifdef BOND_2DIR
				for(i=0;i<2;i++)
#else
				for(i=0;i<1;i++)
#endif
				{
					if (i && !me.settle_setting.gw_bonding_inoutvlan.out_port_num)
						continue;

					sprintf(cmd,"bond%d", i);
					if(get_if_status(cmd,&linkstatus)==MM_FAIL)
					{
						RUNNING_LOG_ERROR("Missing dev %s 1\n",cmd);
						err++;
						break;
					}
				}
				if(err)
				{
					for(i=0;i<me.port_cnt;i++)
					{
						sprintf(cmd,"vEth%d",i);
						if(get_if_status(cmd,&linkstatus)==MM_FAIL)
						{
							RUNNING_LOG_ERROR("Missing dev %s 2\n",cmd);
							err++;
							break;
						}
					}
				}

				if(!err)
					init_state=2;
				else
					sleep(10);

				break;

			case 2:
#ifdef BOND_2DIR
				for(i=0;i<2;i++)
#else
				for(i=0;i<1;i++)
#endif
				{
					if (i && !me.settle_setting.gw_bonding_inoutvlan.out_port_num)
						continue;

					sprintf(cmd,"ifconfig bond%d 0.0.0.0 up", i);
					run_cmd(cmd);
				}

				init_state=3;
				break;

			case 3:
				err=0;
				for(i=0;i<me.port_cnt;i++)
				{
					sprintf(cmd,"vEth%d",i);
					if(get_if_flags(cmd,&flags)==MM_FAIL)
					{
						RUNNING_LOG_ERROR("Missing dev %s 3\n",cmd);
						err++;
						break;
					}
					else
					{
						RUNNING_LOG_DEBUG("vif dev %s state=%x, %x is ok\n",cmd,flags,(IFF_RUNNING|IFF_UP));
					}

					if((flags & (IFF_RUNNING|IFF_UP))!=
						(IFF_RUNNING|IFF_UP))
					{
						RUNNING_LOG_ERROR("vif dev %s state=%x, not %x, err\n",cmd,flags,(IFF_RUNNING|IFF_UP));
						err++;
						break;
					}
				}

				if(!err)
					init_state=4;
				else
				{
					for(i=0;i<me.port_cnt;i++)
					{
							sprintf(cmd,"ifconfig vEth%d 0.0.0.0 up",i);
						run_cmd(cmd);
					}
					sleep(10);
				}

				//break;

			case 4:
				err=0;
				{

					found=0;
					for(j=0;j<me.port_cnt;j++)
					{
#ifdef BOND_2DIR
//						i = j>>1;
						if (!me.settle_setting.gw_bonding_inoutvlan.out_port_num)
							i=0;
						else
							i = phy_port_bond_index(j, me.port_cnt);
#else
						i = 0;
#endif
						sprintf(cmd,"ifenslave bond%d vEth%d", i, j);
						run_cmd(cmd);
						sleep(1);

						sprintf(cmd,"/sys/class/net/bond%d/bonding/slaves",i);
						if((fd = fopen(cmd, "r")) == NULL)
						{
							RUNNING_LOG_ERROR("open %s fail,retry %d\n",cmd,j);
							continue;
						}

						sprintf(cmd,"vEth%d", j);
						while(fgets(buffer, sizeof(buffer), fd))
						{
							//RUNNING_LOG_INFO("file slaves str = %s,cmd=%s\n",buffer,cmd);
							if(strstr(buffer,cmd))
							{
								found=1;
								RUNNING_LOG_INFO("found if %s\n",cmd);
								break;
							}
						}

						fclose(fd);
						if(!found)
						{
							err++;
							RUNNING_LOG_INFO("bond%d vEth%d fail,rerty\n", i, j);
							break;
						}
					}

				}

				if(!err)
					init_state=5;
				else
					sleep(10);

				break;

			case 5:
				sprintf(cmd,"ifconfig bond0 %s netmask %s up",
					ip2str(name1, me.settle_setting.gw_bonding_inoutvlan.in_ip),
					ip2str(name2, me.settle_setting.gw_bonding_inoutvlan.in_ipmask));
				run_cmd(cmd);

#ifdef BOND_2DIR
				if (me.settle_setting.gw_bonding_inoutvlan.out_port_num)
				{
					sprintf(cmd,"ifconfig bond1 %s netmask %s up",
						ip2str(name1, me.settle_setting.gw_bonding_inoutvlan.out_ip),
						ip2str(name2, me.settle_setting.gw_bonding_inoutvlan.out_ipmask));
					run_cmd(cmd);
				}
#endif

				init_state=6;
				ping_thread_start=1;
				break;

			case 6:
			default:
				err=0;
				for(i=0;i<me.port_cnt;i++)
				{
					sprintf(cmd,"vEth%d",i);
					if(get_if_flags(cmd,&flags)==MM_FAIL)
					{
						RUNNING_LOG_ERROR("Missing dev %s 6\n",cmd);
						err++;
						goto if_reconfig;
					}

					if((flags & (IFF_UP|IFF_RUNNING|IFF_SLAVE))!=
						(IFF_UP|IFF_RUNNING|IFF_SLAVE))
					{
						RUNNING_LOG_ERROR("vif dev %s state=0x%x,not 0x%x, err\n",cmd,flags,(IFF_UP|IFF_RUNNING|IFF_SLAVE));
						err++;
						goto if_reconfig;
					}
				}
#ifdef BOND_2DIR
				for(i=0;i<2;i++)
#else
				for(i=0;i<1;i++)
#endif
				{
					uint32_t addr;

					if (i && !me.settle_setting.gw_bonding_inoutvlan.out_port_num)
						continue;

					sprintf(cmd,"bond%d",i);
					if(get_if_flags(cmd,&flags)==MM_FAIL)
					{
						RUNNING_LOG_ERROR("Missing dev %s\n",cmd);
						err++;
						goto if_reconfig;
					}

					if((flags & (IFF_UP|IFF_RUNNING|IFF_MASTER))!=
						(IFF_UP|IFF_RUNNING|IFF_MASTER))
					{
						RUNNING_LOG_ERROR("bond dev %s state= %x,not %x err\n",cmd,flags,(IFF_UP|IFF_RUNNING|IFF_MASTER));
						err++;
						goto if_reconfig;
					}

					if(get_ipaddr(cmd,&addr)==MM_FAIL)
					{
						RUNNING_LOG_ERROR("Missing dev %s get addr\n",cmd);
						err++;
						goto if_reconfig;
					}

					if((addr == me.settle_setting.gw_bonding_inoutvlan.in_ip) ||
						(addr == me.settle_setting.gw_bonding_inoutvlan.out_ip))
					{
					}else{
						RUNNING_LOG_ERROR("bond dev %s addr=0x%x, err  \n",cmd,addr);
						err++;
						goto if_reconfig;
					}
				}

				//check link
//				if(link_mon())
//					{
//					RUNNING_LOG_ERROR(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> link status change,reconfig vif\n");
//					err++;
//					goto if_reconfig;
//					}

				for(i=0;i<me.port_cnt;i++)
				{
					rte_eth_link_get_nowait(i, &link);
					if (link.link_status == ETH_LINK_DOWN)
						link_status_map&=(~(1ULL<<i));
					else
						link_status_map|=(1ULL<<i);
				}

				if(link_status_map != link_ok_mask)
				{
					RUNNING_LOG_ERROR(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> some link off,status=%x, not %x,reconfig vif\n",
						link_status_map,link_ok_mask);

					err++;
					sleep(30);
					goto if_reconfig;
				}

#if 0
				ok_mask=((1ULL<<p->dev_cnt)-1);
				if((fd=fopen("/proc/net/arp","r"))!=NULL)
					{
					cbuf[0]=0;
					fgets(cbuf, sizeof(cbuf), fd);
					tmp_mask=0;
					while (!feof(fd))
						{
							fgets(cbuf, sizeof(cbuf), fd);
							sscanf(cbuf,"%s%*[ ]%s%*[ ]%s%*[ ]%s%*[ ]%s%*[ ]%s",
								ipaddr,type,flag,mac,mask,dev);

							for(k=0;k<p->dev_cnt;k++)
								{
								sprintf(cmd,"bond%d",k);
								if(strncmp(cmd,dev,strlen(dev))==0)
									{
										t=&mac[0];
										for(i=0;i<6;i++,t+=3)
											{
											*(t+2)=0;
											j=(int)strtol(t, &str, 16);
											tmp_mac[i]=j;
											}

										if(tmp_mac[0]||tmp_mac[1]||tmp_mac[2]||
											tmp_mac[3]||tmp_mac[4]||tmp_mac[5])
											{
											tmp_mask|=(1ULL<<k);
											}
									}
								}


						}
					fclose(fd);

					if(tmp_mask == ok_mask)
						{
//							do{
//								l=__builtin_ffsll(io_mask)-1;
//								io_mask &= ~(1ULL<<l);

//								lcore[l].io_in.l2_sig=1;
//								rte_wmb();
//							}while(io_mask);
//							RUNNING_LOG_INFO("bond dev neigh ok %x %x\n",cmd,tmp_mask,ok_mask);
						}
					else
						{
//							do{
//								l=__builtin_ffsll(io_mask)-1;
//								io_mask &= ~(1ULL<<l);
//
//								lcore[l].io_in.l2_sig=0;
//								rte_wmb();
//							}while(io_mask);
//							err++;
//							RUNNING_LOG_ERROR("bond dev neigh fail %x %x\n",cmd,tmp_mask,ok_mask);
						}
					}
#endif

if_reconfig:
				if(err)
				{
//					ping_thread_start=0;
					init_state=4;
					sleep(10);
				}
				break;
			}
	}

	RUNNING_LOG_INFO("%s : vif init thread exit now\n",__FUNCTION__);
}

int vif_init()
{
	int rc;

	RUNNING_LOG_INFO("vif_init start\n");

	rc = pthread_create(&vif_init_thread_id, NULL, &vif_init_thread, NULL);
	if (rc != 0) {
		RUNNING_LOG_ERROR("Failed to create vif init thread, err=%s\n", strerror(errno));
		return MM_FAIL;
	}

	RUNNING_LOG_INFO("vif_init OK\n");

	return MM_SUCCESS;
}

int if_init_process(void)
{
	int i;

	while(1)
		{
		for(i=0;i<me.port_cnt;i++)
			{
			if(init_step==STEP_FAIL)
				return MM_FAIL;
			else if(init_step==STEP_OK)
				return MM_SUCCESS;
#ifdef __MAIN_LOOP_KNI__
			rte_kni_handle_request(lcore[me.kni_no].kni.kni_array[i]);
#endif
			}
		}
}

//char **argv0;


int m_plat_init(__attribute__((unused)) void *m)
{
	int r;
	char cmd[256];

	RUNNING_LOG_DEBUG("%s\n",__FUNCTION__);

//	switch_curr=0;
//	timer_curr=0;

	rte_openlog_stream(running_log_fp);
    rte_set_log_level(RTE_LOG_DEBUG);

//	strcpy(&me.param.argv_buf[0][0],argv0[0]);
//	me.param.argv[0]=&me.param.argv_buf[0][0];


	RUNNING_LOG_DEBUG("%s %d\n",__FUNCTION__,me.param.argc);
	r = rte_eal_init(me.param.argc, me.param.argv);
	if (r < 0)
		{
		RUNNING_LOG_ERROR("%s : eal init fail\n",__FUNCTION__);
		exit(1);
		}

	/* init RTE timer library */
	rte_timer_subsystem_init();

//	term_delay=1;
	if(prepare_setup()== MM_FAIL)
		{
		RUNNING_LOG_ERROR("%s : prepare_setup fail!\n",__FUNCTION__);
		exit(1);
		}

	if(!check_all_ports_link_status(me.port_cnt,me.port_mask))
		{
		RUNNING_LOG_ERROR("%s :some data link down !!!\n",__FUNCTION__);
		exit(1);
		}

//	term_delay=0;
//	if(term_pending)
//		{
//		RUNNING_LOG_ERROR("%s : term delay happend!\n",__FUNCTION__);
//		exit(1);
//		}

#if defined(VLAN_ON)
	if(me.settle_setting.mode==INTERFACE_MODE_GW_BONDING)
	{
		run_cmd("modprobe -r 8021q");
		run_cmd("modprobe -r bonding");

		if(check_module("8021q","8021q",1)==MM_FAIL)
			{
			RUNNING_LOG_ERROR("Missing module 8021q in gw bonding mode\n");
			exit(1);
			}

		if(check_module("bonding","bonding",1)==MM_FAIL)
			{
			RUNNING_LOG_ERROR("Missing module bonding in gw bonding mode\n");
			exit(1);
			}

		sprintf(cmd,"ifconfig %s up",BOND_IF_NAME);
		if(run_cmd(cmd)==MM_FAIL)
			{
			RUNNING_LOG_ERROR("running cmd %s fail\n",cmd);
			exit(1);
			}
		}


//	if(init_nl()==MM_FAIL)
//		{
//		RUNNING_LOG_ERROR("%s : nl init fail\n",__FUNCTION__);
//		exit(1);
//		}

	init_step=STEP_IF_INITED;
#else

#ifdef __MAIN_LOOP_KNI__
	if(vif_init()==MM_FAIL)
		{
		RUNNING_LOG_ERROR("%s : vif init fail\n",__FUNCTION__);
		exit(1);
		}
#endif

	if(init_ping()==MM_FAIL)
		{
		RUNNING_LOG_ERROR("%s : nl init fail\n",__FUNCTION__);
		exit(1);
		}

#endif

	if(dev_mon_init()==MM_FAIL)
		{
		RUNNING_LOG_ERROR("%s : mon init fail\n",__FUNCTION__);
		exit(1);
		}

#ifdef VLAN_ON
	if(if_init_process()==MM_FAIL)
		{
		RUNNING_LOG_ERROR("%s : if init fail\n",__FUNCTION__);
		exit(1);
		}

	if(init_ping()==MM_FAIL)
		{
		RUNNING_LOG_ERROR("%s : nl init fail\n",__FUNCTION__);
		exit(1);
		}

#endif

	RUNNING_LOG_DEBUG("%s finished\n",__FUNCTION__);

	return MM_SUCCESS;
}

int m_plat_preinit(__attribute__((unused)) void *m)
{
	int mountfd;
	char cbuf[PATH_MAX];
	FILE *fp0,*fp1;
	char *p0,*p1;
	int r,len;

	RUNNING_LOG_DEBUG("%s\n",__FUNCTION__);

	time_t now;

	time(&now);
	attack_event_id=(uint64_t)now;


	p0=NR_HUGEPAGE_2M_NODE_0;
	p1=NR_HUGEPAGE_2M_NODE_1;

	//setup hugepage
	mountfd = mount("nodev", HUGETLBFS_MOUNT_POINT, "hugetlbfs", 0, NULL);
	if(mountfd == -1)
		{
		RUNNING_LOG_ERROR("%s : mount hugepage fail\n",__FUNCTION__);
		exit(1);
		}

	snprintf(cbuf, sizeof(cbuf), "%d", me.param.nr_hugepages);

	if(me.param.hugepage_size == PAGE_1G)
		{
		p0=NR_HUGEPAGE_1G_NODE_0;
		p1=NR_HUGEPAGE_1G_NODE_1;
		}

	if((fp0 = fopen(p0, "w")) == NULL)
		{
		RUNNING_LOG_ERROR("%s : fail open %s\n",__FUNCTION__,p0);
		exit(1);
		}

	if((fp1 = fopen(p1, "w")) == NULL)
		{
		RUNNING_LOG_ERROR("%s : fail open %s\n",__FUNCTION__,p1);
		fclose(fp0);
		exit(1);
		}

	if((len=fwrite(cbuf,1,strlen(cbuf),fp0))!=strlen(cbuf))
		{
		RUNNING_LOG_ERROR("fwrite fail %s %d %d\n",cbuf,len,strlen(cbuf));
		goto plat_preinit_fail;
		}

	if((len=fwrite(cbuf,1,strlen(cbuf),fp1))!=strlen(cbuf))
		{
		RUNNING_LOG_ERROR("fwrite fail %s %d %d\n",cbuf,len,strlen(cbuf));
		goto plat_preinit_fail;
		}

	fclose(fp0);
	fclose(fp1);

	//ubind bind dev
	if(list_empty(&port_list))
		{
		RUNNING_LOG_ERROR("%s : port list is empty\n", __FUNCTION__);
		exit(1);
		}

	struct dev_list *dd, *temp;
	int x;
	struct stat buf;
	char driver[256];

	list_for_each_entry_safe(dd,temp,&port_list,list){
		sprintf(cbuf,SYSFS_PCI_DEVICES"/%s/driver",dd->dev_id);
		driver[0]=0;
		r=stat(cbuf, &buf);
		if(r==-1)
			{
			list_del_init(&dd->list);
			RUNNING_LOG_INFO("dev can not access, cleanup = %s %s\n",dd->dev_id,dd->kernel_driver);
			free(dd->dev_id);
			free(dd->kernel_driver);
			free(dd);
			continue;
			}

		x=pci_get_kernel_driver_by_path(cbuf,driver);
		RUNNING_LOG_INFO("pci_get_kernel_driver_by_path return value = %d %s %s\n",x,driver,dd->dev_id);
		if(driver[0])
			{
			sprintf(cbuf,"/sys/bus/pci/drivers/%s",driver);
			dd->kernel_driver=mystrdup(cbuf);
			if(dd->kernel_driver==NULL)
				{
				RUNNING_LOG_INFO("kernel driver alloc fail\n");
				exit(1);
				}
			}

		if(pci_unbind_kernel_driver(dd->dev_id)==MM_FAIL)
			exit(1);

		if(pci_bind_uio_driver(dd->dev_id)==MM_FAIL)
			exit(1);
	}

	if(list_empty(&port_list))
		{
		RUNNING_LOG_ERROR("%s : no valid dev in port list,check config\n");
		exit(1);
		}

	RUNNING_LOG_DEBUG("%s finished\n",__FUNCTION__);
	return MM_SUCCESS;

plat_preinit_fail:
	fclose(fp0);
	fclose(fp1);
	exit(1);
}

int m_plat_deinit(__attribute__((unused)) void *m)
{
	char cbuf[PATH_MAX];
	char *p0,*p1;
	int i;

	RUNNING_LOG_INFO("%s...\n", __FUNCTION__);

	struct dev_list *dd, *temp;

	//stop ping thread
	ping_thread_stop=1;

	sleep(5);
#ifdef __MAIN_LOOP_KNI__
	for(i=0;i<me.port_cnt;i++)
	{
		if(lcore[me.kni_no].kni.kni_array[i])
			{
			kni_free_kni(i,lcore[me.kni_no].kni.kni_array[i]);
			RUNNING_LOG_INFO("relese kni port %d\n",i);
			lcore[me.kni_no].kni.kni_array[i]=NULL;
			}
	}
#endif
#if 0
	// some bug
	if(!list_empty(&port_list))
		list_for_each_entry_safe(dd,temp,&port_list,list){
			list_del_init(&dd->list);
			RUNNING_LOG_INFO("cleanup dev = %s %s\n",dd->dev_id,dd->kernel_driver);
			pci_unbind_uio_driver(dd->dev_id);
//			sleep(3);
			pci_bind_kernel_driver(dd->dev_id,dd->kernel_driver);
			if (dd->dev_id)
				free(dd->dev_id);
			if (dd->kernel_driver)
				free(dd->kernel_driver);
			if (dd)
				free(dd);
		}
#endif

	for(i=0;i<me.port_cnt;i++)
	{
		//stop port..
		rte_eth_dev_stop(i);
	}
//	system("modprobe -r bonding");
//	system("modprobe -r 8021q");
//	system("rmmod rte_kni.ko");
//	system("rmmod igb_uio.ko");
//	system("modprobe -r uio");

	p0=NR_HUGEPAGE_2M_NODE_0;
	p1=NR_HUGEPAGE_2M_NODE_1;

	if(me.param.hugepage_size == PAGE_1G)
		{
		p0=NR_HUGEPAGE_1G_NODE_0;
		p1=NR_HUGEPAGE_1G_NODE_1;
		}

	sprintf(cbuf,"echo 0 > %s",p0);
	system(cbuf);

	sprintf(cbuf,"echo 0 > %s",p1);
	system(cbuf);

	RUNNING_LOG_INFO("%s finished.\n",__FUNCTION__);

	return MM_SUCCESS;
}

