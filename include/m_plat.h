#ifndef __M_PLAT_H
#define __M_PLAT_H

#define DEBUG_BUILD_POOL

#define LOCAL_PKT_SZ	(64*1024)
#define LOCAL_PKT_CACHE_SZ	(256)
#define LOCAL_PKT_ALLOC_BLUK	(32)

#define IO_FIFO_SZ		(8*1024)
#define IO_FIFO_CACHE_SZ	(256)
#define TIMER_FIFO_SZ	(8*1024)



#define MAX_PACKET_SZ           2048

/* Number of bytes needed for each mbuf */
#define MBUF_SIZE \
	(MAX_PACKET_SZ + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

/* Number of mbufs in mempool that is created */
#define NB_MBUF                 (1024*1024)

#define RX_RING_SIZE 256
#define TX_RING_SIZE 512

#define POOL_BULK_SZ	10000

#undef ALIGN
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))




#define	TIMER_RANGE	(5*60)	//5min
#define TIMER_UNIT	(1)		// 1s

//extern char **argv0;

extern uint32_t link_status_map;
extern struct mmb mm_plat;
extern struct list_head port_list;
extern struct lcore_info_s lcore[MAX_CPU];

#define mb()	rte_mb()
#define wmb()	rte_wmb()
#define rmb()	rte_rmb()

#define MP_TYPE_SOCKET	1
#define	MP_TYPE_PERCORE	2
#define	MP_TYPE_CORES	3

static inline void __attribute__((always_inline))
wd_register(struct wd_pack *w,int idx,int type,struct wd_ops *ops)
{
	w[idx].top[0].curr=w[idx].top[1].curr=0;
	w[idx].ops=ops;
}

static inline void __attribute__((always_inline))
wd_deregister(struct wd_pack *w,int *sz,int type)
{
	int i;

	if(*sz==0)
		return;

	for(i=0;i<*sz;i++)
		{
		if(w[i].ops->type==type)
			{
			if(*sz==1)
				{
				w[i].ops=NULL;
				*sz=0;
				}
			else
				{
				rte_memcpy(&w[i],&w[*sz-1],sizeof(w[i]));
				*sz--;
				}
			break;
			}
		}
}

int m_plat_init(void *m);
int m_plat_preinit(void *m);
int m_plat_deinit(void *m);

#define phy_port_bond_index(port, port_max) ((port_max==4)? (port>>1): port) //(port >> 1)

#endif
