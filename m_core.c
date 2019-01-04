#include "all.h"
#include "cJSON.h"

uint64_t core_stat[MAX_CPU];
uint64_t core_prev[MAX_CPU];

static uint16_t tcp_port_rover;
static uint16_t udp_port_rover;

int init_step=STEP_STARTED;
pid_t myapp_pid;

static inline int
rte_ipv4_frag_pkt_is_fragmented(const struct ipv4_hdr * hdr) {
	uint16_t flag_offset, ip_flag, ip_ofs;

	flag_offset = rte_be_to_cpu_16(hdr->fragment_offset);
	ip_ofs = (uint16_t)(flag_offset & IPV4_HDR_OFFSET_MASK);
	ip_flag = (uint16_t)(flag_offset & IPV4_HDR_MF_FLAG);

	return ip_flag != 0 || ip_ofs  != 0;
}

static const uint8_t tcp_valid_flags[(TCPHDR_FIN|TCPHDR_SYN|TCPHDR_RST|TCPHDR_ACK|
				 TCPHDR_URG) + 1] =
{
	[TCPHDR_SYN]				= 1,
	[TCPHDR_SYN|TCPHDR_URG]			= 1,
	[TCPHDR_SYN|TCPHDR_ACK]			= 1,
	[TCPHDR_RST]				= 1,
	[TCPHDR_RST|TCPHDR_ACK]			= 1,
	[TCPHDR_FIN|TCPHDR_ACK]			= 1,
	[TCPHDR_FIN|TCPHDR_ACK|TCPHDR_URG]	= 1,
	[TCPHDR_ACK]				= 1,
	[TCPHDR_ACK|TCPHDR_URG]			= 1,
};


static unsigned char const pacp_file_header[24] = {
	0xd4,0xc3,0xb2,0xa1,0x02,0x00,0x04,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0xff,0xff,0x00,0x00,0x01,0x00,0x00,0x00
};

static inline int __attribute__((always_inline))
msg_P_snd_poll(struct hash_array *pending,struct hash_array *snd_depot)
{
	if((!snd_depot->load)&&(pending->load))
		{
//		HW_LOG("core %d :P do snd pending=%d snd=%d\n",
//			rte_lcore_id(),pending->load,snd_depot->load);

		list_splice_tail_init(&pending->header,&snd_depot->header);
		rte_smp_wmb();
		snd_depot->load=pending->load;
		rte_smp_wmb();
		pending->load=0;

		return MM_SUCCESS;
		}

	return MM_FAIL;
}

static inline int __attribute__((always_inline))
msg_P_retrieve_poll(struct hash_array *retrieve_bin,struct hash_array *pool)
{
	if(retrieve_bin->load)
		{
//		HW_LOG("core %d :P get back.load=%d pool.load=%d\n",
//			rte_lcore_id(),retrieve_bin->load,pool->load);

		list_splice_tail_init(&retrieve_bin->header,&pool->header);
		pool->load+=retrieve_bin->load;
		rte_smp_wmb();
		retrieve_bin->load=0;
		rte_smp_wmb();

		return MM_SUCCESS;
		}

	return MM_FAIL;
}

static inline int __attribute__((always_inline))
msg_C_rcv_poll(struct hash_array *rcv_depot,struct hash_array *tmp)
{
	if(rcv_depot->load)
		{
//		HW_LOG("core %d :C get msg.lod=%d cur tmp.load=%d\n",
//			rte_lcore_id(),rcv_depot->load,tmp->load);

		list_splice_tail_init(&rcv_depot->header,&tmp->header);
		tmp->load+=rcv_depot->load;
		rte_smp_wmb();
		rcv_depot->load=0;
		rte_smp_wmb();

		return MM_SUCCESS;
		}
	return MM_FAIL;
}

static inline int __attribute__((always_inline))
msg_C_return_poll(struct hash_array *back_depot,struct hash_array *retrieve_bin)
{
	if((!retrieve_bin->load)&&(back_depot->load))
		{
//		HW_LOG("core %d :C push back pending=%d bin=%d\n",
//			rte_lcore_id(),back_depot->load,retrieve_bin->load);

		list_splice_tail_init(&back_depot->header,&retrieve_bin->header);
		rte_smp_wmb();
		retrieve_bin->load=back_depot->load;
		rte_smp_wmb();
		back_depot->load=0;

		return MM_SUCCESS;
		}
	return MM_FAIL;
}
#if 0
static inline uint8_t
em_get_ipv4_dst_port(void *ipv4_hdr, uint8_t portid, void *lookup_struct)
{
	int ret = 0;
	union ipv4_5tuple_host key;
	struct rte_hash *ipv4_l3fwd_lookup_struct =
		(struct rte_hash *)lookup_struct;

	ipv4_hdr = (uint8_t *)ipv4_hdr + offsetof(struct ipv4_hdr, time_to_live);

	/*
	 * Get 5 tuple: dst port, src port, dst IP address,
	 * src IP address and protocol.
	 */
	key.xmm = em_mask_key(ipv4_hdr, mask0.x);

	/* Find destination port */
	ret = rte_hash_lookup(ipv4_l3fwd_lookup_struct, (const void *)&key);
	return (uint8_t)((ret < 0) ? portid : ipv4_l3fwd_out_if[ret]);
}
#endif

static inline int __attribute__((always_inline))
is_valid_ipv4_pkt(struct ipv4_hdr *pkt, uint32_t link_len)
{
	/* From http://www.rfc-editor.org/rfc/rfc1812.txt section 5.2.2 */
	/*
	 * 1. The packet length reported by the Link Layer must be large
	 * enough to hold the minimum length legal IP datagram (20 bytes).
	 */
	if (link_len < sizeof(struct ipv4_hdr))
		return MM_FAIL;

	/* 2. The IP checksum must be correct. */
	/* this is checked in H/W */

	/*
	 * 3. The IP version number must be 4. If the version number is not 4
	 * then the packet may be another version of IP, such as IPng or
	 * ST-II.
	 */
	if (((pkt->version_ihl) >> 4) != 4)
		return MM_FAIL;
	/*
	 * 4. The IP header length field must be large enough to hold the
	 * minimum length legal IP datagram (20 bytes = 5 words).
	 */
	if ((pkt->version_ihl & IPV4_HDR_IHL_MASK) < 5)
		return MM_FAIL;

	/*
	 * 5. The IP total length field must be large enough to hold the IP
	 * datagram header, whose length is specified in the IP header length
	 * field.
	 */
	if (rte_cpu_to_be_16(pkt->total_length) < sizeof(struct ipv4_hdr))
		return MM_FAIL;

	return MM_SUCCESS;
}

#if 0
inline int cmp_ip_bps_sum(int a,int b,void *tt,int dir)
{
	struct ip_sum_s2 *ipa,*ipb;
	struct topK *t=(struct topK *)tt;

	ipa=(struct ip_sum_s2 *)t->arr[a];
	ipb=(struct ip_sum_s2 *)t->arr[b];

	return (ipa->ip_sum[dir].ip_bps.cnt > ipb->ip_sum[dir].ip_bps.cnt);
}

inline int cmp_ip_pps_sum(int a,int b,void *tt,int dir)
{
	struct ip_sum_s2 *ipa,*ipb;
	struct topK *t=(struct topK *)tt;

	ipa=(struct ip_sum_s2 *)t->arr[a];
	ipb=(struct ip_sum_s2 *)t->arr[b];

	return (ipa->ip_sum[dir].ip_pps.cnt > ipb->ip_sum[dir].ip_pps.cnt);
}

inline int cmp_ip_bps(int a,int b,void *tt,int dir)
{
	struct ip_g_s2 *ipa,*ipb;
	struct topK *t=(struct topK *)tt;

	ipa=(struct ip_g_s2 *)t->arr[a];
	ipb=(struct ip_g_s2 *)t->arr[b];

	return ((ipa->ip_info[dir].cnt&(PPS_OFFSET-1))>(ipb->ip_info[dir].cnt&(PPS_OFFSET-1)));
}

inline int cmp_ip_pps(int a,int b,void *tt,int dir)
{
	struct ip_g_s2 *ipa,*ipb;
	struct topK *t=(struct topK *)tt;

	ipa=(struct ip_g_s2 *)t->arr[a];
	ipb=(struct ip_g_s2 *)t->arr[b];

	return ((ipa->ip_info[dir].cnt>>PPS_SHIFT)>(ipb->ip_info[dir].cnt>>PPS_SHIFT));
}
#endif

//void MaxHeapify(int heapSize, int currentNode,struct topK *t,int dir)
//{
//	int leftChild, rightChild,  largest;
//	void *tmp;

//	leftChild = 2*currentNode + 1;
//	rightChild = 2*currentNode + 2;

//	if(leftChild < heapSize && t->cmp(leftChild,currentNode,(void *)t,dir))
//		{
//		largest = leftChild;
//		}
//	else
//		{
//		largest = currentNode;
//		}
//
//	if(rightChild < heapSize && t->cmp(rightChild,largest,(void *)t,dir))
//		{
//		largest = rightChild;
//		}
//
//	if(largest != currentNode)
//	{
//		tmp=t->arr[largest];
//		t->arr[largest]=t->arr[currentNode];
//		t->arr[currentNode]=tmp;
//		MaxHeapify(heapSize, largest,t,dir);
//	}
//}

//void MaxHeapCreat(int heapSize,struct topK *t,int dir)
//{
//	int i;
//	for(i = heapSize/2-1; i >= 0; i--)
//	{
//		MaxHeapify(heapSize, i,t,dir);
//	}
//}

//void MaxHeapSort(int heapSize,struct topK *t,int dir)
//{
//    MaxHeapCreat(heapSize,t,dir);
//
//    int i;
//    int arraySize = heapSize;
//	void *tmp;
//    for(i = arraySize - 1; i >= 1; i--)
//    {
//    	tmp=t->arr[0];
//		t->arr[0]=t->arr[i];
//		t->arr[i]=tmp;
//        heapSize--;
//        MaxHeapify(heapSize, 0,t,dir);
//    }
//}

//void MinHeapify(int heapSize, int currentNode,struct topK *t,int dir)
//{
//    int leftChild, rightChild,  minimum;
//	void *tmp;
//
//    leftChild = 2*currentNode + 1;
//    rightChild = 2*currentNode + 2;
//    if(leftChild < heapSize && t->cmp(currentNode,leftChild,(void *)t,dir))
//        minimum = leftChild;
//    else
//        minimum = currentNode;
//    if(rightChild < heapSize && t->cmp(minimum,rightChild,(void *)t,dir))
//        minimum = rightChild;
//    if(minimum != currentNode)
//    {
// 		tmp=t->arr[minimum];
//		t->arr[minimum]=t->arr[currentNode];
//		t->arr[currentNode]=tmp;

//		MinHeapify(heapSize, minimum,t,dir);
//    }
//}

//void MinHeapCreat(int heapSize,struct topK *t,int dir)
//{
//    int i;
//    for(i = heapSize/2-1; i >= 0; i--)
//    {
//        MinHeapify(heapSize, i,t,dir);
//    }
//}





#if 0

static inline void __attribute__((always_inline))
flush_fpts()
{
}

static inline void __attribute__((always_inline))
set_state()
{
}


static inline void __attribute__((always_inline))
update_flow(struct flow_point_s *fpt,
	struct rte_mbuf *m,
	struct flow_s *fm,
	int dir)
{
	struct ipv4_info *hdr=rte_pktmbuf_mtod(m,struct ipv4_info *);

	//update flow
	fpt=list_first_entry(flow_pts->next,struct flow_point_s,list);
	list_del_init(&fpt->list);
	list_add_tail(&fpt->list,&fm->pt[dir]);
	fpt->timestamp=m->->udata64;
	fpt->len=m->pkt_len;
	if(m->seqn & F_TCP)
		{
		fpt->seq=hdr->proto.tcp.window;
		fpt->wz=hdr->proto.tcp.window;
		}

	set_state();
	fm->common.cnt[dir]+=PPS_OFFSET;
	fm->common.cnt[dir]+=fpt->len;
	if(++fm->common.pt_cnt>100)
		{
		flush_fpts();
		fm->common.pt_cnt=0;
		}
}




void flow_process_v4(struct rte_mbuf *m,
	struct list_head *flow,
	struct list_head *flow_pts,
	struct list_head *ip,
	struct hash_array *flow_hash,
	struct hash_array *ip_hash)
{
	struct pkt_info *pkt=(struct pkt_info *)m;
	uint32_t flow_idx=m->hash.rss&(FLOW_HASH_ARRAY_SZ-1);
//	uint32_t srcip_idx=pkt->ip.saddr&(IP_HASH_ARRAY_SZ-1);
//	uint32_t dstip_idx=pkt->ip.daddr&(IP_HASH_ARRAY_SZ-1);
	struct flow_s *fm,*fmtmp,*ff;
//	struct ip_g_s *ipm,*iptmp,*ipip;
	int match=0;//bit 0:flow match , bit 1:srcip match,bit 2:dstip match
	struct flow_point_s *fpt;

	if(m->seqn & (F_TCP|F_UDP))
		{
		int dir=0;

		//lookup flow
		if(flow_hash[flow_idx].load)
			{
			list_for_each_entry_safe(fm, fmtmp, &flow_hash[flow_idx].header, list)
				{
				//find pos/neg dir
				if((pkt->ip.saddr==fm->common.tuple.ip_src)&&
					(pkt->ip.daddr==fm->common.tuple.ip_dst)&&
					(pkt->proto.port.source==fm->common.tuple.port_src)&&
					(pkt->proto.port.dest==fm->common.tuple.port_dst))
					{
					//dir=0;
					match|=1;
					break;
					}
				else if((pkt->ip.saddr==fm->common.tuple.ip_dst)&&
					(pkt->ip.daddr==fm->common.tuple.ip_src)&&
					(pkt->proto.port.source==fm->common.tuple.port_dst)&&
					(pkt->proto.port.dest==fm->common.tuple.port_src))//found it
					{
					dir=1;
					match|=1;
					break;
					}
				}
			}

		if(match)//found
			{
			if(list_empty(flow_pts))
				{
				//flow pts is not enough
				RUNNING_LOG_DEBUG("core %d : flow pts is not enough\n",rte_lcore_id());
				flush_fpts();
				rte_pktmbuf_free(m);
				}
			else
				{
				//update flow
				update_flow(fpt,m,fm,dir);

				//
				}

			return;
			}
		else
			{
			}
		}
}
#endif

static inline void __attribute__((always_inline))
update_ip2(struct ip_g_s2 *ipm,
	uint32_t packet_type,
	int idx,
	int byte_len)
{
	ipm->ip_info[idx].ip.pps++;
	ipm->ip_info[idx].ip.bps+=byte_len;

	if(packet_type&FLAG(F_IPV4))
		{
		if(packet_type&FLAG(F_TCP))
			{
			ipm->ip_info[idx].tcp.pps++;
			ipm->ip_info[idx].tcp.bps+=byte_len;

			if(packet_type&FLAG(F_TCP_SYN))
				{
				ipm->ip_info[idx].tcp.syn++;
				}
			else if(packet_type&FLAG(F_TCP_SYN_ACK))
				{
				ipm->ip_info[idx].tcp.syn_ack++;
				}
			else if(packet_type&FLAG(F_TCP_ACK))
				{
				ipm->ip_info[idx].tcp.ack++;
				}
			else if(packet_type&FLAG(F_TCP_FIN))
				{
				ipm->ip_info[idx].tcp.fin++;
				}
			else if(packet_type&FLAG(F_TCP_RST))
				{
				ipm->ip_info[idx].tcp.rst++;
				}
			}
		else if(packet_type&FLAG(F_UDP))
			{
			ipm->ip_info[idx].udp.pps++;
			ipm->ip_info[idx].udp.bps+=byte_len;
			}
		else if(packet_type&FLAG(F_ICMP))
			{
			ipm->ip_info[idx].icmp.pps++;
			ipm->ip_info[idx].icmp.bps+=byte_len;
			}
		else if(packet_type&FLAG(F_IGMP))
			{
			ipm->ip_info[idx].igmp.pps++;
			ipm->ip_info[idx].igmp.bps+=byte_len;
			}
		}
}

char *ip2str(char str[], uint32_t ip)
{
	char *ptr = (char *)&ip;
	sprintf(str, "%u.%u.%u.%u", ptr[0]&0xff, ptr[1]&0xff, ptr[2]&0xff, ptr[3]&0xff);
	return str;
}

char *ip2strle(char str[], uint32_t ip)
{
	char *ptr = (char *)&ip;
	sprintf(str, "%u.%u.%u.%u", ptr[3]&0xff, ptr[2]&0xff, ptr[1]&0xff, ptr[0]&0xff);
	return str;
}


#if 0
static inline void __attribute__((always_inline))
dump_sum_ip2(struct ip_sum_s2 *sum,int dir)
{
	char ip_str[64];

	if(sum->ip_sum[dir].ip_bps.cnt)
		{
		RUNNING_LOG_INFO("%s: core<%d> ip=%s dir=%d\n",__FUNCTION__,rte_lcore_id(),ip2str(ip_str,sum->addr),dir);
		RUNNING_LOG_INFO("ip_bps=%llu ip_pps=%llu tcp_bps=%llu tcp_pps=%llu udp_bps=%llu udp_pps=%llu \n",
			sum->ip_sum[dir].ip_bps.cnt,sum->ip_sum[dir].ip_pps.cnt,
			sum->ip_sum[dir].tcp_bps.cnt,sum->ip_sum[dir].tcp_pps.cnt,
			sum->ip_sum[dir].udp_bps.cnt,sum->ip_sum[dir].udp_pps.cnt);
		}
}

static inline void __attribute__((always_inline))
dump_g_ip2(struct ip_g_s2 *sum,int dir)
{
	char ip_str[64];

	if(sum->ip_info[dir].cnt)
		{
		RUNNING_LOG_INFO("%s: core<%d> ip=%s dir=%d\n",__FUNCTION__,rte_lcore_id(),ip2str(ip_str,sum->addr),dir);
		RUNNING_LOG_INFO("ip_bps=%llu ip_pps=%llu tcp_bps=%llu tcp_pps=%llu udp_bps=%llu udp_pps=%llu \n",
			sum->ip_info[dir].cnt&(PPS_OFFSET-1),sum->ip_info[dir].cnt>>PPS_SHIFT,
			sum->ip_info[dir].tcp.cnt&(PPS_OFFSET-1),sum->ip_info[dir].tcp.cnt>>PPS_SHIFT,
			sum->ip_info[dir].udp.cnt&(PPS_OFFSET-1),sum->ip_info[dir].udp.cnt>>PPS_SHIFT);
		}
}



static inline void __attribute__((always_inline))
sum_ip2(struct ip_sum_s2 *sum,struct ip_g_s2 *ip,int dir)
{
	//tcp
	sum->ip_sum[dir].tcp_bps.cnt+=(ip->ip_info[dir].tcp.cnt&(PPS_OFFSET-1));
	sum->ip_sum[dir].tcp_pps.cnt+=(ip->ip_info[dir].tcp.cnt>>PPS_SHIFT);
	sum->ip_sum[dir].tcp_pps.syn+=ip->ip_info[dir].tcp.syn;
	sum->ip_sum[dir].tcp_pps.syn_ack+=ip->ip_info[dir].tcp.syn_ack;
	sum->ip_sum[dir].tcp_pps.ack+=ip->ip_info[dir].tcp.ack;
	sum->ip_sum[dir].tcp_pps.rst+=ip->ip_info[dir].tcp.rst;
	sum->ip_sum[dir].tcp_pps.fin+=ip->ip_info[dir].tcp.fin;

	//udp
	sum->ip_sum[dir].udp_bps.cnt+=(ip->ip_info[dir].udp.cnt&(PPS_OFFSET-1));
	sum->ip_sum[dir].udp_pps.cnt+=(ip->ip_info[dir].udp.cnt>>PPS_SHIFT);
	sum->ip_sum[dir].udp_pps.flow+=ip->ip_info[dir].udp.flow;

	//icmp
	sum->ip_sum[dir].icmp_bps.cnt+=(ip->ip_info[dir].icmp.cnt&(PPS_OFFSET-1));
	sum->ip_sum[dir].icmp_pps.cnt+=(ip->ip_info[dir].icmp.cnt>>PPS_SHIFT);
	sum->ip_sum[dir].icmp_pps.echo+=ip->ip_info[dir].icmp.echo;
	sum->ip_sum[dir].icmp_pps.redir+=ip->ip_info[dir].icmp.redir;
	sum->ip_sum[dir].icmp_pps.unreach+=ip->ip_info[dir].icmp.unreach;

	//igmp
	sum->ip_sum[dir].igmp_bps.cnt+=(ip->ip_info[dir].igmp.cnt&(PPS_OFFSET-1));
	sum->ip_sum[dir].igmp_pps.cnt+=(ip->ip_info[dir].igmp.cnt>>PPS_SHIFT);
	sum->ip_sum[dir].igmp_pps.v1+=ip->ip_info[dir].igmp.v1;
	sum->ip_sum[dir].igmp_pps.v2+=ip->ip_info[dir].igmp.v2;
	sum->ip_sum[dir].igmp_pps.v3+=ip->ip_info[dir].igmp.v3;

	//ip
	sum->ip_sum[dir].ip_bps.cnt+=(ip->ip_info[dir].cnt&(PPS_OFFSET-1));
	sum->ip_sum[dir].ip_pps.cnt+=(ip->ip_info[dir].cnt>>PPS_SHIFT);
	sum->ip_sum[dir].ip_pps.ip_option+=ip->ip_info[dir].ip_option;

	//attack
	sum->ip_sum[dir].attack_pps.chargen+=ip->ip_info[dir].chargen;
	sum->ip_sum[dir].attack_pps.dns+=ip->ip_info[dir].dns;
	sum->ip_sum[dir].attack_pps.frag+=ip->ip_info[dir].frag;
	sum->ip_sum[dir].attack_pps.frag_err+=ip->ip_info[dir].frag_err;
	sum->ip_sum[dir].attack_pps.tcp_flag_err+=ip->ip_info[dir].tcp_flag_err;
	sum->ip_sum[dir].attack_pps.smurf+=ip->ip_info[dir].smurf;
	sum->ip_sum[dir].attack_pps.fraggle+=ip->ip_info[dir].fraggle;
	sum->ip_sum[dir].attack_pps.nuker+=ip->ip_info[dir].nuker;
	sum->ip_sum[dir].attack_pps.ssdp+=ip->ip_info[dir].ssdp;
	sum->ip_sum[dir].attack_pps.ntp+=ip->ip_info[dir].ntp;
	sum->ip_sum[dir].attack_pps.snmp+=ip->ip_info[dir].snmp;
	sum->ip_sum[dir].attack_pps.tracert+=ip->ip_info[dir].tracert;
}
#endif

static inline int __attribute__((always_inline))
mincmp_pps_dst(void *x,void *y)
{
	struct ip_sum_b *a,*b;

	a=(struct ip_sum_b *)x;
	b=(struct ip_sum_b *)y;

	return (a->ip_sum[DIR_IN].ip.pps > b->ip_sum[DIR_IN].ip.pps);
}

static inline int __attribute__((always_inline))
mincmp_pps_src(void *x,void *y)
{
	struct ip_sum_b *a,*b;

	a=(struct ip_sum_b *)x;
	b=(struct ip_sum_b *)y;

	return (a->ip_sum[DIR_OUT].ip.pps > b->ip_sum[DIR_OUT].ip.pps);
}

static inline int __attribute__((always_inline))
mincmp_bps_dst(void *x,void *y)
{
	struct ip_sum_b *a,*b;

	a=(struct ip_sum_b *)x;
	b=(struct ip_sum_b *)y;

	return (a->ip_sum[DIR_IN].ip.bps > b->ip_sum[DIR_IN].ip.bps);
}


void wd_minheap_modify(int heapSize, int currentNode,struct wd_pack *w,int s)
{
    int leftChild, rightChild,  minimum;
	void *tmp;

    leftChild = 2*currentNode + 1;
    rightChild = 2*currentNode + 2;
    if(leftChild < heapSize &&
		w->ops->mincmp((void *)(w->top[s].arr[currentNode]),(void *)(w->top[s].arr[leftChild])))
        minimum = leftChild;
    else
        minimum = currentNode;
    if(rightChild < heapSize &&
		w->ops->mincmp((void *)(w->top[s].arr[minimum]),(void *)(w->top[s].arr[rightChild])))
        minimum = rightChild;

    if(minimum != currentNode)
    	{
 		tmp=w->top[s].arr[minimum];
		w->top[s].arr[minimum]=w->top[s].arr[currentNode];
		w->top[s].arr[currentNode]=tmp;
		wd_minheap_modify(heapSize, minimum,w,s);
		}
}

void wd_minheap_creat(int heapSize,struct wd_pack *w,int s)
{
    int i;
    for(i = heapSize/2-1; i >= 0; i--)
    	{
        wd_minheap_modify(heapSize,i,w,s);
    	}
}

void wd_process_pps_dst(void *in,struct wd_pack *w,int s)
{
	struct ip_sum_b *p=(struct ip_sum_b *)in;

	if(p->ip_sum[DIR_IN].ip.pps==0)
		return;

	if(w->top[s].curr<MAX_TOPN_PER)
		{
		if(!(p->flag & FLAG(WD_PPS_DST)))
			{
			p->flag |= FLAG(WD_PPS_DST);
			w->top[s].arr[w->top[s].curr++]=in;
//		RUNNING_LOG_INFO("core<%d> wd_process_pps_dst w=%p ip=%x flag=%llx curr=%d\n",rte_lcore_id(),
//			w,p->addr,p->flag,w->top[s].curr);

			if(w->top[s].curr==MAX_TOPN_PER)
				{
				w->ops->minheap_creat(MAX_TOPN_PER,w,s);
				}
			}
		}
	else
		{
		if(!(p->flag & FLAG(WD_PPS_DST)))
			{
			if(w->ops->mincmp(p,w->top[s].arr[0]))
				{
				p->flag |= FLAG(WD_PPS_DST);
				w->top[s].arr[0]=in;
				w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
				}
			}
		else
			{
			w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
			}
		}
}

void wd_dump_pps_dst(struct wd_pack *w,int s)
{
	int i;

//	RUNNING_LOG_INFO("%s(%d): core<%d> curr=%d s=%d\n",__FUNCTION__,__LINE__,rte_lcore_id(),w->top[s].curr,s);
	for(i=0;i<w->top[s].curr;i++)
		{
		struct ip_sum_b *p=(struct ip_sum_b *)w->top[s].arr[i];

		RUNNING_LOG_INFO("core<%d> NO.%d ip=%x dst pps=%llu\n",rte_lcore_id(),i,
			p->addr,p->ip_sum[0].ip.pps);
		}
}

void wd_soft_pps_dst(struct wd_pack *w,int s)
{
	int i,j;
	void *tmp;

	if(w->top[s].curr<=1)
		return;

	if(w->top[s].curr<MAX_TOPN_PER)
		w->ops->minheap_creat(w->top[s].curr,w,s);

	j=w->top[s].curr;
	for(i=w->top[s].curr-1;i>=1;i--)
		{
		tmp=w->top[s].arr[i];
		w->top[s].arr[i]=w->top[s].arr[0];
		w->top[s].arr[0]=tmp;
		j--;
		w->ops->minheap_mod(j,0,w,s);
		}
}

void wd_process_bps_dst(void *in,struct wd_pack *w,int s)
{
	struct ip_sum_b *p=(struct ip_sum_b *)in;

	if(p->ip_sum[DIR_IN].ip.bps==0)
		return;

	if(w->top[s].curr<MAX_TOPN_PER)
		{
		if(!(p->flag & FLAG(WD_BPS_DST)))
			{
			p->flag |= FLAG(WD_BPS_DST);
			w->top[s].arr[w->top[s].curr++]=in;
			if(w->top[s].curr==MAX_TOPN_PER)
				{
				w->ops->minheap_creat(MAX_TOPN_PER,w,s);
				}
			}
		}
	else
		{
		if(!(p->flag & FLAG(WD_BPS_DST)))
			{
			if(w->ops->mincmp(p,w->top[s].arr[0]))
				{
				p->flag |= FLAG(WD_BPS_DST);
				w->top[s].arr[0]=in;
				w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
				}
			}
		else
			{
			w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
			}
		}
}


void wd_dump_bps_dst(struct wd_pack *w,int s)
{
	int i;

//	RUNNING_LOG_INFO("%s(%d): core<%d> curr=%d s=%d\n",__FUNCTION__,__LINE__,rte_lcore_id(),w->top[s].curr,s);
	for(i=0;i<w->top[s].curr;i++)
		{
		struct ip_sum_b *p=(struct ip_sum_b *)w->top[s].arr[i];

		RUNNING_LOG_INFO("core<%d> NO.%d ip=%x dst bps=%llu\n",rte_lcore_id(),i,
			p->addr,p->ip_sum[0].ip.bps);
		}
}

void wd_process_pps_src(void *in,struct wd_pack *w,int s)
{
	struct ip_sum_b *p=(struct ip_sum_b *)in;

	if(p->ip_sum[DIR_OUT].ip.pps==0)
		return;

	if(w->top[s].curr<MAX_TOPN_PER)
		{
		if(!(p->flag & FLAG(WD_PPS_SRC)))
			{
			p->flag |= FLAG(WD_PPS_SRC);
			w->top[s].arr[w->top[s].curr++]=in;
			if(w->top[s].curr==MAX_TOPN_PER)
				{
				w->ops->minheap_creat(MAX_TOPN_PER,w,s);
				}
			}
		}
	else
		{
		if(!(p->flag & FLAG(WD_PPS_SRC)))
			{
			if(w->ops->mincmp(p,w->top[s].arr[0]))
				{
				p->flag |= FLAG(WD_PPS_SRC);
				w->top[s].arr[0]=in;
				w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
				}
			}
		else
			{
			w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
			}
		}
}


void wd_dump_pps_src(struct wd_pack *w,int s)
{
	int i;

//	RUNNING_LOG_INFO("%s(%d): core<%d> curr=%d s=%d\n",__FUNCTION__,__LINE__,rte_lcore_id(),w->top[s].curr,s);
	for(i=0;i<w->top[s].curr;i++)
		{
		struct ip_sum_b *p=(struct ip_sum_b *)w->top[s].arr[i];

		RUNNING_LOG_INFO("core<%d> NO.%d ip=%x src pps=%llu\n",rte_lcore_id(),i,
			p->addr,p->ip_sum[1].ip.pps);
		}
}


struct wd_ops ip_pps_dst_ops={
	.type=WD_PPS_DST,
	.mincmp=mincmp_pps_dst,
	.minheap_creat=wd_minheap_creat,
	.minheap_mod=wd_minheap_modify,
	.process=wd_process_pps_dst,
	.dump=wd_dump_pps_dst,
	.soft=wd_soft_pps_dst,
};

struct wd_ops ip_pps_src_ops={
	.type=WD_PPS_SRC,
	.mincmp=mincmp_pps_src,
	.minheap_creat=wd_minheap_creat,
	.minheap_mod=wd_minheap_modify,
	.process=wd_process_pps_src,
	.dump=wd_dump_pps_src,
	.soft=wd_soft_pps_dst,
};

struct wd_ops ip_bps_dst_ops={
	.type=WD_BPS_DST,
	.mincmp=mincmp_bps_dst,
	.minheap_creat=wd_minheap_creat,
	.minheap_mod=wd_minheap_modify,
	.process=wd_process_bps_dst,
	.dump=wd_dump_bps_dst,
	.soft=wd_soft_pps_dst,
};

// l4 tcp wd
static inline int __attribute__((always_inline))
wd_l4_mincmp_all_dst(void *x,void *y)
{
	struct l4_port_g_b *a,*b;

	a=(struct l4_port_g_b *)x;
	b=(struct l4_port_g_b *)y;


	return (a->info.all[DIR_IN] > b->info.all[DIR_IN]);
}

static inline int __attribute__((always_inline))
wd_l4_mincmp_all_src(void *x,void *y)
{
	struct l4_port_g_b *a,*b;

	a=(struct l4_port_g_b *)x;
	b=(struct l4_port_g_b *)y;


	return (a->info.all[DIR_OUT] > b->info.all[DIR_OUT]);
}

static inline int __attribute__((always_inline))
wd_l4_mincmp_tcp_dst(void *x,void *y)
{
	struct l4_port_g_b *a,*b;

	a=(struct l4_port_g_b *)x;
	b=(struct l4_port_g_b *)y;


	return (a->info.tcp[DIR_IN] > b->info.tcp[DIR_IN]);
}

static inline int __attribute__((always_inline))
wd_l4_mincmp_tcp_src(void *x,void *y)
{
	struct l4_port_g_b *a,*b;

	a=(struct l4_port_g_b *)x;
	b=(struct l4_port_g_b *)y;


	return (a->info.tcp[DIR_OUT] > b->info.tcp[DIR_OUT]);
}

static inline int __attribute__((always_inline))
wd_l4_mincmp_udp_dst(void *x,void *y)
{
	struct l4_port_g_b *a,*b;

	a=(struct l4_port_g_b *)x;
	b=(struct l4_port_g_b *)y;


	return (a->info.udp[DIR_IN] > b->info.udp[DIR_IN]);
}

static inline int __attribute__((always_inline))
wd_l4_mincmp_udp_src(void *x,void *y)
{
	struct l4_port_g_b *a,*b;

	a=(struct l4_port_g_b *)x;
	b=(struct l4_port_g_b *)y;


	return (a->info.udp[DIR_OUT] > b->info.udp[DIR_OUT]);
}

static inline int __attribute__((always_inline))
wd_l4_mincmp_all_dst2(void *x,void *y)
{
	struct l4_port_sum_b *a,*b;

	a=(struct l4_port_sum_b *)x;
	b=(struct l4_port_sum_b *)y;


	return (a->info.all[DIR_IN] > b->info.all[DIR_IN]);
}

static inline int __attribute__((always_inline))
wd_l4_mincmp_all_src2(void *x,void *y)
{
	struct l4_port_sum_b *a,*b;

	a=(struct l4_port_sum_b *)x;
	b=(struct l4_port_sum_b *)y;


	return (a->info.all[DIR_OUT] > b->info.all[DIR_OUT]);
}

static inline int __attribute__((always_inline))
wd_l4_mincmp_tcp_dst2(void *x,void *y)
{
	struct l4_port_sum_b *a,*b;

	a=(struct l4_port_sum_b *)x;
	b=(struct l4_port_sum_b *)y;


	return (a->info.tcp[DIR_IN] > b->info.tcp[DIR_IN]);
}

static inline int __attribute__((always_inline))
wd_l4_mincmp_tcp_src2(void *x,void *y)
{
	struct l4_port_sum_b *a,*b;

	a=(struct l4_port_sum_b *)x;
	b=(struct l4_port_sum_b *)y;


	return (a->info.tcp[DIR_OUT] > b->info.tcp[DIR_OUT]);
}

static inline int __attribute__((always_inline))
wd_l4_mincmp_udp_dst2(void *x,void *y)
{
	struct l4_port_sum_b *a,*b;

	a=(struct l4_port_sum_b *)x;
	b=(struct l4_port_sum_b *)y;


	return (a->info.udp[DIR_IN] > b->info.udp[DIR_IN]);
}

static inline int __attribute__((always_inline))
wd_l4_mincmp_udp_src2(void *x,void *y)
{
	struct l4_port_sum_b *a,*b;

	a=(struct l4_port_sum_b *)x;
	b=(struct l4_port_sum_b *)y;


	return (a->info.udp[DIR_OUT] > b->info.udp[DIR_OUT]);
}

void wd_l4_process_all_dst(void *in,struct wd_pack *w,int s)
{
	struct l4_port_g_b *p=(struct l4_port_g_b *)in;

	if(p->info.all[DIR_IN]==0)
		return;

	if(w->top[s].curr<MAX_TOPN_PER)
		{
		w->top[s].arr[w->top[s].curr++]=in;
		if(w->top[s].curr==MAX_TOPN_PER)
			{
			w->ops->minheap_creat(MAX_TOPN_PER,w,s);
			}
		}
	else
		{
		if(w->ops->mincmp(p,w->top[s].arr[0]))
			{
			w->top[s].arr[0]=in;
			w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
			}
		}
}

void wd_l4_process_all_src(void *in,struct wd_pack *w,int s)
{
	struct l4_port_g_b *p=(struct l4_port_g_b *)in;

	if(p->info.all[DIR_OUT]==0)
		return;

	if(w->top[s].curr<MAX_TOPN_PER)
		{
		w->top[s].arr[w->top[s].curr++]=in;
		if(w->top[s].curr==MAX_TOPN_PER)
			{
			w->ops->minheap_creat(MAX_TOPN_PER,w,s);
			}
		}
	else
		{
		if(w->ops->mincmp(p,w->top[s].arr[0]))
			{
			w->top[s].arr[0]=in;
			w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
			}
		}
}

void wd_l4_process_tcp_dst(void *in,struct wd_pack *w,int s)
{
	struct l4_port_g_b *p=(struct l4_port_g_b *)in;

	if(p->info.tcp[DIR_IN]==0)
		return;

	if(w->top[s].curr<MAX_TOPN_PER)
		{
		w->top[s].arr[w->top[s].curr++]=in;
		if(w->top[s].curr==MAX_TOPN_PER)
			{
			w->ops->minheap_creat(MAX_TOPN_PER,w,s);
			}
		}
	else
		{
		if(w->ops->mincmp(p,w->top[s].arr[0]))
			{
			w->top[s].arr[0]=in;
			w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
			}
		}
}

void wd_l4_process_tcp_src(void *in,struct wd_pack *w,int s)
{
	struct l4_port_g_b *p=(struct l4_port_g_b *)in;

	if(p->info.tcp[DIR_OUT]==0)
		return;

	if(w->top[s].curr<MAX_TOPN_PER)
		{
		w->top[s].arr[w->top[s].curr++]=in;
		if(w->top[s].curr==MAX_TOPN_PER)
			{
			w->ops->minheap_creat(MAX_TOPN_PER,w,s);
			}
		}
	else
		{
		if(w->ops->mincmp(p,w->top[s].arr[0]))
			{
			w->top[s].arr[0]=in;
			w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
			}
		}
}

void wd_l4_process_udp_dst(void *in,struct wd_pack *w,int s)
{
	struct l4_port_g_b *p=(struct l4_port_g_b *)in;

	if(p->info.udp[DIR_IN]==0)
		return;

	if(w->top[s].curr<MAX_TOPN_PER)
		{
		w->top[s].arr[w->top[s].curr++]=in;
		if(w->top[s].curr==MAX_TOPN_PER)
			{
			w->ops->minheap_creat(MAX_TOPN_PER,w,s);
			}
		}
	else
		{
		if(w->ops->mincmp(p,w->top[s].arr[0]))
			{
			w->top[s].arr[0]=in;
			w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
			}
		}
}

void wd_l4_process_udp_src(void *in,struct wd_pack *w,int s)
{
	struct l4_port_g_b *p=(struct l4_port_g_b *)in;

	if(p->info.udp[DIR_OUT]==0)
		return;

	if(w->top[s].curr<MAX_TOPN_PER)
		{
		w->top[s].arr[w->top[s].curr++]=in;
		if(w->top[s].curr==MAX_TOPN_PER)
			{
			w->ops->minheap_creat(MAX_TOPN_PER,w,s);
			}
		}
	else
		{
		if(w->ops->mincmp(p,w->top[s].arr[0]))
			{
			w->top[s].arr[0]=in;
			w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
			}
		}
}

void wd_l4_process_all_dst2(void *in,struct wd_pack *w,int s)
{
	struct l4_port_sum_b *p=(struct l4_port_sum_b *)in;

	if(p->info.all[DIR_IN]==0)
		return;

	if(w->top[s].curr<MAX_TOPN_PER)
		{
		w->top[s].arr[w->top[s].curr++]=in;
		if(w->top[s].curr==MAX_TOPN_PER)
			{
			w->ops->minheap_creat(MAX_TOPN_PER,w,s);
			}
		}
	else
		{
		if(w->ops->mincmp(p,w->top[s].arr[0]))
			{
			w->top[s].arr[0]=in;
			w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
			}
		}
}

void wd_l4_process_all_src2(void *in,struct wd_pack *w,int s)
{
	struct l4_port_sum_b *p=(struct l4_port_sum_b *)in;

	if(p->info.all[DIR_OUT]==0)
		return;

	if(w->top[s].curr<MAX_TOPN_PER)
		{
		w->top[s].arr[w->top[s].curr++]=in;
		if(w->top[s].curr==MAX_TOPN_PER)
			{
			w->ops->minheap_creat(MAX_TOPN_PER,w,s);
			}
		}
	else
		{
		if(w->ops->mincmp(p,w->top[s].arr[0]))
			{
			w->top[s].arr[0]=in;
			w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
			}
		}
}

void wd_l4_process_tcp_dst2(void *in,struct wd_pack *w,int s)
{
	struct l4_port_sum_b *p=(struct l4_port_sum_b *)in;

	if(p->info.tcp[DIR_IN]==0)
		return;

	if(w->top[s].curr<MAX_TOPN_PER)
		{
		w->top[s].arr[w->top[s].curr++]=in;
		if(w->top[s].curr==MAX_TOPN_PER)
			{
			w->ops->minheap_creat(MAX_TOPN_PER,w,s);
			}
		}
	else
		{
		if(w->ops->mincmp(p,w->top[s].arr[0]))
			{
			w->top[s].arr[0]=in;
			w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
			}
		}
}

void wd_l4_process_tcp_src2(void *in,struct wd_pack *w,int s)
{
	struct l4_port_sum_b *p=(struct l4_port_sum_b *)in;

	if(p->info.tcp[DIR_OUT]==0)
		return;

	if(w->top[s].curr<MAX_TOPN_PER)
		{
		w->top[s].arr[w->top[s].curr++]=in;
		if(w->top[s].curr==MAX_TOPN_PER)
			{
			w->ops->minheap_creat(MAX_TOPN_PER,w,s);
			}
		}
	else
		{
		if(w->ops->mincmp(p,w->top[s].arr[0]))
			{
			w->top[s].arr[0]=in;
			w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
			}
		}
}

void wd_l4_process_udp_dst2(void *in,struct wd_pack *w,int s)
{
	struct l4_port_sum_b *p=(struct l4_port_sum_b *)in;

	if(p->info.udp[DIR_IN]==0)
		return;

	if(w->top[s].curr<MAX_TOPN_PER)
		{
		w->top[s].arr[w->top[s].curr++]=in;
		if(w->top[s].curr==MAX_TOPN_PER)
			{
			w->ops->minheap_creat(MAX_TOPN_PER,w,s);
			}
		}
	else
		{
		if(w->ops->mincmp(p,w->top[s].arr[0]))
			{
			w->top[s].arr[0]=in;
			w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
			}
		}
}

void wd_l4_process_udp_src2(void *in,struct wd_pack *w,int s)
{
	struct l4_port_sum_b *p=(struct l4_port_sum_b *)in;

	if(p->info.udp[DIR_OUT]==0)
		return;

	if(w->top[s].curr<MAX_TOPN_PER)
		{
		w->top[s].arr[w->top[s].curr++]=in;
		if(w->top[s].curr==MAX_TOPN_PER)
			{
			w->ops->minheap_creat(MAX_TOPN_PER,w,s);
			}
		}
	else
		{
		if(w->ops->mincmp(p,w->top[s].arr[0]))
			{
			w->top[s].arr[0]=in;
			w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
			}
		}
}

void wd_l4_dump_all_dst(struct wd_pack *w,int s)
{
	int i;
	struct l4_port_g_b *p;

//	RUNNING_LOG_INFO("%s(%d): core<%d> curr=%d s=%d\n",__FUNCTION__,__LINE__,rte_lcore_id(),w->top[s].curr,s);
	for(i=0;i<w->top[s].curr;i++)
		{
		p=(struct l4_port_g_b *)w->top[s].arr[i];

		RUNNING_LOG_INFO("core<%d> NO.%d all dst port %d=%llu\n",rte_lcore_id(),i,rte_be_to_cpu_16(p->no),p->info.all[DIR_IN]);
		}
}

void wd_l4_dump_all_src(struct wd_pack *w,int s)
{
	int i;
	struct l4_port_g_b *p;

//	RUNNING_LOG_INFO("%s(%d): core<%d> curr=%d s=%d\n",__FUNCTION__,__LINE__,rte_lcore_id(),w->top[s].curr,s);
	for(i=0;i<w->top[s].curr;i++)
		{
		p=(struct l4_port_g_b *)w->top[s].arr[i];

		RUNNING_LOG_INFO("core<%d> NO.%d all src port %d=%llu\n",rte_lcore_id(),i,rte_be_to_cpu_16(p->no),p->info.all[DIR_OUT]);
		}
}

void wd_l4_dump_tcp_dst(struct wd_pack *w,int s)
{
	int i;
	struct l4_port_g_b *p;

//	RUNNING_LOG_INFO("%s(%d): core<%d> curr=%d s=%d\n",__FUNCTION__,__LINE__,rte_lcore_id(),w->top[s].curr,s);
	for(i=0;i<w->top[s].curr;i++)
		{
		p=(struct l4_port_g_b *)w->top[s].arr[i];

		RUNNING_LOG_INFO("core<%d> NO.%d tcp dst port %d=%llu\n",rte_lcore_id(),i,rte_be_to_cpu_16(p->no),p->info.tcp[DIR_IN]);
		}
}

void wd_l4_dump_tcp_src(struct wd_pack *w,int s)
{
	int i;
	struct l4_port_g_b *p;

//	RUNNING_LOG_INFO("%s(%d): core<%d> curr=%d s=%d\n",__FUNCTION__,__LINE__,rte_lcore_id(),w->top[s].curr,s);
	for(i=0;i<w->top[s].curr;i++)
		{
		p=(struct l4_port_g_b *)w->top[s].arr[i];

		RUNNING_LOG_INFO("core<%d> NO.%d tcp src port %d=%llu\n",rte_lcore_id(),i,rte_be_to_cpu_16(p->no),p->info.tcp[DIR_OUT]);
		}
}

void wd_l4_dump_udp_dst(struct wd_pack *w,int s)
{
	int i;
	struct l4_port_g_b *p;

//	RUNNING_LOG_INFO("%s(%d): core<%d> curr=%d s=%d\n",__FUNCTION__,__LINE__,rte_lcore_id(),w->top[s].curr,s);
	for(i=0;i<w->top[s].curr;i++)
		{
		p=(struct l4_port_g_b *)w->top[s].arr[i];

		RUNNING_LOG_INFO("core<%d> NO.%d udp dst port %d=%llu\n",rte_lcore_id(),i,rte_be_to_cpu_16(p->no),p->info.udp[DIR_IN]);
		}
}

void wd_l4_dump_udp_src(struct wd_pack *w,int s)
{
	int i;
	struct l4_port_g_b *p;

//	RUNNING_LOG_INFO("%s(%d): core<%d> curr=%d s=%d\n",__FUNCTION__,__LINE__,rte_lcore_id(),w->top[s].curr,s);
	for(i=0;i<w->top[s].curr;i++)
		{
		p=(struct l4_port_g_b *)w->top[s].arr[i];

		RUNNING_LOG_INFO("core<%d> NO.%d all src port %d=%llu\n",rte_lcore_id(),i,rte_be_to_cpu_16(p->no),p->info.udp[DIR_OUT]);
		}
}

void wd_l4_dump_all_dst2(struct wd_pack *w,int s)
{
	int i;
	struct l4_port_sum_b *p;

//	RUNNING_LOG_INFO("%s(%d): core<%d> curr=%d s=%d\n",__FUNCTION__,__LINE__,rte_lcore_id(),w->top[s].curr,s);
	for(i=0;i<w->top[s].curr;i++)
		{
		p=(struct l4_port_sum_b *)w->top[s].arr[i];

		RUNNING_LOG_INFO("core<%d> NO.%d all dst port %d=%llu ip=%x\n",rte_lcore_id(),i,
			rte_be_to_cpu_16(p->no),p->info.all[DIR_IN],p->l3p->addr);
		}
}

void wd_l4_dump_all_src2(struct wd_pack *w,int s)
{
	int i;
	struct l4_port_sum_b *p;

//	RUNNING_LOG_INFO("%s(%d): core<%d> curr=%d s=%d\n",__FUNCTION__,__LINE__,rte_lcore_id(),w->top[s].curr,s);
	for(i=0;i<w->top[s].curr;i++)
		{
		p=(struct l4_port_sum_b *)w->top[s].arr[i];

		RUNNING_LOG_INFO("core<%d> NO.%d all src port %d=%llu ip=%x\n",rte_lcore_id(),i,
			rte_be_to_cpu_16(p->no),p->info.all[DIR_OUT],p->l3p->addr);
		}
}

void wd_l4_dump_tcp_dst2(struct wd_pack *w,int s)
{
	int i;
	struct l4_port_sum_b *p;

//	RUNNING_LOG_INFO("%s(%d): core<%d> curr=%d s=%d\n",__FUNCTION__,__LINE__,rte_lcore_id(),w->top[s].curr,s);
	for(i=0;i<w->top[s].curr;i++)
		{
		p=(struct l4_port_sum_b *)w->top[s].arr[i];

		RUNNING_LOG_INFO("core<%d> NO.%d tcp dst port %d=%llu ip=%x\n",rte_lcore_id(),i,
			rte_be_to_cpu_16(p->no),p->info.tcp[DIR_IN],p->l3p->addr);
		}
}

void wd_l4_dump_tcp_src2(struct wd_pack *w,int s)
{
	int i;
	struct l4_port_sum_b *p;

//	RUNNING_LOG_INFO("%s(%d): core<%d> curr=%d s=%d\n",__FUNCTION__,__LINE__,rte_lcore_id(),w->top[s].curr,s);
	for(i=0;i<w->top[s].curr;i++)
		{
		p=(struct l4_port_sum_b *)w->top[s].arr[i];

		RUNNING_LOG_INFO("core<%d> NO.%d tcp src port %d=%llu ip=%x\n",rte_lcore_id(),i,
			rte_be_to_cpu_16(p->no),p->info.tcp[DIR_OUT],p->l3p->addr);
		}
}

void wd_l4_dump_udp_dst2(struct wd_pack *w,int s)
{
	int i;
	struct l4_port_sum_b *p;

//	RUNNING_LOG_INFO("%s(%d): core<%d> curr=%d s=%d\n",__FUNCTION__,__LINE__,rte_lcore_id(),w->top[s].curr,s);
	for(i=0;i<w->top[s].curr;i++)
		{
		p=(struct l4_port_sum_b *)w->top[s].arr[i];

		RUNNING_LOG_INFO("core<%d> NO.%d udp dst port %d=%llu ip=%x\n",rte_lcore_id(),i,
			rte_be_to_cpu_16(p->no),p->info.udp[DIR_IN],p->l3p->addr);
		}
}

void wd_l4_dump_udp_src2(struct wd_pack *w,int s)
{
	int i;
	struct l4_port_sum_b *p;

//	RUNNING_LOG_INFO("%s(%d): core<%d> curr=%d s=%d\n",__FUNCTION__,__LINE__,rte_lcore_id(),w->top[s].curr,s);
	for(i=0;i<w->top[s].curr;i++)
		{
		p=(struct l4_port_sum_b *)w->top[s].arr[i];

		RUNNING_LOG_INFO("core<%d> NO.%d all src port %d=%llu ip=%x\n",rte_lcore_id(),i,
			rte_be_to_cpu_16(p->no),p->info.udp[DIR_OUT],p->l3p->addr);
		}
}

struct wd_ops l4_all_dst_ops={
	.type=WDL4_ALL_DST,
	.mincmp=wd_l4_mincmp_all_dst,
	.minheap_creat=wd_minheap_creat,
	.minheap_mod=wd_minheap_modify,
	.process=wd_l4_process_all_dst,
	.dump=wd_l4_dump_all_dst,
	.soft=wd_soft_pps_dst,
};

struct wd_ops l4_all_src_ops={
	.type=WDL4_ALL_SRC,
	.mincmp=wd_l4_mincmp_all_src,
	.minheap_creat=wd_minheap_creat,
	.minheap_mod=wd_minheap_modify,
	.process=wd_l4_process_all_src,
	.dump=wd_l4_dump_all_src,
	.soft=wd_soft_pps_dst,
};

struct wd_ops l4_tcp_dst_ops={
	.type=WDL4_TCP_DST,
	.mincmp=wd_l4_mincmp_tcp_dst,
	.minheap_creat=wd_minheap_creat,
	.minheap_mod=wd_minheap_modify,
	.process=wd_l4_process_tcp_dst,
	.dump=wd_l4_dump_tcp_dst,
	.soft=wd_soft_pps_dst,
};

struct wd_ops l4_tcp_src_ops={
	.type=WDL4_TCP_SRC,
	.mincmp=wd_l4_mincmp_tcp_src,
	.minheap_creat=wd_minheap_creat,
	.minheap_mod=wd_minheap_modify,
	.process=wd_l4_process_tcp_src,
	.dump=wd_l4_dump_tcp_src,
	.soft=wd_soft_pps_dst,
};

struct wd_ops l4_udp_dst_ops={
	.type=WDL4_UDP_DST,
	.mincmp=wd_l4_mincmp_udp_dst,
	.minheap_creat=wd_minheap_creat,
	.minheap_mod=wd_minheap_modify,
	.process=wd_l4_process_udp_dst,
	.dump=wd_l4_dump_udp_dst,
	.soft=wd_soft_pps_dst,
};

struct wd_ops l4_udp_src_ops={
	.type=WDL4_UDP_SRC,
	.mincmp=wd_l4_mincmp_udp_src,
	.minheap_creat=wd_minheap_creat,
	.minheap_mod=wd_minheap_modify,
	.process=wd_l4_process_udp_src,
	.dump=wd_l4_dump_udp_src,
	.soft=wd_soft_pps_dst,
};

struct wd_ops l4_all_dst_ops2={
	.type=WDL4_ALL_DST,
	.mincmp=wd_l4_mincmp_all_dst2,
	.minheap_creat=wd_minheap_creat,
	.minheap_mod=wd_minheap_modify,
	.process=wd_l4_process_all_dst2,
	.dump=wd_l4_dump_all_dst2,
	.soft=wd_soft_pps_dst,
};

struct wd_ops l4_all_src_ops2={
	.type=WDL4_ALL_SRC,
	.mincmp=wd_l4_mincmp_all_src2,
	.minheap_creat=wd_minheap_creat,
	.minheap_mod=wd_minheap_modify,
	.process=wd_l4_process_all_src2,
	.dump=wd_l4_dump_all_src2,
	.soft=wd_soft_pps_dst,
};

struct wd_ops l4_tcp_dst_ops2={
	.type=WDL4_TCP_DST,
	.mincmp=wd_l4_mincmp_tcp_dst2,
	.minheap_creat=wd_minheap_creat,
	.minheap_mod=wd_minheap_modify,
	.process=wd_l4_process_tcp_dst2,
	.dump=wd_l4_dump_tcp_dst2,
	.soft=wd_soft_pps_dst,
};

struct wd_ops l4_tcp_src_ops2={
	.type=WDL4_TCP_SRC,
	.mincmp=wd_l4_mincmp_tcp_src2,
	.minheap_creat=wd_minheap_creat,
	.minheap_mod=wd_minheap_modify,
	.process=wd_l4_process_tcp_src2,
	.dump=wd_l4_dump_tcp_src2,
	.soft=wd_soft_pps_dst,
};

struct wd_ops l4_udp_dst_ops2={
	.type=WDL4_UDP_DST,
	.mincmp=wd_l4_mincmp_udp_dst2,
	.minheap_creat=wd_minheap_creat,
	.minheap_mod=wd_minheap_modify,
	.process=wd_l4_process_udp_dst2,
	.dump=wd_l4_dump_udp_dst2,
	.soft=wd_soft_pps_dst,
};

struct wd_ops l4_udp_src_ops2={
	.type=WDL4_UDP_SRC,
	.mincmp=wd_l4_mincmp_udp_src2,
	.minheap_creat=wd_minheap_creat,
	.minheap_mod=wd_minheap_modify,
	.process=wd_l4_process_udp_src2,
	.dump=wd_l4_dump_udp_src2,
	.soft=wd_soft_pps_dst,
};

static inline int __attribute__((always_inline))
wd_dn1_mincmp_all_name_src(void *x,void *y)
{
	struct dn1_ti_b *a,*b;

	a=(struct dn1_ti_b *)x;
	b=(struct dn1_ti_b *)y;


	return (a->cnt > b->cnt);
}

void wd_dn1_process_name_src(void *in,struct wd_pack *w,int s)
{
	struct dn1_ti_b *p=(struct dn1_ti_b *)in;

	if(p->cnt==0)
		return;

	if(w->top[s].curr<MAX_TOPN_PER)
		{
		w->top[s].arr[w->top[s].curr++]=in;
		if(w->top[s].curr==MAX_TOPN_PER)
			{
			w->ops->minheap_creat(MAX_TOPN_PER,w,s);
			}
		}
	else
		{
		if(w->ops->mincmp(p,w->top[s].arr[0]))
			{
			w->top[s].arr[0]=in;
			w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
			}
		}
}

void wd_dn1_dump_name_src(struct wd_pack *w,int s)
{
	int i;
	struct dn1_ti_b *p;

	for(i=0;i<w->top[s].curr;i++)
		{
		p=(struct dn1_ti_b *)w->top[s].arr[i];

		RUNNING_LOG_INFO("core<%d> NO.%d name=%s cnt=%llu len=%d a=%d b=%d\n",
			rte_lcore_id(),i,p->name,p->cnt,p->len,p->name[0],p->name[p->name[0]+1]);
		}
}

struct wd_ops name_1_src_ops={
	.type=WDDN1_NAME_SRC,
	.mincmp=wd_dn1_mincmp_all_name_src,
	.minheap_creat=wd_minheap_creat,
	.minheap_mod=wd_minheap_modify,
	.process=wd_dn1_process_name_src,
	.dump=wd_dn1_dump_name_src,
	.soft=wd_soft_pps_dst,
};


static inline int __attribute__((always_inline))
wd_dn1_mincmp_all_name_src_ip(void *x,void *y)
{
	struct dn1_sum_b *a,*b;

	a=(struct dn1_sum_b *)x;
	b=(struct dn1_sum_b *)y;


	return (a->cnt > b->cnt);
}

void wd_dn1_process_name_src_ip(void *in,struct wd_pack *w,int s)
{
	struct dn1_sum_b *p=(struct dn1_sum_b *)in;

	if(p->cnt==0)
		return;

	if(w->top[s].curr<MAX_TOPN_PER)
		{
		w->top[s].arr[w->top[s].curr++]=in;
		if(w->top[s].curr==MAX_TOPN_PER)
			{
			w->ops->minheap_creat(MAX_TOPN_PER,w,s);
			}
		}
	else
		{
		if(w->ops->mincmp(p,w->top[s].arr[0]))
			{
			w->top[s].arr[0]=in;
			w->ops->minheap_mod(MAX_TOPN_PER,0,w,s);
			}
		}
}

void wd_dn1_dump_name_src_ip(struct wd_pack *w,int s)
{
	int i;
	struct dn1_sum_b *p;

	for(i=0;i<w->top[s].curr;i++)
		{
		p=(struct dn1_sum_b *)w->top[s].arr[i];

		RUNNING_LOG_INFO("core<%d> NO.%d ip=%x name=%s cnt=%u len=%d a=%d b=%d\n",
			rte_lcore_id(),i,p->l3p->addr,p->name,p->cnt,p->len,p->name[0],p->name[p->name[0]+1]);
		}
}

struct wd_ops name_1_srcip_ops={
	.type=WDDN1_NAME_SRC_IP,
	.mincmp=wd_dn1_mincmp_all_name_src_ip,
	.minheap_creat=wd_minheap_creat,
	.minheap_mod=wd_minheap_modify,
	.process=wd_dn1_process_name_src_ip,
	.dump=wd_dn1_dump_name_src_ip,
	.soft=wd_soft_pps_dst,
};

const char http_get_str[4]={'G','E','T',' '};
const char http_post_str[4]={'P','O','S','T'};
const char http_head_str[4]={'H','E','A','D'};
const char http_put_str[4]={'P','U','T',' '};
const char http_del_str[4]={'D','E','L','E'};
const char http_conn_str[4]={'C','O','N','N'};
const char http_opt_str[4]={'O','P','T','I'};
const char http_trace_str[4]={'T','R','A','C'};

const char http_host1_str[4]={'H','o','s','t'};
const char http_host2_str[4]={'h','o','s','t'};


static inline void __attribute__((always_inline))
do_burst(struct hash_array *burst,struct hash_array *cache,int i)
{
	struct ip_g_s2 *ipm,*iptmp;
	int x=0;//test

	if((!burst->load)&&(cache->load))
	{
		list_for_each_entry_safe(ipm, iptmp, &cache->header, pending_list)
		{
			list_del_init(&ipm->list);
			x++;
			RUNNING_LOG_DEBUG("%s: core<%d> burst ready ip=%x cnt=%d\n",__FUNCTION__,rte_lcore_id(),ipm->addr,x);
		}

		list_splice_tail_init(&cache->header,&burst->header);

		RUNNING_LOG_DEBUG("%s: core<%d> burst<%d> send %d\n",__FUNCTION__,rte_lcore_id(),i,
			cache->load);

		rte_smp_wmb();
		burst->load=cache->load;
		rte_smp_wmb();
		cache->load=0;
	}
}

static inline void __attribute__((always_inline))
do_burst2(struct hash_array *burst,struct hash_array *cache,int i)
{
	struct src_sum *ipm,*iptmp,*ipdst;
	int x=0,k,j=0;//test

	if((!burst->load)&&(cache->load))
	{
		list_for_each_entry_safe(ipm, iptmp, &cache->header, pending_list)
		{
			list_del_init(&ipm->list);
			RUNNING_LOG_DEBUG("%s: core<%d> burst ready ip=%#x ip2=%#x cnt=%d\n",__FUNCTION__,rte_lcore_id(),
				ipm->src_addr,ipm->dst_addr,++x);
		}

		list_splice_tail_init(&cache->header,&burst->header);

		RUNNING_LOG_DEBUG("%s: core<%d> burst<%d> send %d\n",__FUNCTION__,rte_lcore_id(),i,cache->load);

		rte_smp_wmb();
		burst->load=cache->load;
		rte_smp_wmb();
		cache->load=0;
	}
}


static inline void __attribute__((always_inline))
netport_process(struct ip_g_s2 *ip,
	uint16_t port,int s,struct hash_array *pool,uint32_t *miss_alloced,int type)
{
	struct l4_port_g_s2 *pp,*pptmp;
	int match=0;

	if(!list_empty(&ip->l4.header))
		{
		list_for_each_entry_safe(pp, pptmp, &ip->l4.header, alloc_list)
			{
			if(pp->no==port)//found it
				{
				pp->info.all[s]++;
				if(type==L4_TYPE_UDP)
					pp->info.udp[s]++;
				else
					pp->info.tcp[s]++;
				match=1;

//				RUNNING_LOG_DEBUG("core %d (%d) :io port hit,ip=%x,port=%d,all[%d]=%d,type=%d \n",
//					rte_lcore_id(),__LINE__,ip->addr,port,s,pp->info.all[s],type);

				break;
				}
			}

		if(!match)
			{
			goto alloc_port;
			}
		}
	else
		{
alloc_port:
		if(pool->load)
			{
			pp=list_first_entry(&pool->header,struct l4_port_g_s2,alloc_list);
			pp->no=port;
			memset(&pp->info,0,sizeof(struct l4_port_info));
			pp->info.all[s]=1;
			if(type==L4_TYPE_UDP)
				pp->info.udp[s]=1;
			else
				pp->info.tcp[s]=1;

			list_move_tail(&pp->alloc_list,&ip->l4.header);
			pool->load--;
			ip->l4.load++;

//			RUNNING_LOG_DEBUG("core %d (%d) :port alloc,ip=%x,port=%d,all[%d]=%d,type=%d\n",
//				rte_lcore_id(),__LINE__,ip->addr,port,s,pp->info.all[s],type);
			}
		else
			{
			*miss_alloced++;
			}
		}
}

static inline int __attribute__((always_inline))
process_flow_tcp_state_noseqcheck(uint32_t packet_type,
		uint32_t *state)
{
	int ret=0;//0 not finished

	if((*state==FLOW_STATE_TCP_SYN)||(*state==FLOW_STATE_TCP_SYNACK))
		{
		if(packet_type & FLAG(F_TCP_ACK))
			{
			*state=FLOW_STATE_TCP_ACK;
			}
//		else if(packet_type & FLAG(F_TCP_FIN))
//			{
//			*state=FLOW_STATE_TCP_END;
//			ret=1;
//			}
//		else if((packet_type & (FLAG(F_TCP_FIN)|FLAG(F_TCP_ACK)))==(FLAG(F_TCP_FIN)|FLAG(F_TCP_ACK)))
//			{
//			*state=FLOW_STATE_TCP_END;
//			ret=1;
//			}
//		else if((packet_type & (FLAG(F_TCP_FIN)|FLAG(F_TCP_ACK)))==FLAG(F_TCP_FIN))
//			{
//			*state=FLOW_STATE_TCP_FIN;
//			}
		else if(packet_type & FLAG(F_TCP_RST))
			{
			*state=FLOW_STATE_TCP_END;
			ret=1;
			}
		}
	else if(*state==FLOW_STATE_TCP_ACK)
		{
//		if((packet_type & (FLAG(F_TCP_FIN)|FLAG(F_TCP_ACK)))==(FLAG(F_TCP_FIN)|FLAG(F_TCP_ACK)))
//			{
//			*state=FLOW_STATE_TCP_END;
//			ret=1;
//			}
//		else if((packet_type & (FLAG(F_TCP_FIN)|FLAG(F_TCP_ACK)))==FLAG(F_TCP_FIN))
//			{
//			*state=FLOW_STATE_TCP_FIN;
//			}
//		if(packet_type & FLAG(F_TCP_FIN))
//			{
//			*state=FLOW_STATE_TCP_END;
//			ret=1;
//			}
		if(packet_type & FLAG(F_TCP_RST))
			{
			*state=FLOW_STATE_TCP_END;
			ret=1;
			}
		}
//	else if(*state==FLOW_STATE_TCP_FIN)
//		{
//		if(packet_type & FLAG(F_TCP_ACK))
//			{
//			*state=FLOW_STATE_TCP_END;
//			ret=1;
//			}
//		else if(packet_type & FLAG(F_TCP_RST))
//			{
//			*state=FLOW_STATE_TCP_END;
//			ret=1;
//			}
//		}

	return ret;
}

static inline int __attribute__((always_inline))
#ifndef DN1_ON

pkt_process(struct rte_mbuf *m,
		struct port_info_sum *p,
		struct hash_array *ip_pool,
		struct hash_array *ip_burst_cache,
		struct hash_array *ip_hash,
		struct hash_array *netport_pool,
		struct hash_array *flow_pool,
		struct hash_array *flow_hash,
		int sum_cnt,uint32_t *miss_alloced,uint32_t *miss_alloced_netport,
		uint32_t *miss_alloced_flow)

#else

pkt_process(struct rte_mbuf *m,
		struct port_info_sum *p,
		struct hash_array *ip_pool,
		struct hash_array *ip_burst_cache,
		struct hash_array *ip_hash,
		struct hash_array *netport_pool,
		struct hash_array *dn1_pool,
		struct hash_array *dn1_hash,
		int sum_cnt,uint32_t *miss_alloced,uint32_t *miss_alloced_netport,
		uint32_t *miss_alloced_dn1)

#endif
{
	struct ether_hdr *eth_hdr;
	uint32_t packet_type = 0;
	uint16_t ether_type;
	void *l3;
	int l3_hdr_len;
	int total_len;
	int l4_hdr_len=0;
	struct ipv4_hdr *ipv4_hdr;
	struct ipv6_hdr *ipv6_hdr;
//	union ipv4_5tuple_xmm xmm[2];
	int action=ACT_DROP;//ACT_FORWARD;
	uint32_t rss_idx;
	struct tcp_hdr *tcp;
	struct udp_hdr *udp;
	char *l5;
	int load_len;
	int i;
	int type=100;
	int src_port,dst_port;
	struct ipv4_4tuple adir,bdir;

//	rss=m->hash.rss;
	p->sub[0].in_pps++;
	p->sub[0].in_bps+=m->pkt_len;

	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ether_type = eth_hdr->ether_type;
	l3 = (uint8_t *)eth_hdr + sizeof(struct ether_hdr);
	if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
		ipv4_hdr = (struct ipv4_hdr *)l3;

		total_len=rte_be_to_cpu_16(ipv4_hdr->total_length);
		l3_hdr_len=(ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK)<<2;

		if(unlikely(total_len > (m->pkt_len-sizeof(struct ether_hdr))))
			{
			p->sub[0].bad_ipv4_pkts++;
			action=ACT_DROP;

			ALERT_LOG("bbbbbbbbbbbbbbbbbbbbbb\n");

			save_pcap_file(m);

//			RUNNING_LOG_DEBUG("core %d :ipv4 bad pkt\n",rte_lcore_id());
			goto ae1;
			}

		load_len = m->pkt_len - sizeof(struct ether_hdr) - l3_hdr_len;

//		RUNNING_LOG_DEBUG("core %d :ipv4\n",rte_lcore_id());

		p->sub[0].ip.pps++;
		p->sub[0].ip.bps+=m->pkt_len;

		if(is_valid_ipv4_pkt(ipv4_hdr, m->pkt_len)!=MM_SUCCESS)
			{
			p->sub[0].bad_ipv4_pkts++;
			action=ACT_DROP;

//			RUNNING_LOG_DEBUG("core %d :ipv4 bad pkt\n",rte_lcore_id());
			goto ae1;
			}

		if(unlikely((ipv4_hdr->dst_addr == ipv4_hdr->src_addr)
		|| (ipv4_hdr->src_addr&rte_be_to_cpu_32(0xff000000)==rte_be_to_cpu_32(0x7f000000))))//land
			{
			p->sub[0].attack.land++;
			packet_type |= FLAG(F_LAND);
			action=ACT_DROP;

//			RUNNING_LOG_DEBUG("core %d :ipv4 land\n",rte_lcore_id());
			goto ae1;
			}

		if(unlikely(!ipv4_hdr->time_to_live))//tracert
			{
			p->sub[0].attack.tracert++;
			packet_type |= FLAG(F_TRACERT);
//			RUNNING_LOG_DEBUG("core %d :ipv4 tracert\n",rte_lcore_id());
			goto ae1;
			}

		if (unlikely(l3_hdr_len > sizeof(struct ipv4_hdr)/*20*/))//ip option
			{
			p->sub[0].ip.ip_option++;
			packet_type |= FLAG(F_IPOPTION);
//			RUNNING_LOG_DEBUG("core %d :ipv4 ip option\n",rte_lcore_id());

			ALERT_LOG("ooooooooooooooooo\n");
			rte_pktmbuf_dump(alert_log_fp,m,m->pkt_len);

			save_pcap_file(m);

//			goto ae1;
			goto pkt_exit;
			}

		//frag need
		//smurf need
		//not all dir sum
		//not icmp code decode
		//no ip option decode

		packet_type |= FLAG(F_IPV4);

		if (ipv4_hdr->next_proto_id == IPPROTO_TCP)
			{
			uint8_t tcpflags;

			packet_type |= FLAG(F_TCP);
			type=L4_TYPE_TCP;
			tcp = (struct tcp_hdr *)((unsigned char *)ipv4_hdr +
						sizeof(struct ipv4_hdr));
			l4_hdr_len=(tcp->data_off & 0xf0) >> 2 ;
			if(l4_hdr_len > (sizeof(struct tcp_hdr)+40))// bad tcp option,max 40b
				goto tcp_bad;

			if(l4_hdr_len > sizeof(struct tcp_hdr))
				packet_type |= FLAG(F_TCP_OPTION);

			load_len-=l4_hdr_len;
			l5=(char *)((char *)tcp + l4_hdr_len);
			src_port=tcp->src_port;
			dst_port=tcp->dst_port;
			tcpflags = (tcp->tcp_flags & ~(TCPHDR_ECE|TCPHDR_CWR|TCPHDR_PSH));

//			RUNNING_LOG_DEBUG("core %d :ipv4 tcp\n",rte_lcore_id());
			if (!tcp_valid_flags[tcpflags])
				{
tcp_bad:
				p->sub[0].bad_ipv4_pkts++;
				p->sub[0].attack.tcp_flag_err++;

//				RUNNING_LOG_DEBUG("core %d :ipv4 tcp bad flag\n",rte_lcore_id());

				action=ACT_DROP;

				goto ae1;
				}
			else
				{
				p->sub[0].tcp.pps++;
				p->sub[0].tcp.bps+=m->pkt_len;
				if((tcpflags&(TCPHDR_SYN|TCPHDR_ACK))==(TCPHDR_SYN|TCPHDR_ACK))
					{
					p->sub[0].tcp.syn_ack++;
					packet_type |= FLAG(F_TCP_SYN_ACK);

//					RUNNING_LOG_DEBUG("core %d :ipv4 tcp synack\n",rte_lcore_id());
					}
				else
					{
					if(tcpflags&TCPHDR_SYN)
						{
						p->sub[0].tcp.syn++;
						packet_type |= FLAG(F_TCP_SYN);

//						RUNNING_LOG_DEBUG("core %d :ipv4 tcp syn\n",rte_lcore_id());
						}
					else
						{
						if(tcpflags&TCPHDR_ACK)
							{
							p->sub[0].tcp.ack++;
							packet_type |= FLAG(F_TCP_ACK);

//							RUNNING_LOG_DEBUG("core %d :ipv4 tcp ack\n",rte_lcore_id());
							}

						if(tcpflags&TCPHDR_RST)
							{
							p->sub[0].tcp.rst++;
							packet_type |= FLAG(F_TCP_RST);

//							RUNNING_LOG_DEBUG("core %d :ipv4 tcp rst\n",rte_lcore_id());
							}

						if(tcpflags&TCPHDR_FIN)
							{
							p->sub[0].tcp.fin++;
							packet_type |= FLAG(F_TCP_FIN);

//							RUNNING_LOG_DEBUG("core %d :ipv4 tcp fin\n",rte_lcore_id());
							}

						if((tcp->dst_port == 0x8b00)&&(tcpflags&TCPHDR_URG)&&
							(tcp->tcp_urp))
							{
							p->sub[0].attack.nuker++;
							packet_type |= FLAG(F_NUKER);

//							RUNNING_LOG_DEBUG("core %d :ipv4 tcp nuker\n",rte_lcore_id());
							}
						}
					}
				}
			}
		else if (ipv4_hdr->next_proto_id == IPPROTO_UDP)
			{
			udp = (struct udp_hdr *)((unsigned char *)ipv4_hdr +
						sizeof(struct ipv4_hdr));
			l4_hdr_len=sizeof(struct udp_hdr);
			load_len-=l4_hdr_len;
			l5=(char *)((char *)udp+sizeof(struct udp_hdr));

			type=L4_TYPE_UDP;
			src_port=udp->src_port;
			dst_port=udp->dst_port;
//			RUNNING_LOG_DEBUG("core %d :ipv4 udp\n",rte_lcore_id());

			packet_type |= FLAG(F_UDP);
			p->sub[0].udp.pps++;
			p->sub[0].udp.bps+=m->pkt_len;
			if((udp->dst_port == 0x1300)||(udp->src_port == 0x1300))
				{
				packet_type |= FLAG(F_FRAGGLE);
//				p->sub[0].attack.chargen++;

//				RUNNING_LOG_DEBUG("core %d :ipv4 udp chargen\n",rte_lcore_id());
				}
			else if((udp->dst_port == 0x6c07)||(udp->src_port == 0x6c07))
				{
				packet_type |= FLAG(F_SSDP);
				p->sub[0].attack.ssdp++;

//				RUNNING_LOG_DEBUG("core %d :ipv4 udp ssdp\n",rte_lcore_id());
				}
				/*
			else if((udp->dst_port == 0xa100)||(udp->src_port == 0xa100))
				{
				packet_type |= FLAG(F_SNMP);
				p->sub[0].attack.snmp++;

//				RUNNING_LOG_DEBUG("core %d :ipv4 udp snmp\n",rte_lcore_id());
				}
			else if((udp->dst_port == 0x3500)||(udp->src_port == 0x3500))
				{
				packet_type |= FLAG(F_DNS);
				p->sub[0].attack.dns++;

//				RUNNING_LOG_DEBUG("core %d :ipv4 udp dns\n",rte_lcore_id());
				}
				*/
			else if((udp->dst_port == 0x7b00)||(udp->src_port == 0x7b00))
				{
				packet_type |= FLAG(F_NTP);
				p->sub[0].attack.ntp++;

//				RUNNING_LOG_DEBUG("core %d :ipv4 udp ntp\n",rte_lcore_id());
				}
			}
		else if(ipv4_hdr->next_proto_id == IPPROTO_ICMP)
			{
			//struct icmp_hdr *icmp_h;

			packet_type |= FLAG(F_ICMP);
			p->sub[0].icmp.pps++;
			p->sub[0].icmp.bps+=m->pkt_len;

//			RUNNING_LOG_DEBUG("core %d :ipv4 icmp\n",rte_lcore_id());

/*
			icmp_h = (struct icmp_hdr *) ((char *)ipv4_hdr +
							  sizeof(struct ipv4_hdr));
			if(icmp_h)
			if (! ((ipv4_hdr->next_proto_id == IPPROTO_ICMP) &&
				   (icmp_h->icmp_type == ICMP_ECHO&&
				   (icmp_h->icmp_code == 0))) {
				rte_pktmbuf_free(pkt);
				continue;
			}
*/
			}
		else if(ipv4_hdr->next_proto_id == IPPROTO_IGMP)
			{
			packet_type |= FLAG(F_IGMP);
			p->sub[0].igmp.pps++;
			p->sub[0].igmp.bps+=m->pkt_len;

//			RUNNING_LOG_DEBUG("core %d :ipv4 igmp\n",rte_lcore_id());
			}

		//m->hash.rss = packet_type;
	}
#if 0
	else if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6)) {
		ipv6_hdr = (struct ipv6_hdr *)l3;
		packet_type |= FLAG(F_IPV6);
		p->sub.ip_pps.ipv6++;
		p->sub.ip_bps.ipv6+=m->pkt_len;
		/*
		if (ipv6_hdr->next_proto_id == IPPROTO_TCP)
			packet_type |= FLAG(F_TCP);
		else if (ipv6_hdr->next_proto_id == IPPROTO_UDP)
			packet_type |= FLAG(F_UDP);
			*/

		RUNNING_LOG_DEBUG("core %d :ipv6\n",rte_lcore_id());

		goto ae1;
	}
#endif
	else
		{
//		RUNNING_LOG_DEBUG("core %d :ethertype=%x\n",rte_lcore_id(),ether_type);
		return ACT_DROP;
		}

ae1:
	m->seqn = packet_type;

	uint32_t srcip_idx,srcip;
	uint32_t dstip_idx,dstip;
	int split_src_idx;
	int split_dst_idx;
	struct ip_g_s2 *ipm,*iptmp,*ipsrc;
	int match=0;

	//look up src ip hash
	srcip=rte_be_to_cpu_32(ipv4_hdr->src_addr);
//	srcip_idx=(ipv4_hdr->src_addr>>(32-IP_HASH_ARRAY_OFF))&(IP_HASH_ARRAY_SZ-1);
	srcip_idx=srcip&(IP_HASH_ARRAY_SZ-1);
	split_src_idx=srcip&(sum_cnt-1);
//	if(ip_hash[srcip_idx].load)
	if(!list_empty(&ip_hash[srcip_idx].header))
		{
		list_for_each_entry_safe(ipsrc, iptmp, &ip_hash[srcip_idx].header, list)
//		for(i=0;i<ip_hash[srcip_idx].load;i++)
			{
//			ipm=list_first_entry(&ip_hash[srcip_idx].header,struct ip_g_s2,list);
			if(ipv4_hdr->src_addr==ipsrc->addr)//found it
				{
				RUNNING_LOG_DEBUG("core %d (%d) :src match,found hash match,ip=%x\n",
					rte_lcore_id(),__LINE__,ipsrc->addr);

				update_ip2(ipsrc,packet_type,DIR_OUT,m->pkt_len);
				match=1;
				break;
				}
			}

		if(!match)
			{
//			RUNNING_LOG_DEBUG("core %d :not found src hashx\n",rte_lcore_id());
			goto alloc_srcip;
			}
		}
	else//alloc ip and set
		{
alloc_srcip:
		ipsrc=NULL;
		if(ip_pool->load)
			{
//			RUNNING_LOG_DEBUG("core %d :alloc src %llx hashx idx=%llx\n",rte_lcore_id(),ipv4_hdr->src_addr,srcip_idx);
			ipsrc=list_first_entry(&ip_pool->header,struct ip_g_s2,list);
			list_del_init(&ipsrc->list);
			INIT_LIST_HEAD(&ipsrc->pending_list);
			INIT_LIST_HEAD(&ipsrc->l4.header);
			INIT_LIST_HEAD(&ipsrc->name_dnsreq.header);
			INIT_LIST_HEAD(&ipsrc->name_http.header);
			ipsrc->l4.load=0;
			ipsrc->name_dnsreq.load=0;
			ipsrc->name_http.load=0;
			memset(ipsrc->ip_info,0,sizeof(ipsrc->ip_info[0])*2);
			ip_pool->load--;
			ipsrc->addr=ipv4_hdr->src_addr;
//			ipm->flag=0;
			update_ip2(ipsrc,packet_type,DIR_OUT,m->pkt_len);
			list_add_tail(&ipsrc->list,&ip_hash[srcip_idx].header);
//			ip_hash[srcip_idx].load++;
			list_add_tail(&ipsrc->pending_list,&ip_burst_cache[split_src_idx].header);
			ip_burst_cache[split_src_idx].load++;

			RUNNING_LOG_DEBUG("core %d (%d) :src alloc,ip=%x,ip_hash[%d].load=%d cache[%d].load=%d ip_pool->load=%d\n",
				rte_lcore_id(),__LINE__,ipsrc->addr,srcip_idx,ip_hash[srcip_idx].load,split_src_idx,
				ip_burst_cache[split_src_idx].load,ip_pool->load);

			}
		else
			{
			action=ACT_DROP;
			*miss_alloced++;
			}
		}

	if((ipsrc)&&(type<=L4_TYPE_TCP))
	{
		netport_process(ipsrc,src_port,DIR_OUT,netport_pool,miss_alloced_netport,type);

#ifdef DN1_ON
		if((type==L4_TYPE_TCP)&&(packet_type&FLAG(F_TCP_ACK))&&
			(m->pkt_len>(ETH_HLEN+20+20+10))&&
			(dst_port==rte_cpu_to_be_16(80)))//http
			{
				uint32_t *p=(uint32_t *)l5;
				uint16_t *p16;
				char *ps=l5+4;
				int pkt_len=m->pkt_len-(ETH_HLEN+20+20)-4;
				int flag;
				char *pos[32];
				int ll[32];
				uint32_t idx=0;
				int tt_len;
				char buff[256];
				char *tmp_start;
				uint32_t hash_idx=0;
				struct dn1_g_s2 *d,*dtmp;
				int len;
				char *pp;
				int ff=0;

				if((*p==*((uint32_t *)http_get_str))||
					(*p==*((uint32_t *)http_post_str))||
					(*p==*((uint32_t *)http_put_str))||
					(*p==*((uint32_t *)http_head_str))||
					(*p==*((uint32_t *)http_del_str))||
					(*p==*((uint32_t *)http_conn_str))||
					(*p==*((uint32_t *)http_opt_str))||
					(*p==*((uint32_t *)http_trace_str)))
					{
					flag=0;
					for(i=0;i<pkt_len;i++,ps++)
						{
						if(*ps==0x0d)
							flag|=1;
						else if(*ps==0x0a)
							flag|=2;

						if(flag==3)
							break;
						}

					if(flag==3)
						{
						pkt_len-=i;
						if(pkt_len>10)
							{
							p=(uint32_t *)(++ps);
							if((*p==*((uint32_t *)http_host1_str))||
								(*p==*((uint32_t *)http_host2_str)))
								{
								p16=(uint16_t *)++p;
								if(*p16==0x203a)
									{
//									ALERT_LOG("i=%d pkt_len=%d at all\n",i,pkt_len);
//									rte_pktmbuf_dump(alert_log_fp,m,m->pkt_len);

									ps=(char *)++p16;
									pkt_len-=6;
									tt_len=0;
									tmp_start=ps;
									idx=0;
									for(i=0;i<min(pkt_len,255);i++,ps++)
										{
										if(*ps==0x0d)
											{
											pos[idx]=&buff[i+1];
											buff[i+1]=0;
											ff=1;
											break;
											}
#if 0//debug
										memcpy(buf,p+1,*p);
										buf[*p]=0;
					//					RUNNING_LOG_DEBUG("get name len=%d,%p %s\n",*p,p,buf);
#endif
										buff[i+1]=*ps;
										if(*ps=='.')
											{
											pos[idx]=&buff[i+1];
											idx++;
											}
										}

									if(ff==0)
										{
										ALERT_LOG("alert cap bad http222222222 len=%d\n",len);
										save_pcap_file(m);
										rte_pktmbuf_dump(alert_log_fp,m,m->pkt_len);

										goto outxx;
										}

									if(unlikely(idx==0))
										{
									ALERT_LOG("nnnnnnnnnnnnnnnnnnn\n");
									rte_pktmbuf_dump(alert_log_fp,m,m->pkt_len);

									save_pcap_file(m);
									goto outxx;

//										len=pos[idx]-&buff[0]-1;
//										buff[0]=len;
//										pp=buff;
										}

									if(idx==1)
										{
										len=pos[idx]-pos[idx-1]-1;
										*pos[idx-1]=len;
										buff[0]=pos[0]-&buff[0]-1;
										len+=(pos[0]-&buff[0]-1);
										pp=buff;
										}
									else
										{
										len=pos[idx]-pos[idx-1]-1;
										*pos[idx-1]=len;
										*pos[idx-2]=pos[idx-1]-pos[idx-2]-1;
										len+=((pos[idx-1]-pos[idx-2]-1)+2);
										pp=pos[idx-2];
										}

//									if(unlikely(len>254))
//									{
//									ALERT_LOG("alert cap bad http len=%d\n",len);
//									save_pcap_file(m);
//									rte_pktmbuf_dump(alert_log_fp,m,m->pkt_len);

//									goto outxx;
//									}

//									ALERT_LOG("dxi=%d pkt_len=%d at all %s\n",idx,pkt_len,buff);
//									save_pcap_file(m);
									hash_idx=*((uint16_t *)pp);

									if(ipsrc->name_http.load)
										{
										list_for_each_entry_safe(d, dtmp, &ipsrc->name_http.header, alloc_list)
											{
											if((d->len==len)&&
												(!memcmp(pp,d->name,len)))
												{
												RUNNING_LOG_DEBUG("core %d (%d) :http dn1 match,found hash match,%p ip=%x,idx=%x,len=%d,name=%s,cnt=%d\n",
													rte_lcore_id(),__LINE__,ipsrc,ipsrc->addr,hash_idx,len,d->name,d->cnt);

												d->cnt++;
												match=1;
												break;
												}
										if(!match)
												{
									//			RUNNING_LOG_DEBUG("core %d :not found dst hashx\n",rte_lcore_id());
												goto alloc_dn1_http;
												}
											}
										}
									else//alloc ip and set
										{
alloc_dn1_http:
											d=NULL;
											if(dn1_pool->load)
												{
												d=list_first_entry(&dn1_pool->header,struct dn1_g_s2,alloc_list);
										//						INIT_LIST_HEAD(&d->list_hash);
												d->cnt=1;
												rte_memcpy(d->name,pp,len);
												d->len=len;
												d->name[d->len]=0;
												hash_idx=*((uint16_t *)d->name);///*(len<<16)+*/((uint32_t)d->name[0]<<8)+(uint32_t)d->name[1];
										//						list_add_tail(&d->list_hash,&dn1_hash[hash_idx].header);
										//						dn1_hash[hash_idx].load++;
												list_move_tail(&d->alloc_list,&ipsrc->name_http.header);
												dn1_pool->load--;
												ipsrc->name_http.load++;

												RUNNING_LOG_DEBUG("core %d (%s:%d) : %p name=%s len=%d idx=%x\n",
													rte_lcore_id(),__FUNCTION__,__LINE__,ipsrc,d->name,d->len,hash_idx);
												}
											else
												{
												*miss_alloced_dn1++;
												}
										}

										}
									}
								}
							}
						}
					}

		else if((type==L4_TYPE_UDP)&&(dst_port==rte_cpu_to_be_16(53))&&
			(m->pkt_len>(ETH_HLEN+20+8)))//dns
			{
				char *p = l5+12;//rte_pktmbuf_mtod_offset(m, char *,ETH_HLEN+20+8+12);
				char *pp;
				char *pos[100];
				int ll[100];
				uint32_t idx=0;
				struct dn1_g_s2 *d,*dtmp;
				int len;
				int match=0;
				char buf[64];
				int pkt_len=m->pkt_len-(ETH_HLEN+20+8+12);

				if(p)
					{
					uint32_t hash_idx=0;

					for(i=0;i<pkt_len;i++)
						{
						if(*p==0)
							break;

#if 0//debug
						memcpy(buf,p+1,*p);
						buf[*p]=0;
	//					RUNNING_LOG_DEBUG("get name len=%d,%p %s\n",*p,p,buf);
#endif
						ll[idx]=*p;
						pos[idx]=p;
						idx++;
						p+=(*p+1);
						}

					if(i==pkt_len)
					{
						ALERT_LOG("i=%d pkt_len=%d at all\n",i,pkt_len);
						rte_pktmbuf_dump(alert_log_fp,m,m->pkt_len);
						save_pcap_file(m);
					}

//					for(;*p;)
//						{
//#if 0//debug
//						memcpy(buf,p+1,*p);
//						buf[*p]=0;
//	//					RUNNING_LOG_DEBUG("get name len=%d,%p %s\n",*p,p,buf);
//#endif
//						ll[idx]=*p;
//						pos[idx]=p;
//						idx++;
//						p+=(*p+1);
//						}

					if(idx==0)
					{
						ALERT_LOG("nothing at all\n");
						rte_pktmbuf_dump(alert_log_fp,m,m->pkt_len);
						save_pcap_file(m);
						goto outxx;
					}

					if(unlikely(idx==1))
						{
						len=ll[0]+1;
						pp=pos[0];
						}
					else
						{
						len=ll[idx-1]+ll[idx-2]+2;
						pp=pos[idx-2];
						}

					if(unlikely(len<5))
						goto outxx;

					if(unlikely(len>254))
					{
					ALERT_LOG("alert cap dns bad len=%d\n",len);
					save_pcap_file(m);
					goto outxx;
					}

					hash_idx=*((uint16_t *)pp);///*(len<<16)+*/((uint32_t)*pp<<8)+(uint32_t)*(pp+1);

					if(ipsrc->name_dnsreq.load)
						{
						list_for_each_entry_safe(d, dtmp, &ipsrc->name_dnsreq.header, alloc_list)
							{
							if((d->len==len)&&
								(!memcmp(pp,d->name,len)))
								{
								RUNNING_LOG_DEBUG("core %d (%d) :dn1 match,found hash match,%p ip=%x,idx=%x,len=%d,name=%s,cnt=%d\n",
									rte_lcore_id(),__LINE__,ipsrc,ipsrc->addr,hash_idx,len,d->name,d->cnt);

								d->cnt++;
								match=1;
								break;
								}
						if(!match)
								{
					//			RUNNING_LOG_DEBUG("core %d :not found dst hashx\n",rte_lcore_id());
								goto alloc_dn1;
								}
							}
						}
					else//alloc ip and set
						{
	alloc_dn1:
						d=NULL;
						if(dn1_pool->load)
							{
							d=list_first_entry(&dn1_pool->header,struct dn1_g_s2,alloc_list);
	//						INIT_LIST_HEAD(&d->list_hash);
							d->cnt=1;
							rte_memcpy(d->name,pp,len);
							d->len=len;
							d->name[d->len]=0;
							hash_idx=*((uint16_t *)d->name);///*(len<<16)+*/((uint32_t)d->name[0]<<8)+(uint32_t)d->name[1];
	//						list_add_tail(&d->list_hash,&dn1_hash[hash_idx].header);
	//						dn1_hash[hash_idx].load++;
							list_move_tail(&d->alloc_list,&ipsrc->name_dnsreq.header);
							dn1_pool->load--;
							ipsrc->name_dnsreq.load++;

							RUNNING_LOG_DEBUG("core %d (%s:%d) : %p name=%s len=%d idx=%x\n",
								rte_lcore_id(),__FUNCTION__,__LINE__,ipsrc,d->name,d->len,hash_idx);
							}
						else
							{
							*miss_alloced_dn1++;
							}
						}

					}
			}
#endif
	}

#ifdef DN1_ON
outxx:
#endif
	//look up dst ip hash
	dstip=rte_be_to_cpu_32(ipv4_hdr->dst_addr);
//	dstip_idx=(ipv4_hdr->dst_addr>>(32-IP_HASH_ARRAY_OFF))&(IP_HASH_ARRAY_SZ-1);
	dstip_idx=dstip&(IP_HASH_ARRAY_SZ-1);
	split_dst_idx=dstip&(sum_cnt-1);
	match=0;
	if(!list_empty(&ip_hash[dstip_idx].header))
//	if(ip_hash[dstip_idx].load)
		{
		list_for_each_entry_safe(ipm, iptmp, &ip_hash[dstip_idx].header, list)
//		for(i=0;i<ip_hash[dstip_idx].load;i++)
			{
//			ipm=list_first_entry(&ip_hash[dstip_idx].header,struct ip_g_s2,list);
			if(ipv4_hdr->dst_addr==ipm->addr)//found it
				{
				RUNNING_LOG_DEBUG("core %d (%d) :dst match,found hash match,ip=%x\n",
					rte_lcore_id(),__LINE__,ipm->addr);

				update_ip2(ipm,packet_type,DIR_IN,m->pkt_len);
				match=1;
				break;
				}
			}

		if(!match)
			{
//			RUNNING_LOG_DEBUG("core %d :not found dst hashx\n",rte_lcore_id());
			goto alloc_dstip;
			}
		}
	else//alloc ip and set
		{
alloc_dstip:
		ipm=NULL;
		if(ip_pool->load)
			{
//			RUNNING_LOG_DEBUG("core %d :alloc src %llx hashx idx=%llx\n",rte_lcore_id(),ipv4_hdr->src_addr,srcip_idx);
			ipm=list_first_entry(&ip_pool->header,struct ip_g_s2,list);
			list_del_init(&ipm->list);
			INIT_LIST_HEAD(&ipm->pending_list);
			INIT_LIST_HEAD(&ipm->l4.header);
			INIT_LIST_HEAD(&ipm->name_dnsreq.header);
			INIT_LIST_HEAD(&ipm->name_http.header);
			ipm->l4.load=0;
			ipm->name_dnsreq.load=0;
			ipm->name_http.load=0;
			memset(ipm->ip_info,0,sizeof(ipm->ip_info[0])*2);
			ip_pool->load--;
			ipm->addr=ipv4_hdr->dst_addr;
//			ipm->flag=0;
			update_ip2(ipm,packet_type,DIR_IN,m->pkt_len);
			list_add_tail(&ipm->list,&ip_hash[dstip_idx].header);
//			ip_hash[dstip_idx].load++;
			list_add_tail(&ipm->pending_list,&ip_burst_cache[split_dst_idx].header);
			ip_burst_cache[split_dst_idx].load++;

			RUNNING_LOG_DEBUG("core %d (%d) :dst alloc,ip=%x,ip_hash[%d].load=%d cache[%d].load=%d ip_pool->load=%d\n",
				rte_lcore_id(),__LINE__,ipm->addr,dstip_idx,ip_hash[dstip_idx].load,split_dst_idx,
				ip_burst_cache[split_dst_idx].load,ip_pool->load);
			}
		else
			{
			action=ACT_DROP;
			*miss_alloced++;
			}
		}

#ifdef DN1_ON
	if(type==L4_TYPE_UDP)//test
	{
//		ALERT_LOG("alert cap dst dnsssssssssssssssssss len=%d\n",m->pkt_len);
		if(dst_port==rte_cpu_to_be_16(53))
			cap_pcap_file(m,"dnsdst.pcap");
		else if(src_port==rte_cpu_to_be_16(53))
			cap_pcap_file(m,"dnssrc.pcap");
//		rte_pktmbuf_dump(alert_log_fp,m,m->pkt_len);
	}
#endif

	if((ipm)&&(type<=L4_TYPE_TCP))
		netport_process(ipm,dst_port,DIR_IN,netport_pool,miss_alloced_netport,type);
//	else
//		goto pkt_exit;

	//flow
	if(type==L4_TYPE_TCP)
	{
		struct flow_s *ff,*fftmp;

		rss_idx=m->hash.rss&(FLOW_HASH_ARRAY_SZ-1);
		match=0;
		if(!list_empty(&flow_hash[rss_idx].header))
			{
			list_for_each_entry_safe(ff, fftmp, &flow_hash[rss_idx].header, tbl_list)
				{
				if(ipv4_hdr->dst_addr==ipm->addr)//found it
					{
					RUNNING_LOG_DEBUG("core %d (%d) :dst match,found hash match,ip=%x\n",
						rte_lcore_id(),__LINE__,ipm->addr);

					update_ip2(ipm,packet_type,DIR_IN,m->pkt_len);
					match=1;
					break;
					}
				}

			if(!match)
				{
	//			RUNNING_LOG_DEBUG("core %d :not found dst hashx\n",rte_lcore_id());
				goto alloc_dstip;
				}
			}
		else//alloc ip and set
			{
alloc_flow:
			ipm=NULL;
			if(ip_pool->load)
				{
	//			RUNNING_LOG_DEBUG("core %d :alloc src %llx hashx idx=%llx\n",rte_lcore_id(),ipv4_hdr->src_addr,srcip_idx);
				ipm=list_first_entry(&ip_pool->header,struct ip_g_s2,list);
				list_del_init(&ipm->list);
				INIT_LIST_HEAD(&ipm->pending_list);
				INIT_LIST_HEAD(&ipm->l4.header);
				INIT_LIST_HEAD(&ipm->name_dnsreq.header);
				INIT_LIST_HEAD(&ipm->name_http.header);
				ipm->l4.load=0;
				ipm->name_dnsreq.load=0;
				ipm->name_http.load=0;
				memset(ipm->ip_info,0,sizeof(ipm->ip_info[0])*2);
				ip_pool->load--;
				ipm->addr=ipv4_hdr->dst_addr;
	//			ipm->flag=0;
				update_ip2(ipm,packet_type,DIR_IN,m->pkt_len);
				list_add_tail(&ipm->list,&ip_hash[dstip_idx].header);
	//			ip_hash[dstip_idx].load++;
				list_add_tail(&ipm->pending_list,&ip_burst_cache[split_dst_idx].header);
				ip_burst_cache[split_dst_idx].load++;

				RUNNING_LOG_DEBUG("core %d (%d) :dst alloc,ip=%x,ip_hash[%d].load=%d cache[%d].load=%d ip_pool->load=%d\n",
					rte_lcore_id(),__LINE__,ipm->addr,dstip_idx,ip_hash[dstip_idx].load,split_dst_idx,
					ip_burst_cache[split_dst_idx].load,ip_pool->load);
				}
			else
				{
				action=ACT_DROP;
				*miss_alloced++;
				}
			}
	}


pkt_exit:
	return action;
}


int main_loop_io_sj(void)
{
	int my_lcore;
	int i,j,k,nb_rx,ret;
	int port_cnt;
	uint8_t port_arr[MAX_DEV];
	uint16_t queue_arr[MAX_DEV];
	struct rte_mbuf *pkts_burst[BURST_SZ];
	int prev_req,curr_req;
	struct hash_array *ip_hash;
	struct hash_array *dn1_hash;
	struct hash_array *flow_hash;
	struct lcore_info_s *local;
	uint64_t cur_tsc, prev_tsc,diff_tsc, hz;
	uint64_t local_mask;
	int sum_cnt;
	uint64_t start,end,count=0;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1)/US_PER_S * 100000;
	struct hash_array *local_ip_pool,*local_ip_burst,*local_ip_burstcache,*local_ip_back;
	struct hash_array *local_netport_pool,*local_netport_back;
	struct hash_array *local_dn1_pool,*local_dn1_back;
	struct port_info_sum *port_statA=NULL,*port_statB=NULL,*port_stat;

	my_lcore=rte_lcore_id();
	local_mask=(1ULL<<my_lcore);
	local=&lcore[my_lcore];
	port_cnt=local->port_cnt;
	rte_memcpy(port_arr,local->port_id,sizeof(local->port_id[0])*MAX_DEV);
	rte_memcpy(queue_arr,local->queue_id,sizeof(local->queue_id[0])*MAX_DEV);
	ip_hash=local->io_in.io_in_hash;
	dn1_hash=local->io_in.io_dn1_hash;
	hz = rte_get_timer_hz();
	local_ip_pool=&local->io_in.ip_pool;
	local_ip_burst=local->io_in.ip_io2sum_burst;
	local_ip_burstcache=local->io_in.ip_io2sum_pending;
	local_ip_back=local->io_in.ip_sum2io_burst;
	local_netport_pool=&local->io_in.netport_pool;
	local_netport_back=local->io_in.netport_sum2io_burst;
	local_dn1_pool=&local->io_in.dn1_pool;
	local_dn1_back=local->io_in.dn1_sum2io_burst;
	sum_cnt=__builtin_popcountll(me.sum_mask);
	port_statA=&local->io_in.port_sub[0];
	port_statB=&local->io_in.port_sub[MAX_DEV];
	port_stat=port_statA;

	core_stat[my_lcore]=core_prev[my_lcore]=0;

	RUNNING_LOG_INFO("core %d :main_loop_io_rtc\n",my_lcore);

	prev_tsc=cur_tsc=rte_rdtsc();

	while(1){
		count++;
		start=rte_rdtsc();

		//process pkts
		for(i=0;i<port_cnt;i++)
			{
			nb_rx = rte_eth_rx_burst(port_arr[i], queue_arr[i], pkts_burst,BURST_SZ);
			if(nb_rx)
				{
				core_stat[my_lcore]+=nb_rx;

				for(j=0;j<nb_rx;j++)
					{
					ret=pkt_process(pkts_burst[j],&port_stat[port_arr[i]],local_ip_pool,
						local_ip_burstcache,ip_hash,
						local_netport_pool,
						local_dn1_pool,dn1_hash,
						sum_cnt,
						&local->io_in.miss_alloced,
						&local->io_in.miss_alloced_netport,
						&local->io_in.miss_alloced_dn1);

					if(ret==ACT_DROP)
						{
						rte_pktmbuf_free(pkts_burst[j]);
						}
					}
				}
			}

		//process timer
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc))
			{
			for(i=0;i<sum_cnt;i++)
				do_burst(&local_ip_burst[i],&local_ip_burstcache[i],i);

			prev_tsc = cur_tsc;
			}

		for(i=0;i<sum_cnt;i++)
			{
			if(local_ip_back[i].load)
				{
#if 0//test
{
				int x=0;
				struct ip_g_s2 *ipm,*iptmp;

				list_for_each_entry_safe(ipm, iptmp, &local_ip_back[i].header, list)
					{
					x++;
					RUNNING_LOG_DEBUG("%s: core<%d> get back test ip=%x cnt=%d\n",__FUNCTION__,rte_lcore_id(),ipm->addr,
						x);
					}
}
#endif


				list_splice_tail_init(&local_ip_back[i].header,&local_ip_pool->header);
				local_ip_pool->load+=local_ip_back[i].load;
				rte_smp_wmb();

				RUNNING_LOG_DEBUG("core %d :get back pool local_ip_back[%d].load=%d local_ip_pool.load=%d\n",
					my_lcore,i,local_ip_back[i].load,local_ip_pool->load);

				local_ip_back[i].load=0;



#if 0//test
{
				int x=0;
				struct ip_g_s2 *ips,*ipstmp;

				list_for_each_entry_safe(ips, ipstmp, &local_ip_pool->header, list)
					{
					x++;
					}
				RUNNING_LOG_DEBUG("%s: core<%d> report my pool %d\n",__FUNCTION__,rte_lcore_id(),x);

}
#endif


				rte_smp_wmb();
				}

			if(local_netport_back[i].load)
				{
#if 0//test
{
				int x=0;
				struct l4_port_g_s2 *ipp,*ipptmp;

				list_for_each_entry_safe(ipp, ipptmp, &local_netport_back[i].header, alloc_list)
					{
					x++;
					RUNNING_LOG_DEBUG("%s: core<%d> get back test port=%d cnt=%d\n",
						__FUNCTION__,rte_lcore_id(),ipp->no,x);
					}

}
#endif
				list_splice_tail_init(&local_netport_back[i].header,&local_netport_pool->header);
				local_netport_pool->load+=local_netport_back[i].load;
				rte_smp_wmb();

				RUNNING_LOG_DEBUG("core %d :get back L4pool<%d> back.load=%d pool.load=%d\n",
					my_lcore,i,local_netport_back[i].load,local_netport_pool->load);

				local_netport_back[i].load=0;

				rte_smp_wmb();
				}

#ifdef DN1_ON
			if(local_dn1_back[i].load)
				{
#if 0//test
{
				int x=0;
				struct dn1_g_s2 *ipp,*ipptmp;

				list_for_each_entry_safe(ipp, ipptmp, &local_dn1_back[i].header, alloc_list)
					{
					x++;
					RUNNING_LOG_DEBUG("%s: core<%d> get back test name=%s cnt=%d\n",
						__FUNCTION__,rte_lcore_id(),ipp->name,x);
					}

}
#endif
				list_splice_tail_init(&local_dn1_back[i].header,&local_dn1_pool->header);
				local_dn1_pool->load+=local_dn1_back[i].load;
				rte_smp_wmb();

				RUNNING_LOG_DEBUG("core %d :get back dn1pool<%d> back.load=%d pool.load=%d\n",
					my_lcore,i,local_dn1_back[i].load,local_dn1_pool->load);

				local_dn1_back[i].load=0;

				rte_smp_wmb();
				}
#endif
			}

		if(unlikely(local->timer_flag))
			{
				if(port_stat==port_statA)
					port_stat=port_statB;
				else
					port_stat=port_statA;

				local->timer_flag=0;
				rte_smp_wmb();
				memset(port_stat,0,sizeof(struct port_info_sum)*MAX_DEV);
			}

		end=rte_rdtsc()-start;

#if 1//perform test

		if(end>timer_perform_max[my_lcore])
			timer_perform_max[my_lcore]=end;
		if((end<timer_perform_min[my_lcore])||!timer_perform_min[my_lcore])
			timer_perform_min[my_lcore]=end;

		if(timer_perform_aver[my_lcore]==0)
			timer_perform_aver[my_lcore]=end;
		else
			timer_perform_aver[my_lcore]=((count-1)*timer_perform_aver[my_lcore]+end)/count;

//		RUNNING_LOG_INFO("core %d :sum perform min=%llu aver=%llu max=%llu\n",
//			my_lcore,timer_perform_min[my_lcore],timer_perform_aver[my_lcore],timer_perform_max[my_lcore]);

#endif


	}
}

static inline void __attribute__((always_inline))
update_sum_ip(struct ip_sum_b *sum,struct ip_g_s2 *ip,int dir)
{
	//tcp
	sum->ip_sum[dir].tcp.pps+=ip->ip_info[dir].tcp.pps;
	sum->ip_sum[dir].tcp.bps+=ip->ip_info[dir].tcp.bps;
	sum->ip_sum[dir].tcp.fin+=ip->ip_info[dir].tcp.fin;
	sum->ip_sum[dir].tcp.flow+=ip->ip_info[dir].tcp.flow;
	sum->ip_sum[dir].tcp.rst+=ip->ip_info[dir].tcp.rst;
	sum->ip_sum[dir].tcp.ack+=ip->ip_info[dir].tcp.ack;
	sum->ip_sum[dir].tcp.syn+=ip->ip_info[dir].tcp.syn;
	sum->ip_sum[dir].tcp.syn_ack+=ip->ip_info[dir].tcp.syn_ack;

	//udp
	sum->ip_sum[dir].udp.pps+=ip->ip_info[dir].udp.pps;
	sum->ip_sum[dir].udp.bps+=ip->ip_info[dir].udp.bps;
	sum->ip_sum[dir].udp.flow+=ip->ip_info[dir].udp.flow;

	//icmp
	sum->ip_sum[dir].icmp.pps+=ip->ip_info[dir].icmp.pps;
	sum->ip_sum[dir].icmp.bps+=ip->ip_info[dir].icmp.bps;
	sum->ip_sum[dir].icmp.echo+=ip->ip_info[dir].icmp.echo;
	sum->ip_sum[dir].icmp.redir+=ip->ip_info[dir].icmp.redir;
	sum->ip_sum[dir].icmp.unreach+=ip->ip_info[dir].icmp.unreach;

	//igmp
	sum->ip_sum[dir].igmp.pps+=ip->ip_info[dir].igmp.pps;
	sum->ip_sum[dir].igmp.bps+=ip->ip_info[dir].igmp.bps;
	sum->ip_sum[dir].igmp.v1+=ip->ip_info[dir].igmp.v1;
	sum->ip_sum[dir].igmp.v2+=ip->ip_info[dir].igmp.v2;
	sum->ip_sum[dir].igmp.v3+=ip->ip_info[dir].igmp.v3;

	//ip
	sum->ip_sum[dir].ip.pps+=ip->ip_info[dir].ip.pps;
	sum->ip_sum[dir].ip.bps+=ip->ip_info[dir].ip.bps;
	sum->ip_sum[dir].ip.ip_option+=ip->ip_info[dir].ip.ip_option;

	//attack
//	sum->ip_sum[dir].attack.chargen+=ip->ip_info[dir].attack.chargen;
	sum->ip_sum[dir].attack.dns+=ip->ip_info[dir].attack.dns;
	sum->ip_sum[dir].attack.frag+=ip->ip_info[dir].attack.frag;
	sum->ip_sum[dir].attack.frag_err+=ip->ip_info[dir].attack.frag_err;
	sum->ip_sum[dir].attack.tcp_flag_err+=ip->ip_info[dir].attack.tcp_flag_err;
	sum->ip_sum[dir].attack.smurf+=ip->ip_info[dir].attack.smurf;
	sum->ip_sum[dir].attack.fraggle+=ip->ip_info[dir].attack.fraggle;
	sum->ip_sum[dir].attack.nuker+=ip->ip_info[dir].attack.nuker;
	sum->ip_sum[dir].attack.ssdp+=ip->ip_info[dir].attack.ssdp;
	sum->ip_sum[dir].attack.ntp+=ip->ip_info[dir].attack.ntp;
	sum->ip_sum[dir].attack.snmp+=ip->ip_info[dir].attack.snmp;
	sum->ip_sum[dir].attack.tracert+=ip->ip_info[dir].attack.tracert;
}

static inline void __attribute__((always_inline))
process_l4(struct ip_g_s2 *in,struct ip_sum_b *ips,
	struct hash_array *netport_pool,
	struct hash_array *netport_back_pendig,
	struct hash_array *netport_alloced,
	struct l4_port_g_b *netport_tbl,
	uint32_t *miss_alloced_netport)
{
	struct l4_port_g_s2 *pl4,*pl4tmp;
	struct l4_port_sum_b *pl4_s,*pl4tmp_s;
	int match=0;

	if(in->l4.load)
		{
//		if(!list_empty(&ips->alloc_list))
//			{
//			list_del_init(&ips->alloc_list);
//			ip_alloced_list->load--;
//
//			RUNNING_LOG_DEBUG("core %d(%s:%d) : remove ips_ip=%x,ip_alloced_list->load=%d\n",
//				rte_lcore_id(),__FUNCTION__,__LINE__,ips->addr,ip_alloced_list->load);
//			}

		list_for_each_entry_safe(pl4, pl4tmp, &in->l4.header, alloc_list)
			{
			netport_tbl[pl4->no].info.all[0]+=pl4->info.all[0];
			netport_tbl[pl4->no].info.all[1]+=pl4->info.all[1];
			netport_tbl[pl4->no].info.tcp[0]+=pl4->info.tcp[0];
			netport_tbl[pl4->no].info.tcp[1]+=pl4->info.tcp[1];
			netport_tbl[pl4->no].info.udp[0]+=pl4->info.udp[0];
			netport_tbl[pl4->no].info.udp[1]+=pl4->info.udp[1];

			ips->l4_g.all[0]+=pl4->info.all[0];
			ips->l4_g.all[1]+=pl4->info.all[1];
			ips->l4_g.tcp[0]+=pl4->info.tcp[0];
			ips->l4_g.tcp[1]+=pl4->info.tcp[1];
			ips->l4_g.udp[0]+=pl4->info.udp[0];
			ips->l4_g.udp[1]+=pl4->info.udp[1];

#if 1//debug
			RUNNING_LOG_DEBUG("core %d(%s:%d) : in_ip=%x,in_load=%d,port=%d netport_tbl[%d].load=%d\n",
				rte_lcore_id(),__FUNCTION__,__LINE__,in->addr,in->l4.load,pl4->no,pl4->no,netport_tbl[pl4->no].chain.load);
#endif
			if(!list_empty(&ips->l4.header))
				{
				list_for_each_entry_safe(pl4_s, pl4tmp_s, &ips->l4.header, list_ip)
					{
					RUNNING_LOG_DEBUG("core %d(%s:%d) : search ips=%x,ips_load=%d,port=%d l3paddr=%x\n",
						rte_lcore_id(),__FUNCTION__,__LINE__,ips->addr,ips->l4.load,pl4_s->no,pl4_s->l3p->addr);

					if(pl4_s->no==pl4->no)//found it
						{
						RUNNING_LOG_DEBUG("core %d (%d) :sum l4 hit,ip=%x,port=%d,port_pool->load=%d\n",
							rte_lcore_id(),__LINE__,ips->addr,in->addr,pl4_s->no,netport_pool->load);

						pl4_s->info.all[0]+=pl4->info.all[0];
						pl4_s->info.all[1]+=pl4->info.all[1];
						pl4_s->info.tcp[0]+=pl4->info.tcp[0];
						pl4_s->info.tcp[1]+=pl4->info.tcp[1];
						pl4_s->info.udp[0]+=pl4->info.udp[0];
						pl4_s->info.udp[1]+=pl4->info.udp[1];

						match=1;
						break;
						}
					}

				if(!match)
					{
					goto alloc_sumport;
					}
				}
			else//alloc ip and set
				{
alloc_sumport:
				if(netport_pool->load)
					{
					pl4_s=list_first_entry(&netport_pool->header,struct l4_port_sum_b,alloc_list);
					INIT_LIST_HEAD(&pl4_s->list_tbl);
					INIT_LIST_HEAD(&pl4_s->list_ip);

					pl4_s->info.all[0]=pl4->info.all[0];
					pl4_s->info.all[1]=pl4->info.all[1];
					pl4_s->info.tcp[0]=pl4->info.tcp[0];
					pl4_s->info.tcp[1]=pl4->info.tcp[1];
					pl4_s->info.udp[0]=pl4->info.udp[0];
					pl4_s->info.udp[1]=pl4->info.udp[1];

//					pl4_s->flag=FLAG(L4_SUM_ALLOCED);
					pl4_s->no=pl4->no;
					pl4_s->l3p=ips;

//					if(ips->flag & FLAG(SUM_ALLOCED))
//						{
//						list_del_init(&ips->alloc_list);
//						ips->flag=0;//&=(~ FLAG(SUM_ALLOCED));
//						ip_alloced_list->load--;
//						RUNNING_LOG_DEBUG("core %d %s (%d) :remove from alloced list ip=%x local_alloced_list.load=%d\n",
//							rte_lcore_id(),__FUNCTION__,__LINE__,ips->addr,ip_alloced_list->load);
//						}

					list_add_tail(&pl4_s->list_tbl,&netport_tbl[pl4_s->no].chain.header);
					netport_tbl[pl4->no].chain.load++;

					list_add_tail(&pl4_s->list_ip,&ips->l4.header);
					ips->l4.load++;
					list_move_tail(&pl4_s->alloc_list,&netport_alloced->header);
					netport_pool->load--;
					netport_alloced->load++;

					RUNNING_LOG_DEBUG("core %d (%d) :sum port alloc,ip=%x,port=%d:%d,pool=%d netport_tbl[%d].load=%d alloced.load=%d\n",
						rte_lcore_id(),__LINE__,ips->addr,pl4->no,pl4_s->no,netport_pool->load,
						pl4_s->no,netport_tbl[pl4->no].chain.load,netport_alloced->load);
					}
				else
					{
					*miss_alloced_netport++;

					RUNNING_LOG_DEBUG("core %d (%d) :sum port alloc fail,ip=%x,port=%d,pool=%d\n",
						rte_lcore_id(),__LINE__,ips->addr,pl4->no,netport_pool->load);

					return;
					}
				}

			list_move_tail(&pl4->alloc_list,&netport_back_pendig->header);
			netport_back_pendig->load++;

			RUNNING_LOG_DEBUG("core %d (%d) :sum port backed=%d\n",
				rte_lcore_id(),__LINE__,netport_back_pendig->load);
			}
		}
}

static inline void __attribute__((always_inline))
process_dn1_http(struct ip_g_s2 *in,struct ip_sum_b *ips,
	struct hash_array *dn1_pool,
	struct hash_array *dn1_back_pendig,
	struct hash_array *dn1_alloced,
	struct dn1_pending *dn1_hash,
	uint32_t *miss_alloced_dn1)
{
	struct dn1_g_s2 *d,*dtmp;
	struct dn1_sum_b *d_s,*dtmp_s;
	uint32_t hash_idx;
	int match=0;

	if(in->name_http.load)
		{
		list_for_each_entry_safe(d, dtmp, &in->name_http.header, alloc_list)
			{
			hash_idx=*((uint16_t *)d->name);///*(d->len<<16)+*/((uint32_t)d->name[0]<<8)+(uint32_t)d->name[1];

			match=0;

#if 0//debug
			RUNNING_LOG_DEBUG("core %d(%s:%d) : %p in_ip=%x,in_load=%d,name=%s len=%d dn1_hash[%x]=%d\n",
				rte_lcore_id(),__FUNCTION__,__LINE__,in,in->addr,in->l4.load,d->name,d->len,
				hash_idx,dn1_hash->pending[hash_idx].load);
#endif
			if(!list_empty(&ips->dn1_http.header))
				{
				list_for_each_entry_safe(d_s, dtmp_s, &ips->dn1_http.header, list_ip)
					{
//					RUNNING_LOG_DEBUG("core %d(%s:%d) : search dn1 ips=%x,ips_load=%d,name=%s len=%d\n",
//						rte_lcore_id(),__FUNCTION__,__LINE__,ips->addr,ips->dn1.load,d_s->name,d_s->len);

					if((d_s->len==d->len)&&
						(!memcmp(d_s->name,d->name,d_s->len)))//found it
						{
						RUNNING_LOG_DEBUG("core %d (%d) :sum dn1 hit,ip=%x,name=%s len=%d pool=%d\n",
							rte_lcore_id(),__LINE__,ips->addr,d_s->name,d->len,dn1_pool->load);

						d_s->cnt+=d->cnt;

						match=1;
						break;
						}
					}

				if(!match)
					{
					goto alloc_sumdn1;
					}
				}
			else//alloc ip and set
				{
alloc_sumdn1:
				if(dn1_pool->load)
					{
					d_s=list_first_entry(&dn1_pool->header,struct dn1_sum_b,alloc_list);
					INIT_LIST_HEAD(&d_s->list_tbl);
					INIT_LIST_HEAD(&d_s->list_ip);
					d_s->cnt=d->cnt;
					d_s->l3p=ips;
					d_s->len=d->len;
					rte_memcpy(d_s->name,d->name,d_s->len);
					d_s->name[d_s->len]=0;
//					hash_idx=(d_s->len<<16)+((uint32_t)d_s->name[0]<<8)+(uint32_t)d_s->name[1];
					if(dn1_hash->pending[hash_idx].load==0)
						{
						dn1_hash->hash_idx[dn1_hash->pending_cnt++]=hash_idx;
						}

					list_add_tail(&d_s->list_tbl,&dn1_hash->pending[hash_idx].header);
					dn1_hash->pending[hash_idx].load++;

					list_add_tail(&d_s->list_ip,&ips->dn1_http.header);
					ips->dn1_http.load++;
					list_del_init(&d_s->alloc_list);
					list_add_tail(&d_s->alloc_list,&dn1_alloced->header);
					dn1_pool->load--;
					dn1_alloced->load++;

					RUNNING_LOG_DEBUG("core %d (%d) :sum dn1 alloc %p,ip=%x,name=%s ,pool=%d dn1_tbl[%x]=%d alloced=%d len=%d cnt=%d pending_cnt=%d\n",
						rte_lcore_id(),__LINE__,d_s,ips->addr,d_s->name,dn1_pool->load,hash_idx,dn1_hash->pending[hash_idx].load,
						dn1_alloced->load,d_s->len,d_s->cnt,dn1_hash->pending_cnt);
					}
				else
					{
					*miss_alloced_dn1++;

					RUNNING_LOG_DEBUG("core %d (%d) :sum dn1 alloc fail,ip=%x,%s,pool=%d\n",
						rte_lcore_id(),__LINE__,ips->addr,d->name,dn1_pool->load);

					return;
					}
				}

			list_move_tail(&d->alloc_list,&dn1_back_pendig->header);
			dn1_back_pendig->load++;

			RUNNING_LOG_DEBUG("core %d (%d) :sum dn1 backed=%d\n",
				rte_lcore_id(),__LINE__,dn1_back_pendig->load);
			}
		}
}


static inline void __attribute__((always_inline))
process_dn1(struct ip_g_s2 *in,struct ip_sum_b *ips,
	struct hash_array *dn1_pool,
	struct hash_array *dn1_back_pendig,
	struct hash_array *dn1_alloced,
	struct dn1_pending *dn1_hash,
	uint32_t *miss_alloced_dn1)
{
	struct dn1_g_s2 *d,*dtmp;
	struct dn1_sum_b *d_s,*dtmp_s;
	uint32_t hash_idx;
	int match=0;

	if(in->name_dnsreq.load)
		{
		list_for_each_entry_safe(d, dtmp, &in->name_dnsreq.header, alloc_list)
			{
			hash_idx=*((uint16_t *)d->name);///*(d->len<<16)+*/((uint32_t)d->name[0]<<8)+(uint32_t)d->name[1];

			match=0;

#if 0//debug
			RUNNING_LOG_DEBUG("core %d(%s:%d) : %p in_ip=%x,in_load=%d,name=%s len=%d dn1_hash[%x]=%d\n",
				rte_lcore_id(),__FUNCTION__,__LINE__,in,in->addr,in->l4.load,d->name,d->len,
				hash_idx,dn1_hash->pending[hash_idx].load);
#endif
			if(!list_empty(&ips->dn1.header))
				{
				list_for_each_entry_safe(d_s, dtmp_s, &ips->dn1.header, list_ip)
					{
//					RUNNING_LOG_DEBUG("core %d(%s:%d) : search dn1 ips=%x,ips_load=%d,name=%s len=%d\n",
//						rte_lcore_id(),__FUNCTION__,__LINE__,ips->addr,ips->dn1.load,d_s->name,d_s->len);

					if((d_s->len==d->len)&&
						(!memcmp(d_s->name,d->name,d_s->len)))//found it
						{
						RUNNING_LOG_DEBUG("core %d (%d) :sum dn1 hit,ip=%x,name=%s len=%d pool=%d\n",
							rte_lcore_id(),__LINE__,ips->addr,d_s->name,d->len,dn1_pool->load);

						d_s->cnt+=d->cnt;

						match=1;
						break;
						}
					}

				if(!match)
					{
					goto alloc_sumdn1;
					}
				}
			else//alloc ip and set
				{
alloc_sumdn1:
				if(dn1_pool->load)
					{
					d_s=list_first_entry(&dn1_pool->header,struct dn1_sum_b,alloc_list);
					INIT_LIST_HEAD(&d_s->list_tbl);
					INIT_LIST_HEAD(&d_s->list_ip);
					d_s->cnt=d->cnt;
					d_s->l3p=ips;
					d_s->len=d->len;
					rte_memcpy(d_s->name,d->name,d_s->len);
					d_s->name[d_s->len]=0;
//					hash_idx=(d_s->len<<16)+((uint32_t)d_s->name[0]<<8)+(uint32_t)d_s->name[1];
					if(dn1_hash->pending[hash_idx].load==0)
						{
						dn1_hash->hash_idx[dn1_hash->pending_cnt++]=hash_idx;
						}

					list_add_tail(&d_s->list_tbl,&dn1_hash->pending[hash_idx].header);
					dn1_hash->pending[hash_idx].load++;

					list_add_tail(&d_s->list_ip,&ips->dn1.header);
					ips->dn1.load++;
					list_del_init(&d_s->alloc_list);
					list_add_tail(&d_s->alloc_list,&dn1_alloced->header);
					dn1_pool->load--;
					dn1_alloced->load++;

					RUNNING_LOG_DEBUG("core %d (%d) :sum dn1 alloc %p,ip=%x,name=%s ,pool=%d dn1_tbl[%x]=%d alloced=%d len=%d cnt=%d pending_cnt=%d\n",
						rte_lcore_id(),__LINE__,d_s,ips->addr,d_s->name,dn1_pool->load,hash_idx,dn1_hash->pending[hash_idx].load,
						dn1_alloced->load,d_s->len,d_s->cnt,dn1_hash->pending_cnt);
					}
				else
					{
					*miss_alloced_dn1++;

					RUNNING_LOG_DEBUG("core %d (%d) :sum dn1 alloc fail,ip=%x,%s,pool=%d\n",
						rte_lcore_id(),__LINE__,ips->addr,d->name,dn1_pool->load);

					return;
					}
				}

			list_move_tail(&d->alloc_list,&dn1_back_pendig->header);
			dn1_back_pendig->load++;

			RUNNING_LOG_DEBUG("core %d (%d) :sum dn1 backed=%d\n",
				rte_lcore_id(),__LINE__,dn1_back_pendig->load);
			}
		}
}


static inline void __attribute__((always_inline))
process_sum(struct hash_array *ip_pool,
		struct hash_array *ip_hash,
		struct hash_array *ip_alloced,
		struct hash_array *netport_alloced,
		struct hash_array *netport_pool,
		struct hash_array *netport_back_pendig,
		struct l4_port_g_b *netport_tbl,
		struct hash_array *dn1_pool,
		struct hash_array *dn1_alloced,
		struct hash_array *dn1_back_pendig,
		struct dn1_pending *dn1_hash,
		struct dn1_pending *dn1_hash_http,
		struct ip_g_s2 *in,uint32_t *miss_alloced,uint32_t *miss_alloced_netport,uint32_t *miss_alloced_dn1,
		struct wd_pack *wd,int wd_cnt,uint32_t tick)
{
	uint32_t ip_idx;
	struct ip_sum_b *ips,*ipstmp;
	int match=0;
	int i;

	ip_idx=rte_be_to_cpu_32(in->addr)&(IP_HASH_ARRAY_SZ-1);
//	if((!list_empty(&ip_hash[ip_idx].header))&&(ip_hash[ip_idx].load!=tick))//force clean hash list
//		{
//		RUNNING_LOG_DEBUG("core %d (%d) :sum force clean hash idx=%x tick=%d old tick=%d\n",
//			rte_lcore_id(),__LINE__,ip_idx,tick,ip_hash[ip_idx].load);

//		INIT_LIST_HEAD(&ip_hash[ip_idx].header);
//		}

//	RUNNING_LOG_DEBUG("core %d (%d) :sum hash idx=%x set tick=%d old tick=%d\n",
//		rte_lcore_id(),__LINE__,ip_idx,tick,ip_hash[ip_idx].load);

//	ip_hash[ip_idx].load=tick;

	//look up ip hash
//	if(ip_hash[ip_idx].load)
	if(!list_empty(&ip_hash[ip_idx].header))
		{
		list_for_each_entry_safe(ips, ipstmp, &ip_hash[ip_idx].header, list)
			{
			if(in->addr==ips->addr)//found it
				{
				RUNNING_LOG_DEBUG("core %d (%d) :sum hash hit,ip=%x,ip_hash[%d].load=%d ip_pool->load=%d ip_alloc.load=%d\n",
					rte_lcore_id(),__LINE__,ips->addr,ip_idx,ip_hash[ip_idx].load,ip_pool->load,ip_alloced->load);

				update_sum_ip(ips,in,DIR_OUT);
				update_sum_ip(ips,in,DIR_IN);
				match=1;
				break;
				}
			}

		if(!match)
			{
			goto alloc_sumip;
			}
		}
	else//alloc ip and set
		{
alloc_sumip:
		if(ip_pool->load)
			{
//			RUNNING_LOG_DEBUG("core %d :alloc src %llx hashx idx=%llx\n",rte_lcore_id(),ipv4_hdr->src_addr,srcip_idx);
			ips=list_first_entry(&ip_pool->header,struct ip_sum_b,alloc_list);
			ips->flag=FLAG(SUM_ALLOCED);
			ips->addr=in->addr;
//			list_del_init(&ips->alloc_list);
			INIT_LIST_HEAD(&ips->list);
			INIT_LIST_HEAD(&ips->l4.header);
			ips->l4.load=0;
#ifdef DN1_ON
			INIT_LIST_HEAD(&ips->dn1.header);
			INIT_LIST_HEAD(&ips->dn1_http.header);
			ips->dn1.load=0;
			ips->dn1_http.load=0;
#endif
			memset(ips->ip_sum,0,sizeof(ips->ip_sum[0])*2);
			memset(&ips->l4_g,0,sizeof(struct l4_port_info));
			ip_pool->load--;
			update_sum_ip(ips,in,DIR_OUT);
			update_sum_ip(ips,in,DIR_IN);

			list_add_tail(&ips->list,&ip_hash[ip_idx].header);
//			ip_hash[ip_idx].load++;
//			list_add_tail(&ips->alloc_list,&ip_alloced->header);
			list_move_tail(&ips->alloc_list,&ip_alloced->header);
			ip_alloced->load++;

			RUNNING_LOG_DEBUG("core %d (%d) :sum alloc,ip=%x,ip_hash[%d].load=%d ip_pool->load=%d ip_alloc.load=%d\n",
				rte_lcore_id(),__LINE__,ips->addr,ip_idx,ip_hash[ip_idx].load,ip_pool->load,ip_alloced->load);
			}
		else
			{
			*miss_alloced++;

			RUNNING_LOG_DEBUG("core %d (%d) :sum alloc fail,ip=%x,idx=%d,ip_pool->load=%d miss_alloced=%d\n",
				rte_lcore_id(),__LINE__,in->addr,ip_idx,ip_pool->load,*miss_alloced);

			return;
			}
		}

#ifdef DN1_ON
	//dn1 process
	process_dn1(in,ips,dn1_pool,dn1_back_pendig,dn1_alloced,dn1_hash,miss_alloced_dn1);
	process_dn1_http(in,ips,dn1_pool,dn1_back_pendig,dn1_alloced,dn1_hash_http,miss_alloced_dn1);
#endif

	//netport process
	process_l4(in,ips,netport_pool,netport_back_pendig,netport_alloced,netport_tbl,miss_alloced_netport);



	//wd process
	for(i=0;i<wd_cnt;i++)
		{
		wd[i].ops->process((void *)ips,&wd[i],0);
		if(wd[i].top[0].curr)
			{
			RUNNING_LOG_DEBUG("core %d (%d) :show wd[%d].curr=%d\n",
				rte_lcore_id(),__LINE__,i,wd[i].top[0].curr);
			}
		}
}

static inline struct ip_sum_b * __attribute__((always_inline))
process_sum_dstip(struct hash_array *ip_pool,
		struct hash_array *ip_hash,
		struct hash_array *ip_alloced,
		struct ip_g_s2 *in,struct priv_sum *sum)
{
	uint32_t ip_idx;
	struct ip_sum_b *ips,*ipstmp;
	int match=0;
	int i;

//	ip_idx=rte_be_to_cpu_32(in->addr)&(IP_HASH_ARRAY_SZ-1);

	ip_idx=rte_jhash_2words(rte_be_to_cpu_32(in->addr),rte_be_to_cpu_16(in->port),PRIME_VALUE);
	ip_idx&=(IP_HASH_ARRAY_SZ-1);

//	if((!list_empty(&ip_hash[ip_idx].header))&&(ip_hash[ip_idx].load!=tick))//force clean hash list
//		{
//		RUNNING_LOG_DEBUG("core %d (%d) :sum force clean hash idx=%x tick=%d old tick=%d\n",
//			rte_lcore_id(),__LINE__,ip_idx,tick,ip_hash[ip_idx].load);

//		INIT_LIST_HEAD(&ip_hash[ip_idx].header);
//		}

//	RUNNING_LOG_DEBUG("core %d (%d) :sum hash idx=%x set tick=%d old tick=%d\n",
//		rte_lcore_id(),__LINE__,ip_idx,tick,ip_hash[ip_idx].load);

//	ip_hash[ip_idx].load=tick;

	//look up ip hash
//	if(ip_hash[ip_idx].load)
	if(!list_empty(&ip_hash[ip_idx].header))
		{
		list_for_each_entry_safe(ips, ipstmp, &ip_hash[ip_idx].header, list)
			{
			if((in->addr==ips->addr)&&(in->port == ips->port))//found it
				{
				RUNNING_LOG_DEBUG("core %d (%d) :sum hash hit,ip=%x,ip_hash[%d].load=%d ip_pool->load=%d ip_alloc.load=%d\n",
					rte_lcore_id(),__LINE__,ips->addr,ip_idx,ip_hash[ip_idx].load,ip_pool->load,ip_alloced->load);

				update_sum_ip(ips,in,DIR_OUT);
				update_sum_ip(ips,in,DIR_IN);
				return ips;
				}
			}
		}

	//alloc ip and set
	ips=NULL;
	if(ip_pool->load)
		{
//			RUNNING_LOG_DEBUG("core %d :alloc src %llx hashx idx=%llx\n",rte_lcore_id(),ipv4_hdr->src_addr,srcip_idx);
		ips=list_first_entry(&ip_pool->header,struct ip_sum_b,alloc_list);
//		ips->flag=FLAG(SUM_ALLOCED);
		ips->addr=in->addr;
		ips->port=in->port;
		ips->ip_idx = in->ip_idx;
//			list_del_init(&ips->alloc_list);
		INIT_LIST_HEAD(&ips->list);
		memset(ips->ip_sum,0,sizeof(ips->ip_sum[0])*2);
		ip_pool->load--;
		update_sum_ip(ips,in,DIR_OUT);
		update_sum_ip(ips,in,DIR_IN);

		list_add_tail(&ips->list,&ip_hash[ip_idx].header);
//			ip_hash[ip_idx].load++;
//			list_add_tail(&ips->alloc_list,&ip_alloced->header);
		list_move_tail(&ips->alloc_list,&ip_alloced->header);
		ip_alloced->load++;

		RUNNING_LOG_DEBUG("core %d (%d) :sum alloc,ip=%x,ip_hash[%d].load=%d ip_pool->load=%d ip_alloc.load=%d\n",
			rte_lcore_id(),__LINE__,ips->addr,ip_idx,ip_hash[ip_idx].load,ip_pool->load,ip_alloced->load);
		}
	else
		{
		sum->miss_alloced++;

		RUNNING_LOG_DEBUG("core %d (%d) :sum alloc fail,ip=%x,idx=%d,ip_pool->load=%d miss_alloced=%d\n",
			rte_lcore_id(),__LINE__,ips->addr,ip_idx,ip_pool->load,sum->miss_alloced);
		}

	return ips;
}

uint64_t timer_perform_aver[MAX_CPU]={0};
uint64_t timer_perform_min[MAX_CPU]={0};
uint64_t timer_perform_max[MAX_CPU]={0};

uint32_t nat_flow_limit[(NAT_MAX_DSTNUM>>5)+1]={0};

int main_loop_sum(void)
{
	int my_lcore;
	int i,j,k;
	struct lcore_info_s *local;
	uint64_t cur_tsc, prev_tsc,diff_tsc, hz;
	uint64_t start,end,count=0;
	struct hash_array *ip_hash;
	struct hash_array *remote_burst[MAX_CPU];
	struct hash_array *remote_back[MAX_CPU];
	struct hash_array *remote_back_netport[MAX_CPU];
	struct hash_array *remote_back_dn1[MAX_CPU];
	struct hash_array local_rcv[MAX_CPU];
	struct hash_array *local_snd,*local_snd_netport,*local_snd_dn1;
	struct hash_array local_alloced_list;
	struct hash_array local_alloced_list_netport;
	struct hash_array local_alloced_list_dn1;
	int io_cnt;
	int tmp;
	struct hash_array *local_ip_pool,*local_netport_pool,*local_dn1_pool;
	struct ip_g_s2 *ipm,*ipmtmp;
	struct wd_pack *localwd;
	uint32_t tick=0;
//	struct l4_port_g_b *tk;
	struct l4_port_g_b *netport_tbl_pending,*netport_tbl_burst;
	struct dn1_pending *dn1_hash_pending,*dn1_hash_burst;
	struct dn1_pending *dn1_hash_pending_http,*dn1_hash_burst_http;

	my_lcore=rte_lcore_id();
	local=&lcore[my_lcore];
	ip_hash=local->sum.sum_hash;
	io_cnt=__builtin_popcountll(me.io_in_mask);
	rte_memcpy(remote_burst,local->sum.sum_ip_io2sum_burst,sizeof(struct hash_array *)*io_cnt);
	rte_memcpy(remote_back,local->sum.sum_ip_sum2io_burst,sizeof(struct hash_array *)*io_cnt);
	rte_memcpy(remote_back_netport,local->sum.sum_netport_sum2io_burst,sizeof(struct hash_array *)*io_cnt);
	rte_memcpy(remote_back_dn1,local->sum.sum_dn1_sum2io_burst,sizeof(struct hash_array *)*io_cnt);
	local_ip_pool=&local->sum.ip_sum_pool;
	local_netport_pool=&local->sum.netport_sum_pool;
	local_snd=local->sum.sum_sum2io_pending;
	local_snd_netport=local->sum.sum_netport_sum2io_pending;
	local_snd_dn1=local->sum.sum_dn1_sum2io_pending;
	INIT_LIST_HEAD(&local_alloced_list.header);
	local_alloced_list.load=0;
	INIT_LIST_HEAD(&local_alloced_list_netport.header);
	local_alloced_list_netport.load=0;
	INIT_LIST_HEAD(&local_alloced_list_dn1.header);
	local_alloced_list_dn1.load=0;
	netport_tbl_pending=local->sum.netport_tbl[0];
	netport_tbl_burst=local->sum.netport_tbl[1];
	local_dn1_pool=&local->sum.dn1_sum_pool;
	dn1_hash_pending=local->sum.sum_dn1_hash[0];
	dn1_hash_burst=local->sum.sum_dn1_hash[1];
	dn1_hash_pending_http=local->sum.sum_dn1_hash_http[0];
	dn1_hash_burst_http=local->sum.sum_dn1_hash_http[1];

//	tk=local->sum.netport_tbl[0];

	for(i=0;i<io_cnt;i++)
		{
		INIT_LIST_HEAD(&local_rcv[i].header);
		local_rcv[i].load=0;
		}
	localwd=local->sum.wd;

	RUNNING_LOG_INFO("core %d :main_loop_sum\n",my_lcore);

	while(1){
		count++;
		start=rte_rdtsc();

		for(i=0;i<io_cnt;i++)//rcv
			{
			if(remote_burst[i]->load)
				{
				list_splice_tail_init(&remote_burst[i]->header,&local_rcv[i].header);
				tmp=remote_burst[i]->load;
				rte_smp_wmb();
				remote_burst[i]->load=0;
				rte_smp_wmb();
				local_rcv[i].load+=tmp;

#if 0//test
{
				int x=0;
				struct ip_g_s2 *ipm,*iptmp;

				list_for_each_entry_safe(ipm, iptmp, &local_rcv[i].header, pending_list)
					{
					x++;
					RUNNING_LOG_DEBUG("%s: core<%d> rcv test ip=%x cnt=%d\n",__FUNCTION__,rte_lcore_id(),ipm->addr,
						x);
					}
}
#endif

				RUNNING_LOG_DEBUG("core %d :remote_burst[%d]->load=%d local_rcv.load=%d\n",
					my_lcore,i,tmp,local_rcv[i].load);

				}
			}

		for(i=0;i<io_cnt;i++)//process
			{
			if(local_rcv[i].load)
				{
				RUNNING_LOG_DEBUG("core %d :local_rcv[%d]->load=%d local_snd.load=%d\n",
					my_lcore,i,local_rcv[i].load,local_snd[i].load);

				list_for_each_entry_safe(ipm,ipmtmp,&local_rcv[i].header,pending_list)
					{
					process_sum(local_ip_pool,ip_hash,&local_alloced_list,
						&local_alloced_list_netport,local_netport_pool,&local_snd_netport[i],
						/*tk*/netport_tbl_pending,local_dn1_pool,&local_alloced_list_dn1,
						&local_snd_dn1[i],dn1_hash_pending,dn1_hash_pending_http,
						ipm,
						&local->sum.miss_alloced,&local->sum.miss_alloced_netport,
						&local->sum.miss_alloced_dn1,localwd,local->sum.wd_valid_cnt,tick);
					list_del_init(&ipm->pending_list);
					list_add_tail(&ipm->list,&local_snd[i].header);
					local_snd[i].load++;
					local_rcv[i].load--;
					}
//				local_snd[i].load+=local_rcv[i].load;
//				local_rcv[i].load=0;

				RUNNING_LOG_DEBUG("core %d :deal local_snd[%d].load=%d local_rcv[i].load=%d\n",
					my_lcore,i,local_snd[i].load,local_rcv[i].load);

				}
			}

		for(i=0;i<io_cnt;i++)//free back
			{
			//ip
			if((!remote_back[i]->load)&&(local_snd[i].load))
				{
				list_splice_tail_init(&local_snd[i].header,&remote_back[i]->header);
				rte_smp_wmb();
				remote_back[i]->load=local_snd[i].load;
				rte_smp_wmb();
				local_snd[i].load=0;

				RUNNING_LOG_DEBUG("core %d :push back remote_back[%d]->load=%d\n",
					my_lcore,i,remote_back[i]->load);
				}

			//port
			if((!remote_back_netport[i]->load)&&(local_snd_netport[i].load))
				{
				list_splice_tail_init(&local_snd_netport[i].header,&remote_back_netport[i]->header);
				rte_smp_wmb();
				remote_back_netport[i]->load=local_snd_netport[i].load;
				rte_smp_wmb();
				local_snd_netport[i].load=0;

				RUNNING_LOG_DEBUG("core %d :push back remote_back_port[%d]->load=%d\n",
					my_lcore,i,remote_back_netport[i]->load);
				}

#ifdef DN1_ON
			//dn1
			if((!remote_back_dn1[i]->load)&&(local_snd_dn1[i].load))
				{
				list_splice_tail_init(&local_snd_dn1[i].header,&remote_back_dn1[i]->header);
				rte_smp_wmb();
				remote_back_dn1[i]->load=local_snd_dn1[i].load;
				rte_smp_wmb();
				local_snd_dn1[i].load=0;

				RUNNING_LOG_DEBUG("core %d :push back remote_back_dn1[%d]->load=%d\n",
					my_lcore,i,remote_back_dn1[i]->load);
				}
#endif
			}

		if(unlikely(local->timer_flag))
			{
			struct ip_sum_b *ppx;

//			if(local->sum.l4_tlb_idx)
//				tk=local->sum.netport_tbl[1];
//			else
//				tk=local->sum.netport_tbl[0];

			tick++;

			for(i=0;i<local->sum.wd_valid_cnt;i++)
				{
				if(local->sum.wd[i].top[0].curr)
					{
					rte_memcpy((void *)&local->sum.wd[i].top[1],
						(void *)&local->sum.wd[i].top[0],sizeof(struct topK));

//					for(j=0;j<local->sum.wd[i].top[0].curr;j++)
//						{
//						struct ip_sum_b * pq;
//						ppx=(struct ip_sum_b *)local->sum.wd[i].top[0].arr[j];
//						pq=(struct ip_sum_b *)local->sum.wd[i].top[1].arr[j];

//						local->sum.wd[i].top[1].arr[j]=local->sum.wd[i].top[0].arr[j];

//						}
//					local->sum.wd[i].top[1].curr=local->sum.wd[i].top[0].curr;

					RUNNING_LOG_DEBUG("core %d (%d) :remove from alloced list wd[%d].curr=%d wd[].curr2=%d local_alloced_list.load=%d\n",
						rte_lcore_id(),__LINE__,i,local->sum.wd[i].top[0].curr,
						local->sum.wd[i].top[1].curr,local_alloced_list.load);
					}
				else
					local->sum.wd[i].top[1].curr=0;

//				for(j=0;j<local->sum.wd[i].top[0].curr;j++)
//					{
//					ppx=(struct ip_sum_b *)local->sum.wd[i].top[0].arr[j];
//					if(ppx->flag & FLAG(SUM_ALLOCED))
//						{
//						list_del_init(&ppx->alloc_list);
//						ppx->flag=0;//&=(~ FLAG(SUM_ALLOCED));
//						local_alloced_list.load--;
//						RUNNING_LOG_INFO("core %d (%d) :remove from alloced list j=%d ip=%x local_alloced_list.load=%d\n",
//							rte_lcore_id(),__LINE__,j,ppx->addr,local_alloced_list.load);
//						}
//					}

//				local->sum.wd[i].top[1].curr=local->sum.wd[i].top[0].curr;
				local->sum.wd[i].top[0].curr=0;


#if 0//debug
				for(j=0;j<local->sum.wd[i].top[0].curr;j++)
					{
					struct ip_sum_b *ppx=(struct ip_sum_b *)local->sum.wd[i].top[0].arr[j];

					RUNNING_LOG_DEBUG("core %d %s(%d): wd[%d].arr[%d] ip=%x\n",
						my_lcore,__FUNCTION__,__LINE__,i,j,ppx->addr);
					}
#endif
				}

//			rte_smp_wmb();

			//netport
			rte_memcpy(netport_tbl_burst,netport_tbl_pending,sizeof(struct l4_port_g_b)*65536);

#ifdef DN1_ON

			//dn1
			uint32_t idd;
			for(i=0;i<dn1_hash_pending->pending_cnt;i++)
				{
				idd=dn1_hash_pending->hash_idx[i];
				INIT_LIST_HEAD(&dn1_hash_burst->pending[idd].header);

				list_splice_tail_init(&dn1_hash_pending->pending[idd].header,
					&dn1_hash_burst->pending[idd].header);

				dn1_hash_burst->pending[idd].load=dn1_hash_pending->pending[idd].load;
				dn1_hash_pending->pending[idd].load=0;

				dn1_hash_burst->hash_idx[i]=idd;


#if 0//test
{
				int x=0;
				struct dn1_sum_b *ipm,*iptmp;

				list_for_each_entry_safe(ipm, iptmp, &dn1_hash_burst->pending[idd].header, list_tbl)
					{
					x++;
					RUNNING_LOG_DEBUG("%s: core<%d> rcv test %s cnt=%d\n",
						__FUNCTION__,rte_lcore_id(),ipm->name,
						x);
					}
}
#endif


				RUNNING_LOG_DEBUG("core %d (%d) :sum push hash_idx=%x i=%d cnt=%d\n",
					rte_lcore_id(),__LINE__,dn1_hash_burst->hash_idx[i],i,dn1_hash_burst->pending[idd].load);
				}

			dn1_hash_burst->pending_cnt=dn1_hash_pending->pending_cnt;
			dn1_hash_pending->pending_cnt=0;

			//dn1 http
			for(i=0;i<dn1_hash_pending_http->pending_cnt;i++)
				{
				idd=dn1_hash_pending_http->hash_idx[i];
				INIT_LIST_HEAD(&dn1_hash_burst_http->pending[idd].header);

				list_splice_tail_init(&dn1_hash_pending_http->pending[idd].header,
					&dn1_hash_burst_http->pending[idd].header);

				dn1_hash_burst_http->pending[idd].load=dn1_hash_pending_http->pending[idd].load;
				dn1_hash_pending_http->pending[idd].load=0;

				dn1_hash_burst_http->hash_idx[i]=idd;


#if 0//test
{
				int x=0;
				struct dn1_sum_b *ipm,*iptmp;

				list_for_each_entry_safe(ipm, iptmp, &dn1_hash_burst->pending[idd].header, list_tbl)
					{
					x++;
					RUNNING_LOG_DEBUG("%s: core<%d> rcv test %s cnt=%d\n",
						__FUNCTION__,rte_lcore_id(),ipm->name,
						x);
					}
}
#endif


				RUNNING_LOG_DEBUG("core %d (%d) :sum push http hash_idx=%x i=%d cnt=%d\n",
					rte_lcore_id(),__LINE__,dn1_hash_burst_http->hash_idx[i],i,dn1_hash_burst_http->pending[idd].load);
				}

			dn1_hash_burst_http->pending_cnt=dn1_hash_pending_http->pending_cnt;
			dn1_hash_pending_http->pending_cnt=0;
#endif
//			rte_smp_wmb();


//			rte_memcpy(dn1_hash_burst,dn1_hash_pending,sizeof(struct dn1_pending));


			//mon_ip
			uint32_t ip_idx,ipk;
			struct ip_sum_b *ips,*ipstmp;

			for(i=0;i<local->sum.mon_ip_core[local->sum.mon_ip_idx].curr;i++)
				{
				ipk=local->sum.mon_ip_core[local->sum.mon_ip_idx].arr[i];
				ip_idx=rte_be_to_cpu_32(ipk)&(IP_HASH_ARRAY_SZ-1);
				if(!list_empty(&ip_hash[ip_idx].header))
					{
					list_for_each_entry_safe(ips, ipstmp, &ip_hash[ip_idx].header, list)
						{
						if(ipk==ips->addr)//found it
							{
							local->sum.mon_ip_burst[local->sum.mon_ip_burst_cnt++]=ips;

							RUNNING_LOG_DEBUG("core %d (%d) :sum found ip=%x spec,cnt=%d\n",
								rte_lcore_id(),__LINE__,ips->addr,local->sum.mon_ip_burst_cnt);

							break;
							}
						}
					}
				}

			rte_smp_wmb();
			local->sum.wd_switch=1;
			rte_smp_wmb();

			memset(/*tk*/netport_tbl_pending,0,sizeof(struct l4_port_g_b)*65536);
			for(i=0;i<65536;i++)
				{
				INIT_LIST_HEAD(&netport_tbl_pending[i].chain.header);
				netport_tbl_pending[i].no=i;
				}

//			memset(dn1_hash_pending,0,sizeof(struct dn1_pending));
//			for(i=0;i<DN1_HASH_ARRAY_SZ;i++)
//				{
//				INIT_LIST_HEAD(&dn1_hash_pending->pending[i].header);
//				}

			for(i=0;i<IP_HASH_ARRAY_SZ;i++)
				{
				INIT_LIST_HEAD(&ip_hash[i].header);
				}

			local->timer_flag=0;
			rte_smp_wmb();
			}

		if(unlikely(local->timer_idle))
			{
			local->sum.mon_ip_burst_cnt=0;

			//ip
			if(local_alloced_list.load)
				{
				RUNNING_LOG_DEBUG("core %d :timer triger free sum local_alloced_list.load=%d\n",
					my_lcore,local_alloced_list.load);

#if 0//test
{
				int x=0;
				struct ip_sum_b *ips,*ipstmp;

				list_for_each_entry_safe(ips, ipstmp, &local_alloced_list.header, alloc_list)
					{
					x++;
					RUNNING_LOG_DEBUG("%s: core<%d> local_alloced_list ready free test ip=%x cnt=%d\n",__FUNCTION__,rte_lcore_id(),ips->addr,
						x);
					}

}
#endif

				list_splice_tail_init(&local_alloced_list.header,&local_ip_pool->header);
				local_ip_pool->load+=local_alloced_list.load;
				local_alloced_list.load=0;

				RUNNING_LOG_DEBUG("core %d :timer triger pool.load=%d\n",
					my_lcore,local_ip_pool->load);
				}

			if(local_alloced_list_netport.load)
				{
#if 0//test
{
				int x=0;
				struct l4_port_sum_b *ips,*ipstmp;

				list_for_each_entry_safe(ips, ipstmp, &local_alloced_list_netport.header, alloc_list)
					{
					x++;
					RUNNING_LOG_DEBUG("%s: core<%d> local_alloced_list_netport ready free test port=%d ip=%x cnt=%d\n",
						__FUNCTION__,rte_lcore_id(),ips->no,ips->l3p->addr,x);
					}

}
#endif

				list_splice_tail_init(&local_alloced_list_netport.header,&local_netport_pool->header);
				local_netport_pool->load+=local_alloced_list_netport.load;
				local_alloced_list_netport.load=0;

				RUNNING_LOG_DEBUG("core %d :timer idle netport pool.load=%d\n",
					my_lcore,local_netport_pool->load);
				}

#ifdef DN1_ON

			if(local_alloced_list_dn1.load)
				{
#if 0//test
{
				int x=0;
				struct dn1_sum_b *ips,*ipstmp;

				list_for_each_entry_safe(ips, ipstmp, &local_alloced_list_netport.header, alloc_list)
					{
					x++;
					RUNNING_LOG_DEBUG("%s: core<%d> local_alloced_list_dn1t ready free test name=%s cnt=%d\n",
						__FUNCTION__,rte_lcore_id(),ips->name,x);
					}

}
#endif

				list_splice_tail_init(&local_alloced_list_dn1.header,&local_dn1_pool->header);
				local_dn1_pool->load+=local_alloced_list_dn1.load;
				local_alloced_list_dn1.load=0;

				RUNNING_LOG_DEBUG("core %d :timer idle dn1 pool.load=%d\n",
					my_lcore,local_dn1_pool->load);
				}
#endif

			local->timer_idle=0;
			rte_smp_wmb();
			}

		end=rte_rdtsc()-start;

		if(unlikely(local->sum.mon_ip_switch))
			{
			local->sum.mon_ip_idx^=1;
			local->sum.mon_ip_switch=0;

#if 0//debug
{
			int x;

			RUNNING_LOG_DEBUG("core %d :new mon ip,idx=%d,sz=%d\n",
				my_lcore,local->sum.mon_ip_idx,local->sum.mon_ip_core[local->sum.mon_ip_idx].curr);

			for(x=0;x<local->sum.mon_ip_core[local->sum.mon_ip_idx].curr;x++)
				{
				RUNNING_LOG_DEBUG("core %d :new mon ip=%x\n",
					my_lcore,local->sum.mon_ip_core[local->sum.mon_ip_idx].arr[x]);
				}
}
#endif
			}

#if 1//perform test

		if(end>timer_perform_max[my_lcore])
			timer_perform_max[my_lcore]=end;
		if((end<timer_perform_min[my_lcore])||!timer_perform_min[my_lcore])
			timer_perform_min[my_lcore]=end;

		if(timer_perform_aver[my_lcore]==0)
			timer_perform_aver[my_lcore]=end;
		else
			timer_perform_aver[my_lcore]=((count-1)*timer_perform_aver[my_lcore]+end)/count;

//		RUNNING_LOG_INFO("core %d :sum perform min=%llu aver=%llu max=%llu\n",
//			my_lcore,timer_perform_min[my_lcore],timer_perform_aver[my_lcore],timer_perform_max[my_lcore]);

#endif

		}
}

#if 0


static inline void __attribute__((always_inline))
port_stat_reap_1(struct port_sum_per_s *p,struct port_sum_total_s *pp,struct port_sum_s **tmp,int cnt,int dir)//only in
{
	int i;

	for(i=0;i<cnt;i++)
		{
		//per
		p->in_bps+=tmp[i]->sub.in_bps;
		p->in_pps+=tmp[i]->sub.in_pps;
		p->bad_ipv4_pkts+=tmp[i]->sub.bad_ipv4_pkts;

		//tcp
		p->tcp_bps.ack+=tmp[i]->sub.tcp_bps.ack;
		p->tcp_bps.cnt+=tmp[i]->sub.tcp_bps.cnt;
		p->tcp_bps.fin+=tmp[i]->sub.tcp_bps.fin;
		p->tcp_bps.flow+=tmp[i]->sub.tcp_bps.flow;
		p->tcp_bps.rst+=tmp[i]->sub.tcp_bps.rst;
		p->tcp_bps.syn+=tmp[i]->sub.tcp_bps.syn;
		p->tcp_bps.syn_ack+=tmp[i]->sub.tcp_bps.syn_ack;

		p->tcp_pps.ack+=tmp[i]->sub.tcp_pps.ack;
		p->tcp_pps.cnt+=tmp[i]->sub.tcp_pps.cnt;
		p->tcp_pps.fin+=tmp[i]->sub.tcp_pps.fin;
		p->tcp_pps.flow+=tmp[i]->sub.tcp_pps.flow;
		p->tcp_pps.rst+=tmp[i]->sub.tcp_pps.rst;
		p->tcp_pps.syn+=tmp[i]->sub.tcp_pps.syn;
		p->tcp_pps.syn_ack+=tmp[i]->sub.tcp_pps.syn_ack;

		//udp
		p->udp_bps.cnt+=tmp[i]->sub.udp_bps.cnt;
		p->udp_bps.flow+=tmp[i]->sub.udp_bps.flow;

		p->udp_pps.cnt+=tmp[i]->sub.udp_pps.cnt;
		p->udp_pps.flow+=tmp[i]->sub.udp_pps.flow;

		//icmp
		p->icmp_bps.cnt+=tmp[i]->sub.icmp_bps.cnt;
		p->icmp_bps.echo+=tmp[i]->sub.icmp_bps.echo;
		p->icmp_bps.redir+=tmp[i]->sub.icmp_bps.redir;
		p->icmp_bps.unreach+=tmp[i]->sub.icmp_bps.unreach;

		p->icmp_pps.cnt+=tmp[i]->sub.icmp_pps.cnt;
		p->icmp_pps.echo+=tmp[i]->sub.icmp_pps.echo;
		p->icmp_pps.redir+=tmp[i]->sub.icmp_pps.redir;
		p->icmp_pps.unreach+=tmp[i]->sub.icmp_pps.unreach;

		//igmp
		p->igmp_bps.cnt+=tmp[i]->sub.igmp_bps.cnt;
		p->igmp_bps.v1+=tmp[i]->sub.igmp_bps.v1;
		p->igmp_bps.v2+=tmp[i]->sub.igmp_bps.v2;
		p->igmp_bps.v3+=tmp[i]->sub.igmp_bps.v3;

		p->igmp_pps.cnt+=tmp[i]->sub.igmp_pps.cnt;
		p->igmp_pps.v1+=tmp[i]->sub.igmp_pps.v1;
		p->igmp_pps.v2+=tmp[i]->sub.igmp_pps.v2;
		p->igmp_pps.v3+=tmp[i]->sub.igmp_pps.v3;

		//ip
		p->ip_bps.cnt+=tmp[i]->sub.ip_bps.cnt;
		p->ip_bps.ip_option+=tmp[i]->sub.ip_bps.ip_option;
		p->ip_bps.ipv6+=tmp[i]->sub.ip_bps.ipv6;

		p->ip_pps.cnt+=tmp[i]->sub.ip_pps.cnt;
		p->ip_pps.ip_option+=tmp[i]->sub.ip_pps.ip_option;
		p->ip_pps.ipv6+=tmp[i]->sub.ip_pps.ipv6;

		//attack
		p->attack_bps.chargen+=tmp[i]->sub.attack_bps.chargen;
		p->attack_bps.dns+=tmp[i]->sub.attack_bps.dns;
		p->attack_bps.frag+=tmp[i]->sub.attack_bps.frag;
		p->attack_bps.fraggle+=tmp[i]->sub.attack_bps.fraggle;
		p->attack_bps.frag_err+=tmp[i]->sub.attack_bps.frag_err;
		p->attack_bps.land+=tmp[i]->sub.attack_bps.land;
		p->attack_bps.ntp+=tmp[i]->sub.attack_bps.ntp;
		p->attack_bps.nuker+=tmp[i]->sub.attack_bps.nuker;
		p->attack_bps.smurf+=tmp[i]->sub.attack_bps.smurf;
		p->attack_bps.snmp+=tmp[i]->sub.attack_bps.snmp;
		p->attack_bps.ssdp+=tmp[i]->sub.attack_bps.ssdp;
		p->attack_bps.tcp_flag_err+=tmp[i]->sub.attack_bps.tcp_flag_err;
		p->attack_bps.tracert+=tmp[i]->sub.attack_bps.tracert;

		p->attack_pps.chargen+=tmp[i]->sub.attack_pps.chargen;
		p->attack_pps.dns+=tmp[i]->sub.attack_pps.dns;
		p->attack_pps.frag+=tmp[i]->sub.attack_pps.frag;
		p->attack_pps.fraggle+=tmp[i]->sub.attack_pps.fraggle;
		p->attack_pps.frag_err+=tmp[i]->sub.attack_pps.frag_err;
		p->attack_pps.land+=tmp[i]->sub.attack_pps.land;
		p->attack_pps.ntp+=tmp[i]->sub.attack_pps.ntp;
		p->attack_pps.nuker+=tmp[i]->sub.attack_pps.nuker;
		p->attack_pps.smurf+=tmp[i]->sub.attack_pps.smurf;
		p->attack_pps.snmp+=tmp[i]->sub.attack_pps.snmp;
		p->attack_pps.ssdp+=tmp[i]->sub.attack_pps.ssdp;
		p->attack_pps.tcp_flag_err+=tmp[i]->sub.attack_pps.tcp_flag_err;
		p->attack_pps.tracert+=tmp[i]->sub.attack_pps.tracert;

		//total
		//tcp
		pp->tcp_sum_bytes.ack+=tmp[i]->sub.tcp_bps.ack;
		pp->tcp_sum_bytes.cnt+=tmp[i]->sub.tcp_bps.cnt;
		pp->tcp_sum_bytes.fin+=tmp[i]->sub.tcp_bps.fin;
		pp->tcp_sum_bytes.flow+=tmp[i]->sub.tcp_bps.flow;
		pp->tcp_sum_bytes.rst+=tmp[i]->sub.tcp_bps.rst;
		pp->tcp_sum_bytes.syn+=tmp[i]->sub.tcp_bps.syn;
		pp->tcp_sum_bytes.syn_ack+=tmp[i]->sub.tcp_bps.syn_ack;

		pp->tcp_sum_pkts.ack+=tmp[i]->sub.tcp_pps.ack;
		pp->tcp_sum_pkts.cnt+=tmp[i]->sub.tcp_pps.cnt;
		pp->tcp_sum_pkts.fin+=tmp[i]->sub.tcp_pps.fin;
		pp->tcp_sum_pkts.flow+=tmp[i]->sub.tcp_pps.flow;
		pp->tcp_sum_pkts.rst+=tmp[i]->sub.tcp_pps.rst;
		pp->tcp_sum_pkts.syn+=tmp[i]->sub.tcp_pps.syn;
		pp->tcp_sum_pkts.syn_ack+=tmp[i]->sub.tcp_pps.syn_ack;

		//udp
		pp->udp_sum_bytes.cnt+=tmp[i]->sub.udp_bps.cnt;
		pp->udp_sum_bytes.flow+=tmp[i]->sub.udp_bps.flow;

		pp->udp_sum_pkts.cnt+=tmp[i]->sub.udp_pps.cnt;
		pp->udp_sum_pkts.flow+=tmp[i]->sub.udp_pps.flow;

		//icmp
		pp->icmp_sum_bytes.cnt+=tmp[i]->sub.icmp_bps.cnt;
		pp->icmp_sum_bytes.echo+=tmp[i]->sub.icmp_bps.echo;
		pp->icmp_sum_bytes.redir+=tmp[i]->sub.icmp_bps.redir;
		pp->icmp_sum_bytes.unreach+=tmp[i]->sub.icmp_bps.unreach;

		pp->icmp_sum_pkts.cnt+=tmp[i]->sub.icmp_pps.cnt;
		pp->icmp_sum_pkts.echo+=tmp[i]->sub.icmp_pps.echo;
		pp->icmp_sum_pkts.redir+=tmp[i]->sub.icmp_pps.redir;
		pp->icmp_sum_pkts.unreach+=tmp[i]->sub.icmp_pps.unreach;

		//igmp
		pp->igmp_sum_bytes.cnt+=tmp[i]->sub.igmp_bps.cnt;
		pp->igmp_sum_bytes.v1+=tmp[i]->sub.igmp_bps.v1;
		pp->igmp_sum_bytes.v2+=tmp[i]->sub.igmp_bps.v2;
		pp->igmp_sum_bytes.v3+=tmp[i]->sub.igmp_bps.v3;

		pp->igmp_sum_pkts.cnt+=tmp[i]->sub.igmp_pps.cnt;
		pp->igmp_sum_pkts.v1+=tmp[i]->sub.igmp_pps.v1;
		pp->igmp_sum_pkts.v2+=tmp[i]->sub.igmp_pps.v2;
		pp->igmp_sum_pkts.v3+=tmp[i]->sub.igmp_pps.v3;

		//ip
		pp->ip_sum_bytes.cnt+=tmp[i]->sub.ip_bps.cnt;
		pp->ip_sum_bytes.ip_option+=tmp[i]->sub.ip_bps.ip_option;
		pp->ip_sum_bytes.ipv6+=tmp[i]->sub.ip_bps.ipv6;

		pp->ip_sum_pkts.cnt+=tmp[i]->sub.ip_pps.cnt;
		pp->ip_sum_pkts.ip_option+=tmp[i]->sub.ip_pps.ip_option;
		pp->ip_sum_pkts.ipv6+=tmp[i]->sub.ip_pps.ipv6;

		//attack
		pp->attack_sum_bytes.chargen+=tmp[i]->sub.attack_bps.chargen;
		pp->attack_sum_bytes.dns+=tmp[i]->sub.attack_bps.dns;
		pp->attack_sum_bytes.frag+=tmp[i]->sub.attack_bps.frag;
		pp->attack_sum_bytes.fraggle+=tmp[i]->sub.attack_bps.fraggle;
		pp->attack_sum_bytes.frag_err+=tmp[i]->sub.attack_bps.frag_err;
		pp->attack_sum_bytes.land+=tmp[i]->sub.attack_bps.land;
		pp->attack_sum_bytes.ntp+=tmp[i]->sub.attack_bps.ntp;
		pp->attack_sum_bytes.nuker+=tmp[i]->sub.attack_bps.nuker;
		pp->attack_sum_bytes.smurf+=tmp[i]->sub.attack_bps.smurf;
		pp->attack_sum_bytes.snmp+=tmp[i]->sub.attack_bps.snmp;
		pp->attack_sum_bytes.ssdp+=tmp[i]->sub.attack_bps.ssdp;
		pp->attack_sum_bytes.tcp_flag_err+=tmp[i]->sub.attack_bps.tcp_flag_err;
		pp->attack_sum_bytes.tracert+=tmp[i]->sub.attack_bps.tracert;

		pp->attack_sum_pkts.chargen+=tmp[i]->sub.attack_pps.chargen;
		pp->attack_sum_pkts.dns+=tmp[i]->sub.attack_pps.dns;
		pp->attack_sum_pkts.frag+=tmp[i]->sub.attack_pps.frag;
		pp->attack_sum_pkts.fraggle+=tmp[i]->sub.attack_pps.fraggle;
		pp->attack_sum_pkts.frag_err+=tmp[i]->sub.attack_pps.frag_err;
		pp->attack_sum_pkts.land+=tmp[i]->sub.attack_pps.land;
		pp->attack_sum_pkts.ntp+=tmp[i]->sub.attack_pps.ntp;
		pp->attack_sum_pkts.nuker+=tmp[i]->sub.attack_pps.nuker;
		pp->attack_sum_pkts.smurf+=tmp[i]->sub.attack_pps.smurf;
		pp->attack_sum_pkts.snmp+=tmp[i]->sub.attack_pps.snmp;
		pp->attack_sum_pkts.ssdp+=tmp[i]->sub.attack_pps.ssdp;
		pp->attack_sum_pkts.tcp_flag_err+=tmp[i]->sub.attack_pps.tcp_flag_err;
		pp->attack_sum_pkts.tracert+=tmp[i]->sub.attack_pps.tracert;
		}
}
#endif

static inline void __attribute__((always_inline))
dump_allport_sum(struct port_info_sum *total)
{
	int i=0;

		{
			HW_LOG("===> all port in :\n");
			HW_LOG("in_pps: %llu in_bps: %llu bad_ipv4_pkts: %llu\n",
				total[i].sub[0].in_pps,total[i].sub[0].in_bps*8,total[i].sub[0].bad_ipv4_pkts);
			HW_LOG("tcp: %llu pps, %llu bps, %llu ack, %llu syn, %llu syn_ack, %llu rst, %llu fin, %llu flow\n"
				,total[i].sub[0].tcp.pps,total[i].sub[0].tcp.bps*8,total[i].sub[0].tcp.ack,total[i].sub[0].tcp.syn,
				total[i].sub[0].tcp.syn_ack,total[i].sub[0].tcp.rst,total[i].sub[0].tcp.fin,total[i].sub[0].tcp.flow);
			HW_LOG("udp: %llu pps, %llu bps, %llu flow :icmp: %llu pps, %llu bps, %llu echo, %llu redir, %llu unreach\n"
				,total[i].sub[0].udp.pps,total[i].sub[0].udp.bps*8,total[i].sub[0].udp.flow,total[i].sub[0].icmp.pps,
				total[i].sub[0].icmp.bps*8,total[i].sub[0].icmp.echo,total[i].sub[0].icmp.redir,total[i].sub[0].icmp.unreach);
			HW_LOG("igmp: %llu pps, %llu bps, %llu v1, %llu v2, %llu v3\n"
				,total[i].sub[0].igmp.pps,total[i].sub[0].igmp.bps*8,total[i].sub[0].igmp.v1,
				total[i].sub[0].igmp.v2,total[i].sub[0].igmp.v3);
			HW_LOG("attack: %llu dns: %llu frag: %llu fraggle: %llu frag_err: %llu land: %llu ntp: %llu nuker\n"
				,
				total[i].sub[0].attack.dns,
				total[i].sub[0].attack.frag,
				total[i].sub[0].attack.fraggle,
				total[i].sub[0].attack.frag_err,
				total[i].sub[0].attack.land,
				total[i].sub[0].attack.ntp,
				total[i].sub[0].attack.nuker);
			HW_LOG("attack: %llu smurf: %llu snmp: %llu ssdp: %llu tcp_flag_err: %llu tracert\n"
				,total[i].sub[0].attack.smurf,
				total[i].sub[0].attack.snmp,
				total[i].sub[0].attack.ssdp,
				total[i].sub[0].attack.tcp_flag_err,
				total[i].sub[0].attack.tracert);
		}

		{
			HW_LOG("<=== all port out :\n");
			HW_LOG("in_pps: %llu in_bps: %llu out_drop: %llu\n",
				total[i].sub[1].in_pps,total[i].sub[1].in_bps*8,total[i].sub[1].bad_ipv4_pkts);
			HW_LOG("tcp: %llu pps, %llu bps, %llu ack, %llu syn, %llu syn_ack, %llu rst, %llu fin, %llu flow\n"
				,total[i].sub[1].tcp.pps,total[i].sub[1].tcp.bps*8,total[i].sub[1].tcp.ack,total[i].sub[1].tcp.syn,
				total[i].sub[1].tcp.syn_ack,total[i].sub[1].tcp.rst,total[i].sub[1].tcp.fin,total[i].sub[1].tcp.flow);
			HW_LOG("udp: %llu pps, %llu bps, %llu flow :icmp: %llu pps, %llu bps, %llu echo, %llu redir, %llu unreach\n"
				,total[i].sub[1].udp.pps,total[i].sub[1].udp.bps*8,total[i].sub[1].udp.flow,total[i].sub[1].icmp.pps,
				total[i].sub[1].icmp.bps*8,total[i].sub[1].icmp.echo,total[i].sub[1].icmp.redir,total[i].sub[1].icmp.unreach);
			HW_LOG("igmp: %llu pps, %llu bps, %llu v1, %llu v2, %llu v3\n"
				,total[i].sub[1].igmp.pps,total[i].sub[1].igmp.bps*8,total[i].sub[1].igmp.v1,
				total[i].sub[1].igmp.v2,total[i].sub[1].igmp.v3);
			HW_LOG("attack: %llu dns: %llu frag: %llu fraggle: %llu frag_err: %llu land: %llu ntp: %llu nuker\n"
				,
				total[i].sub[1].attack.dns,
				total[i].sub[1].attack.frag,
				total[i].sub[1].attack.fraggle,
				total[i].sub[1].attack.frag_err,
				total[i].sub[1].attack.land,
				total[i].sub[1].attack.ntp,
				total[i].sub[1].attack.nuker);
			HW_LOG("attack: %llu smurf: %llu snmp: %llu ssdp: %llu tcp_flag_err: %llu tracert\n"
				,total[i].sub[1].attack.smurf,
				total[i].sub[1].attack.snmp,
				total[i].sub[1].attack.ssdp,
				total[i].sub[1].attack.tcp_flag_err,
				total[i].sub[1].attack.tracert);
		}

}


static inline void __attribute__((always_inline))
dump_port_sum(struct port_info_sum *total)
{
	int i;

	for(i=0;i<MAX_DEV;i++)
		{
			// port in
			HW_LOG("===> port in %d :\n",i);
			HW_LOG("in_pps: %llu in_bps: %llu bad_ipv4_pkts: %llu\n",
				total[i].sub[0].in_pps,total[i].sub[0].in_bps*8,total[i].sub[0].bad_ipv4_pkts);
			HW_LOG("tcp: %llu pps, %llu bps, %llu ack, %llu syn, %llu syn_ack, %llu rst, %llu fin, %llu flow\n"
				,total[i].sub[0].tcp.pps,total[i].sub[0].tcp.bps*8,total[i].sub[0].tcp.ack,total[i].sub[0].tcp.syn,
				total[i].sub[0].tcp.syn_ack,total[i].sub[0].tcp.rst,total[i].sub[0].tcp.fin,total[i].sub[0].tcp.flow);
			HW_LOG("udp: %llu pps, %llu bps, %llu flow :icmp: %llu pps, %llu bps, %llu echo, %llu redir, %llu unreach\n"
				,total[i].sub[0].udp.pps,total[i].sub[0].udp.bps*8,total[i].sub[0].udp.flow,total[i].sub[0].icmp.pps,
				total[i].sub[0].icmp.bps*8,total[i].sub[0].icmp.echo,total[i].sub[0].icmp.redir,total[i].sub[0].icmp.unreach);
			HW_LOG("igmp: %llu pps, %llu bps, %llu v1, %llu v2, %llu v3\n"
				,total[i].sub[0].igmp.pps,total[i].sub[0].igmp.bps*8,total[i].sub[0].igmp.v1,
				total[i].sub[0].igmp.v2,total[i].sub[0].igmp.v3);
			HW_LOG("attack: %llu dns: %llu frag: %llu fraggle: %llu frag_err: %llu land: %llu ntp: %llu nuker\n"
				,
				total[i].sub[0].attack.dns,
				total[i].sub[0].attack.frag,
				total[i].sub[0].attack.fraggle,
				total[i].sub[0].attack.frag_err,
				total[i].sub[0].attack.land,
				total[i].sub[0].attack.ntp,
				total[i].sub[0].attack.nuker);
			HW_LOG("attack: %llu smurf: %llu snmp: %llu ssdp: %llu tcp_flag_err: %llu tracert\n"
				,total[i].sub[0].attack.smurf,
				total[i].sub[0].attack.snmp,
				total[i].sub[0].attack.ssdp,
				total[i].sub[0].attack.tcp_flag_err,
				total[i].sub[0].attack.tracert);

			//port out
			HW_LOG("<=== port out %d :\n",i);
			HW_LOG("in_pps: %llu in_bps: %llu out_drop: %llu\n",
				total[i].sub[1].in_pps,total[i].sub[1].in_bps*8,total[i].sub[1].bad_ipv4_pkts);
			HW_LOG("tcp: %llu pps, %llu bps, %llu ack, %llu syn, %llu syn_ack, %llu rst, %llu fin, %llu flow\n"
				,total[i].sub[1].tcp.pps,total[i].sub[1].tcp.bps*8,total[i].sub[1].tcp.ack,total[i].sub[1].tcp.syn,
				total[i].sub[1].tcp.syn_ack,total[i].sub[1].tcp.rst,total[i].sub[1].tcp.fin,total[i].sub[1].tcp.flow);
			HW_LOG("udp: %llu pps, %llu bps, %llu flow :icmp: %llu pps, %llu bps, %llu echo, %llu redir, %llu unreach\n"
				,total[i].sub[1].udp.pps,total[i].sub[1].udp.bps*8,total[i].sub[1].udp.flow,total[i].sub[1].icmp.pps,
				total[i].sub[1].icmp.bps*8,total[i].sub[1].icmp.echo,total[i].sub[1].icmp.redir,total[i].sub[1].icmp.unreach);
			HW_LOG("igmp: %llu pps, %llu bps, %llu v1, %llu v2, %llu v3\n"
				,total[i].sub[1].igmp.pps,total[i].sub[1].igmp.bps*8,total[i].sub[1].igmp.v1,
				total[i].sub[1].igmp.v2,total[i].sub[1].igmp.v3);
			HW_LOG("attack: %llu dns: %llu frag: %llu fraggle: %llu frag_err: %llu land: %llu ntp: %llu nuker\n"
				,
				total[i].sub[1].attack.dns,
				total[i].sub[1].attack.frag,
				total[i].sub[1].attack.fraggle,
				total[i].sub[1].attack.frag_err,
				total[i].sub[1].attack.land,
				total[i].sub[1].attack.ntp,
				total[i].sub[1].attack.nuker);
			HW_LOG("attack: %llu smurf: %llu snmp: %llu ssdp: %llu tcp_flag_err: %llu tracert\n"
				,total[i].sub[1].attack.smurf,
				total[i].sub[1].attack.snmp,
				total[i].sub[1].attack.ssdp,
				total[i].sub[1].attack.tcp_flag_err,
				total[i].sub[1].attack.tracert);
		}
}

static inline void __attribute__((always_inline))
do_port_sum_dir(struct port_info_sum *total,struct port_info_sum *per,int dir)
{
	total->sub[dir].in_pps+=per->sub[dir].in_pps;
	total->sub[dir].in_bps+=per->sub[dir].in_bps;
	total->sub[dir].bad_ipv4_pkts+=per->sub[dir].bad_ipv4_pkts;

	total->sub[dir].ip.pps+=per->sub[dir].ip.pps;
	total->sub[dir].ip.bps+=per->sub[dir].ip.bps;
	total->sub[dir].ip.ip_option+=per->sub[dir].ip.ip_option;

	total->sub[dir].tcp.pps+=per->sub[dir].tcp.pps;
	total->sub[dir].tcp.bps+=per->sub[dir].tcp.bps;
	total->sub[dir].tcp.syn+=per->sub[dir].tcp.syn;
	total->sub[dir].tcp.syn_ack+=per->sub[dir].tcp.syn_ack;
	total->sub[dir].tcp.ack+=per->sub[dir].tcp.ack;
	total->sub[dir].tcp.fin+=per->sub[dir].tcp.fin;
	total->sub[dir].tcp.flow+=per->sub[dir].tcp.flow;
	total->sub[dir].tcp.rst+=per->sub[dir].tcp.rst;

	total->sub[dir].udp.pps+=per->sub[dir].udp.pps;
	total->sub[dir].udp.bps+=per->sub[dir].udp.bps;
	total->sub[dir].udp.flow+=per->sub[dir].udp.flow;

	total->sub[dir].icmp.pps+=per->sub[dir].icmp.pps;
	total->sub[dir].icmp.bps+=per->sub[dir].icmp.bps;
	total->sub[dir].icmp.echo+=per->sub[dir].icmp.echo;
	total->sub[dir].icmp.redir+=per->sub[dir].icmp.redir;
	total->sub[dir].icmp.unreach+=per->sub[dir].icmp.unreach;

	total->sub[dir].igmp.pps+=per->sub[dir].igmp.pps;
	total->sub[dir].igmp.bps+=per->sub[dir].igmp.bps;
	total->sub[dir].igmp.v1+=per->sub[dir].igmp.v1;
	total->sub[dir].igmp.v2+=per->sub[dir].igmp.v2;
	total->sub[dir].igmp.v3+=per->sub[dir].igmp.v3;

	total->sub[dir].attack.dns+=per->sub[dir].attack.dns;
	total->sub[dir].attack.frag+=per->sub[dir].attack.frag;
	total->sub[dir].attack.fraggle+=per->sub[dir].attack.fraggle;
	total->sub[dir].attack.frag_err+=per->sub[dir].attack.frag_err;
	total->sub[dir].attack.land+=per->sub[dir].attack.land;
	total->sub[dir].attack.ntp+=per->sub[dir].attack.ntp;
	total->sub[dir].attack.nuker+=per->sub[dir].attack.nuker;
	total->sub[dir].attack.smurf+=per->sub[dir].attack.smurf;
	total->sub[dir].attack.snmp+=per->sub[dir].attack.snmp;
	total->sub[dir].attack.ssdp+=per->sub[dir].attack.ssdp;
	total->sub[dir].attack.tcp_flag_err+=per->sub[dir].attack.tcp_flag_err;
	total->sub[dir].attack.tracert+=per->sub[dir].attack.tracert;
}


static inline void __attribute__((always_inline))
process_port_sum(struct port_info_sum *total,int s)
{
	uint64_t io_mask=me.io_in_mask;
	int i,j,idx,k;
	struct port_info_sum *port;

	if(s)
		k=MAX_DEV;
	else
		k=0;

	do{
		i=__builtin_ffsll(io_mask)-1;
		if(lcore[i].timer_flag==0)
			{
			for(j=0;j<lcore[i].port_cnt;j++)
				{
				idx=lcore[i].port_id[j];
				do_port_sum_dir(&total[idx],&lcore[i].io_in.port_sub[idx+k],0);
				}
			io_mask &= ~(1ULL<<i);
			}
	}while(io_mask);
}

static inline void __attribute__((always_inline))
process_wdl4_sum(struct wd_pack *w1,int wd1_cnt,
	struct wd_pack *w2,int wd2_cnt,
	int sum_cnt,struct l4_port_g_b **sum_map,struct l4_port_g_b *netport_tbl)
{
	int i,j,k;
	struct l4_port_g_b *p;
	struct l4_port_sum_b *lp,*lp_tmp;

	for(i=0;i<65536;i++)
		{
		INIT_LIST_HEAD(&netport_tbl[i].chain.header);
		netport_tbl[i].no=i;
		for(j=0;j<sum_cnt;j++)
			{
			p=sum_map[j];
			if(p[i].chain.load)
				{
//				RUNNING_LOG_DEBUG("%s:%d found chain %d load=%d\n",__FUNCTION__,
//					__LINE__,i,p[i].chain.load);

				netport_tbl[i].info.all[0]+=p[i].info.all[0];
				netport_tbl[i].info.all[1]+=p[i].info.all[1];
				netport_tbl[i].info.tcp[0]+=p[i].info.tcp[0];
				netport_tbl[i].info.tcp[1]+=p[i].info.tcp[1];
				netport_tbl[i].info.udp[0]+=p[i].info.udp[0];
				netport_tbl[i].info.udp[1]+=p[i].info.udp[1];
				list_splice_tail_init(&p[i].chain.header,&netport_tbl[i].chain.header);
				netport_tbl[i].chain.load+=p[i].chain.load;
#if 0//test
{
				int x=0;
				struct l4_port_sum_b *ipm,*iptmp;

				RUNNING_LOG_DEBUG("%s: core<%d> port=%d,load=%d gload=%d\n",__FUNCTION__,
					rte_lcore_id(),rte_be_to_cpu_16(i),p[i].chain.load,netport_tbl[i].chain.load);

				list_for_each_entry_safe(ipm, iptmp, &netport_tbl[i].chain.header, alloc_list)
					{
					x++;
					RUNNING_LOG_DEBUG("%s: core<%d> get back test port=%d ip=%x dst=%d src=%d\n",__FUNCTION__,
						rte_lcore_id(),rte_be_to_cpu_16(i),ipm->l3p->addr,ipm->info.all[0],ipm->info.all[1]);
					}
}
#endif

				}
			}

		//wd
		for(j=0;j<wd1_cnt;j++)
			{
			w1[j].ops->process(&netport_tbl[i],&w1[j],0);
			}
		}

	for(i=0;i<wd1_cnt;i++)
		{
		for(j=0;j<w1[i].top[0].curr;j++)
			{
			p=(struct l4_port_g_b *)w1[i].top[0].arr[j];
//				RUNNING_LOG_DEBUG("%s(%d): core<%d> l4 aaaaaaaaaaaaprocess\n",__FUNCTION__,__LINE__,
//					rte_lcore_id());

			list_for_each_entry_safe(lp, lp_tmp, &p->chain.header, list_tbl)
				{
				for(k=0;k<wd2_cnt;k++)
					w2[k].ops->process(lp,&w2[k],0);

//				RUNNING_LOG_DEBUG("%s(%d): core<%d> l4 process port=%d ip=%x\n",__FUNCTION__,__LINE__,
//					rte_lcore_id(),lp->no,lp->l3p->addr);

				}

			//format & output
			for(k=0;k<wd2_cnt;k++)
				{
				w2[k].ops->soft(&w2[k],0);
				w2[k].ops->dump(&w2[k],0);//debug
				w2[k].top[0].curr=0;
				}
			}
		}

	RUNNING_LOG_INFO("%s(%d): >>>>>>>>>>>>>>>>>>>>. begin show mon port %d\n",
		__FUNCTION__,__LINE__,mon_netport_core.curr);

	for(i=0;i<mon_netport_core.curr;i++)
		{
		j=mon_netport_core.arr[i];

		if(!list_empty(&netport_tbl[j].chain.header))
			{
			list_for_each_entry_safe(lp, lp_tmp, &netport_tbl[j].chain.header, list_tbl)
				{
				for(k=0;k<wd2_cnt;k++)
					w2[k].ops->process(lp,&w2[k],0);

//				RUNNING_LOG_DEBUG("%s(%d): core<%d> l4 process port=%d ip=%x\n",__FUNCTION__,__LINE__,
//					rte_lcore_id(),lp->no,lp->l3p->addr);

				}

			//format & output
			for(k=0;k<wd2_cnt;k++)
				{
				w2[k].ops->soft(&w2[k],0);
				w2[k].ops->dump(&w2[k],0);//debug
				w2[k].top[0].curr=0;
				}
			}
		}

	RUNNING_LOG_INFO("%s(%d): <<<<<<<<<<<<<<<,, finished show mon port\n",__FUNCTION__,__LINE__);


	//format & output
	for(i=0;i<wd1_cnt;i++)
		{
		w1[i].ops->soft(&w1[i],0);
		w1[i].ops->dump(&w1[i],0);//debug
		w1[i].top[0].curr=0;
		}
}

static inline void __attribute__((always_inline))
process_wddn1_sum(struct wd_pack *w1,int wd1_cnt,
	int sum_cnt,struct dn1_pending **sum_map,struct dn1_pending *dn1_hash,
	struct hash_array *pool,struct hash_array *alloced,uint32_t *miss_alloced,
	struct wd_pack *w2,int wd2_cnt)
{
	int i,j,k;
	struct dn1_pending *p;
	struct dn1_sum_b *lp,*lp_tmp,*lp2,*lp2_tmp;
	struct dn1_ti_b *tp,*ttmp;
	int match=0;

	for(j=0;j<sum_cnt;j++)
		{
		p=sum_map[j];

		for(i=0;i<p->pending_cnt;i++)
			{
			k=p->hash_idx[i];
			RUNNING_LOG_DEBUG("core %d(%s:%d) : get j=%d i=%d k=%x pending_cnt=%d\n",
				rte_lcore_id(),__FUNCTION__,__LINE__,j,i,k,p->pending_cnt);

loop0:
			if(dn1_hash->pending[k].load)
				{
					list_for_each_entry_safe(lp, lp_tmp, &p->pending[k].header, list_tbl)
						{
						RUNNING_LOG_DEBUG("core %d(%s:%d) : search lp name=%s len=%d\n",
							rte_lcore_id(),__FUNCTION__,__LINE__,lp->name,lp->len);

						match=0;
						list_for_each_entry_safe(tp, ttmp, &dn1_hash->pending[k].header, list_hash)
							{
							RUNNING_LOG_DEBUG("core %d(%s:%d) : search olp dn1 name=%s len=%d\n",
								rte_lcore_id(),__FUNCTION__,__LINE__,tp->name,tp->len);

							if((lp->len==tp->len)&&
								(!memcmp(lp->name,tp->name,lp->len)))//found it
								{
								list_move_tail(&lp->list_tbl,&tp->chain.header);
								tp->chain.load++;
								tp->cnt+=lp->cnt;
								match=1;

								RUNNING_LOG_DEBUG("core %d(%s:%d) : found match dn1 name=%s len=%d %d %d chainload=%d ip=%x\n",
									rte_lcore_id(),__FUNCTION__,__LINE__,tp->name,tp->len,tp->cnt,lp->cnt,tp->chain.load
									,lp->l3p->addr);
								break;
								}
							}

						if(!match)
							{
							if(pool->load)
								{
								tp=list_first_entry(&pool->header,struct dn1_ti_b,alloc_list);
								INIT_LIST_HEAD(&tp->chain.header);
								list_move_tail(&tp->alloc_list,&alloced->header);
								pool->load--;
								alloced->load++;

								tp->cnt=lp->cnt;
								tp->name=lp->name;
								tp->len=lp->len;
								list_move_tail(&lp->list_tbl,&tp->chain.header);
								tp->chain.load=1;

								list_add_tail(&tp->list_hash,&dn1_hash->pending[k].header);
								dn1_hash->pending[k].load++;
								}
							else
								{
								*miss_alloced++;
								}

							RUNNING_LOG_DEBUG("core %d(%s:%d) : add dn1 name=%s len=%d %d aloc=%d pool=%d ip=%x\n",
								rte_lcore_id(),__FUNCTION__,__LINE__,tp->name,tp->len,tp->cnt,
								alloced->load,pool->load,lp->l3p->addr);
							}
						}
				}
			else
				{
				if(pool->load)
					{
					lp=list_first_entry(&p->pending[k].header,struct dn1_sum_b,list_tbl);

					tp=list_first_entry(&pool->header,struct dn1_ti_b,alloc_list);
					INIT_LIST_HEAD(&tp->chain.header);
					list_move_tail(&tp->alloc_list,&alloced->header);
					pool->load--;
					alloced->load++;

					tp->cnt=lp->cnt;
					tp->name=lp->name;
					tp->len=lp->len;
					list_move_tail(&lp->list_tbl,&tp->chain.header);
					tp->chain.load=1;

					list_add_tail(&tp->list_hash,&dn1_hash->pending[k].header);
					dn1_hash->pending[k].load++;

					dn1_hash->hash_idx[dn1_hash->pending_cnt++]=k;

					RUNNING_LOG_DEBUG("core %d(%s:%d) : i=%d j=%d k=%x new dn1 name=%s len=%d %d aloc=%d pool=%d\n",
						rte_lcore_id(),__FUNCTION__,__LINE__,i,j,k,tp->name,tp->len,tp->cnt,
						alloced->load,pool->load);

					goto loop0;
					}
				else
					{
					*miss_alloced++;
					}
				}
			}
		}

	for(i=0;i<dn1_hash->pending_cnt;i++)
		{
			RUNNING_LOG_DEBUG("core %d(%s:%d) : wd process i=%d pending_cnt=%d hash_idx=%x\n",
				rte_lcore_id(),__FUNCTION__,__LINE__,i,dn1_hash->pending_cnt,dn1_hash->hash_idx[i]);

			list_for_each_entry_safe(tp, ttmp, &dn1_hash->pending[dn1_hash->hash_idx[i]].header, list_hash)
				{
			RUNNING_LOG_DEBUG("core %d(%s:%d) : wd process %p pending_cnt=%d hash_idx=%x name=%s cnt=%d\n",
				rte_lcore_id(),__FUNCTION__,__LINE__,tp,dn1_hash->pending_cnt,dn1_hash->hash_idx[i],
				tp->name,tp->cnt);

				for(j=0;j<wd1_cnt;j++)
					{
					w1[j].ops->process(tp,&w1[j],0);
					}

#if 0//test
{
				int x=0;
				int fb;
				struct dn1_ti_b *tq,*ttq;
				struct dn1_sum_b *ipm,*iptmp;

				list_for_each_entry_safe(tq, ttq, &dn1_hash->pending[dn1_hash->hash_idx[i]].header, list_hash)
					{
					x++;
				RUNNING_LOG_INFO("core %d(%s:%d) : creaete %p dn1 hash_idx=%x load=%d pending_cnt=%d name=%s len=%d cnt=%d\n",
					rte_lcore_id(),__FUNCTION__,__LINE__,tq,dn1_hash->hash_idx[i],dn1_hash->pending[dn1_hash->hash_idx[i]].load,dn1_hash->pending_cnt,
					tq->name,tq->len,tq->cnt);


					list_for_each_entry_safe(ipm, iptmp, &tq->chain.header, list_tbl)
						{
						RUNNING_LOG_INFO("core %d(%s:%d) : splt ip=%x  name=%s len=%d cnt=%d\n",
							rte_lcore_id(),__FUNCTION__,__LINE__,ipm->l3p->addr,ipm->name,ipm->len,ipm->cnt);
						}
					}

				for(fb=0;fb<dn1_hash->pending_cnt;fb++)
				{
				RUNNING_LOG_INFO("core %d(%s:%d) : creaete show i=%d hash_idx=%x\n",
					rte_lcore_id(),__FUNCTION__,__LINE__,fb,dn1_hash->hash_idx[fb]);
				}
}
#endif

				}
//			INIT_LIST_HEAD(&dn1_hash->pending[dn1_hash->hash_idx[i]].header);
		}
//	dn1_hash->pending_cnt=0;

	struct dn1_ti_b *pp;

	for(i=0;i<wd1_cnt;i++)
		{
		for(j=0;j<w1[i].top[0].curr;j++)
			{
			pp=(struct dn1_ti_b *)w1[i].top[0].arr[j];
//				RUNNING_LOG_DEBUG("%s(%d): core<%d> l4 aaaaaaaaaaaaprocess\n",__FUNCTION__,__LINE__,
//					rte_lcore_id());

			list_for_each_entry_safe(lp, lp_tmp, &pp->chain.header, list_tbl)
				{
				for(k=0;k<wd2_cnt;k++)
					w2[k].ops->process(lp,&w2[k],0);

//				RUNNING_LOG_DEBUG("%s(%d): core<%d> l4 process port=%d ip=%x\n",__FUNCTION__,__LINE__,
//					rte_lcore_id(),lp->no,lp->l3p->addr);

				}

			//format & output
			for(k=0;k<wd2_cnt;k++)
				{
				w2[k].ops->soft(&w2[k],0);
				w2[k].ops->dump(&w2[k],0);//debug
				w2[k].top[0].curr=0;
				}
			}
		}

	//format & output
	for(i=0;i<wd1_cnt;i++)
		{
		w1[i].ops->soft(&w1[i],0);
		w1[i].ops->dump(&w1[i],0);//debug
		w1[i].top[0].curr=0;
		}
}

#if 0
static inline void __attribute__((always_inline))
process_wddn1_sum2(struct wd_pack *w1,int wd1_cnt,
	int sum_cnt,struct dn1_pending **sum_map,struct dn1_pending *dn1_hash)
{
	int i,j,k;
	struct dn1_pending *p;
	struct dn1_sum_b *lp,*lp_tmp,*olp,*olp_tmp;
	int match=0;

//	rte_memcpy(dn1_hash,sum_map[0],sizeof(struct hash_array)*DN1_HASH_ARRAY_SZ);
	for(j=0;j<sum_cnt;j++)
		{
		p=sum_map[j];

		for(i=0;i<p->pending_cnt;i++)
			{
			k=p->hash_idx[i];
			RUNNING_LOG_INFO("core %d(%s:%d) : get j=%d i=%d k=%x pending_cnt=%d\n",
				rte_lcore_id(),__FUNCTION__,__LINE__,j,i,k,p->pending_cnt);

			if(dn1_hash->pending[k].load)
				{
					list_for_each_entry_safe(lp, lp_tmp, &p->pending[k].header, list_tbl)
						{
						RUNNING_LOG_INFO("core %d(%s:%d) : search lp name=%s len=%d\n",
							rte_lcore_id(),__FUNCTION__,__LINE__,lp->name,lp->len);

						match=0;
						list_for_each_entry_safe(olp, olp_tmp, &dn1_hash->pending[k].header, list_tbl)
							{
							RUNNING_LOG_INFO("core %d(%s:%d) : search olp dn1 name=%s len=%d\n",
								rte_lcore_id(),__FUNCTION__,__LINE__,olp->name,olp->len);

							if((lp->len==olp->len)&&
								(!memcmp(lp->name,olp->name,lp->len)))//found it
								{
								list_del_init(&lp->list_tbl);
								olp->cnt+=lp->cnt;
								match=1;
								RUNNING_LOG_INFO("core %d(%s:%d) : found match dn1 name=%s len=%d %d %d\n",
									rte_lcore_id(),__FUNCTION__,__LINE__,olp->name,olp->len,olp->cnt,lp->cnt);
								break;
								}
							}

						if(!match)
							{
							list_move_tail(&lp->list_tbl,&dn1_hash->pending[k].header);
							dn1_hash->pending[k].load++;
							RUNNING_LOG_INFO("core %d(%s:%d) : add dn1 name=%s len=%d %d\n",
								rte_lcore_id(),__FUNCTION__,__LINE__,lp->name,lp->len,lp->cnt);
							}
						}
				}
			else
				{
				list_splice_tail_init(&p->pending[k].header,&dn1_hash->pending[k].header);
				dn1_hash->pending[k].load=p->pending[k].load;
				dn1_hash->hash_idx[dn1_hash->pending_cnt++]=k;

#if 0//test
{
				int x=0;
				int fb;
				struct dn1_sum_b *ipm,*iptmp;

				list_for_each_entry_safe(ipm, iptmp, &dn1_hash->pending[k].header, list_tbl)
					{
					x++;
				RUNNING_LOG_DEBUG("core %d(%s:%d) : creaete %p dn1 hash_idx=%x load=%d pending_cnt=%d name=%s len=%d cnt=%d\n",
					rte_lcore_id(),__FUNCTION__,__LINE__,ipm,k,dn1_hash->pending[k].load,dn1_hash->pending_cnt,
					ipm->name,ipm->len,ipm->cnt);

					}

				for(fb=0;fb<dn1_hash->pending_cnt;fb++)
				{
				RUNNING_LOG_DEBUG("core %d(%s:%d) : creaete show i=%d hash_idx=%x\n",
					rte_lcore_id(),__FUNCTION__,__LINE__,i,dn1_hash->hash_idx[i]);
				}
}
#endif

				}
			}
		}

	for(i=0;i<dn1_hash->pending_cnt;i++)
		{
			RUNNING_LOG_INFO("core %d(%s:%d) : wd process i=%d pending_cnt=%d hash_idx=%x\n",
				rte_lcore_id(),__FUNCTION__,__LINE__,i,dn1_hash->pending_cnt,dn1_hash->hash_idx[i]);

			list_for_each_entry_safe(lp, lp_tmp, &dn1_hash->pending[dn1_hash->hash_idx[i]].header, list_tbl)
				{
			RUNNING_LOG_INFO("core %d(%s:%d) : wd process %p pending_cnt=%d hash_idx=%x name=%s cnt=%d\n",
				rte_lcore_id(),__FUNCTION__,__LINE__,lp,dn1_hash->pending_cnt,dn1_hash->hash_idx[i],
				lp->name,lp->cnt);

				for(j=0;j<wd1_cnt;j++)
					{
					w1[j].ops->process(lp,&w1[j],0);
					}
				}
//			INIT_LIST_HEAD(&dn1_hash->pending[dn1_hash->hash_idx[i]].header);
		}
//	dn1_hash->pending_cnt=0;


	//format & output
	for(i=0;i<wd1_cnt;i++)
		{
		w1[i].ops->soft(&w1[i],0);
		w1[i].ops->dump(&w1[i],0);//debug
		w1[i].top[0].curr=0;
		}
}
#endif

static inline void __attribute__((always_inline))
dump_ip_sum(struct ip_sum_b *ips)
{
	RUNNING_LOG_INFO("kkkkkkkkkkkkkkkkkkkkkkkkkkk ip %x dump :\n",ips->addr);
}

static inline void __attribute__((always_inline))
process_mon_ip(uint64_t sum_mask)
{
	int i,j,k;
	struct ip_sum_b *p;
	uint64_t mask=sum_mask;
	struct lcore_info_s *core;

	do{
		i=__builtin_ffsll(mask)-1;
		mask &= ~(1ULL<<i);
		core=&lcore[i];

		for(j=0;j<core->sum.mon_ip_burst_cnt;j++)
		{
			dump_ip_sum(core->sum.mon_ip_burst[j]);
		}

	}while(mask);
}

static inline void __attribute__((always_inline))
process_wd_sum(struct wd_pack *w,int wd_cnt,
	uint64_t sum_mask)
{
	int i,j,k;
	struct ip_sum_b *p;
	uint64_t mask=sum_mask;

	do{
		j=__builtin_ffsll(mask)-1;

		if(lcore[j].sum.wd_switch)
			{
			for(i=0;i<wd_cnt;i++)
				{
//				if(lcore[j].sum.wd[i].top[1].curr)
//				{
//					RUNNING_LOG_INFO("%s(%d): aaaaaaaaaaaaaaaaaaaaaaa\n",
//						__FUNCTION__,__LINE__,i);
//
//				}

				for(k=0;k<lcore[j].sum.wd[i].top[1].curr;k++)
					{
					p=(struct ip_sum_b *)lcore[j].sum.wd[i].top[1].arr[k];
					p->flag=0;

					RUNNING_LOG_DEBUG("%s(%d): sumcore=%d i=%d curr=%d ip=%x pps=%d\n",
						__FUNCTION__,__LINE__,j,i,lcore[j].sum.wd[i].top[1].curr,p->addr,p->ip_sum[0].ip.pps);

//					if(list_empty(&p->alloc_list))
//						{
//						list_add_tail(&p->alloc_list,&cache[h].header);
//						cache[h].load++;
//						RUNNING_LOG_DEBUG("%s(%d): core<%d> set scan sum<%d> flag,i=%d,ip=%x,cache[%d].load=%d curr=%d\n",
//							__FUNCTION__,__LINE__,rte_lcore_id(),j,i,p->addr,h,cache[h].load,lcore[j].sum.wd[i].top[1].curr);
//						}
//					else
//						{
//						RUNNING_LOG_DEBUG("%s(%d): core<%d> scan flag had set,sum<%d> i=%d,ip=%x,cache[%d].load=%d curr=%d\n",
//							__FUNCTION__,__LINE__,rte_lcore_id(),j,i,p->addr,h,cache[h].load,lcore[j].sum.wd[i].top[1].curr);
//						}

					w[i].ops->process((void *)p,&w[i],0);
					}
				lcore[j].sum.wd[i].top[1].curr=0;
				}
			mask &= ~(1ULL<<j);
			lcore[j].sum.wd_switch=0;
			}

	}while(mask);

	rte_smp_wmb();

	for(i=0;i<wd_cnt;i++)
		{
		if(w[i].top[0].curr)
			{
			w[i].ops->soft(&w[i],0);
			w[i].ops->dump(&w[i],0);//debug
			w[i].top[0].curr=0;
			}
		}
}


int main_loop_timer(void)
{
	uint64_t cur_tsc, prev_tsc,diff_tsc, hz,start,end,count=0;
	int i,j,k;
	int my_lcore;
	struct lcore_info_s *local;
	uint32_t *ti[MAX_CPU]={NULL};
	uint32_t *ti2[MAX_CPU]={NULL};
	uint32_t ti_cnt;
	struct port_info_sum port_sum[MAX_DEV];
	static struct l4_port_g_b *sum_netport_tbl_map[MAX_CPU];
	static struct dn1_pending *sum_dn1_hash_map[MAX_CPU];
	static struct dn1_pending *sum_dn1_hash_map_http[MAX_CPU];
	int s=0;
	int sum_cnt;
	uint64_t tmp_mask;
	struct l4_port_g_b *local_netport_tbl;
	struct dn1_pending *local_dn1_hash;
	struct dn1_pending *local_dn1_hash_http;
	struct hash_array *local_dn1_pool;
	struct hash_array local_dn1_alloced;
	struct wd_pack wd2[WDL4_MAX];
	int wd2_cnt=0;
	struct wd_pack wddn1[WDDN1_MAX_IP];
	int wddn1ip_cnt=0;
	struct wd_pack wddn1_http[WDDN1_MAX_IP];
	int wddn1ip_cnt_http=0;

	my_lcore=rte_lcore_id();
	local=&lcore[my_lcore];
	sum_cnt=__builtin_popcountll(me.sum_mask);
	rte_memcpy(ti,local->timer.timer_triger,sizeof(uint32_t *)*local->timer.timer_cnt);
	rte_memcpy(ti2,local->timer.timer_idle,sizeof(uint32_t *)*local->timer.timer_cnt);
	ti_cnt=local->timer.timer_cnt;
	hz = rte_get_timer_hz();
	local_netport_tbl=local->timer.netport_tbl;
	local_dn1_hash=local->timer.dn1_hash;
	local_dn1_hash_http=local->timer.dn1_hash_http;
	local_dn1_pool=&local->timer.dn1_timer_pool;

	tmp_mask=me.sum_mask;
	j=0;
	do{
		i=__builtin_ffsll(tmp_mask)-1;
		tmp_mask &= ~(1ULL<<i);

		sum_netport_tbl_map[j]=lcore[i].sum.netport_tbl[1];
		sum_dn1_hash_map[j]=lcore[i].sum.sum_dn1_hash[1];
		sum_dn1_hash_map_http[j]=lcore[i].sum.sum_dn1_hash_http[1];
		j++;
	}while(tmp_mask);
	tmp_mask=me.sum_mask;

	INIT_LIST_HEAD(&local_dn1_alloced.header);
	local_dn1_alloced.load=0;

	wd_register(wd2,wd2_cnt,WDL4_ALL_DST,&l4_all_dst_ops2);
	wd2_cnt++;
	wd_register(wd2,wd2_cnt,WDL4_ALL_SRC,&l4_all_src_ops2);
	wd2_cnt++;
	wd_register(wd2,wd2_cnt,WDL4_TCP_DST,&l4_tcp_dst_ops2);
	wd2_cnt++;
	wd_register(wd2,wd2_cnt,WDL4_TCP_SRC,&l4_tcp_src_ops2);
	wd2_cnt++;
	wd_register(wd2,wd2_cnt,WDL4_UDP_DST,&l4_udp_dst_ops2);
	wd2_cnt++;
	wd_register(wd2,wd2_cnt,WDL4_UDP_SRC,&l4_udp_src_ops2);
	wd2_cnt++;

#ifdef DN1_ON

	wd_register(wddn1,wddn1ip_cnt,WDDN1_MAX_IP,&name_1_srcip_ops);
	wddn1ip_cnt++;

	wd_register(wddn1_http,wddn1ip_cnt_http,WDDN1_MAX_IP,&name_1_srcip_ops);
	wddn1ip_cnt_http++;

#endif
//	wait_init_finished();

	RUNNING_LOG_INFO("core %d :timer ti_cnt=%d\n",my_lcore,ti_cnt);
	prev_tsc = rte_rdtsc();

	while(1)
		{
		cur_tsc = rte_rdtsc();

		diff_tsc=cur_tsc-prev_tsc;
		if(diff_tsc>=TIMER_UNIT*hz)
			{
			start=rte_rdtsc();
			count++;

			for(i=0;i<ti_cnt;i++)
				*ti[i]=1;
			rte_smp_wmb();

			prev_tsc=cur_tsc;

			memset(port_sum,0,sizeof(port_sum[0])*MAX_DEV);
			memset(local_netport_tbl,0,sizeof(struct l4_port_g_b)*65536);
			process_port_sum(port_sum,s);
			process_wd_sum(local->timer.wd,local->timer.wd_valid_cnt,tmp_mask);
			process_wdl4_sum(local->timer.wdl4_g,local->timer.wdl4_g_valid_cnt,wd2,wd2_cnt,
				sum_cnt,sum_netport_tbl_map,local_netport_tbl);

#ifdef DN1_ON

			process_wddn1_sum(local->timer.wddn1_g,local->timer.wddn1_g_valid_cnt,
				sum_cnt,sum_dn1_hash_map,local_dn1_hash,local_dn1_pool,&local_dn1_alloced,
				&local->timer.miss_alloced_dn1,wddn1,wddn1ip_cnt);

			RUNNING_LOG_INFO("split dn1 http >>>>>>>>>>>>>>>>\n");

			process_wddn1_sum(local->timer.wddn1_g_http,local->timer.wddn1_g_valid_cnt_http,
				sum_cnt,sum_dn1_hash_map_http,local_dn1_hash_http,local_dn1_pool,&local_dn1_alloced,
				&local->timer.miss_alloced_dn1,wddn1_http,wddn1ip_cnt_http);
#endif

			process_mon_ip(tmp_mask);
			rte_smp_wmb();
			s^=1;

			dump_port_sum(port_sum);

			for(i=0;i<ti_cnt;i++)
				*ti2[i]=1;
			rte_smp_wmb();

			end=rte_rdtsc()-start;
			RUNNING_LOG_DEBUG("reaper wwwwwwwwwwwwwwwwaste tick %llu hz=%llu %d s=%d\n",
				end,hz,ti_cnt,s);

			if(local_dn1_alloced.load)
				{
				list_splice_tail_init(&local_dn1_alloced.header,&local_dn1_pool->header);
				local_dn1_pool->load+=local_dn1_alloced.load;
				local_dn1_alloced.load=0;

				RUNNING_LOG_DEBUG("core %d :timer get back dn1 pool.load=%d\n",
					my_lcore,local_dn1_pool->load);
				}

			memset(local_dn1_hash,0,sizeof(struct dn1_pending));
			for(i=0;i<DN1_HASH_ARRAY_SZ;i++)
			{
			INIT_LIST_HEAD(&local_dn1_hash->pending[i].header);
			}

			memset(local_dn1_hash_http,0,sizeof(struct dn1_pending));
			for(i=0;i<DN1_HASH_ARRAY_SZ;i++)
			{
			INIT_LIST_HEAD(&local_dn1_hash_http->pending[i].header);
			}

#if 1//perform test

		if(end>timer_perform_max[my_lcore])
			timer_perform_max[my_lcore]=end;
		if((end<timer_perform_min[my_lcore])||!timer_perform_min[my_lcore])
			timer_perform_min[my_lcore]=end;

		if(timer_perform_aver[my_lcore]==0)
			timer_perform_aver[my_lcore]=end;
		else
			timer_perform_aver[my_lcore]=((count-1)*timer_perform_aver[my_lcore]+end)/count;

//		RUNNING_LOG_INFO("core %d :sum perform min=%llu aver=%llu max=%llu\n",
//			my_lcore,timer_perform_min[my_lcore],timer_perform_aver[my_lcore],timer_perform_max[my_lcore]);

#endif

			}

		if(unlikely(mon_netport_sig))
			{
			rte_memcpy(mon_netport_core.arr,mon_netport_arr.arr,sizeof(uint32_t)*mon_netport_arr.max);
			mon_netport_core.curr=mon_netport_arr.curr;
			mon_netport_core.max=mon_netport_arr.max;
			rte_smp_wmb();
			mon_netport_sig=0;
			rte_smp_wmb();

#if 0//debug
{
			for(i=0;i<mon_netport_core.curr;i++)
			{
				RUNNING_LOG_DEBUG("new mon sz=%d port %d\n",
					mon_netport_core.curr,mon_netport_core.arr[i]);
			}
}
#endif
			}
		}
}


#if 1

static inline int __attribute__((always_inline))
split_check(struct rte_mbuf *m,struct pp_info *packet_info)
{
}

static inline void __attribute__((always_inline))
update_port_sum_out(struct rte_mbuf *m,struct port_info_sum *p)
{
	uint32_t packet_info=m->seqn;

	p->sub[1].in_pps++;
	p->sub[1].in_bps+=m->pkt_len;

	if(packet_info & FLAG(F_IPV4))
		{
		p->sub[1].ip.pps++;
		p->sub[1].ip.bps+=m->pkt_len;

		if(packet_info & FLAG(F_LAND))
			{
			p->sub[1].attack.land++;
			return;
			}

		else if(packet_info & FLAG(F_TRACERT))
			{
			p->sub[1].attack.tracert++;
			return;
			}

		else if(packet_info & FLAG(F_IPOPTION))
			{
			p->sub[1].ip.ip_option++;
			return;
			}

		if(packet_info & FLAG(F_TCP))
			{
			p->sub[1].tcp.pps++;
			p->sub[1].tcp.bps+=m->pkt_len;

			if(packet_info & FLAG(F_TCP_FLAG_ERR))
				{
				p->sub[1].attack.tcp_flag_err++;
				return;
				}

//			if(packet_info & FLAG(F_TCP_OPTION))
//				{
//				}

			else if(packet_info & FLAG(F_TCP_SYN))
				{
				p->sub[1].tcp.syn++;
				return;
				}
			else if(packet_info & FLAG(F_TCP_SYN_ACK))
				{
				p->sub[1].tcp.syn_ack++;
				return;
				}

			else if(packet_info & FLAG(F_TCP_ACK))
				{
				p->sub[1].tcp.ack++;
				}

			else if(packet_info & FLAG(F_TCP_RST))
				{
				p->sub[1].tcp.rst++;
				}

			else if(packet_info & FLAG(F_TCP_FIN))
				{
				p->sub[1].tcp.fin++;
				}

			else if(packet_info & FLAG(F_NUKER))
				{
				p->sub[1].attack.nuker++;
				}
			}
		else if(packet_info & FLAG(F_UDP))
			{
			p->sub[1].udp.pps++;
			p->sub[1].udp.bps+=m->pkt_len;

			if(packet_info & FLAG(F_FRAGGLE))
				{
				p->sub[1].attack.fraggle++;
				}
			else if(packet_info & FLAG(F_SSDP))
				{
				p->sub[1].attack.ssdp++;
				}
			else if(packet_info & FLAG(F_SNMP))
				{
				p->sub[1].attack.snmp++;
				}
			else if(packet_info & FLAG(F_DNS))
				{
				p->sub[1].attack.dns++;
				}
			else if(packet_info & FLAG(F_NTP))
				{
				p->sub[1].attack.ntp++;
				}
			}
		else if(packet_info & FLAG(F_ICMP))
			{
			p->sub[1].icmp.pps++;
			p->sub[1].icmp.bps+=m->pkt_len;

			if(packet_info & FLAG(F_SMURF))
				{
				p->sub[1].attack.smurf++;
				}
			}
		else if(packet_info & FLAG(F_IGMP))
			{
			p->sub[1].igmp.pps++;
			p->sub[1].igmp.bps+=m->pkt_len;
			}
		}
	else
		{
		p->sub[1].notipv4_pps++;
		p->sub[1].notipv4_bps+=m->pkt_len;
		}
}

static inline size_t __attribute__((always_inline))
get_vlan_offset(struct ether_hdr *eth_hdr, uint16_t *proto)
{
	size_t vlan_offset = 0;

	if (rte_cpu_to_be_16(ETHER_TYPE_VLAN) == *proto) {
		struct vlan_hdr *vlan_hdr = (struct vlan_hdr *)(eth_hdr + 1);

		vlan_offset = sizeof(struct vlan_hdr);
		*proto = vlan_hdr->eth_proto;

/*double vlan
		if (rte_cpu_to_be_16(ETHER_TYPE_VLAN) == *proto) {
			vlan_hdr = vlan_hdr + 1;

			*proto = vlan_hdr->eth_proto;
			vlan_offset += sizeof(struct vlan_hdr);
		}
*/
	}
	return vlan_offset;
}

static inline struct ip_g_s2 * __attribute__((always_inline))
pkt_dstip_handler(struct rte_mbuf *m,
	struct pp_info *packet_info,struct hash_array *ip_pool,
		struct hash_array *ip_burst_cache,
		struct hash_array *ip_hash,int sum_cnt,struct priv_io_in *io, int dir, int ip_idx)
{

	uint32_t srcip_idx, srcip, sport;
	int split_dst_idx;
	struct ip_g_s2 *ipm,*iptmp,*ipdst;
	int match=0;

	//look up src ip hash
	if (DIR_OUT == dir){
		srcip=packet_info->srcip;
		sport=packet_info->sport&0xffff;
	} else {
		srcip=packet_info->dstip;
		sport=packet_info->dport&0xffff;
	}

//	RUNNING_LOG_INFO("core %d :%s ip=0x%x,sport=%d dir=%d\n",
//		rte_lcore_id(), __FUNCTION__, srcip,packet_info->sport, dir);

//	srcip_idx=(ipv4_hdr->src_addr>>(32-IP_HASH_ARRAY_OFF))&(IP_HASH_ARRAY_SZ-1);

	srcip_idx=rte_jhash_2words(srcip, sport, PRIME_VALUE);
	srcip_idx&=(IP_HASH_ARRAY_SZ-1);
//	srcip_idx=srcip&(IP_HASH_ARRAY_SZ-1);
	split_dst_idx=srcip&(sum_cnt-1);
	if(!list_empty(&ip_hash[srcip_idx].header))
	{
		list_for_each_entry_safe(ipdst, iptmp, &ip_hash[srcip_idx].header, list)
		{
			if((srcip==ipdst->addr)&&(sport==ipdst->port))//found it
			{
//				RUNNING_LOG_DEBUG("core %d (%d) :src match,found hash match,ip=%x\n",rte_lcore_id(),__LINE__,ipdst->addr);

				update_ip2(ipdst,packet_info->packet_info,dir,m->pkt_len);
				return ipdst;
			}
		}
	}

	//alloc ip and set

	ipdst=NULL;
	if(ip_pool->load)
		{
//		RUNNING_LOG_DEBUG("core %d :alloc src %llx hashx idx=%llx\n",rte_lcore_id(),srcip,srcip_idx);
		ipdst=list_first_entry(&ip_pool->header,struct ip_g_s2,list);
		list_del_init(&ipdst->list);
		INIT_LIST_HEAD(&ipdst->pending_list);
		memset(ipdst->ip_info,0,sizeof(ipdst->ip_info[0])*2);
		ip_pool->load--;
		ipdst->addr=srcip;
		ipdst->port=sport;
		ipdst->ip_idx = ip_idx;
		update_ip2(ipdst,packet_info->packet_info,dir,m->pkt_len);
		list_add_tail(&ipdst->list,&ip_hash[srcip_idx].header);
		list_add_tail(&ipdst->pending_list,&ip_burst_cache[split_dst_idx].header);
		ip_burst_cache[split_dst_idx].load++;

//		RUNNING_LOG_DEBUG("core %d (%d) :src alloc,ip=%x,ip_hash[%d].load=%d cache[%d].load=%d ip_pool->load=%d\n",
//			rte_lcore_id(),__LINE__,ipdst->addr,srcip_idx,ip_hash[srcip_idx].load,split_dst_idx,
//			ip_burst_cache[split_dst_idx].load,ip_pool->load);

		}
	else
		{
		io->miss_alloced++;
		}

	return ipdst;
}

static inline struct src_sum * __attribute__((always_inline))
pkt_srcip_handler(struct pp_info *packet_info,
	struct hash_array *srcsum_pool,
	struct hash_array *srcsum_hash,struct hash_array *srcsum_pending,int sumsrc_cnt,
	struct src_sum_tmp *intmp)
{

	uint32_t srcip_idx,srcip;
//	int split_dst_idx;
	struct src_sum *iptmp,*ipdst;
//	int match=0,i;

	int split_src_idx;

	//look up src ip hash
	srcip=packet_info->srcip;
	srcip_idx=srcip&(IP_HASH_ARRAY_SZ-1);
	split_src_idx=srcip&(sumsrc_cnt-1);

	if(!list_empty(&srcsum_hash[srcip_idx].header))
		{
		list_for_each_entry_safe(ipdst, iptmp, &srcsum_hash[srcip_idx].header, list)
			{
			if((packet_info->srcip==ipdst->src_addr)&&
				(packet_info->dstip==ipdst->dst_addr))
				{
//				ALERT_LOG("core %d :SRC FOUND hash idx=%d map=%llx mask=%llx idx=%x srcip=%x dstip%x\n",
//					rte_lcore_id(),split_src_idx,*pos,mask,srcip_idx,packet_info->srcip,
//					packet_info->dstip);

				ipdst->halfreq_flow+=intmp->halfreq_flow;
				ipdst->new_build_tcp_flow+=intmp->new_build_tcp_flow;
				ipdst->finish_tcp_flow+=intmp->finish_tcp_flow;
				ipdst->new_build_udp_flow+=intmp->new_build_udp_flow;
				ipdst->finish_udp_flow+=intmp->finish_udp_flow;

//				if(ipdst->state)
//					{
//					ALERT_LOG("&&&&&&&&&&&&& core %d (%d) :src match,found hash match,ip=%x s=%d\n",
//						rte_lcore_id(),__LINE__,ipdst->addr,ipdst->state);
//					}

				return ipdst;
				}
			}
		}

alloc_src:
	//alloc ip and set
	ipdst=NULL;
	//	if(likely(srcsum_pool->load))//kickit323
	if(!list_empty(&srcsum_pool->header))
		{
//			RUNNING_LOG_DEBUG("core %d :alloc src %llx hashx idx=%llx\n",rte_lcore_id(),ipv4_hdr->src_addr,srcip_idx);
		ipdst=list_first_entry(&srcsum_pool->header,struct src_sum,pending_list);
		list_del_init(&ipdst->pending_list);
//		memset(ipdst,0,sizeof(struct src_sum));
		ipdst->src_addr=packet_info->srcip;
		ipdst->dst_addr=packet_info->dstip;
//		INIT_LIST_HEAD(&ipdst->alloc_list);
		INIT_LIST_HEAD(&ipdst->list);
		ipdst->halfreq_flow=intmp->halfreq_flow;
		ipdst->new_build_tcp_flow=intmp->new_build_tcp_flow;
		ipdst->finish_tcp_flow=intmp->finish_tcp_flow;
		ipdst->new_build_udp_flow=intmp->new_build_udp_flow;
		ipdst->finish_udp_flow=intmp->finish_udp_flow;

		srcsum_pool->load--;

		list_add_tail(&ipdst->list,&srcsum_hash[srcip_idx].header);

		list_add_tail(&ipdst->pending_list,&srcsum_pending[split_src_idx].header);

		srcsum_pending[split_src_idx].load++;

//		ALERT_LOG("core %d :SRC NEW hash idx=%d map=%llx mask=%llx idx=%x srcip=%x dstip=%x %p\n",
//			rte_lcore_id(),split_src_idx,*pos,mask,srcip_idx,packet_info->srcip,
//			packet_info->dstip,&alloced[split_src_idx]);


//		RUNNING_LOG_DEBUG("aaaaaaaaaaaaaaa core %d (%d) :src alloc,ip=%x,ip_hash[%d].load=%d cache[%d].load=%d ip_pool->load=%d\n",
//			rte_lcore_id(),__LINE__,ipdst->addr,dstip_idx,ip_hash[dstip_idx].load,split_dst_idx,
//			ip_burst_cache[split_dst_idx].load,ip_pool->load);

		}
	else
		{
		RUNNING_LOG_ERROR("core %d :src_sumsrc pool empty\n",rte_lcore_id());
		}

	return ipdst;
}

static inline int __attribute__((always_inline))
pkt_getip(struct rte_mbuf *m, struct pp_info *packet_info,
	uint32_t *port_ip, uint32_t *port_ipmask)
{
	struct ether_hdr *eth_hdr;
	uint32_t packet_type = 0;
	uint16_t ether_type,offset;
	struct ipv4_hdr *ipv4_hdr;
	int ipv4_hdr_len;
	int total_len;
	uint32_t srcip = 0;
	uint32_t dstip = 0;
	int ret=0;

	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
	offset=0;

	//RUNNING_LOG_DEBUG("core %d :%s\n",rte_lcore_id(), __FUNCTION__);
	if (ether_type == ETHER_TYPE_IPv4)
	{
//		save_pcap_file(m);

		ipv4_hdr = (struct ipv4_hdr *)((uint8_t *)eth_hdr + sizeof(struct ether_hdr) + offset);

//		total_len=rte_be_to_cpu_16(ipv4_hdr->total_length);
//		ipv4_hdr_len=(ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK)<<2;

		packet_type = FLAG(F_IPV4);

		srcip=rte_be_to_cpu_32(ipv4_hdr->src_addr);
		dstip=rte_be_to_cpu_32(ipv4_hdr->dst_addr);

		if ((ipv4_hdr->next_proto_id == IPPROTO_TCP)||(ipv4_hdr->next_proto_id == IPPROTO_UDP))
		{
			struct tcp_hdr *tcp;

			packet_type |= FLAG(F_TCP);

			ipv4_hdr_len=(ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK)<<2;
			tcp = (struct tcp_hdr *)((unsigned char *)ipv4_hdr + ipv4_hdr_len);

			packet_info->sport=rte_be_to_cpu_16(tcp->src_port);
			packet_info->dport=rte_be_to_cpu_16(tcp->dst_port);
		}

#ifdef __INTER_CONN_IP__
		if (ipv4_hdr->next_proto_id == IPPROTO_ICMP)
		{
#ifdef BOND_2DIR
			if(((dstip&port_ipmask[0])==(port_ip[0]&port_ipmask[0])) ||
				((dstip&port_ipmask[1])==(port_ip[1]&port_ipmask[1])))
			{
//				RUNNING_LOG_WARN("core %d:  hhhhhhhhhit kernel ip %x\n",rte_lcore_id(),dstip);
				ret|=FLAG(POLICY_ACT_PING_REPLY);
			}
#else	// #ifdef BOND_2DIR
			if(unlikely((dstip&port_ipmask[0])==(port_ip[0]&port_ipmask[0])))
			{
//				RUNNING_LOG_WARN("core %d :hhhhhhhhhhhhhhhhhhhhhhhhhhh hit kernel ip %#x\n",rte_lcore_id(),dstip);
				ret|=FLAG(POLICY_ACT_PING_REPLY);
			}
#endif	// #ifdef BOND_2DIR

		}
#endif

//		if (ipv4_hdr->next_proto_id == 89) //OSPF
//		{
//			RUNNING_LOG_INFO("core %d :rev OSPF pkt!\n",rte_lcore_id());
//			return FLAG(POLICY_ACT_KERNEL);
//		}
		//RUNNING_LOG_DEBUG("core %d :ipv4 srcip=%x dstip=%x mask[0]=%x ip[0]=%x mask[1]=%x ip[1]=%x\n",rte_lcore_id(),
			//srcip,dstip,port_ipmask[0],port_ipmask[1],port_ip[0],port_ip[1]);
	}
	else if ((ether_type == ETHER_TYPE_ARP) ||(ether_type == ETHER_TYPE_RARP))
	{
		ret=FLAG(POLICY_ACT_KERNEL);
	}
    	else //if (ether_type == ETHER_TYPE_IPv6)
	{
		ret=FLAG(POLICY_ACT_DROP);
	}

	packet_info->srcip = srcip;
	packet_info->dstip = dstip;
	packet_info->packet_info=packet_type;
	return ret;
}

static inline int __attribute__((always_inline))
pkt_get_ipport(struct rte_mbuf *m, struct pp_info *packet_info)
{
	struct ether_hdr *eth_hdr;
	uint32_t packet_type = 0;
	uint16_t ether_type,offset;
	struct ipv4_hdr *ipv4_hdr;
	int ipv4_hdr_len;
	int total_len;
	struct tcp_hdr *tcp;
	struct udp_hdr *udp;
        int l4_hdr_len=0;
	char *l5;
	int load_len;
	uint32_t srcip,dstip;
	uint16_t src_port,dst_port;
	int ret;

	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
	offset=0;

	//RUNNING_LOG_DEBUG("core %d :%s\n",rte_lcore_id(), __FUNCTION__);
	if (ether_type == ETHER_TYPE_IPv4)
	{
		ipv4_hdr = (struct ipv4_hdr *)((uint8_t *)eth_hdr + sizeof(struct ether_hdr) + offset);

//		total_len=rte_be_to_cpu_16(ipv4_hdr->total_length);
		ipv4_hdr_len=(ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK)<<2;

		packet_type = FLAG(F_IPV4);

		packet_info->srcip=rte_be_to_cpu_32(ipv4_hdr->src_addr);
		packet_info->dstip=rte_be_to_cpu_32(ipv4_hdr->dst_addr);

		//RUNNING_LOG_DEBUG("core %d :ipv4 srcip=%x dstip=%x mask[0]=%x ip[0]=%x mask[1]=%x ip[1]=%x\n",rte_lcore_id(),
			//srcip,dstip,port_ipmask[0],port_ipmask[1],port_ip[0],port_ip[1]);

		if (ipv4_hdr->next_proto_id == IPPROTO_TCP)
		{
			uint8_t tcpflags;

			packet_type |= FLAG(F_TCP);
			tcp = (struct tcp_hdr *)((unsigned char *)ipv4_hdr + ipv4_hdr_len);
                        l4_hdr_len=(tcp->data_off & 0xf0) >> 2 ;
                        if(l4_hdr_len > sizeof(struct tcp_hdr))
				packet_type |= FLAG(F_TCP_OPTION);

			packet_info->sport=rte_be_to_cpu_16(tcp->src_port);
			packet_info->dport=rte_be_to_cpu_16(tcp->dst_port);

			tcpflags = (tcp->tcp_flags & ~(TCPHDR_ECE|TCPHDR_CWR|TCPHDR_PSH));
			if((tcpflags&(TCPHDR_SYN|TCPHDR_ACK))==(TCPHDR_SYN|TCPHDR_ACK))
			{
				packet_type |= FLAG(F_TCP_SYN_ACK);
			}
			else
			{
				if(tcpflags&TCPHDR_SYN)
				{
					packet_type |= FLAG(F_TCP_SYN);
				}
				else
				{
					if(tcpflags&TCPHDR_ACK)
					{
						packet_type |= FLAG(F_TCP_ACK);
					}

					if(tcpflags&TCPHDR_RST)
					{
						packet_type |= FLAG(F_TCP_RST);

					}

					if(tcpflags&TCPHDR_FIN)
					{
						packet_type |= FLAG(F_TCP_FIN);

					}

				}
			}
		}
		else if (ipv4_hdr->next_proto_id == IPPROTO_UDP)
		{
			packet_type |= FLAG(F_UDP);
			udp = (struct udp_hdr *)((unsigned char *)ipv4_hdr + sizeof(struct ipv4_hdr));
			packet_info->sport=rte_be_to_cpu_16(udp->src_port);
			packet_info->dport=rte_be_to_cpu_16(udp->dst_port);
		}
		else if (ipv4_hdr->next_proto_id == IPPROTO_ICMP)
		{
			packet_type |= FLAG(F_ICMP);
		}

		ret=0;

	}
	else if (ether_type == ETHER_TYPE_IPv6)
	{
		ret=FLAG(POLICY_ACT_DROP);
	}
	else
	{
		ret=FLAG(POLICY_ACT_KERNEL);
	}

	packet_info->packet_info=packet_type;
	return ret;
}

static inline int __attribute__((always_inline))
pkt_getinfo(struct rte_mbuf *m,
		struct port_info_sum *p,
		struct policy *mypolicy,struct pp_info *packet_info,uint64_t state,
		uint32_t *port_ip,uint32_t *port_ipmask,int port_cnt,int i_vlan,int o_vlan,
		int l2_valid,
		struct hash_array *ip_pool,
		struct hash_array *ip_burst_cache,
		struct hash_array *ip_hash,int sum_cnt,struct priv_io_in *io,struct ip_g_s2 **ipdst)
{
	struct ether_hdr *eth_hdr;
	uint32_t packet_type = 0;
	uint16_t ether_type,offset;
	struct ipv4_hdr *ipv4_hdr;
	int ipv4_hdr_len;
	int total_len;
	struct ipv6_hdr *ipv6_hdr;
	struct tcp_hdr *tcp;
	struct udp_hdr *udp;
	int l4_hdr_len=0;
	char *l5;
	int load_len;
	uint32_t srcip,dstip;
	uint16_t src_port,dst_port;
	int i,ret;

//	rss=m->hash.rss;
	p->sub[0].in_pps++;
	p->sub[0].in_bps+=m->pkt_len;


	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ether_type = eth_hdr->ether_type;
	offset=0;

#if defined(VLAN_ON) ||defined(BOND_2DIR_VLAN)
{
#define VLAN_MASK	0xfff

		struct vlan_hdr *vlan_hdr;
		int vlanid_in;

		offset = get_vlan_offset(eth_hdr, &ether_type);

		if(!offset)//no vlan tag in
			{
			RUNNING_LOG_DEBUG("core %d : no vlan\n",rte_lcore_id());
//			rte_pktmbuf_dump(running_log_fp,m,m->data_len);
			ret=FLAG(POLICY_ACT_KERNEL);
			goto direct_out;
			}

		vlan_hdr = (struct vlan_hdr *)(eth_hdr + 1);
		if(((rte_cpu_to_be_16(vlan_hdr->vlan_tci)&VLAN_MASK)!=i_vlan)
			&&((rte_cpu_to_be_16(vlan_hdr->vlan_tci)&VLAN_MASK)!=o_vlan))
			{
			RUNNING_LOG_DEBUG("core %d : vlan miss match %d %d\n",rte_lcore_id(),
				(rte_cpu_to_be_16(vlan_hdr->vlan_tci)&VLAN_MASK),i_vlan);
//			rte_pktmbuf_dump(running_log_fp,m,m->data_len);
			ret=FLAG(POLICY_ACT_KERNEL);
			goto direct_out;
			}

		if(!l2_valid)//l2 not ready
			{
			RUNNING_LOG_DEBUG("core %d :l2 not ready to k\n",rte_lcore_id());

			ret=FLAG(POLICY_ACT_KERNEL);
			goto direct_out;
			}
}
#endif

	if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4))
	{
		ipv4_hdr = (struct ipv4_hdr *)((uint8_t *)eth_hdr + sizeof(struct ether_hdr) + offset);

		total_len=rte_be_to_cpu_16(ipv4_hdr->total_length);
		ipv4_hdr_len=(ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK)<<2;

		packet_type = FLAG(F_IPV4);

		srcip=rte_be_to_cpu_32(ipv4_hdr->src_addr);
		dstip=rte_be_to_cpu_32(ipv4_hdr->dst_addr);

		packet_info->srcip=srcip;
		packet_info->dstip=dstip;

		//RUNNING_LOG_DEBUG("core %d :ipv4 srcip=%x dstip=%x mask[0]=%x ip[0]=%x mask[1]=%x ip[1]=%x\n",rte_lcore_id(),
			//srcip,dstip,port_ipmask[0],port_ipmask[1],port_ip[0],port_ip[1]);

#ifdef BOND_2DIR
		if(unlikely((dstip == port_ip[0]) ||(dstip == port_ip[1])))
		{
			RUNNING_LOG_DEBUG("core %d:  hhhhhhhhhit kernel ip %x\n",rte_lcore_id(),dstip);
			return FLAG(POLICY_ACT_KERNEL);
		}
#else
//		if(((dstip&port_ipmask[0])==port_ip[0])||
//			((dstip&port_ipmask[1])==port_ip[1]))
		if((dstip&port_ipmask[0])==port_ip[0])
		{
			RUNNING_LOG_DEBUG("core %d :hhhhhhhhhhhhhhhhhhhhhhhhhhh hit kernel ip %x\n",rte_lcore_id(),dstip);
			return FLAG(POLICY_ACT_KERNEL);
		}
#endif


		p->sub[0].ip.pps++;
		p->sub[0].ip.bps+=m->pkt_len;

#if 0
		if(unlikely((srcip == dstip)
		|| (srcip & 0xff000000 == 0x7f000000)))//land
			{
			p->sub[0].attack.land++;
//			RUNNING_LOG_DEBUG("core %d :ipv4 land\n",rte_lcore_id());

			packet_type |= FLAG(F_LAND);
			if(state & (STATE_POLICY_G))
				ret=mypolicy->land_action;
			else
				ret=0;

			goto direct_out;
			}

		if(unlikely(!ipv4_hdr->time_to_live))//tracert
			{
			p->sub[0].attack.tracert++;
//			RUNNING_LOG_DEBUG("core %d :ipv4 tracert\n",rte_lcore_id());
			packet_type |= FLAG(F_TRACERT);
			packet_info->packet_info=packet_type;
			if(state & (STATE_POLICY_G))
				ret=mypolicy->ttl0_action;
			else
				ret=0;

			goto check_dstip;
			}

		if (unlikely(ipv4_hdr_len > 20))//ip option
			{
			p->sub[0].ip.ip_option++;
//			RUNNING_LOG_DEBUG("core %d :ipv4 ip option\n",rte_lcore_id());

//			ALERT_LOG("ooooooooooooooooo\n");
//			rte_pktmbuf_dump(alert_log_fp,m,m->pkt_len);

//			save_pcap_file(m);

			packet_type |= FLAG(F_IPOPTION);

			if((state & (STATE_POLICY_G))&&(mypolicy->ip_option_action & (FLAG(POLICY_ACT_DROP))))
				{
				ret=mypolicy->ip_option_action;
				goto check_dstip;
				}
			//forward
			}
#endif

		//frag need
		//not all dir sum
		//not icmp code decode
		//no ip option decode

//		rte_pktmbuf_dump(running_log_fp,m,m->data_len);

		if (ipv4_hdr->next_proto_id == IPPROTO_TCP)
			{
			uint8_t tcpflags;

			packet_type |= FLAG(F_TCP);
			tcp = (struct tcp_hdr *)((unsigned char *)ipv4_hdr + ipv4_hdr_len);
//			l4_hdr_len=(tcp->data_off & 0xf0) >> 2 ;
//			if(l4_hdr_len > (sizeof(struct tcp_hdr)+40))// bad tcp option,max 40b
//				goto tcp_bad;
//
//			if(l4_hdr_len > sizeof(struct tcp_hdr))
//				packet_type |= FLAG(F_TCP_OPTION);

//			tcpflags = (tcp->tcp_flags & ~(TCPHDR_ECE|TCPHDR_CWR|TCPHDR_PSH));

//			RUNNING_LOG_DEBUG("core %d :ipv4 tcp\n",rte_lcore_id());
//			if (!tcp_valid_flags[tcpflags])
//				{
//tcp_bad:
//				p->sub[0].bad_ipv4_pkts++;
//				p->sub[0].attack.tcp_flag_err++;
//				packet_type |= FLAG(F_TCP_FLAG_ERR);
//
//				RUNNING_LOG_DEBUG("core %d :ipv4 tcp bad flag\n",rte_lcore_id());

//				if(state & (STATE_POLICY_G))
//					ret=mypolicy->tcp_bad_action;
//				else
//					ret=0;
//
//				goto check_dstip;
//				}
//			else
				{
//				l5=(char *)((char *)tcp + l4_hdr_len);
//				src_port=tcp->src_port;
//				dst_port=tcp->dst_port;
				packet_info->sport=rte_be_to_cpu_16(tcp->src_port);
				packet_info->dport=rte_be_to_cpu_16(tcp->dst_port);

				p->sub[0].tcp.pps++;
				p->sub[0].tcp.bps+=m->pkt_len;
#if 0
				if((tcpflags&(TCPHDR_SYN|TCPHDR_ACK))==(TCPHDR_SYN|TCPHDR_ACK))
					{
					p->sub[0].tcp.syn_ack++;
					packet_type |= FLAG(F_TCP_SYN_ACK);

//					RUNNING_LOG_DEBUG("core %d :ipv4 tcp synack\n",rte_lcore_id());
					}
				else
					{
					if(tcpflags&TCPHDR_SYN)
						{
						p->sub[0].tcp.syn++;
						packet_type |= FLAG(F_TCP_SYN);

//						RUNNING_LOG_DEBUG("core %d :ipv4 tcp syn\n",rte_lcore_id());
						}
					else
						{
						if(tcpflags&TCPHDR_ACK)
							{
							p->sub[0].tcp.ack++;
							packet_type |= FLAG(F_TCP_ACK);

//							RUNNING_LOG_DEBUG("core %d :ipv4 tcp ack\n",rte_lcore_id());
							}

						if(tcpflags&TCPHDR_RST)
							{
							p->sub[0].tcp.rst++;
							packet_type |= FLAG(F_TCP_RST);

//							RUNNING_LOG_DEBUG("core %d :ipv4 tcp rst\n",rte_lcore_id());
							}

						if(tcpflags&TCPHDR_FIN)
							{
							p->sub[0].tcp.fin++;
							packet_type |= FLAG(F_TCP_FIN);

//							RUNNING_LOG_DEBUG("core %d :ipv4 tcp fin\n",rte_lcore_id());
							}

						if((tcp->dst_port == 0x8b00)&&(tcpflags&TCPHDR_URG)&&
							(tcp->tcp_urp))
							{
							p->sub[0].attack.nuker++;
							packet_type |= FLAG(F_NUKER);

//							RUNNING_LOG_DEBUG("core %d :ipv4 tcp nuker\n",rte_lcore_id());

//							packet_info->sport=src_port;
//							packet_info->dport=dst_port;
							if(state & (STATE_POLICY_G))
								ret=mypolicy->nuker_action;
							else
								ret=0;

							goto check_dstip;
							}
						}
					}
#endif
				}
			}
		else if (ipv4_hdr->next_proto_id == IPPROTO_UDP)
			{
			udp = (struct udp_hdr *)((unsigned char *)ipv4_hdr +
						sizeof(struct ipv4_hdr));
//			l4_hdr_len=sizeof(struct udp_hdr);
//			l5=(char *)((char *)udp+sizeof(struct udp_hdr));

			packet_info->sport=rte_be_to_cpu_16(udp->src_port);
			packet_info->dport=rte_be_to_cpu_16(udp->dst_port);

//			RUNNING_LOG_DEBUG("core %d :ipv4 udp\n",rte_lcore_id());

			packet_type |= FLAG(F_UDP);
			p->sub[0].udp.pps++;
			p->sub[0].udp.bps+=m->pkt_len;
#if 0
			if((udp->dst_port == 0x1300)||(udp->dst_port == 0x700))
				{
				packet_type |= FLAG(F_FRAGGLE);
				p->sub[0].attack.fraggle++;

//				RUNNING_LOG_DEBUG("core %d :ipv4 udp chargen\n",rte_lcore_id());
				//packet_info->sport=src_port;
				//packet_info->dport=dst_port;
				if(state & (STATE_POLICY_G))
					ret=mypolicy->fraggle_action;
				else
					ret=0;
				goto check_dstip;
				}
			else if((udp->dst_port == 0x6c07)||(udp->src_port == 0x6c07))
				{
				packet_type |= FLAG(F_SSDP);
				p->sub[0].attack.ssdp++;

//				RUNNING_LOG_DEBUG("core %d :ipv4 udp ssdp\n",rte_lcore_id());
				}
			else if((udp->dst_port == 0xa100)||(udp->src_port == 0xa100))
				{
				packet_type |= FLAG(F_SNMP);
				p->sub[0].attack.snmp++;

//				RUNNING_LOG_DEBUG("core %d :ipv4 udp snmp\n",rte_lcore_id());
				}
			else if((udp->dst_port == 0x3500)||(udp->src_port == 0x3500))
				{
				packet_type |= FLAG(F_DNS);
				p->sub[0].attack.dns++;

//				RUNNING_LOG_DEBUG("core %d :ipv4 udp dns\n",rte_lcore_id());
				}
			else if((udp->dst_port == 0x7b00)||(udp->src_port == 0x7b00))
				{
				packet_type |= FLAG(F_NTP);
				p->sub[0].attack.ntp++;

//				RUNNING_LOG_DEBUG("core %d :ipv4 udp ntp\n",rte_lcore_id());
				}
#endif
			}
		else if(ipv4_hdr->next_proto_id == IPPROTO_ICMP)
			{
			//struct icmp_hdr *icmp_h;

			packet_type |= FLAG(F_ICMP);
			p->sub[0].icmp.pps++;
			p->sub[0].icmp.bps+=m->pkt_len;

//			if((dstip&0xff)==0xff)
//				{
//				packet_type |= FLAG(F_SMURF);
//				p->sub[0].attack.smurf++;
//				if(state & (STATE_POLICY_G))
//					ret=mypolicy->smurf_action;
//				else
//					ret=0;
//				}


//			RUNNING_LOG_DEBUG("core %d :ipv4 icmp\n",rte_lcore_id());

/*
			icmp_h = (struct icmp_hdr *) ((char *)ipv4_hdr +
							  sizeof(struct ipv4_hdr));
			if(icmp_h)
			if (! ((ipv4_hdr->next_proto_id == IPPROTO_ICMP) &&
				   (icmp_h->icmp_type == ICMP_ECHO&&
				   (icmp_h->icmp_code == 0))) {
				rte_pktmbuf_free(pkt);
				continue;
			}
*/
			}
		else if(ipv4_hdr->next_proto_id == IPPROTO_IGMP)
			{
			packet_type |= FLAG(F_IGMP);
			p->sub[0].igmp.pps++;
			p->sub[0].igmp.bps+=m->pkt_len;

//			RUNNING_LOG_DEBUG("core %d :ipv4 igmp\n",rte_lcore_id());
			}

//		load_len = m->pkt_len - sizeof(struct ether_hdr)-ipv4_hdr_len-l4_hdr_len;

		ret=0;

		//goto check_dstip;
		//m->hash.rss = packet_type;
	}
#if 0
	else if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6)) {
		ipv6_hdr = (struct ipv6_hdr *)l3;
		packet_type |= FLAG(F_IPV6);
		p->sub.ip_pps.ipv6++;
		p->sub.ip_bps.ipv6+=m->pkt_len;
		/*
		if (ipv6_hdr->next_proto_id == IPPROTO_TCP)
			packet_type |= FLAG(F_TCP);
		else if (ipv6_hdr->next_proto_id == IPPROTO_UDP)
			packet_type |= FLAG(F_UDP);
			*/

		RUNNING_LOG_DEBUG("core %d :ipv6\n",rte_lcore_id());

		goto ae1;
	}
#endif
	else
		{
		//RUNNING_LOG_DEBUG("core %d :ethertype=%x\n",rte_lcore_id(),rte_be_to_cpu_16(ether_type));
		p->sub[0].notipv4_pps++;
		p->sub[0].notipv4_bps+=m->pkt_len;

//		if (strncmp((char *)eth_hdr, me.settle_setting.gw_bonding_inoutvlan.in_mac, 6))
//		{
			RUNNING_LOG_DEBUG("core %d : %s POLICY_ACT_DROP !\n",rte_lcore_id(), __FUNCTION__);

//			ret=FLAG(POLICY_ACT_DROP);
//			goto direct_out;
//		}

//		rte_pktmbuf_free(m);
		ret=FLAG(POLICY_ACT_KERNEL);
		goto direct_out;
		}

check_dstip:
	packet_info->packet_info=packet_type;
//#ifdef WF_NAT
//	if(((dstip&port_ipmask[0])==port_ip[0]) &&
//		((packet_type & FLAG(F_IGMP)) || (packet_type & FLAG(F_IGMP))))
//	{
//			RUNNING_LOG_DEBUG("core %d :hhhhhhhhhhhhhhhhhhhhhhhhhhh hit kernel ip %x\n",rte_lcore_id(),dstip);
//			return FLAG(POLICY_ACT_KERNEL);
//	}
//#endif
	//*ipdst=pkt_dstip_handler(m, packet_info, ip_pool, ip_burst_cache, ip_hash, sum_cnt, io);
	return ret;

direct_out:
	packet_info->packet_info=packet_type;
	return ret;
}

static inline void __attribute__((always_inline))
quick_first_syn_drop(struct rte_mbuf *m,
		struct pp_info *packet_info,
		struct hash_array *flowtag_pool,
		struct hash_array *flow_hash,struct core_timer *timer,
		struct priv_io_in *io,int *ret,int filter_th)
{
	struct flow_tag *ff,*fftmp;
	uint32_t rss_idx;

	if(packet_info->packet_info & FLAG(TCPHDR_SYN))
		{
		rss_idx=packet_info->srcip & (FLOW_HASH_ARRAY_SZ-1);
		if(!list_empty(&flow_hash[rss_idx].header))
			{
			list_for_each_entry_safe(ff, fftmp, &flow_hash[rss_idx].header, tbl_list)
				{
				if((packet_info->srcip==ff->tuple_v4.a.pair.l3) &&
					(packet_info->dstip==ff->tuple_v4.b.pair.l3)&&
					(packet_info->sport==ff->tuple_v4.a.pair.l4)&&
					(packet_info->dport==ff->tuple_v4.b.pair.l4))
					{
					if((m->udata64-ff->last_tick)>filter_th)
						{
						list_del_init(&ff->alloc_list);
						list_add_tail(&ff->alloc_list,&timer->event[timer->pointer].header);
#if 0
	//					if((packet_info->srcip==0xac10331f)&&(packet_info->dstip==0x70000015))
							{
							RUNNING_LOG_INFO("core %d :syn hit dst=%x src=%x,pass timer change %d %llu\n",rte_lcore_id(),
								packet_info->dstip,packet_info->srcip,timer->pointer,ff->timer_loop);
							}
#endif
						ff->timer_loop=TIMEOUT_FLOWTAG;
						return;//pass
						}
					else
						{
						ff->last_tick=m->udata64;
						*ret=FLAG(POLICY_ACT_DROP);
						}
					}
				}
			}

		//alloc
		if(flowtag_pool->load)
			{
			ff=list_first_entry(&flowtag_pool->header,struct flow_tag,alloc_list);
			memset(&ff->tuple_v4,0,sizeof(struct ipv4_4tuple));
			ff->timer_loop=TIMEOUT_FLOWTAG;
			ff->tuple_v4.a.pair.l3=packet_info->srcip;
			ff->tuple_v4.b.pair.l3=packet_info->dstip;
			ff->tuple_v4.a.pair.l4=packet_info->sport;
			ff->tuple_v4.b.pair.l4=packet_info->dport;
			ff->last_tick=m->udata64;

			INIT_LIST_HEAD(&ff->tbl_list);
			list_add_tail(&ff->tbl_list,&flow_hash[rss_idx].header);
//					flow_hash[rss_idx].load++;
			list_move_tail(&ff->alloc_list,&timer->event[timer->pointer].header);
//			timer->event[timer->pointer].load++;
#if 0//test
//			if((packet_info->srcip==0xac10331f)&&(packet_info->dstip==0x70000015))
				{
				RUNNING_LOG_INFO("core %d :syn miss dst=%x src=%x,alloc,timer %d loop=%llu\n",rte_lcore_id(),
				packet_info->dstip,packet_info->srcip,timer->pointer,TIMEOUT_FLOWTAG);
				}
#endif
			flowtag_pool->load--;
			}
		else
			{
			RUNNING_LOG_INFO("core %d :syn miss dst=%x src=%x,alloc tag fail\n",rte_lcore_id(),
				packet_info->dstip,packet_info->srcip);

			io->miss_alloced_flowtag++;
			}

		*ret=FLAG(POLICY_ACT_DROP);
		}
}

static inline int __attribute__((always_inline))
nat_get_dstip_num( struct dnat_item *dnat_table)
{
	int  i, j,k;
	int num = 0;
//	RUNNING_LOG_INFO("core %d :%s dstip=0x%x\n",rte_lcore_id(), __FUNCTION__, dstip);

	for( i = 0; i < NAT_MAX_DSTNUM; i++)
	{
		if( 0 != dnat_table[i].dst_ip)
		{
			num++;
		}else{
			return num;
		}
	}

	return 0;
}

static inline int __attribute__((always_inline))
nat_dstip_find(uint32_t srcip, uint32_t dstip,
	struct hash_array *ip_hash, uint32_t *ret_ip,  uint32_t *ret_ipidx)
{
	int  i, j,k;
	uint32_t hash_idx = 0;
	uint32_t tmp_ip = 0;
	struct srcip_nat *srcipnat,*ipnat,*ipnattmp;

//	if (unlikely(me.mon_vip && (me.mon_vip  == srcip || me.mon_vip  == dstip)))
//		RUNNING_LOG_ERROR("core %d :%s srcip=%u.%u.%u.%u dstip=%u.%u.%u.%u\n",rte_lcore_id(), __FUNCTION__,
//			srcip>>24, (srcip>>16)&0xff,(srcip>>8)&0xff,(srcip)&0xff,
//			dstip>>24, (dstip>>16)&0xff,(dstip>>8)&0xff,(dstip)&0xff);

#if 0
	for( i = 0; i < NAT_MAX_DSTNUM; i++)
	{
		if( dstip == dnat_table[i].dst_ip)
		{
			*ret_ip = dnat_table[i].dst_ip;
			return dnat_table[i].dst_ip;
		}
	}

	for( i = 0; i < NAT_MAX_DSTNUM; i++)
	{
		for( j = 0; j < NAT_MAX_RULENUM; j++)
		{
			if (0 == dnat_table[i].rule[j].proto)
				break;
			for( k = 0; k < NAT_MAX_NATIPNUM; k++)
			{
				if( srcip == dnat_table[i].rule[j].nat_ip[k])
				{
					*ret_ip = dnat_table[i].dst_ip;
					return dnat_table[i].dst_ip;
				}
				if (0 == dnat_table[i].rule[j].nat_ip[k])
					break;
			}

		}
	}
#endif

	if (srcip == 0)
		goto by_dstip;


	//check srcip
	tmp_ip = srcip;
	hash_idx = tmp_ip & (IP_HASH_ARRAY_SZ - 1);

	if(!list_empty(&ip_hash[hash_idx].header))
	{
		list_for_each_entry_safe(ipnat, ipnattmp, &ip_hash[hash_idx].header, tbl_list)
		{
			if(tmp_ip == ipnat->dstip)
			{
				*ret_ip = ipnat->dstip;
				*ret_ipidx = ipnat->dstip_idx;

				return NAT_IP_SRCWEB;
			}
		}
	}

by_dstip:

	//check dstip
	tmp_ip = dstip;
	hash_idx = tmp_ip & (IP_HASH_ARRAY_SZ - 1);

	if(!list_empty(&ip_hash[hash_idx].header))
	{
		list_for_each_entry_safe(ipnat, ipnattmp, &ip_hash[hash_idx].header, tbl_list)
		{
			if(tmp_ip == ipnat->dstip)
			{
				*ret_ip = dstip;
				*ret_ipidx = ipnat->dstip_idx;


				return NAT_IP_VIP;
			}
		}
	}

	return NAT_IP_NULL;
}

static inline int __attribute__((always_inline))
nat_srcip_find(const struct ipv4_4tuple *tuple, struct hash_array *ip_hash, uint32_t *p_srcip, uint32_t *time)
{
	struct snat_ip *srcipnat,*ipnat,*ipnattmp;

	uint32_t hash_idx = tuple->b.pair.l3 & (IP_HASH_ARRAY_SZ - 1);
	if(!list_empty(&ip_hash[hash_idx].header))
	{
		list_for_each_entry_safe(ipnat, ipnattmp, &ip_hash[hash_idx].header, tbl_list)
		{
			if(tuple->b.pair.l3 == ipnat->dstip)
			{
				rte_memcpy(p_srcip, ipnat->snat_ip, sizeof(uint32_t)*NAT_MAX_SIPNUM);
				*time = ipnat->deadtime;
				return ipnat->sip_sum;
			}
		}
	}

	*time = FLOW_NAT_DEAD_TIME_DEF;
	return 0;
}

#if 0
static inline int __attribute__((always_inline))
nat_srcip_find(const struct ipv4_4tuple *tuple, struct snat_item *snat_table, uint32_t *p_srcip)
{
	int  i, j;

	for( i = 0; i < NAT_MAX_DSTNUM; i++)
	{
		if( (tuple->b.pair.l3 == snat_table[i].dst_ip))
		{
			rte_memcpy(p_srcip, snat_table[i].snat_ip, sizeof(uint32_t)*snat_table[i].sip_num);
			return snat_table[i].sip_num;
		}
		if( (0 == snat_table[i].dst_ip))
			break;
	}
	return 0;
}

static inline enum nat_manip_type __attribute__((always_inline))
dnat_rule_find(const struct ipv4_4tuple *tuple,  int protocol, struct dnat_item *dnat_table, struct dnat_range *range, int *idx)
{
	int  i, j;

	for( i = 0; i < NAT_MAX_DSTNUM; i++)
	{
		if( (tuple->b.pair.l3 == dnat_table[i].dst_ip))
		{
			for( j = 0; j < NAT_MAX_RULENUM; j++)
			{
				if (0 == dnat_table[i].rule[j].proto)
					break;
				if ((tuple->b.pair.l4 == dnat_table[i].rule[j].dst_port) &&
					(protocol & dnat_table[i].rule[j].proto))
				{
					rte_memcpy(range->nat_ip, dnat_table[i].rule[j].nat_ip, sizeof(uint32_t)*NAT_MAX_NATIPNUM);
					range->nat_port = dnat_table[i].rule[j].nat_port;
					range->link_status = dnat_linkstate[i][j];

					dnat_table[i].rule[j].hitcnt++;
					range->index = (dnat_table[i].rule[j].hitcnt) & 0x1f;

					*idx = i;
					return NAT_MANIP_DST;
				}
			}
		}
	}
	return NAT_MANIP_NULL;
}
#endif

static inline enum nat_manip_type __attribute__((always_inline))
dnat_rule_find(const struct ipv4_4tuple *tuple,  int protocol, struct hash_array *dnatconfig_hash, struct dnat_range *range, uint16_t *idx)
{
	uint32_t hash_idx = 0;
	uint32_t data[3];
	struct dnat_config *dnatconfig,*dnatconfigtmp;

	data[0] = tuple->b.pair.l3;
	data[1] = tuple->b.pair.l4;
	data[2] = 0;
	hash_idx = rte_jhash_3words(data[0], data[1], data[2], PRIME_VALUE);
	hash_idx = hash_idx & (DNAT_CONFIG_HASH_ARRAY_SZ - 1);

	if(!list_empty(&dnatconfig_hash[hash_idx].header))
	{
		list_for_each_entry_safe(dnatconfig, dnatconfigtmp, &dnatconfig_hash[hash_idx].header, tbl_list)
		{
			if ((tuple->b.pair.l3 == dnatconfig->dstip) &&
				(tuple->b.pair.l4 == dnatconfig->rule.dst_port) &&
				(protocol & dnatconfig->rule.proto))
			{
//				if(4 != dantconfig->forward_level)
//					return NAT_MANIP_NOT;
				rte_memcpy(range->nat_ip, dnatconfig->rule.nat_ip, sizeof(uint32_t)*NAT_MAX_NATIPNUM);
				range->nat_port = dnatconfig->rule.nat_port;
				range->link_status = rip_linkstate[dnatconfig->index_dstip][dnatconfig->index_rule];

				dnatconfig->rule.hitcnt++;
				range->index = (dnatconfig->rule.hitcnt) & 0x1f;
				range->rip_sum=dnatconfig->rule.rip_sum;
				range->fwd_realip_mode=dnatconfig->fwd_realip_mode;

				*idx = dnatconfig->index_dstip;
//				{
//					int k;

//					RUNNING_LOG_INFO("core %d:%s:\n", rte_lcore_id(),__FUNCTION__);
//					for (k=0;k<20;k++)
//						RUNNING_LOG_INFO("natip:%u.%u.%u.%u\n",
//							range->nat_ip[k]>>24,(range->nat_ip[k]>>16)&0xff,(range->nat_ip[k]>>8)&0xff,range->nat_ip[k]&0xff);
//				}

//				if ((tuple->a.pair.l3 == IPv4(119,188,197,130)) || (tuple->b.pair.l3 == IPv4(119,188,197,130)))
//					RUNNING_LOG_ERROR("%s: core<%d> DDDDD good pkt %u.%u.%u.%u:%u->%u.%u.%u.%u:%u index:%u proto:%u\n",__FUNCTION__,rte_lcore_id(),
//						tuple->a.pair.l3>>24,(tuple->a.pair.l3>>16)&0xff,(tuple->a.pair.l3>>8)&0xff,tuple->a.pair.l3&0xff,tuple->a.pair.l4,
//						tuple->b.pair.l3>>24,(tuple->b.pair.l3>>16)&0xff,(tuple->b.pair.l3>>8)&0xff,tuple->b.pair.l3&0xff,tuple->b.pair.l4,
//						hash_idx,protocol);

				return NAT_MANIP_DST;
			}
//			else{
//				if ((tuple->a.pair.l3 == IPv4(119,188,197,130)) || (tuple->b.pair.l3 == IPv4(119,188,197,130)))
//					RUNNING_LOG_ERROR("%s: core<%d> DDDDD drop pkt %u.%u.%u.%u:%u->%u.%u.%u.%u:%u index:%u proto:%u\n",__FUNCTION__,rte_lcore_id(),
//						tuple->a.pair.l3>>24,(tuple->a.pair.l3>>16)&0xff,(tuple->a.pair.l3>>8)&0xff,tuple->a.pair.l3&0xff,tuple->a.pair.l4,
//						tuple->b.pair.l3>>24,(tuple->b.pair.l3>>16)&0xff,(tuple->b.pair.l3>>8)&0xff,tuple->b.pair.l3&0xff,tuple->b.pair.l4,
//						hash_idx,protocol);
//			}
		}
	}
//	else
//	{
//		if ((tuple->a.pair.l3 == IPv4(119,188,197,130)) || (tuple->b.pair.l3 == IPv4(119,188,197,130)))
//				RUNNING_LOG_ERROR("%s: core<%d> DDDDD drop pkt %u.%u.%u.%u:%u->%u.%u.%u.%u:%u index:%u proto:%u\n",__FUNCTION__,rte_lcore_id(),
//					tuple->a.pair.l3>>24,(tuple->a.pair.l3>>16)&0xff,(tuple->a.pair.l3>>8)&0xff,tuple->a.pair.l3&0xff,tuple->a.pair.l4,
//					tuple->b.pair.l3>>24,(tuple->b.pair.l3>>16)&0xff,(tuple->b.pair.l3>>8)&0xff,tuple->b.pair.l3&0xff,tuple->b.pair.l4,
//					hash_idx,protocol);
//	}

	return NAT_MANIP_NULL;
}

static inline uint32_t __attribute__((always_inline))
dist_dnat_find_vip(uint32_t natip, struct dnat_item *dnat_table)
{
	int i, j, k=0;


	for( i = 0; i < NAT_MAX_DSTNUM; i++)
	{
		if(0 == dnat_table[i].dst_ip){
			break;
		}

		for( j = 0; j < NAT_MAX_RULENUM; j++)
		{
			if (0 == dnat_table[i].rule[j].proto){
				break;
			}

			for( k = 0; k < NAT_MAX_NATIPNUM; k++)
			{
				if (0 == dnat_table[i].rule[j].nat_ip[k]){
					continue;
				}

				if (dnat_table[i].rule[j].nat_ip[k] == natip){
					return dnat_table[i].dst_ip;
				}
			}
		}
	}
	return 0;
}

static inline uint32_t __attribute__((always_inline))
dist_snat_find_vip(uint32_t natip, struct snat_item *snat_table)
{
	int i, j;

	for( i = 0; i < NAT_MAX_DSTNUM; i++)
	{
		if(0 == snat_table[i].dst_ip)
			break;

		for( j = 0; j < NAT_MAX_SIPNUM; j++)
		{
			if (snat_table[i].snat_ip[j] == natip){
				return snat_table[i].dst_ip;
			}
		}
	}
	return 0;
}

static inline int __attribute__((always_inline))
nat_is_vip(uint32_t ip, struct hash_array *ip_hash)
{
	struct snat_ip *srcipnat,*ipnat,*ipnattmp;

	uint32_t hash_idx = ip & (IP_HASH_ARRAY_SZ - 1);
	if(!list_empty(&ip_hash[hash_idx].header))
	{
		list_for_each_entry_safe(ipnat, ipnattmp, &ip_hash[hash_idx].header, tbl_list)
		{
			if(ip == ipnat->dstip)
			{
				return 1;
			}
		}
	}
	return 0;
}

static inline void __attribute__((always_inline))
nat_invert_tuple(struct ipv4_4tuple *tuple,
		   const struct ipv4_4tuple *orig)
{
	tuple->b.pair.l3 = orig->a.pair.l3;
	tuple->b.pair.l4 = orig->a.pair.l4;
	tuple->a.pair.l3 = orig->b.pair.l3;
	tuple->a.pair.l4 = orig->b.pair.l4;
}
#if 0
static inline struct flow_nat * __attribute__((always_inline))
nat_flow_find(struct ipv4_4tuple *tuple,
		struct hash_array *flownat_hash)
{
	struct nat_4tuplehash *nattuple,*tmptuple;
	struct flow_nat *flownat;
	uint32_t data[3];
	uint32_t hash_idx = 0;
	uint32_t tmp = 0;

	data[0] = tuple->a.pair.l3;
	data[1] = tuple->b.pair.l3;
	data[2] = (tuple->a.pair.l4)<<16 | tuple->b.pair.l4;

	hash_idx = rte_jhash_3words(data[0], data[1], data[2], PRIME_VALUE);
	hash_idx = hash_idx & (FLOWNAT_HASH_ARRAY_SZ - 1);
//	RUNNING_LOG_DEBUG("core %d : %s dst=0x%x src=0x%x,sport=%d\n",rte_lcore_id(), __FUNCTION__, tuple->b.pair.l3, tuple->a.pair.l3, tuple->a.pair.l4);
	if(!list_empty(&flownat_hash[hash_idx].header))
	{
		list_for_each_entry_safe(nattuple, tmptuple, &flownat_hash[hash_idx].header, listnode)
		{
			if(nat_equal_tuple(tuple, &nattuple->tuple_v4))
			{
				return container_of(nattuple, struct flow_nat, nat_tuplehash[nattuple->dir]);
			}
		}
	}

	return NULL;
}
#endif

static inline struct flow_nat * __attribute__((always_inline))
nat_flow_find(struct ipv4_4tuple *tuple,
		struct hash_array *flownat_hash, int proto_type)
{
	struct nat_4tuplehash *nattuple,*tmptuple;
	struct flow_nat *flownat;
	uint32_t data[3];
	uint32_t hash_idx = 0;

	data[0] = tuple->a.pair.l3;
	data[1] = tuple->b.pair.l3;
	data[2] = (tuple->a.pair.l4)<<16 | tuple->b.pair.l4;
	hash_idx = rte_jhash_3words(data[0], data[1], data[2], PRIME_VALUE);

//	hash_idx =
	hash_idx = hash_idx & (FLOWNAT_HASH_ARRAY_SZ - 1);
	printf("core %d :%s,sip=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u, proto=0x%x hash_idx(%d)\n",
			rte_lcore_id(),__FUNCTION__,
			tuple->a.pair.l3>>24, (tuple->a.pair.l3>>16)&0xff, (tuple->a.pair.l3>>8)&0xff, (tuple->a.pair.l3)&0xff, tuple->a.pair.l4,
			tuple->b.pair.l3>>24, (tuple->b.pair.l3>>16)&0xff, (tuple->b.pair.l3>>8)&0xff, (tuple->b.pair.l3)&0xff, tuple->b.pair.l4,
			proto_type,hash_idx);
	if(!list_empty(&flownat_hash[hash_idx].header))
	{
		list_for_each_entry_safe(nattuple, tmptuple, &flownat_hash[hash_idx].header, listnode)
		{
			if(nat_equal_tuple(tuple, &nattuple->tuple_v4) && (proto_type == nattuple->proto) )
			{
				return container_of(nattuple, struct flow_nat, nat_tuplehash[nattuple->dir]);
			}
		}
	}

	return NULL;
}


static inline int __attribute__((always_inline))
nat_used_tuple(struct ipv4_4tuple *orig_tuple, const struct hash_array *flownat_hash)
{
	struct nat_4tuplehash *nattuple,*tmptuple;
	uint32_t data[3];
	uint32_t hash_idx = 0;
	struct ipv4_4tuple reply_tuple;
	struct ipv4_4tuple *tuple= &reply_tuple;

	nat_invert_tuple(tuple, orig_tuple);

	data[0] = tuple->a.pair.l3;
	data[1] = tuple->b.pair.l3;
	data[2] = (tuple->a.pair.l4)<<16 | tuple->b.pair.l4;

	hash_idx = rte_jhash_3words(data[0], data[1], data[2], PRIME_VALUE);
	hash_idx = hash_idx & (FLOWNAT_HASH_ARRAY_SZ - 1);
	//hash_idx = hash_idx % FLOWNAT_HASH_ARRAY_SZ;
//	tmp = hash_idx>>FLOW_HASH_ARRAY_OFF;
//	tmp = (uint32_t)tmp<<FLOW_HASH_ARRAY_OFF;
//	hash_idx = hash_idx - tmp;

//	RUNNING_LOG_INFO("core %d : %s src=0x%x dst=0x%x,dport=%d,hash_idx=0x%x\n",
//		rte_lcore_id(), __FUNCTION__, data[0], data[1], (tuple->b.pair.l4),hash_idx);

	if(!list_empty(&flownat_hash[hash_idx].header))
	{
		list_for_each_entry_safe(nattuple, tmptuple, &flownat_hash[hash_idx].header, listnode)
		{
			if((tuple->a.pair.l3 == nattuple->tuple_v4.a.pair.l3) &&
				(tuple->b.pair.l3 == nattuple->tuple_v4.b.pair.l3)&&
				(tuple->a.pair.l4 == nattuple->tuple_v4.a.pair.l4)&&
				(tuple->b.pair.l4 == nattuple->tuple_v4.b.pair.l4))
			{
//				RUNNING_LOG_INFO("core %d : %s src=0x%x dst=0x%x,dport=%d,hash_idx=0x%x, find flownat\n",
//					rte_lcore_id(), __FUNCTION__, data[0], data[1], (tuple->b.pair.l4),hash_idx);
				return 1;
			}
		}
	}

	return 0;
}

inline int __attribute__((always_inline))
nat_equal_tuple(const struct ipv4_4tuple *tuple1,
	 const struct ipv4_4tuple *tuple2)
{
	return (tuple1->a.pair.l3 == tuple2->a.pair.l3 &&
		tuple1->a.pair.l4 == tuple2->a.pair.l4 &&
		tuple1->b.pair.l3 == tuple2->b.pair.l3 &&
		tuple1->b.pair.l4 == tuple2->b.pair.l4);
}

// uint64_t tmr1=0,tmr2=0;

static inline int __attribute__((always_inline))
snat_l4proto_get_port(struct ipv4_4tuple *tuple,
				 const struct hash_array *flownat_hash,
				 uint16_t *rover, struct bitmap_s* lbmp)
{
#ifndef __SRCP_BIT_MAP__
	unsigned int range_size, min, i;
	uint32_t *portptr;
	uint16_t off;

	portptr = &tuple->a.pair.l4;

	min = 1;
	range_size = 65535;

	off = *rover + 1;
	uint64_t ttt1, ttt2, ttt3;

	ttt1 = rte_rdtsc();

	for (i = 0; ; ++off) {
		*portptr = (min + off % range_size);
		if (++i != range_size && nat_used_tuple(tuple, flownat_hash))
			continue;
		ttt2=rte_rdtsc();
		*rover = off;
//		return i;
		break;
	}

	ttt3 = ttt2 - ttt1;

	if (!tmr1 || (tmr1 > ttt3))
		tmr1 = ttt3;
	if (!tmr2 || (tmr2 < ttt3))
		tmr2 = ttt3;

	return i;
#else

	get_free_num(lbmp,*rover,rover);
	tuple->a.pair.l4 = *rover;

	set_bitmap(lbmp,*rover);

#endif
}

static inline void __attribute__((always_inline))
nat_l4proto_unique_tuple(struct ipv4_4tuple *tuple,
				 const struct nat_range *range,
				 enum nat_manip_type maniptype,
				 const struct hash_array *flownat_hash,
				 uint16_t *rover)
{
	unsigned int range_size, min, i;
	uint32_t *portptr;
	uint16_t off;

	if (maniptype == NAT_MANIP_SRC)
		portptr = &tuple->a.pair.l4;
	else
		portptr = &tuple->b.pair.l4;

	/* If no range specified... */
	if (range->min_port == 0 &&  range->max_port >= 65535) {
		/* If it's dst rewrite, can't change port */
		if (maniptype == NAT_MANIP_DST)
			return;

		if (*portptr < 1024) {
			/* Loose convention: >> 512 is credential passing */
			if (*portptr < 512) {
				min = 1;
				range_size = 511 - min + 1;
			} else {
				min = 600;
				range_size = 1023 - min + 1;
			}
		} else {
			min = 1024;
			range_size = 65535 - 1024 + 1;
		}
	} else {
		min = range->min_port;
		range_size = range->max_port - min + 1;
	}

	off = *rover;
	for (i = 0; ; ++off) {
		*portptr = (min + off % range_size);
		if (++i != range_size && nat_used_tuple(tuple, flownat_hash))
			continue;
		*rover = off;
		return;
	}
	return;
}

/* Only called for SRC manip */
static inline int __attribute__((always_inline))
nat_find_appropriate_src(const struct ipv4_4tuple *tuple,
			struct ipv4_4tuple *result,
			const struct nat_range *range,
			const struct hash_array *srcnat_hash)
{
	struct nat_4tuplehash *nattuple,*tmptuple;
	struct flow_nat *flownat;
	uint32_t data[2];
	uint32_t hash_idx = 0;
	uint32_t tmp = 0;

	data[0] = tuple->a.pair.l3;
	data[1] = tuple->a.pair.l4;

	hash_idx = rte_jhash_2words(data[0], data[1], PRIME_VALUE);
	//hash_idx = hash_idx % SRCNAT_HASH_ARRAY_SZ;
	tmp = hash_idx>>SRCNAT_HASH_ARRAY_OFF;
	tmp = (uint32_t)tmp<<SRCNAT_HASH_ARRAY_OFF;
	hash_idx = hash_idx - tmp;

	RUNNING_LOG_DEBUG("core %d : %s srcip=%x,srcport=%x,hash_idx=%x\n",rte_lcore_id(), __FUNCTION__,
				data[0], data[1], hash_idx);
	if(!list_empty(&srcnat_hash[hash_idx].header))
	{
		list_for_each_entry_safe(nattuple, tmptuple, &srcnat_hash[hash_idx].header, src_list)
		{
			if((data[0] == nattuple->tuple_v4.a.pair.l3) &&
				(data[1] == nattuple->tuple_v4.b.pair.l3))
			{
				flownat =  container_of(nattuple, struct flow_nat, nat_tuplehash[CT_DIR_ORIGINAL]);
				/* Copy source part from reply tuple. */
				nat_invert_tuple(result,
				       &flownat->nat_tuplehash[CT_DIR_REPLY].tuple_v4);
				result->b.pair.l3 = tuple->b.pair.l3;
				result->b.pair.l4 = tuple->b.pair.l4;
				if ((result->a.pair.l3 >= range->min_ip) &&
					(result->a.pair.l3 <= range->max_ip)&&
					(result->a.pair.l4 >= range->min_port)&&
					(result->a.pair.l4 <= range->max_port)){
					return 1;
				}
			}
		}
	}
	return 0;

}

static inline void __attribute__((always_inline))
nat_find_best_ips_proto(struct ipv4_4tuple *tuple,
		    const struct nat_range *range,
		    enum nat_manip_type maniptype)
{
	uint32_t *var_ipp;
	/* Host order */
	uint32_t minip, maxip, j, dist;

	if (maniptype == NAT_MANIP_SRC)
		var_ipp = &tuple->a.pair.l3;
	else
		var_ipp = &tuple->b.pair.l3;

	/* Fast path: only one choice. */
	if (range->min_ip == range->max_ip) {
		*var_ipp = range->min_ip;
		return;
	}

	/* Hashing source and destination IPs gives a fairly even
	 * spread in practice (if there are a small number of IPs
	 * involved, there usually aren't that many connections
	 * anyway).  The consistency means that servers see the same
	 * client coming from the same IP (some Internet Banking sites
	 * like this), even across reboots.
	 */
	j = rte_jhash_1word(tuple->a.pair.l3, PRIME_VALUE);
	//j =  __rte_jhash_3words(tuple->a.pair.l3 + 4, 4, 4, PRIME_VALUE);

	minip = range->min_ip;
	maxip = range->max_ip;
	dist  = maxip - minip + 1;

	*var_ipp = (uint32_t)(minip + (((uint64_t)j * dist) >> 32));
	RUNNING_LOG_DEBUG("core %d :%s j=%x,natip=0x%x,maniptype=%d\n",rte_lcore_id(),__FUNCTION__, j, *var_ipp, maniptype);

}

#define __FWD_REALIP_MOD__
static inline int __attribute__((always_inline))
rip_status_check(uint32_t ip, uint32_t port, int proto)
{
	char rev[MAX_JSON_LEN];
	char *p;
	char *ipaddr = me.natconfig.addr;
	int portaddr = me.natconfig.port;
	char *usrname = me.natconfig.usrname;
	char *password = me.natconfig.password;
	int ret;
	cJSON * pJson = NULL;
	cJSON * pArrayItem = NULL;
	cJSON *t;
	uint64_t pre_tsc = rte_rdtsc();

	ret = get_rip_status(ipaddr, portaddr, usrname, password, ip,port,proto, rev);
	if (0 == ret)
	{
		RUNNING_LOG_ERROR("core %d:get_rip_status fail\n", rte_lcore_id() );
		return FALSE;
	}
	p = strchr(rev, '{');
	pJson = cJSON_Parse(p);
	if(pJson == NULL)
	{
		rev[PORT_STRING_SIZE-1]='\0';
		RUNNING_LOG_DEBUG("core %d:%s Fail to parse rev=%s\n",rte_lcore_id(),  __FUNCTION__,p);
		return FALSE;
	}
	t = cJSON_GetObjectItem(pJson,"status");
	if (t)
	{
		if ( !strcmp(t->valuestring, "OK")) {
			RUNNING_LOG_ERROR("TTTTTTsc: %llu\n", rte_rdtsc()-pre_tsc);
			return TRUE;
		}
	}

	RUNNING_LOG_ERROR("core %d:%s 0x%x:%u, result is FALSE\n",rte_lcore_id(), __FUNCTION__,ip,port);
	return FALSE;

}

static inline int __attribute__((always_inline))
dnat_get_unique_tuple(struct ipv4_4tuple *tuple,
		 const struct ipv4_4tuple *orig_tuple,
		 const struct dnat_range *range,
		 const struct hash_array *flownat_hash)
{
	int i, j;
	uint32_t linkup_idx[NAT_MAX_NATIPNUM] = {0};
	uint32_t tmp_mask = range->link_status;
	uint32_t cnt = __builtin_popcount(tmp_mask);
	uint32_t rip_index;

	rip_index=rte_jhash_2words(orig_tuple->a.pair.l3,orig_tuple->b.pair.l3,PRIME_VALUE) % range->rip_sum;

	RUNNING_LOG_DEBUG("core %d :%s ori_ip=%#x,idx=0x%x mode:%u tmpmask=%#x cnt:%u\n",rte_lcore_id(), __FUNCTION__,
			orig_tuple->a.pair.l3, rip_index, range->fwd_realip_mode, tmp_mask,cnt);

#ifdef __FWD_REALIP_MOD__
	if (REALIP_SEL_DSH == range->fwd_realip_mode)
	{
		tuple->a.pair.l3 = orig_tuple->a.pair.l3;
		tuple->a.pair.l4 = orig_tuple->a.pair.l4;

		if (cnt <= 1){
			tuple->b.pair.l3 = range->nat_ip[0];
		}
		else if ((cnt > 1)&&(tmp_mask & (1 << rip_index))) {
			tuple->b.pair.l3 = range->nat_ip[rip_index];
		}else {
//			if (rip_status_check(range->nat_ip[rip_index], range->nat_port,L4_TYPE_TCP))
//				tuple->b.pair.l3 = range->nat_ip[rip_index];
//			else
//				tuple->b.pair.l3 = range->nat_ip[0];  // default for realip[0]
				for (i=0; i < range->rip_sum; i++)
				{
					rip_index++;
					rip_index %= range->rip_sum;
					if (tmp_mask & (1 << rip_index)){
						tuple->b.pair.l3 = range->nat_ip[rip_index];
						break;
					}
				}
				if (i >= range->rip_sum)
					tuple->b.pair.l3 = range->nat_ip[0];
		}
		tuple->b.pair.l4 = (uint32_t)range->nat_port;

		RUNNING_LOG_DEBUG("core %d :%s ori_ip=%#x,natip=0x%x,idx=0x%x sdh mode\n",rte_lcore_id(), __FUNCTION__,
			orig_tuple->a.pair.l3, tuple->b.pair.l3, rip_index);

		return 1;
	}
#endif

	{
		j = 0;
		do{
			i=__builtin_ffsll(tmp_mask)-1;
			tmp_mask &= ~(1ULL<<i);

			linkup_idx[j] = i;
			j++;
		}while(tmp_mask);

		*tuple = *orig_tuple;
		if (cnt > 1)
			tuple->b.pair.l3 = range->nat_ip[linkup_idx[range->index%cnt]];
		else
			tuple->b.pair.l3 = range->nat_ip[0];  // default for realip[0]
		tuple->b.pair.l4 = (uint32_t)range->nat_port;
		//tuple->a.pair.l3 = (uint32_t)orig_tuple->b.pair.l3;
		RUNNING_LOG_DEBUG("core %d :%s cnt=%d,natip=0x%x,idx=0x%x rr mode\n",rte_lcore_id(), __FUNCTION__, 
			cnt, tuple->b.pair.l3, linkup_idx[range->index%cnt]);

		return 2;
	}

}
static inline int __attribute__((always_inline))
nat_get_unique_tuple(struct ipv4_4tuple *tuple,
		 const struct ipv4_4tuple *orig_tuple,
		 const struct nat_range *range,
		 const struct hash_array *flownat_hash,
		 const struct hash_array *srcnat_hash,
		 const struct pp_info *packet_info,
		 enum nat_manip_type maniptype)
{
	uint32_t port;

	/* 1) If this srcip/proto/src-proto-part is currently mapped,
	 * and that same mapping gives a unique tuple within the given
	 * range, use that.
	 *
	 * This is only required for source (ie. NAT/masq) mappings.
	 * So far, we don't do local source mappings, so multiple
	 * manips not an issue.
	 */
	if (maniptype == NAT_MANIP_SRC)
	{
		/* try the original tuple first */
		if ((orig_tuple->a.pair.l3 >= range->min_ip) &&
			(orig_tuple->a.pair.l3 <= range->max_ip) &&
			(orig_tuple->a.pair.l4 >= range->min_port) &&
			(orig_tuple->a.pair.l4 <=  range->max_port ))
		{
			*tuple = *orig_tuple;
			return 0;
		} else if (nat_find_appropriate_src(orig_tuple, tuple, range,srcnat_hash)) {
			return 1;
		}
	}

	/* 2) Select the least-used IP/proto combination in the given range */
	*tuple = *orig_tuple;
	nat_find_best_ips_proto(tuple, range, maniptype);

	/* 3) The per-protocol part of the manip is made to map into
	 * the range to make a unique tuple.
	 */

	/* Only bother mapping if it's not already in range and unique */
	if (maniptype == NAT_MANIP_SRC)
	{
		port = tuple->a.pair.l4;
	}else{
		port = tuple->b.pair.l4;
	}

	if ((port >= range->min_port) &&
			(port <=  range->max_port ) &&
	    (range->min_port == range->max_port ||
	     !nat_used_tuple(tuple, flownat_hash))){
		return 2;
		}

	/* Last change: get protocol to try to obtain unique tuple. */
	if (packet_info->packet_info & FLAG(F_UDP))
	{
		nat_l4proto_unique_tuple(tuple, range, maniptype, flownat_hash, &udp_port_rover);
	}else if (packet_info->packet_info & FLAG(F_TCP))
	{
		nat_l4proto_unique_tuple(tuple, range, maniptype, flownat_hash, &tcp_port_rover);
	}
	return 3;
}

static inline unsigned short from32to16(unsigned a)
{
	unsigned short b = a >> 16;
	asm("addw %w2,%w0\n\t"
	    "adcw $0,%w0\n"
	    : "=r" (b)
	    : "0" (b), "r" (a));
	return b;
}

static inline unsigned add32_with_carry(unsigned a, unsigned b)
{
	asm("addl %2,%0\n\t"
	    "adcl $0,%0"
	    : "=r" (a)
	    : "0" (a), "r" (b));
	return a;
}

/*
 * Do a 64-bit checksum on an arbitrary memory area.
 * Returns a 32bit checksum.
 *
 * This isn't as time critical as it used to be because many NICs
 * do hardware checksumming these days.
 *
 * Things tried and found to not make it faster:
 * Manual Prefetching
 * Unrolling to an 128 bytes inner loop.
 * Using interleaving with more registers to break the carry chains.
 */
static unsigned do_csum(const unsigned char *buff, unsigned len)
{
	unsigned odd, count;
	unsigned long result = 0;

	if (unlikely(len == 0))
		return result;
	odd = 1 & (unsigned long) buff;
	if (unlikely(odd)) {
		result = *buff << 8;
		len--;
		buff++;
	}
	count = len >> 1;		/* nr of 16-bit words.. */
	if (count) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *)buff;
			count--;
			len -= 2;
			buff += 2;
		}
		count >>= 1;		/* nr of 32-bit words.. */
		if (count) {
			unsigned long zero;
			unsigned count64;
			if (4 & (unsigned long) buff) {
				result += *(unsigned int *) buff;
				count--;
				len -= 4;
				buff += 4;
			}
			count >>= 1;	/* nr of 64-bit words.. */

			/* main loop using 64byte blocks */
			zero = 0;
			count64 = count >> 3;
			while (count64) {
				asm("addq 0*8(%[src]),%[res]\n\t"
				    "adcq 1*8(%[src]),%[res]\n\t"
				    "adcq 2*8(%[src]),%[res]\n\t"
				    "adcq 3*8(%[src]),%[res]\n\t"
				    "adcq 4*8(%[src]),%[res]\n\t"
				    "adcq 5*8(%[src]),%[res]\n\t"
				    "adcq 6*8(%[src]),%[res]\n\t"
				    "adcq 7*8(%[src]),%[res]\n\t"
				    "adcq %[zero],%[res]"
				    : [res] "=r" (result)
				    : [src] "r" (buff), [zero] "r" (zero),
				    "[res]" (result));
				buff += 64;
				count64--;
			}

			/* last up to 7 8byte blocks */
			count %= 8;
			while (count) {
				asm("addq %1,%0\n\t"
				    "adcq %2,%0\n"
					    : "=r" (result)
				    : "m" (*(unsigned long *)buff),
				    "r" (zero),  "0" (result));
				--count;
					buff += 8;
			}
			result = add32_with_carry(result>>32,
						  result&0xffffffff);

			if (len & 4) {
				result += *(unsigned int *) buff;
				buff += 4;
			}
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
		result += *buff;
	result = add32_with_carry(result>>32, result & 0xffffffff);
	if (unlikely(odd)) {
		result = from32to16(result);
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
	}
	return result;
}

/*
 * computes the checksum of a memory block at buff, length len,
 * and adds in "sum" (32-bit)
 *
 * returns a 32-bit number suitable for feeding into itself
 * or csum_tcpudp_magic
 *
 * this function must be called with even lengths, except
 * for the last fragment, which may be odd
 *
 * it's best to have buff aligned on a 64-bit boundary
 */
uint32_t csum_partial(const void *buff, int len, uint32_t sum)
{
	return ( uint32_t)add32_with_carry(do_csum(buff, len), ( uint32_t)sum);
}

static inline uint32_t csum_unfold(uint16_t n)
{
	return (uint32_t)n;
}

/**
 * csum_fold - Fold and invert a 32bit checksum.
 * sum: 32bit unfolded sum
 *
 * Fold a 32bit running checksum to 16bit and invert it. This is usually
 * the last step before putting a checksum into a packet.
 * Make sure not to mix with 64bit checksums.
 */
static inline uint16_t csum_fold(uint32_t sum)
{
	asm("  addl %1,%0\n"
	    "  adcl $0xffff,%0"
	    : "=r" (sum)
	    : "r" (( uint32_t)sum << 16),
	      "0" (( uint32_t)sum & 0xffff0000));
	return ( uint16_t)(~( uint32_t)sum >> 16);
}
/*
static inline uint16_t csum_fold(uint32_t csum)
{
	uint32_t sum = ( uint32_t)csum;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return ~((uint16_t)sum);
}
*/
static inline void __attribute__((always_inline))
csum_replace4(uint16_t *sum, __be32 from, __be32 to)
{
	__be32 diff[] = { ~from, to };

	*sum = csum_fold(csum_partial(diff, sizeof(diff), ~csum_unfold(*sum)));
}

static inline void __attribute__((always_inline))
nat_proto_csum_replace4(uint16_t *sum, __be32 from, __be32 to, int pseudohdr)
{
	__be32 diff[] = { ~from, to };
	*sum = csum_fold(csum_partial(diff, sizeof(diff), ~csum_unfold(*sum)));
//	if (pseudohdr)
//	{
//	*sum = ~csum_fold(csum_partial(diff, sizeof(diff), csum_unfold(*sum)));
//	}else{
//	*sum = csum_fold(csum_partial(diff, sizeof(diff), ~csum_unfold(*sum)));
//	}
}

static inline void __attribute__((always_inline))
csum_replace16(uint16_t *sum, const __be32 * old, const __be32 * new)
{
	__be32 diff[8] = { ~old[3], ~old[2], ~old[1], ~old[0],
		new[3], new[2], new[1], new[0]
	};

	*sum = csum_fold(csum_partial(diff, sizeof(diff), ~csum_unfold(*sum)));
}

static inline void __attribute__((always_inline))
nat_ipv4_csum_update(struct rte_mbuf *mbuf,
				    unsigned int iphdroff, uint16_t *check,
				    const struct ipv4_4tuple *t,
				    enum nat_manip_type maniptype)
{
	struct ether_hdr *eth_hdr;
	struct iphdr *iph;
	__be32 oldip, newip;

	eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	iph = (struct iphdr *)((uint8_t *)eth_hdr + iphdroff);

	if (maniptype == NAT_MANIP_SRC) {
		oldip = iph->saddr;
		newip = rte_cpu_to_be_32(t->a.pair.l3);
	} else {
		oldip = iph->daddr;
		newip = rte_cpu_to_be_32(t->b.pair.l3);
	}
	nat_proto_csum_replace4(check, oldip, newip, 1);
}

static inline void __attribute__((always_inline))
nat_udp_manip_pkt(struct rte_mbuf *mbuf,
	      unsigned int iphdroff, unsigned int hdroff,
	      const struct ipv4_4tuple *tuple,
	      enum nat_manip_type maniptype)
{
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct udphdr *hdr;
	__be16 *portptr, newport;
	int ipv4_hdr_len;

	eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)((uint8_t *)eth_hdr + iphdroff);
	hdr = (struct udphdr *)((uint8_t *)eth_hdr + hdroff);

	if (maniptype == NAT_MANIP_SRC) {
		/* Get rid of src port */
		newport = rte_cpu_to_be_16((uint16_t)tuple->a.pair.l4);
		portptr = &hdr->source;
	} else {
		/* Get rid of dst port */
		newport = rte_cpu_to_be_16((uint16_t)tuple->b.pair.l4);
		portptr = &hdr->dest;
	}

	*portptr = newport;

	if (hdr->check) {
		nat_ipv4_csum_update(mbuf, iphdroff, &hdr->check, tuple, maniptype);
		nat_proto_csum_replace4(&hdr->check, ( __be32) *portptr, ( __be32)newport, 0);
		if (!hdr->check)
			hdr->check = CSUM_MANGLED_0;
	}

}

static inline void __attribute__((always_inline))
nat_tcp_manip_pkt(struct rte_mbuf *mbuf,
	      unsigned int iphdroff, unsigned int hdroff,
	      const struct ipv4_4tuple *tuple,
	      enum nat_manip_type maniptype)
{
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct tcphdr *hdr;
	__be16 *portptr, newport, oldport;
	int ipv4_hdr_len;
	int hdrsize = 8;

	/* this could be a inner header returned in icmp packet; in such
	   cases we cannot update the checksum field since it is outside of
	   the 8 bytes of transport layer headers we are guaranteed */
	if (mbuf->pkt_len >= hdroff + sizeof(struct tcphdr))
		hdrsize = sizeof(struct tcphdr);

	eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)((uint8_t *)eth_hdr + iphdroff);
	hdr = (struct tcphdr *)((uint8_t *)eth_hdr + hdroff);

	if (maniptype == NAT_MANIP_SRC) {
		/* Get rid of src port */
		newport = rte_cpu_to_be_16((uint16_t)tuple->a.pair.l4);
		portptr = &hdr->source;
	} else {
		/* Get rid of dst port */
		newport = rte_cpu_to_be_16((uint16_t)tuple->b.pair.l4);
		portptr = &hdr->dest;
	}

	oldport = *portptr;
	*portptr = newport;

	if (hdrsize < sizeof(*hdr))
		return ;

	nat_ipv4_csum_update(mbuf, iphdroff, &hdr->check, tuple, maniptype);
	nat_proto_csum_replace4(&hdr->check, ( __be32) oldport, ( __be32)newport, 0);

	return ;
}

static inline void __attribute__((always_inline))
nat_ipv4_manip_pkt(struct rte_mbuf *mbuf,
				  const struct pp_info *packet_info,
				  const struct ipv4_4tuple *target,
				  enum nat_manip_type maniptype)
{
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ipv4_hdr;
	unsigned int hdroff;
	int ipv4_hdr_len;
	uint16_t ether_type, iphdroff = 0, offset = 0;

	eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	ether_type = eth_hdr->ether_type;

#if defined(VLAN_ON) ||defined(BOND_2DIR_VLAN)
{
	offset = get_vlan_offset(eth_hdr, &ether_type);
}
#endif

	iphdroff =  sizeof(struct ether_hdr) + offset;
	ipv4_hdr = (struct ipv4_hdr *)((uint8_t *)eth_hdr + iphdroff);

	ipv4_hdr_len=(ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK)<<2;
	hdroff = iphdroff + ipv4_hdr_len;

	if (packet_info->packet_info & FLAG(F_UDP))
	{
		nat_udp_manip_pkt(mbuf, iphdroff, hdroff, target, maniptype);
	}
	else if (packet_info->packet_info & FLAG(F_TCP))
	{
		nat_tcp_manip_pkt(mbuf, iphdroff, hdroff, target, maniptype);
	}


	if (maniptype == NAT_MANIP_SRC) {
		csum_replace4(&ipv4_hdr->hdr_checksum, ipv4_hdr->src_addr, rte_cpu_to_be_32(target->a.pair.l3));
		ipv4_hdr->src_addr = rte_cpu_to_be_32(target->a.pair.l3);
	} else {
		csum_replace4(&ipv4_hdr->hdr_checksum, ipv4_hdr->dst_addr, rte_cpu_to_be_32(target->b.pair.l3));
		ipv4_hdr->dst_addr = rte_cpu_to_be_32(target->b.pair.l3);
	}

}

static inline void __attribute__((always_inline))
nat_timer_handler(void *timer,void *core, uint64_t deadtime)
{
	struct flow_nat *fnat,*fnattmp;
	struct flow_s *flow;
	struct core_timer *t=(struct core_timer *)timer;
	struct lcore_info_s *mycore=(struct lcore_info_s *)core;
	struct list_head *plist, *tmplist;
	int i;
	int my_lcore=rte_lcore_id();

	uint64_t cur_tsc = rte_rdtsc();
        uint32_t mon_ip = me.mon_vip;

	for (i = 0; i < t->queue_sz; i++)
	{
		if(!list_empty(&t->natlist[i].header))
		{
			list_for_each_entry_safe(fnat, fnattmp, &t->natlist[i].header, alloc_list)
			{
				if(cur_tsc - fnat->last_tick > deadtime)
				{
//					RUNNING_LOG_DEBUG("core %d: del natlist srcip=0x%x dstip=0x%x, srcip=0x%x dstip=0x%x,sport=%d\n",
//						mycore->core_id, fnat->nat_tuplehash[0].tuple_v4.a.pair.l3,
//						fnat->nat_tuplehash[0].tuple_v4.b.pair.l3,
//						fnat->nat_tuplehash[1].tuple_v4.a.pair.l3,
//						fnat->nat_tuplehash[1].tuple_v4.b.pair.l3,
//						fnat->nat_tuplehash[0].tuple_v4.a.pair.l4);

					if (mon_ip && (fnat->nat_tuplehash[0].tuple_v4.b.pair.l3==mon_ip||fnat->nat_tuplehash[1].tuple_v4.a.pair.l3==mon_ip))
					{
						RUNNING_LOG_INFO("core %d: del natlist srcip=0x%x vip=0x%x => srcip=0x%x relip=0x%x,sport=%d,dport=%d\n",
        						mycore->core_id, fnat->nat_tuplehash[0].tuple_v4.a.pair.l3,
        						fnat->nat_tuplehash[0].tuple_v4.b.pair.l3,
        						fnat->nat_tuplehash[1].tuple_v4.a.pair.l3,
        						fnat->nat_tuplehash[1].tuple_v4.b.pair.l3,
        						fnat->nat_tuplehash[0].tuple_v4.a.pair.l4,
                                                        fnat->nat_tuplehash[0].tuple_v4.b.pair.l4);
					}
					//delete
					if(list_is_singular(&fnat->nat_tuplehash[0].listnode)){
						INIT_LIST_HEAD(fnat->nat_tuplehash[0].listnode.prev);
						INIT_LIST_HEAD(&fnat->nat_tuplehash[0].listnode);
					}else{
						list_del_init(&fnat->nat_tuplehash[0].listnode);
					}

					if(list_is_singular(&fnat->nat_tuplehash[1].listnode)){
						INIT_LIST_HEAD(fnat->nat_tuplehash[1].listnode.prev);
						INIT_LIST_HEAD(&fnat->nat_tuplehash[1].listnode);
					}else{
						list_del_init(&fnat->nat_tuplehash[1].listnode);
					}

					list_del_init(&fnat->alloc_list);
					list_move_tail(&fnat->alloc_list,&mycore->io_in.flownat_pool.header);
					mycore->io_in.flownat_pool.load++;

				}
			}
		}
	}
}


#if 1//timer test
int timer_test_start=0;
#endif

void in_timer_handler(void *tt,void *c)
{
	struct flow_tag *ftag,*ftagtmp;
	struct flow_s *flow;
	struct core_timer *t=(struct core_timer *)tt;
	struct lcore_info_s *core=(struct lcore_info_s *)c;


	t->pointer++;

	if(t->pointer >= t->queue_sz)
		t->pointer=0;

	if(!list_empty(&t->event[t->pointer].header))
	{
			list_for_each_entry_safe(ftag, ftagtmp, &t->event[t->pointer].header, alloc_list)
			{
				if((--ftag->timer_loop)==0)
				{
					if(ftag->type == TYPE_FLOW_TAG)//tag
					{
//						RUNNING_LOG_INFO("core<%d> del tag srcip=%x dstip=%x timer %d\n",
//							rte_lcore_id(),ftag->tuple_v4.a.pair.l3,ftag->tuple_v4.b.pair.l3,t->pointer);
						list_del_init(&ftag->tbl_list);
						list_move_tail(&ftag->alloc_list,&core->io_in.flowtag_pool.header);
						core->io_in.flowtag_pool.load++;
					}
					else//flow
					{
						flow=(struct flow_s *)ftag;
						list_del_init(&flow->tbl_list);
						list_move_tail(&flow->alloc_list,&core->io_in.flow_pool.header);
						core->io_in.flow_pool.load++;
					}
				}
			}
	}
}


int main_loop_out(void)
{
	uint64_t cur_tsc, prev_tsc,diff_tsc, hz;
	int i,j,k,x,y,queue_idx,pos,aa;
	int my_lcore;
	struct lcore_info_s *local;
	struct rte_mbuf *tx_buf[MAX_TX_QUEUE][BURST_SZ]={NULL};
	int tx_buf_pos[MAX_TX_QUEUE]={0};
	struct rte_mbuf *m;
	int nb_tx;
	uint8_t port_arr[MAX_DEV];
	struct out_burst_cell *o,*otmp;
	int in_shift[MAX_DEV];
//	struct hash_array tmp_back_list[MAX_DEV][MAX_CPU];
//	struct hash_array tmp_send_list[MAX_DEV][MAX_CPU];
//	struct hash_array *back_list,*send_list;
	struct out_buf_s out[MAX_DEV];
	int out_queue[MAX_DEV][MAX_TX_QUEUE]={0};
	int out_queue_sz[MAX_DEV]={0};
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1)/US_PER_S * 100;//100us

	my_lcore=rte_lcore_id();
	local=&lcore[my_lcore];

//	for(i=0;i<MAX_DEV;i++)
//		in_shift[i]=__builtin_popcountll(me.port2core_mask_out[i]);
	rte_memcpy(port_arr,local->port_id,sizeof(local->port_id[0])*MAX_DEV);

//	for(k=0;k<MAX_DEV;k++)
//		{
//		for(j=0;j<MAX_CPU;j++)
//			{
//			INIT_LIST_HEAD(&tmp_back_list[k][j].header);
//			tmp_back_list[k][j].load=0;
//			INIT_LIST_HEAD(&tmp_send_list[k][j].header);
//			tmp_send_list[k][j].load=0;
//			}
//		}

	memset(out,0,sizeof(out[0])*MAX_DEV);
	for(i=0;i<local->port_cnt;i++)
		{
		out_queue_sz[i]=local->io_out.port_do_pop[i].port_queue_arr_sz;
		rte_memcpy(out_queue[i],local->io_out.port_do_pop[i].port_queue_arr,sizeof(int)*MAX_TX_QUEUE);
		}

	RUNNING_LOG_INFO("core %d :out start\n",my_lcore);

	prev_tsc=cur_tsc=rte_rdtsc();

	while(1)
		{
		cur_tsc = rte_rdtsc();

		for(i=0;i<local->port_cnt;i++)
			{
//			back_list=&tmp_back_list[i][0];
//			send_list=&tmp_send_list[i][0];
			for(j=0;j<local->io_out.port_do_pop[i].count;j++)
				{
				if(local->io_out.port_do_pop[i].remote_submit_list[j]->load)
					{
					RUNNING_LOG_DEBUG("%s: core<%d> get port<%d> i=%d j=%d submit %p load %d\n",
						__FUNCTION__,rte_lcore_id(),local->io_out.port_do_pop[i].port_id,
						i,j,local->io_out.port_do_pop[i].remote_submit_list[j],
						local->io_out.port_do_pop[i].remote_submit_list[j]->load);

					list_splice_tail_init(&local->io_out.port_do_pop[i].remote_submit_list[j]->header,
						&local->io_out.port_do_pop[i].tmp_send_list[j].header);

					local->io_out.port_do_pop[i].tmp_send_list[j].load+=
						local->io_out.port_do_pop[i].remote_submit_list[j]->load;
					rte_smp_wmb();
					local->io_out.port_do_pop[i].remote_submit_list[j]->load=0;
					rte_smp_wmb();
					}
				}
			}

		//send
		for(i=0;i<local->port_cnt;i++)
			{
			for(j=0;j<local->io_out.port_do_pop[i].count;j++)
				{
				if(!list_empty(&local->io_out.port_do_pop[i].tmp_send_list[j].header))
					{
					list_for_each_entry_safe(o, otmp, &local->io_out.port_do_pop[i].tmp_send_list[j].header, alloc_list)
						{
							//do tx
							m=(struct rte_mbuf *)o->burst_buf[0];
							queue_idx=(m->hash.rss>>4)%out_queue_sz[i];
							pos=out[i].queue_buf[queue_idx].buf_pos;
							out[i].queue_buf[queue_idx].buf[pos]=m;
							out[i].queue_buf[queue_idx].buf_pos++;
							RUNNING_LOG_DEBUG("%s: core<%d> send portidx=%d port=%d qidx=%d q=%d pos=%d\n",
								__FUNCTION__,rte_lcore_id(),i,port_arr[i],
								queue_idx,out_queue[i][queue_idx],out[i].queue_buf[queue_idx].buf_pos);

							if(unlikely(out[i].queue_buf[queue_idx].buf_pos >= BURST_SZ))
								{
								//RUNNING_LOG_DEBUG("%s: core<%d> burst portidx=%d port=%d qidx=%d q=%d\n",
									//__FUNCTION__,rte_lcore_id(),i,port_arr[i],
									//queue_idx,out_queue[i][queue_idx]);

								nb_tx=rte_eth_tx_burst(port_arr[i],out_queue[i][queue_idx],(struct rte_mbuf **)&out[i].queue_buf[queue_idx].buf,BURST_SZ);
								if (unlikely(nb_tx < BURST_SZ))
									{
//									port_stat[port_arr[i]].sub[1].bad_ipv4_pkts+=(BURST_SZ-nb_tx);
									for(;nb_tx<BURST_SZ;nb_tx++)
										{
										rte_pktmbuf_free(out[i].queue_buf[queue_idx].buf[nb_tx]);
										}
									}
								out[i].queue_buf[queue_idx].buf_pos=0;
								}

//							update_port_sum_out(pkts_burst[j],&port_stat[port_arr[i]]);


						list_del_init(&o->alloc_list);
						list_add_tail(&o->alloc_list,&local->io_out.port_do_pop[i].tmp_back_list[j].header);
						local->io_out.port_do_pop[i].tmp_back_list[j].load++;
						local->io_out.port_do_pop[i].tmp_send_list[j].load--;
						}
					}

				}
			}

		//back
		for(i=0;i<local->port_cnt;i++)
			{
			for(j=0;j<local->io_out.port_do_pop[i].count;j++)
				{
				if((local->io_out.port_do_pop[i].tmp_back_list[j].load)&&
					(local->io_out.port_do_pop[i].remote_back_list[j]->load==0))
					{
					list_splice_tail_init(&local->io_out.port_do_pop[i].tmp_back_list[j].header,
						&local->io_out.port_do_pop[i].remote_back_list[j]->header);

					rte_smp_wmb();
					local->io_out.port_do_pop[i].remote_back_list[j]->load=
						local->io_out.port_do_pop[i].tmp_back_list[j].load;
					rte_smp_wmb();
					local->io_out.port_do_pop[i].tmp_back_list[j].load=0;
					}
				}
			}

		//process timer
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc))
			{
			for(i=0;i<local->port_cnt;i++)
				{
				for(j=0;j<out_queue_sz[i];j++)
					{
						if(unlikely(out[i].queue_buf[j].buf_pos))
							{
							RUNNING_LOG_DEBUG("%s: core<%d> 100us burst portidx=%d port=%d qidx=%d q=%d cnt=%d\n",
								__FUNCTION__,rte_lcore_id(),i,port_arr[i],
								j,out_queue[i][j],out[i].queue_buf[j].buf_pos);

							nb_tx=rte_eth_tx_burst(port_arr[i],out_queue[i][j],
								(struct rte_mbuf **)&out[i].queue_buf[j].buf,out[i].queue_buf[j].buf_pos);
							if (unlikely(nb_tx < out[i].queue_buf[j].buf_pos))
								{
//								port_stat[port_arr[i]].sub[1].bad_ipv4_pkts+=(out[i].queue_buf[j].buf_pos-nb_tx);
								for(;nb_tx < out[i].queue_buf[j].buf_pos;nb_tx++)
									{
									rte_pktmbuf_free(out[i].queue_buf[j].buf[nb_tx]);
									}
								}
							out[i].queue_buf[j].buf_pos=0;
							}
					}
				}

			prev_tsc = cur_tsc;
			}

		}
}

#if 0
static inline void __attribute__((always_inline))
do_pkt_push(struct rte_mbuf *m,
	struct port_push *p,
	struct hash_array *pool,
	struct port_info_sum *port_info,uint32_t *miss_alloc)
{
	struct out_burst_cell *cell;
	int rss=m->hash.rss%p->count;

	if(pool->load)
		{
			cell=list_first_entry(&pool->header,struct out_burst_cell,alloc_list);
			cell->burst_cnt=0;
			list_del_init(&cell->alloc_list);
			list_add_tail(&cell->alloc_list,&p->pending_list[rss].header);
			p->pending_list[rss].load++;
			pool->load--;
		}
	else
		{
		*miss_alloc++;
//			port_info->sub[0].outpush_fail_drop++;
		rte_pktmbuf_free(m);
		return;
		}


	cell->burst_buf[0]=(void *)m;
	cell->burst_cnt=1;
	if(cell->burst_cnt==BURST_SZ)
		{
		p->used[rss]=NULL;
		//try burst
		if(likely(p->submit_list[rss].load==0))
			{
			list_splice_tail_init(&p->pending_list[rss].header,
				&p->submit_list[rss].header);

			rte_smp_wmb();
			p->submit_list[rss].load=p->pending_list[rss].load;
			RUNNING_LOG_DEBUG("%s: core<%d> rss=%d submit %d total %d\n",__FUNCTION__,rte_lcore_id(),
				rss,p->pending_list[rss].load,p->submit_list[rss].load);

			rte_smp_wmb();
			p->pending_list[rss].load=0;
			}
		}
}
#endif

uint64_t attack_event_id=0;

#if 1//json

static inline void __attribute__((always_inline))
format_json_attack_event_start(
	char *buf
	)
{
	time_t now;
	int len;

	time(&now);

#if 0
	struct tm *p;
	char timebuf[100];

	p = localtime(&now);
	sprintf(timebuf,"%d-%02d-%02d %02d:%02d:%02d",(1900+p->tm_year),(1+p->tm_mon),p->tm_mday,p->tm_hour,p->tm_min,p->tm_sec);
#endif

	sprintf(buf, "{\"event_id\":\"%llu\","
		"\"device_id\":\"%s\","
		"\"start_time\": %llu,"
		"\"ipaddr\":\"%s\""
		"}",
		attack_event_id, me.id,(uint64_t)now,"0.0.0.0");

	len=strlen(buf);
	if (rd_kafka_produce(me.ch_kafka.channel_kafka[TOPIC_ATTACK_EVENT].rkt, RD_KAFKA_PARTITION_UA,
				 RD_KAFKA_MSG_F_COPY,
				 /* Payload and length */
				 buf, len,
				 /* Optional key and its length */
				 NULL, 0,
				 /* Message opaque, provided in
				  * delivery report callback as
				  * msg_opaque. */
				 NULL) == -1) {
		RUNNING_LOG_ERROR("%% Failed to produce to topic %s "
			"partition %i: %s\n",
			rd_kafka_topic_name(me.ch_kafka.channel_kafka[TOPIC_ATTACK_EVENT].rkt),
			RD_KAFKA_PARTITION_UA,
			rd_kafka_err2str(rd_kafka_last_error()));
		/* Poll to handle delivery reports */
	}
	else
		{
		RUNNING_LOG_DEBUG("%% Sent %zd bytes to topic "
			"%s partition %i\n",
		len, rd_kafka_topic_name(me.ch_kafka.channel_kafka[TOPIC_ATTACK_EVENT].rkt),
		RD_KAFKA_PARTITION_UA);

		}

	rd_kafka_poll(me.ch_kafka.handle, 0);
}


static inline void __attribute__((always_inline))
format_json_attack_event_end(
	struct port_info_sum *total,struct port_info_sum *max,int timer_cnt,
	char *buf
	)
{
	time_t now;
	int len;


	time(&now);

#if 0
	struct tm *p;
	char timebuf[100];

	p = localtime(&now);
	sprintf(timebuf,"%d-%02d-%02d %02d:%02d:%02d",(1900+p->tm_year),(1+p->tm_mon),p->tm_mday,p->tm_hour,p->tm_min,p->tm_sec);
#endif

	sprintf(buf, "{\"event_id\":\"%llu\","
		"\"device_id\":\"%s\","
		"\"end_time\": %llu,"
		"\"ipaddr\":\"%s\","
		"\"avg_in_pps\": %llu,"
		"\"avg_in_bps\": %llu,"
		"\"avg_in_bad_ipv4_pkts\": %llu,"
		"\"avg_in_notipv4_pps\": %llu,"
		"\"avg_in_notipv4_bps\": %llu,"
		"\"avg_in_tcp_pps\": %llu,"
		"\"avg_in_tcp_bps\": %llu,"
		"\"avg_in_tcp_flow\": %llu,"
		"\"avg_in_tcp_syn\": %llu,"
		"\"avg_in_tcp_syn_ack\": %llu,"
		"\"avg_in_tcp_ack\": %llu,"
		"\"avg_in_tcp_rst\": %llu,"
		"\"avg_in_tcp_fin\": %llu,"
		"\"avg_in_udp_pps\": %llu,"
		"\"avg_in_udp_bps\": %llu,"
		"\"avg_in_icmp_pps\": %llu,"
		"\"avg_in_icmp_bps\": %llu,"
		"\"avg_in_igmp_pps\": %llu,"
		"\"avg_in_igmp_bps\": %llu,"
		"\"avg_in_ip_pps\": %llu,"
		"\"avg_in_ip_bps\": %llu,"
		"\"avg_in_ip_frag\": %llu,"
		"\"avg_in_ip_option\": %llu,"
		"\"avg_in_tcp_flag_err\": %llu,"
		"\"avg_in_smurf\": %llu,"
		"\"avg_in_fraggle\": %llu,"
		"\"avg_in_frag\": %llu,"
		"\"avg_in_frag_err\": %llu,"
		"\"avg_in_nuker\": %llu,"
		"\"avg_in_ssdp\": %llu,"
		"\"avg_in_ntp\": %llu,"
		"\"avg_in_dns\": %llu,"
		"\"avg_in_snmp\": %llu,"
		"\"avg_in_tracert\": %llu,"
		"\"avg_in_land\": %llu,"
		"\"avg_out_pps\": %llu,"
		"\"avg_out_bps\": %llu,"
		"\"avg_out_notipv4_pps\": %llu,"
		"\"avg_out_notipv4_bps\": %llu,"
		"\"avg_out_tcp_pps\": %llu,"
		"\"avg_out_tcp_bps\": %llu,"
		"\"avg_out_tcp_syn\": %llu,"
		"\"avg_out_tcp_syn_ack\": %llu,"
		"\"avg_out_tcp_ack\": %llu,"
		"\"avg_out_tcp_rst\": %llu,"
		"\"avg_out_tcp_fin\": %llu,"
		"\"avg_out_udp_pps\": %llu,"
		"\"avg_out_udp_bps\": %llu,"
		"\"avg_out_icmp_pps\": %llu,"
		"\"avg_out_icmp_bps\": %llu,"
		"\"avg_out_igmp_pps\": %llu,"
		"\"avg_out_igmp_bps\": %llu,"
		"\"avg_out_ip_pps\": %llu,"
		"\"avg_out_ip_bps\": %llu,"
		"\"avg_out_ip_frag\": %llu,"
		"\"avg_out_ip_option\": %llu,"
		"\"avg_out_smurf\": %llu,"
		"\"avg_out_fraggle\": %llu,"
		"\"avg_out_frag\": %llu,"
		"\"avg_out_nuker\": %llu,"
		"\"avg_out_ssdp\": %llu,"
		"\"avg_out_ntp\": %llu,"
		"\"avg_out_dns\": %llu,"
		"\"avg_out_snmp\": %llu,"
		"\"avg_out_tracert\": %llu,"
		"\"avg_out_land\": %llu,"
		"\"max_in_pps\": %llu,"
		"\"max_in_bps\": %llu,"
		"\"max_in_bad_ipv4_pkts\": %llu,"
		"\"max_in_notipv4_pps\": %llu,"
		"\"max_in_notipv4_bps\": %llu,"
		"\"max_in_tcp_pps\": %llu,"
		"\"max_in_tcp_bps\": %llu,"
		"\"max_in_tcp_flow\": %llu,"
		"\"max_in_tcp_syn\": %llu,"
		"\"max_in_tcp_syn_ack\": %llu,"
		"\"max_in_tcp_ack\": %llu,"
		"\"max_in_tcp_rst\": %llu,"
		"\"max_in_tcp_fin\": %llu,"
		"\"max_in_udp_pps\": %llu,"
		"\"max_in_udp_bps\": %llu,"
		"\"max_in_icmp_pps\": %llu,"
		"\"max_in_icmp_bps\": %llu,"
		"\"max_in_igmp_pps\": %llu,"
		"\"max_in_igmp_bps\": %llu,"
		"\"max_in_ip_pps\": %llu,"
		"\"max_in_ip_bps\": %llu,"
		"\"max_in_ip_frag\": %llu,"
		"\"max_in_ip_option\": %llu,"
		"\"max_in_tcp_flag_err\": %llu,"
		"\"max_in_smurf\": %llu,"
		"\"max_in_fraggle\": %llu,"
		"\"max_in_frag\": %llu,"
		"\"max_in_frag_err\": %llu,"
		"\"max_in_nuker\": %llu,"
		"\"max_in_ssdp\": %llu,"
		"\"max_in_ntp\": %llu,"
		"\"max_in_dns\": %llu,"
		"\"max_in_snmp\": %llu,"
		"\"max_in_tracert\": %llu,"
		"\"max_in_land\": %llu,"
		"\"max_out_pps\": %llu,"
		"\"max_out_bps\": %llu,"
		"\"max_out_notipv4_pps\": %llu,"
		"\"max_out_notipv4_bps\": %llu,"
		"\"max_out_tcp_pps\": %llu,"
		"\"max_out_tcp_bps\": %llu,"
		"\"max_out_tcp_syn\": %llu,"
		"\"max_out_tcp_syn_ack\": %llu,"
		"\"max_out_tcp_ack\": %llu,"
		"\"max_out_tcp_rst\": %llu,"
		"\"max_out_tcp_fin\": %llu,"
		"\"max_out_udp_pps\": %llu,"
		"\"max_out_udp_bps\": %llu,"
		"\"max_out_icmp_pps\": %llu,"
		"\"max_out_icmp_bps\": %llu,"
		"\"max_out_igmp_pps\": %llu,"
		"\"max_out_igmp_bps\": %llu,"
		"\"max_out_ip_pps\": %llu,"
		"\"max_out_ip_bps\": %llu,"
		"\"max_out_ip_frag\": %llu,"
		"\"max_out_ip_option\": %llu,"
		"\"max_out_smurf\": %llu,"
		"\"max_out_fraggle\": %llu,"
		"\"max_out_frag\": %llu,"
		"\"max_out_nuker\": %llu,"
		"\"max_out_ssdp\": %llu,"
		"\"max_out_ntp\": %llu,"
		"\"max_out_dns\": %llu,"
		"\"max_out_snmp\": %llu,"
		"\"max_out_tracert\": %llu,"
		"\"max_out_land\": %llu,"
		"\"sum_in_pps\": %llu,"
		"\"sum_in_bps\": %llu,"
		"\"sum_in_bad_ipv4_pkts\": %llu,"
		"\"sum_in_notipv4_pps\": %llu,"
		"\"sum_in_notipv4_bps\": %llu,"
		"\"sum_in_tcp_pps\": %llu,"
		"\"sum_in_tcp_bps\": %llu,"
		"\"sum_in_tcp_flow\": %llu,"
		"\"sum_in_tcp_syn\": %llu,"
		"\"sum_in_tcp_syn_ack\": %llu,"
		"\"sum_in_tcp_ack\": %llu,"
		"\"sum_in_tcp_rst\": %llu,"
		"\"sum_in_tcp_fin\": %llu,"
		"\"sum_in_udp_pps\": %llu,"
		"\"sum_in_udp_bps\": %llu,"
		"\"sum_in_icmp_pps\": %llu,"
		"\"sum_in_icmp_bps\": %llu,"
		"\"sum_in_igmp_pps\": %llu,"
		"\"sum_in_igmp_bps\": %llu,"
		"\"sum_in_ip_pps\": %llu,"
		"\"sum_in_ip_bps\": %llu,"
		"\"sum_in_ip_frag\": %llu,"
		"\"sum_in_ip_option\": %llu,"
		"\"sum_in_tcp_flag_err\": %llu,"
		"\"sum_in_smurf\": %llu,"
		"\"sum_in_fraggle\": %llu,"
		"\"sum_in_frag\": %llu,"
		"\"sum_in_frag_err\": %llu,"
		"\"sum_in_nuker\": %llu,"
		"\"sum_in_ssdp\": %llu,"
		"\"sum_in_ntp\": %llu,"
		"\"sum_in_dns\": %llu,"
		"\"sum_in_snmp\": %llu,"
		"\"sum_in_tracert\": %llu,"
		"\"sum_in_land\": %llu,"
		"\"sum_out_pps\": %llu,"
		"\"sum_out_bps\": %llu,"
		"\"sum_out_notipv4_pps\": %llu,"
		"\"sum_out_notipv4_bps\": %llu,"
		"\"sum_out_tcp_pps\": %llu,"
		"\"sum_out_tcp_bps\": %llu,"
		"\"sum_out_tcp_syn\": %llu,"
		"\"sum_out_tcp_syn_ack\": %llu,"
		"\"sum_out_tcp_ack\": %llu,"
		"\"sum_out_tcp_rst\": %llu,"
		"\"sum_out_tcp_fin\": %llu,"
		"\"sum_out_udp_pps\": %llu,"
		"\"sum_out_udp_bps\": %llu,"
		"\"sum_out_icmp_pps\": %llu,"
		"\"sum_out_icmp_bps\": %llu,"
		"\"sum_out_igmp_pps\": %llu,"
		"\"sum_out_igmp_bps\": %llu,"
		"\"sum_out_ip_pps\": %llu,"
		"\"sum_out_ip_bps\": %llu,"
		"\"sum_out_ip_frag\": %llu,"
		"\"sum_out_ip_option\": %llu,"
		"\"sum_out_smurf\": %llu,"
		"\"sum_out_fraggle\": %llu,"
		"\"sum_out_frag\": %llu,"
		"\"sum_out_nuker\": %llu,"
		"\"sum_out_ssdp\": %llu,"
		"\"sum_out_ntp\": %llu,"
		"\"sum_out_dns\": %llu,"
		"\"sum_out_snmp\": %llu,"
		"\"sum_out_tracert\": %llu,"
		"\"sum_out_land\": %llu"
		"}",
		attack_event_id, me.id,(uint64_t)now,"0.0.0.0",
		total->sub[0].in_pps/timer_cnt,
		total->sub[0].in_bps*8/timer_cnt,
		total->sub[0].bad_ipv4_pkts/timer_cnt,
		total->sub[0].notipv4_pps/timer_cnt,
		total->sub[0].notipv4_bps*8/timer_cnt,
		total->sub[0].tcp.pps/timer_cnt,
		total->sub[0].tcp.bps*8/timer_cnt,
		total->sub[0].tcp.flow/timer_cnt,
		total->sub[0].tcp.syn/timer_cnt,
		total->sub[0].tcp.syn_ack/timer_cnt,
		total->sub[0].tcp.ack/timer_cnt,
		total->sub[0].tcp.rst/timer_cnt,
		total->sub[0].tcp.fin/timer_cnt,
		total->sub[0].udp.pps/timer_cnt,
		total->sub[0].udp.bps*8/timer_cnt,
		total->sub[0].icmp.pps/timer_cnt,
		total->sub[0].icmp.bps*8/timer_cnt,
		total->sub[0].igmp.pps/timer_cnt,
		total->sub[0].igmp.bps*8/timer_cnt,
		total->sub[0].ip.pps/timer_cnt,
		total->sub[0].ip.bps*8/timer_cnt,
		total->sub[0].ip.frag/timer_cnt,
		total->sub[0].ip.ip_option/timer_cnt,
		total->sub[0].attack.tcp_flag_err/timer_cnt,
		total->sub[0].attack.smurf/timer_cnt,
		total->sub[0].attack.fraggle/timer_cnt,
		total->sub[0].attack.frag/timer_cnt,
		total->sub[0].attack.frag_err/timer_cnt,
		total->sub[0].attack.nuker/timer_cnt,
		total->sub[0].attack.ssdp/timer_cnt,
		total->sub[0].attack.ntp/timer_cnt,
		total->sub[0].attack.dns/timer_cnt,
		total->sub[0].attack.snmp/timer_cnt,
		total->sub[0].attack.tracert/timer_cnt,
		total->sub[0].attack.land/timer_cnt,
		total->sub[1].in_pps/timer_cnt,
		total->sub[1].in_bps*8/timer_cnt,
		total->sub[1].notipv4_pps/timer_cnt,
		total->sub[1].notipv4_bps*8/timer_cnt,
		total->sub[1].tcp.pps/timer_cnt,
		total->sub[1].tcp.bps*8/timer_cnt,
		total->sub[1].tcp.syn/timer_cnt,
		total->sub[1].tcp.syn_ack/timer_cnt,
		total->sub[1].tcp.ack/timer_cnt,
		total->sub[1].tcp.rst/timer_cnt,
		total->sub[1].tcp.fin/timer_cnt,
		total->sub[1].udp.pps/timer_cnt,
		total->sub[1].udp.bps*8/timer_cnt,
		total->sub[1].icmp.pps/timer_cnt,
		total->sub[1].icmp.bps*8/timer_cnt,
		total->sub[1].igmp.pps/timer_cnt,
		total->sub[1].igmp.bps*8/timer_cnt,
		total->sub[1].ip.pps/timer_cnt,
		total->sub[1].ip.bps*8/timer_cnt,
		total->sub[1].ip.frag/timer_cnt,
		total->sub[1].ip.ip_option/timer_cnt,
		total->sub[1].attack.smurf/timer_cnt,
		total->sub[1].attack.fraggle/timer_cnt,
		total->sub[1].attack.frag/timer_cnt,
		total->sub[1].attack.nuker/timer_cnt,
		total->sub[1].attack.ssdp/timer_cnt,
		total->sub[1].attack.ntp/timer_cnt,
		total->sub[1].attack.dns/timer_cnt,
		total->sub[1].attack.snmp/timer_cnt,
		total->sub[1].attack.tracert/timer_cnt,
		total->sub[1].attack.land/timer_cnt,
		max->sub[0].in_pps,
		max->sub[0].in_bps*8,
		max->sub[0].bad_ipv4_pkts,
		max->sub[0].notipv4_pps,
		max->sub[0].notipv4_bps*8,
		max->sub[0].tcp.pps,
		max->sub[0].tcp.bps*8,
		max->sub[0].tcp.flow,
		max->sub[0].tcp.syn,
		max->sub[0].tcp.syn_ack,
		max->sub[0].tcp.ack,
		max->sub[0].tcp.rst,
		max->sub[0].tcp.fin,
		max->sub[0].udp.pps,
		max->sub[0].udp.bps*8,
		max->sub[0].icmp.pps,
		max->sub[0].icmp.bps*8,
		max->sub[0].igmp.pps,
		max->sub[0].igmp.bps*8,
		max->sub[0].ip.pps,
		max->sub[0].ip.bps*8,
		max->sub[0].ip.frag,
		max->sub[0].ip.ip_option,
		max->sub[0].attack.tcp_flag_err,
		max->sub[0].attack.smurf,
		max->sub[0].attack.fraggle,
		max->sub[0].attack.frag,
		max->sub[0].attack.frag_err,
		max->sub[0].attack.nuker,
		max->sub[0].attack.ssdp,
		max->sub[0].attack.ntp,
		max->sub[0].attack.dns,
		max->sub[0].attack.snmp,
		max->sub[0].attack.tracert,
		max->sub[0].attack.land,
		max->sub[1].in_pps,
		max->sub[1].in_bps*8,
		max->sub[1].notipv4_pps,
		max->sub[1].notipv4_bps*8,
		max->sub[1].tcp.pps,
		max->sub[1].tcp.bps*8,
		max->sub[1].tcp.syn,
		max->sub[1].tcp.syn_ack,
		max->sub[1].tcp.ack,
		max->sub[1].tcp.rst,
		max->sub[1].tcp.fin,
		max->sub[1].udp.pps,
		max->sub[1].udp.bps*8,
		max->sub[1].icmp.pps,
		max->sub[1].icmp.bps*8,
		max->sub[1].igmp.pps,
		max->sub[1].igmp.bps*8,
		max->sub[1].ip.pps,
		max->sub[1].ip.bps*8,
		max->sub[1].ip.frag,
		max->sub[1].ip.ip_option,
		max->sub[1].attack.smurf,
		max->sub[1].attack.fraggle,
		max->sub[1].attack.frag,
		max->sub[1].attack.nuker,
		max->sub[1].attack.ssdp,
		max->sub[1].attack.ntp,
		max->sub[1].attack.dns,
		max->sub[1].attack.snmp,
		max->sub[1].attack.tracert,
		max->sub[1].attack.land,
		total->sub[0].in_pps,
		total->sub[0].in_bps*8,
		total->sub[0].bad_ipv4_pkts,
		total->sub[0].notipv4_pps,
		total->sub[0].notipv4_bps*8,
		total->sub[0].tcp.pps,
		total->sub[0].tcp.bps*8,
		total->sub[0].tcp.flow,
		total->sub[0].tcp.syn,
		total->sub[0].tcp.syn_ack,
		total->sub[0].tcp.ack,
		total->sub[0].tcp.rst,
		total->sub[0].tcp.fin,
		total->sub[0].udp.pps,
		total->sub[0].udp.bps*8,
		total->sub[0].icmp.pps,
		total->sub[0].icmp.bps*8,
		total->sub[0].igmp.pps,
		total->sub[0].igmp.bps*8,
		total->sub[0].ip.pps,
		total->sub[0].ip.bps*8,
		total->sub[0].ip.frag,
		total->sub[0].ip.ip_option,
		total->sub[0].attack.tcp_flag_err,
		total->sub[0].attack.smurf,
		total->sub[0].attack.fraggle,
		total->sub[0].attack.frag,
		total->sub[0].attack.frag_err,
		total->sub[0].attack.nuker,
		total->sub[0].attack.ssdp,
		total->sub[0].attack.ntp,
		total->sub[0].attack.dns,
		total->sub[0].attack.snmp,
		total->sub[0].attack.tracert,
		total->sub[0].attack.land,
		total->sub[1].in_pps,
		total->sub[1].in_bps*8,
		total->sub[1].notipv4_pps,
		total->sub[1].notipv4_bps*8,
		total->sub[1].tcp.pps,
		total->sub[1].tcp.bps*8,
		total->sub[1].tcp.syn,
		total->sub[1].tcp.syn_ack,
		total->sub[1].tcp.ack,
		total->sub[1].tcp.rst,
		total->sub[1].tcp.fin,
		total->sub[1].udp.pps,
		total->sub[1].udp.bps*8,
		total->sub[1].icmp.pps,
		total->sub[1].icmp.bps*8,
		total->sub[1].igmp.pps,
		total->sub[1].igmp.bps*8,
		total->sub[1].ip.pps,
		total->sub[1].ip.bps*8,
		total->sub[1].ip.frag,
		total->sub[1].ip.ip_option,
		total->sub[1].attack.smurf,
		total->sub[1].attack.fraggle,
		total->sub[1].attack.frag,
		total->sub[1].attack.nuker,
		total->sub[1].attack.ssdp,
		total->sub[1].attack.ntp,
		total->sub[1].attack.dns,
		total->sub[1].attack.snmp,
		total->sub[1].attack.tracert,
		total->sub[1].attack.land
		);

	len=strlen(buf);
	if (rd_kafka_produce(me.ch_kafka.channel_kafka[TOPIC_ATTACK_EVENT].rkt, RD_KAFKA_PARTITION_UA,
				 RD_KAFKA_MSG_F_COPY,
				 /* Payload and length */
				 buf, len,
				 /* Optional key and its length */
				 NULL, 0,
				 /* Message opaque, provided in
				  * delivery report callback as
				  * msg_opaque. */
				 NULL) == -1) {
		RUNNING_LOG_ERROR("%% Failed to produce to topic %s "
			"partition %i: %s\n",
			rd_kafka_topic_name(me.ch_kafka.channel_kafka[TOPIC_ATTACK_EVENT].rkt),
			RD_KAFKA_PARTITION_UA,
			rd_kafka_err2str(rd_kafka_last_error()));
		/* Poll to handle delivery reports */
	}
	else
		{
		RUNNING_LOG_DEBUG("%% Sent %zd bytes to topic "
			"%s partition %i\n",
		len, rd_kafka_topic_name(me.ch_kafka.channel_kafka[TOPIC_ATTACK_EVENT].rkt),
		RD_KAFKA_PARTITION_UA);

		}

	attack_event_id=(uint64_t)now;

	rd_kafka_poll(me.ch_kafka.handle, 0);
}

static inline void __attribute__((always_inline))
format_json_dstip_sum(
	struct ip_sum_b *ip,
	char *buf
	)
{
	time_t now;
	int len;
	char ipaddr[64];

//	RUNNING_LOG_INFO("core %d :%s \n", rte_lcore_id(), __FUNCTION__);

	time(&now);

#if 0
	struct tm *p;
	char timebuf[100];

	p = localtime(&now);
	sprintf(timebuf,"%d-%02d-%02d %02d:%02d:%02d",(1900+p->tm_year),(1+p->tm_mon),p->tm_mday,p->tm_hour,p->tm_min,p->tm_sec);
#endif

	sprintf(buf, "{\"clustor_id\":\"%s\","
		"\"device_id\":\"%s\","
		"\"ipaddr\":\"%s\","
		"\"portaddr\":\"%u\","
		"\"timestamp\": %llu,"
		"\"in_pps\": %llu,"
		"\"in_bps\": %llu,"
		"\"in_bad_ipv4_pkts\": %llu,"
		"\"in_notipv4_pps\": %llu,"
		"\"in_notipv4_bps\": %llu,"
		"\"in_tcp_pps\": %llu,"
		"\"in_tcp_bps\": %llu,"
		"\"in_tcp_flow\": %llu,"
		"\"in_tcp_syn\": %llu,"
		"\"in_tcp_syn_ack\": %llu,"
		"\"in_tcp_ack\": %llu,"
		"\"in_tcp_rst\": %llu,"
		"\"in_tcp_fin\": %llu,"
		"\"in_udp_pps\": %llu,"
		"\"in_udp_bps\": %llu,"
		"\"in_icmp_pps\": %llu,"
		"\"in_icmp_bps\": %llu,"
		"\"in_igmp_pps\": %llu,"
		"\"in_igmp_bps\": %llu,"
		"\"in_ip_pps\": %llu,"
		"\"in_ip_bps\": %llu,"
		"\"in_ip_frag\": %llu,"
		"\"out_pps\": %llu,"
		"\"out_bps\": %llu,"
		"\"out_tcp_pps\": %llu,"
		"\"out_tcp_bps\": %llu,"
		"\"out_tcp_syn\": %llu,"
		"\"out_tcp_syn_ack\": %llu,"
		"\"out_tcp_ack\": %llu,"
		"\"out_tcp_rst\": %llu,"
		"\"out_tcp_fin\": %llu,"
		"\"out_udp_pps\": %llu,"
		"\"out_udp_bps\": %llu,"
		"\"out_icmp_pps\": %llu,"
		"\"out_icmp_bps\": %llu,"
		"\"out_igmp_pps\": %llu,"
		"\"out_igmp_bps\": %llu,"
		"\"out_ip_pps\": %llu,"
		"\"out_ip_bps\": %llu,"
		"\"out_ip_frag\": %llu,"
		"\"ip_linkcount\": %llu"
		"}",
		"local", me.id,ip2strle(ipaddr,ip->addr),ip->port,(uint64_t)now,
		ip->ip_sum[0].ip.pps,
		ip->ip_sum[0].ip.bps*8,
		0,//bad_ipv4_pkts
		0,//notipv4_pps
		0,//notipv4_bps
		ip->ip_sum[0].tcp.pps,
		ip->ip_sum[0].tcp.bps*8,
		ip->ip_sum[0].tcp.flow,
		ip->ip_sum[0].tcp.syn,
		ip->ip_sum[0].tcp.syn_ack,
		ip->ip_sum[0].tcp.ack,
		ip->ip_sum[0].tcp.rst,
		ip->ip_sum[0].tcp.fin,
		ip->ip_sum[0].udp.pps,
		ip->ip_sum[0].udp.bps*8,
		ip->ip_sum[0].icmp.pps,
		ip->ip_sum[0].icmp.bps*8,
		ip->ip_sum[0].igmp.pps,
		ip->ip_sum[0].igmp.bps*8,
		ip->ip_sum[0].ip.pps,
		ip->ip_sum[0].ip.bps*8,
		ip->ip_sum[0].ip.frag,
		ip->ip_sum[1].ip.pps,
		ip->ip_sum[1].ip.bps*8,
		ip->ip_sum[1].tcp.pps,
		ip->ip_sum[1].tcp.bps*8,
		ip->ip_sum[1].tcp.syn,
		ip->ip_sum[1].tcp.syn_ack,
		ip->ip_sum[1].tcp.ack,
		ip->ip_sum[1].tcp.rst,
		ip->ip_sum[1].tcp.fin,
		ip->ip_sum[1].udp.pps,
		ip->ip_sum[1].udp.bps*8,
		ip->ip_sum[1].icmp.pps,
		ip->ip_sum[1].icmp.bps*8,
		ip->ip_sum[1].igmp.pps,
		ip->ip_sum[1].igmp.bps*8,
		ip->ip_sum[1].ip.pps,
		ip->ip_sum[1].ip.bps*8,
		ip->ip_sum[1].ip.frag,
		nat_linkcount[ip->ip_idx]
		);

	len=strlen(buf);
	if (rd_kafka_produce(me.ch_kafka.channel_kafka[TOPIC_DSTIP_STAT].rkt, RD_KAFKA_PARTITION_UA,
				 RD_KAFKA_MSG_F_COPY,
				 /* Payload and length */
				 buf, len,
				 /* Optional key and its length */
				 NULL, 0,
				 /* Message opaque, provided in
				  * delivery report callback as
				  * msg_opaque. */
				 NULL) == -1) {
		RUNNING_LOG_ERROR("%% Failed to produce to topic %s "
			"partition %i: %s\n",
			rd_kafka_topic_name(me.ch_kafka.channel_kafka[TOPIC_DSTIP_STAT].rkt),
			RD_KAFKA_PARTITION_UA,
			rd_kafka_err2str(rd_kafka_last_error()));
		/* Poll to handle delivery reports */
	}
	else
		{
		RUNNING_LOG_DEBUG("%% Sent %zd bytes to topic "
			"%s partition %i\n",
		len, rd_kafka_topic_name(me.ch_kafka.channel_kafka[TOPIC_DSTIP_STAT].rkt),
		RD_KAFKA_PARTITION_UA);

		}

	rd_kafka_poll(me.ch_kafka.handle, 0);
}

static inline void __attribute__((always_inline))
format_json_machine_sum(
	struct port_info_sum *total,
	char *buf
	)
{
	time_t now;
	int len;


	time(&now);

#if 0
	struct tm *p;
	char timebuf[100];

	p = localtime(&now);
	sprintf(timebuf,"%d-%02d-%02d %02d:%02d:%02d",(1900+p->tm_year),(1+p->tm_mon),p->tm_mday,p->tm_hour,p->tm_min,p->tm_sec);
#endif

	sprintf(buf, "{\"clustor_id\":\"%s\","
		"\"device_id\":\"%s\","
		"\"ipaddr\":\"%s\","
		"\"timestamp\": %llu,"
		"\"in_pps\": %llu,"
		"\"in_bps\": %llu,"
		"\"in_bad_ipv4_pkts\": %llu,"
		"\"in_notipv4_pps\": %llu,"
		"\"in_notipv4_bps\": %llu,"
		"\"in_tcp_pps\": %llu,"
		"\"in_tcp_bps\": %llu,"
		"\"in_tcp_flow\": %llu,"
		"\"in_tcp_syn\": %llu,"
		"\"in_tcp_syn_ack\": %llu,"
		"\"in_tcp_ack\": %llu,"
		"\"in_tcp_rst\": %llu,"
		"\"in_tcp_fin\": %llu,"
		"\"in_udp_pps\": %llu,"
		"\"in_udp_bps\": %llu,"
		"\"in_icmp_pps\": %llu,"
		"\"in_icmp_bps\": %llu,"
		"\"in_igmp_pps\": %llu,"
		"\"in_igmp_bps\": %llu,"
		"\"in_ip_pps\": %llu,"
		"\"in_ip_bps\": %llu,"
		"\"in_ip_frag\": %llu,"
		"\"in_ip_option\": %llu,"
		"\"in_smurf\": %llu,"
		"\"in_fraggle\": %llu,"
		"\"in_frag\": %llu,"
		"\"in_frag_err\": %llu,"
		"\"in_nuker\": %llu,"
		"\"in_ssdp\": %llu,"
		"\"in_ntp\": %llu,"
		"\"in_dns\": %llu,"
		"\"in_snmp\": %llu,"
		"\"in_tracert\": %llu,"
		"\"in_land\": %llu,"
		"\"out_pps\": %llu,"
		"\"out_bps\": %llu,"
		"\"out_notipv4_pps\": %llu,"
		"\"out_notipv4_bps\": %llu,"
		"\"out_tcp_pps\": %llu,"
		"\"out_tcp_bps\": %llu,"
		"\"out_tcp_syn\": %llu,"
		"\"out_tcp_syn_ack\": %llu,"
		"\"out_tcp_ack\": %llu,"
		"\"out_tcp_rst\": %llu,"
		"\"out_tcp_fin\": %llu,"
		"\"out_udp_pps\": %llu,"
		"\"out_udp_bps\": %llu,"
		"\"out_icmp_pps\": %llu,"
		"\"out_icmp_bps\": %llu,"
		"\"out_igmp_pps\": %llu,"
		"\"out_igmp_bps\": %llu,"
		"\"out_ip_pps\": %llu,"
		"\"out_ip_bps\": %llu,"
		"\"out_ip_frag\": %llu,"
		"\"out_ip_option\": %llu,"
		"\"out_smurf\": %llu,"
		"\"out_fraggle\": %llu,"
		"\"out_frag\": %llu,"
		"\"out_nuker\": %llu,"
		"\"out_ssdp\": %llu,"
		"\"out_ntp\": %llu,"
		"\"out_dns\": %llu,"
		"\"out_snmp\": %llu,"
		"\"out_tracert\": %llu,"
		"\"out_land\": %llu"
		"}",
		"local", me.id,"0.0.0.0",(uint64_t)now,
		total->sub[0].in_pps,
		total->sub[0].in_bps*8,
		total->sub[0].bad_ipv4_pkts,
		total->sub[0].notipv4_pps,
		total->sub[0].notipv4_bps*8,
		total->sub[0].tcp.pps,
		total->sub[0].tcp.bps*8,
		total->sub[0].tcp.flow,
		total->sub[0].tcp.syn,
		total->sub[0].tcp.syn_ack,
		total->sub[0].tcp.ack,
		total->sub[0].tcp.rst,
		total->sub[0].tcp.fin,
		total->sub[0].udp.pps,
		total->sub[0].udp.bps*8,
		total->sub[0].icmp.pps,
		total->sub[0].icmp.bps*8,
		total->sub[0].igmp.pps,
		total->sub[0].igmp.bps*8,
		total->sub[0].ip.pps,
		total->sub[0].ip.bps*8,
		total->sub[0].ip.frag,
		total->sub[0].ip.ip_option,
		total->sub[0].attack.smurf,
		total->sub[0].attack.fraggle,
		total->sub[0].attack.frag,
		total->sub[0].attack.frag_err,
		total->sub[0].attack.nuker,
		total->sub[0].attack.ssdp,
		total->sub[0].attack.ntp,
		total->sub[0].attack.dns,
		total->sub[0].attack.snmp,
		total->sub[0].attack.tracert,
		total->sub[0].attack.land,
		total->sub[1].in_pps,
		total->sub[1].in_bps*8,
		total->sub[1].notipv4_pps,
		total->sub[1].notipv4_bps*8,
		total->sub[1].tcp.pps,
		total->sub[1].tcp.bps*8,
		total->sub[1].tcp.syn,
		total->sub[1].tcp.syn_ack,
		total->sub[1].tcp.ack,
		total->sub[1].tcp.rst,
		total->sub[1].tcp.fin,
		total->sub[1].udp.pps,
		total->sub[1].udp.bps*8,
		total->sub[1].icmp.pps,
		total->sub[1].icmp.bps*8,
		total->sub[1].igmp.pps,
		total->sub[1].igmp.bps*8,
		total->sub[1].ip.pps,
		total->sub[1].ip.bps*8,
		total->sub[1].ip.frag,
		total->sub[1].ip.ip_option,
		total->sub[1].attack.smurf,
		total->sub[1].attack.fraggle,
		total->sub[1].attack.frag,
		total->sub[1].attack.nuker,
		total->sub[1].attack.ssdp,
		total->sub[1].attack.ntp,
		total->sub[1].attack.dns,
		total->sub[1].attack.snmp,
		total->sub[1].attack.tracert,
		total->sub[1].attack.land
		);

	len=strlen(buf);
	if (rd_kafka_produce(me.ch_kafka.channel_kafka[TOPIC_MACHINE_STAT].rkt, RD_KAFKA_PARTITION_UA,
				 RD_KAFKA_MSG_F_COPY,
				 /* Payload and length */
				 buf, len,
				 /* Optional key and its length */
				 NULL, 0,
				 /* Message opaque, provided in
				  * delivery report callback as
				  * msg_opaque. */
				 NULL) == -1) {
		RUNNING_LOG_ERROR("%% Failed to produce to topic %s "
			"partition %i: %s\n",
			rd_kafka_topic_name(me.ch_kafka.channel_kafka[TOPIC_MACHINE_STAT].rkt),
			RD_KAFKA_PARTITION_UA,
			rd_kafka_err2str(rd_kafka_last_error()));
		/* Poll to handle delivery reports */
	}
	else
	{
//		RUNNING_LOG_DEBUG("%% Sent %zd bytes to topic "
//			"%s partition %i\n",
//		len, rd_kafka_topic_name(me.ch_kafka.channel_kafka[TOPIC_MACHINE_STAT].rkt),
//		RD_KAFKA_PARTITION_UA);

	}

	rd_kafka_poll(me.ch_kafka.handle, 0);
}

#endif

#ifdef __SRC_SUM__
static inline struct srcsum_dst_policy * __attribute__((always_inline))
dstip_pl_get_srcsum(struct src_sum *in,struct hash_array *dstip_pl_pool,
	struct hash_array *dstip_pl_hash)
{
	uint32_t ip_idx;
	struct srcsum_dst_policy *ssp,*ssptmp;

	ip_idx=rte_be_to_cpu_32(in->dst_addr)&(IP_HASH_ARRAY_SZ-1);

	if(!list_empty(&dstip_pl_hash[ip_idx].header))
		{
		list_for_each_entry_safe(ssp, ssptmp, &dstip_pl_hash[ip_idx].header, tbl_list)
			{
			if(ssp->dst_addr==in->dst_addr)
				{
//				RUNNING_LOG_INFO("core %d:FOUND DSTIP %x PL %d\n",
//					rte_lcore_id(),in->dst_addr,ssp->src_block.udp_concurrent_new_connections);

				return ssp;
				}
			}
		}

	return NULL;
}

static inline struct srcsum_dst_policy * __attribute__((always_inline))
dstip_pl_set_srcsum(struct dst_pl_s *in,struct hash_array *dstip_pl_pool,
	struct hash_array *dstip_pl_hash)
{
	uint32_t dstip_idx,dstip;
	struct srcsum_dst_policy *ssp,*ssptmp;

	if (in->dstip == 0 || in->dstip == 0xFFFFFFFFUL)
		return NULL;

//	RUNNING_LOG_INFO("core %d :main_loop_sumsrc to be set config: %u.%u.%u.%u\n",rte_lcore_id(),
//		in->dstip>>24,(in->dstip>>16)&0xff,(in->dstip>>8)&0xff,(in->dstip)&0xff);

	//look up src ip hash
	dstip=rte_be_to_cpu_32(in->dstip);
	dstip_idx=dstip&(IP_HASH_ARRAY_SZ-1);

	if(!list_empty(&dstip_pl_hash[dstip_idx].header))
		{
		list_for_each_entry_safe(ssp, ssptmp, &dstip_pl_hash[dstip_idx].header, tbl_list)
			{
			if(ssp->dst_addr==in->dstip)
				{
//				RUNNING_LOG_INFO("core %d:SET FOUND DSTIP %x PL %d->%d\n",rte_lcore_id(),in->dstip,
//					ssp->src_block.udp_concurrent_new_connections,in->src_bl.udp_concurrent_new_connections);

				ssp->src_block.udp_connections=in->src_bl.udp_connections;
				ssp->src_block.pps=in->src_bl.pps;
				ssp->src_block.tcp_and_udp_connections=in->src_bl.tcp_and_udp_connections;
				ssp->src_block.tcp_concurrent_half=in->src_bl.tcp_concurrent_half;
				ssp->src_block.udp_concurrent_new_connections=in->src_bl.udp_concurrent_new_connections;
				ssp->src_block.tcp_connections=in->src_bl.tcp_connections;
				ssp->src_block.bps=in->src_bl.bps;
				ssp->src_block.icmp=in->src_bl.icmp;
				ssp->src_block.tcp_and_udp_concurrent_new_connections=in->src_bl.tcp_and_udp_concurrent_new_connections;

				return ssp;
				}
			}
		}


	//alloc ip and set
	ssp=NULL;
	if(!list_empty(&dstip_pl_pool->header))
		{
//		ALERT_LOG("core %d:SET NEW DSTIP %x PL %d\n",rte_lcore_id(),in->dstip,
//			in->src_block_udp_concurrent_new_connections);

		ssp=list_first_entry(&dstip_pl_pool->header,struct srcsum_dst_policy,alloc_list);
		list_del_init(&ssp->alloc_list);
		INIT_LIST_HEAD(&ssp->tbl_list);
		dstip_pl_pool->load--;

		ssp->dst_addr=in->dstip;
		ssp->src_block.tcp_concurrent_new_connections=in->src_bl.tcp_concurrent_new_connections;
		ssp->src_block.udp_connections=in->src_bl.udp_connections;
		ssp->src_block.pps=in->src_bl.pps;
		ssp->src_block.tcp_and_udp_connections=in->src_bl.tcp_and_udp_connections;
		ssp->src_block.tcp_concurrent_half=in->src_bl.tcp_concurrent_half;
//		ssp->src_block_udp.concurrent_new_connections=in->src_bl.udp_concurrent_new_connections;
		ssp->src_block.tcp_connections=in->src_bl.tcp_connections;
		ssp->src_block.bps=in->src_bl.bps;
		ssp->src_block.icmp=in->src_bl.icmp;
		ssp->src_block.tcp_and_udp_concurrent_new_connections=in->src_bl.tcp_and_udp_concurrent_new_connections;

		list_add_tail(&ssp->tbl_list,&dstip_pl_hash[dstip_idx].header);
		}

	return ssp;
}


static inline struct src_sum_pack * __attribute__((always_inline))
srcip_sum_process(struct hash_array *srcipsum_pool,
	struct hash_array *srcipsum_hash,struct src_sum *msg,uint64_t tick,
	uint64_t t_1s,struct hash_array *timer,int curr_timer_idx)
{
	uint32_t ip_idx;
	struct src_sum_pack *ssp,*ssptmp;
	int timer_idx;

	ip_idx=rte_be_to_cpu_32(msg->src_addr)&(IP_HASH_ARRAY_SZ-1);

	if(!list_empty(&srcipsum_hash[ip_idx].header))
		{
		list_for_each_entry_safe(ssp, ssptmp, &srcipsum_hash[ip_idx].header, tbl_list)
			{
			if((ssp->src_addr==msg->src_addr)&&
				(ssp->dst_addr==msg->dst_addr))
				{
//				ssp->last_tick=tick;
				timer_idx=(curr_timer_idx+DEFAULT_SUMSRC_TIMEOUT)%TIMER_LOOP_SZ;
				list_del_init(&ssp->alloc_list);
				list_add_tail(&ssp->alloc_list,&timer[timer_idx].header);

				if(time_after(tick,ssp->last_tick+t_1s))
					{
//					RUNNING_LOG_INFO("core %d: 1S AF half=%llu new=%llu udpnew=%d"
//						" inhalf=%llu infin=%llu inudp=%d udpnew=%d tick=%llu curr=%llu idx=%d %d\n",rte_lcore_id(),
//						ssp->src_stat.tcp_concurrent_half,
//						ssp->src_stat.tcp_concurrent_new_connections,
//						ssp->src_stat.udp_concurrent_new_connections,
//						msg->new_build_tcp_flow,
//						msg->halfreq_flow,
//						msg->finish_tcp_flow,
//						msg->new_build_udp_flow,
//						tick,curr_timer_idx,timer_idx);

					ssp->src_stat.tcp_concurrent_new_connections=0;
					ssp->src_stat.tcp_concurrent_half=0;
					ssp->src_stat.udp_concurrent_new_connections=0;
					ssp->src_stat.tcp_and_udp_concurrent_new_connections=0;

					ssp->last_tick=tick;
					}

				ssp->src_stat.tcp_concurrent_half += msg->halfreq_flow;
				ssp->src_stat.tcp_concurrent_new_connections += msg->new_build_tcp_flow;

				ssp->src_stat.udp_concurrent_new_connections += msg->new_build_udp_flow;

				return ssp;
				}
			}
		}

//alloc_sumsrcip:
	ssp=NULL;
	if(!list_empty(&srcipsum_pool->header))
		{
		ssp=list_first_entry(&srcipsum_pool->header,struct src_sum_pack,alloc_list);

		//mark 1234
		if(!msg->new_build_tcp_flow && !msg->halfreq_flow && !msg->new_build_udp_flow)
			{
			return NULL;
			}

		ssp->src_addr=msg->src_addr;
		ssp->dst_addr=msg->dst_addr;

		ssp->last_tick=tick;

		timer_idx=(curr_timer_idx+DEFAULT_SUMSRC_TIMEOUT)%TIMER_LOOP_SZ;
		list_del_init(&ssp->alloc_list);
		list_add_tail(&ssp->alloc_list,&timer[timer_idx].header);
		srcipsum_pool->load--;

		INIT_LIST_HEAD(&ssp->tbl_list);
		list_add_tail(&ssp->tbl_list,&srcipsum_hash[ip_idx].header);

		ssp->src_stat.tcp_concurrent_half = msg->halfreq_flow;
		ssp->src_stat.tcp_concurrent_new_connections = msg->new_build_tcp_flow;

		ssp->src_stat.udp_concurrent_new_connections = msg->new_build_udp_flow;

		ssp->flag = SRC_SUM_NOR;
		}
	else
		{
		RUNNING_LOG_WARN("core %d (%d) :sumsrc alloc fail,ip=%x,idx=%d,ip_pool->load=%d\n",
			rte_lcore_id(),__LINE__,msg->src_addr,ip_idx);
		}

	return ssp;
}
#endif

int  main_loop_sum_src(void)
{
	int my_lcore;
	int i,j;
	struct lcore_info_s *local;

	uint64_t cur_tsc, prev_tsc,diff_tsc;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1)/US_PER_S * TIME_DPI;//100us
	int timer_curr_idx=0;
	struct hash_array *local_timer;
#ifdef __SRC_SUM__
	struct hash_array local_srcsum_timeout;
#endif
	uint64_t perf_start,perf_end=0,perf_tmp=0,perf_cn=0;
	int cnt_1s=0;

	struct hash_array *local_sumsrc2io_msg_pool;
	struct hash_array local_sumsrc2io_msg_send_pending[MAX_CPU];
	struct hash_array *local_sumsrc2io_msg_send[MAX_CPU]={NULL};
	struct hash_array *local_sumsrc2io_msg_back[MAX_CPU]={NULL};

	struct hash_array *io2sumsrc_burst[MAX_CPU]={NULL};
	struct hash_array *io2sumsrc_back[MAX_CPU]={NULL};
	struct hash_array io2sumsrc_backpending[MAX_CPU];
	struct hash_array io2sumsrc_handler[MAX_CPU];
	int io_cnt;
	struct src_sum *ss,*sstmp;
#ifdef __SRC_SUM__
	struct src_sum_pack *ssp,*ssptmp;

	struct hash_array *srcipsum_hash;
	struct hash_array *local_srcipsum_pool;
	uint64_t tick_1s=rte_get_tsc_hz()*2;

	uint32_t dst_pl_cfg_pre=0;
	struct hash_array *local_dstip_pl_pool;
	struct hash_array *dstip_pl_hash;
	struct srcsum_dst_policy *dstip_pl;
#endif

	my_lcore=rte_lcore_id();
	local=&lcore[my_lcore];

#ifdef WF_NAT
	io_cnt=__builtin_popcountll(me.io_in_mask | me.io_out_mask);
#else
	io_cnt=__builtin_popcountll(me.io_in_mask);
#endif

	rte_memcpy(io2sumsrc_burst,local->sumsrc.sum_src_io2s_burst,sizeof(struct hash_array *)*io_cnt);
	rte_memcpy(io2sumsrc_back,local->sumsrc.sum_src_s2io_burst,sizeof(struct hash_array *)*io_cnt);
	for(i=0;i<MAX_CPU;i++)
		{
		INIT_LIST_HEAD(&io2sumsrc_backpending[i].header);
		io2sumsrc_backpending[i].load=0;

		INIT_LIST_HEAD(&io2sumsrc_handler[i].header);
		io2sumsrc_handler[i].load=0;
		}

	for(i=0;i<io_cnt;i++)
		{
		local_sumsrc2io_msg_send[i]=&local->sumsrc.msg_sumsrc2io_send[i];
		local_sumsrc2io_msg_back[i]=&local->sumsrc.msg_sumsrc2io_back[i];

		INIT_LIST_HEAD(&local_sumsrc2io_msg_send_pending[i].header);
		local_sumsrc2io_msg_send_pending[i].load=0;
		}
	local_sumsrc2io_msg_pool=&local->sumsrc.msg_io_pool;

#ifdef __SRC_SUM__
	local_srcipsum_pool=&local->sumsrc.ip_sum_src_pool;
	srcipsum_hash=local->sumsrc.ip_sum_src_hash;

	local_timer=local->sumsrc.ltimer;
	INIT_LIST_HEAD(&local_srcsum_timeout.header);
	local_srcsum_timeout.load=0;

	local_dstip_pl_pool=&local->sumsrc.dstip_policy_pool;
	dstip_pl_hash=local->sumsrc.dstip_policy_hash;
#endif
	prev_tsc=cur_tsc=rte_rdtsc();

	RUNNING_LOG_INFO("core %d :main_loop_sumsrc\n",my_lcore);
	sleep(2);

	while(1)
		{
#ifdef __SRC_SUM__
		// policy
		if (unlikely(dst_pl_cfg_pre != viptoa_curr))
		{
			dst_pl_cfg_pre = viptoa_curr;

			for (i = 0; i < NAT_MAX_DSTNUM; i++)
			{
				if (g_dst_pl && g_dst_pl[i].dstip){
					RUNNING_LOG_DEBUG("core %d :main_loop_sumsrc to be set config:index:%d %u.%u.%u.%u\n",my_lcore,i,
						g_dst_pl[i].dstip>>24,(g_dst_pl[i].dstip>>16)&0xff,(g_dst_pl[i].dstip>>8)&0xff,(g_dst_pl[i].dstip)&0xff);
					dstip_pl_set_srcsum(&g_dst_pl[i],local_dstip_pl_pool,dstip_pl_hash);
				}
			}
		}
#endif
		perf_start = cur_tsc = rte_rdtsc();

		for(i=0;i<io_cnt;i++)
			{
			msg_C_rcv_poll(io2sumsrc_burst[i],&io2sumsrc_handler[i]);
			}

		for(i=0;i<io_cnt;i++)
			{
			if(!list_empty(&io2sumsrc_handler[i].header))
				{
#ifdef __SRC_SUM__
				list_for_each_entry_safe(ss, sstmp, &io2sumsrc_handler[i].header, pending_list)
					{
						dstip_pl=dstip_pl_get_srcsum(ss,local_dstip_pl_pool,dstip_pl_hash);
						if(unlikely(dstip_pl==NULL)){

//							RUNNING_LOG_INFO("core %d :main_loop_sumsrc get %u.%u.%u.%u policy fail\n",my_lcore,
//								ss->dst_addr>>24,(ss->dst_addr>>16)&0xff,(ss->dst_addr>>8)&0xff,(ss->dst_addr)&0xff);

							continue;
						}

//						RUNNING_LOG_INFO("core %d :main_loop_sumsrc for io %u.%u.%u.%u	-->	%u.%u.%u.%u\n",my_lcore,
//							ss->src_addr>>24,(ss->src_addr>>16)&0xff,(ss->src_addr>>8)&0xff,(ss->src_addr)&0xff,
//							ss->dst_addr>>24,(ss->dst_addr>>16)&0xff,(ss->dst_addr>>8)&0xff,(ss->dst_addr)&0xff);
//						RUNNING_LOG_INFO("core %d :main_loop_sumsrc halfreq_flow:%u,new_build_tcp_flow:%u,finish_tcp_flow：%u,new_build_udp_flow:%u,finish_udp_flow:%u\n",
//							my_lcore, ss->halfreq_flow, ss->new_build_tcp_flow, ss->finish_tcp_flow, ss->new_build_udp_flow, ss->finish_udp_flow);

						ssp=srcip_sum_process(local_srcipsum_pool,srcipsum_hash,ss,cur_tsc,tick_1s,local_timer,timer_curr_idx);
						if(ssp)
						{
							// send src ip limit to nat core
							struct sum_msg *sm;

							if((dstip_pl->src_block.tcp_concurrent_new_connections &&
								(ssp->src_stat.tcp_concurrent_new_connections >=
								dstip_pl->src_block.tcp_concurrent_new_connections))||
								(dstip_pl->src_block.udp_concurrent_new_connections &&
								(ssp->src_stat.udp_concurrent_new_connections >=
								dstip_pl->src_block.udp_concurrent_new_connections))||
								(dstip_pl->src_block.tcp_concurrent_half &&
								(ssp->src_stat.tcp_concurrent_half >=
								dstip_pl->src_block.tcp_concurrent_half)))
							{

//								RUNNING_LOG_INFO("core %d :main_loop_sumsrc CHECK %u.%u.%u.%u --> %u.%u.%u.%u\n",my_lcore,
//									ssp->src_addr>>24,(ssp->src_addr>>16)&0xff,(ssp->src_addr>>8)&0xff,(ssp->src_addr)&0xff,
//									ssp->dst_addr>>24,(ssp->dst_addr>>16)&0xff,(ssp->dst_addr>>8)&0xff,(ssp->dst_addr)&0xff);
//								RUNNING_LOG_INFO("core %d :main_loop_sumsrc halfreq_flow		policy:%u real:%u\n",my_lcore,
//									dstip_pl->src_block.tcp_concurrent_half,
//									ssp->src_stat.tcp_concurrent_half);
//								RUNNING_LOG_INFO("core %d :main_loop_sumsrc new_build_tcp_flow	policy:%u real:%u\n",my_lcore,
//									dstip_pl->src_block.tcp_concurrent_new_connections,
//									ssp->src_stat.tcp_concurrent_new_connections);
//								RUNNING_LOG_INFO("core %d :main_loop_sumsrc new_build_udp_flow	policy:%u real:%u\n",my_lcore,
//									dstip_pl->src_block.udp_concurrent_new_connections,
//									ssp->src_stat.udp_concurrent_new_connections);

								ssp->flag =	SRC_SUM_ATTACK;

								for(j=0;j<io_cnt;j++)
								{
//									j = dstip_pl->dst_addr % io_cnt;
									if(!list_empty(&local_sumsrc2io_msg_pool->header))
									{
										sm=list_first_entry(&local_sumsrc2io_msg_pool->header,struct sum_msg,list);

										list_del_init(&sm->list);

										sm->ip=ssp->src_addr;
										sm->ip2=ssp->dst_addr;

										sm->msg=1;

										local_sumsrc2io_msg_pool->load--;

										list_add_tail(&sm->list,&local_sumsrc2io_msg_send_pending[j].header);

										local_sumsrc2io_msg_send_pending[j].load++;
									}
									else
									{
										RUNNING_LOG_WARN("src2io msg pool empty!\n");
										break;
									}
								}
							}else if (ssp->flag == SRC_SUM_ATTACK){
									ssp->flag = SRC_SUM_NOR;
//									RUNNING_LOG_INFO("PPPPPPPPPPPPPPPlease release the anti src ip\n");
									j = dstip_pl->dst_addr % io_cnt;
									if(!list_empty(&local_sumsrc2io_msg_pool->header))
									{
										sm=list_first_entry(&local_sumsrc2io_msg_pool->header,struct sum_msg,list);

										list_del_init(&sm->list);

										sm->ip=ssp->src_addr;
										sm->ip2=ssp->dst_addr;


										sm->msg=0;

										local_sumsrc2io_msg_pool->load--;

										list_add_tail(&sm->list,&local_sumsrc2io_msg_send_pending[j].header);

										local_sumsrc2io_msg_send_pending[j].load++;
									}
									else
									{
										RUNNING_LOG_WARN("src2io msg pool empty!\n");
										break;
									}

							}

						}


					}
#endif
				list_splice_tail_init(&io2sumsrc_handler[i].header,
					&io2sumsrc_backpending[i].header);
				io2sumsrc_backpending[i].load+=io2sumsrc_handler[i].load;
				io2sumsrc_handler[i].load=0;
				}
			}

		for(i=0;i<io_cnt;i++)
			{
			msg_C_return_poll(&io2sumsrc_backpending[i],io2sumsrc_back[i]);
			}

			//msg sumsrc2io
			for(i=0;i<io_cnt;i++)
				{
				msg_P_snd_poll(&local_sumsrc2io_msg_send_pending[i],local_sumsrc2io_msg_send[i]);
				}

			for(i=0;i<io_cnt;i++)
				{
				msg_P_retrieve_poll(local_sumsrc2io_msg_back[i],local_sumsrc2io_msg_pool);
				}
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc))
			{
#ifdef __SRC_SUM__
			if(!list_empty(&local_timer[timer_curr_idx].header))
				{
				list_splice_tail_init(&local_timer[timer_curr_idx].header,&local_srcsum_timeout.header);
//				RUNNING_LOG_INFO("core %d : timeout ,curr=%d\n",my_lcore,timer_curr_idx);
				}
#endif
			timer_curr_idx++;
			if(timer_curr_idx>=TIMER_LOOP_SZ)
				{
				timer_curr_idx=0;
				}

			cnt_1s++;
			if(cnt_1s==10000)	// TICK_CNT_1S_100US
				{
				cnt_1s=0;

				}

			prev_tsc = cur_tsc;
			}
#ifdef __SRC_SUM__
			if(!list_empty(&local_srcsum_timeout.header))
			{
			list_for_each_entry_safe(ssp, ssptmp, &local_srcsum_timeout.header, alloc_list)
				{
				list_del_init(&ssp->alloc_list);
				list_del_init(&ssp->tbl_list);
				list_add_tail(&ssp->alloc_list,&local_srcipsum_pool->header);
				local_srcipsum_pool->load++;

//				RUNNING_LOG_INFO("(%d) : SRC TIMEOUT BACK sip=%x dip=%x pool=%d\n",
//					my_lcore,ssp->src_addr,ssp->dst_addr,local_srcipsum_pool->load);
				}
			}
#endif
#if 1//test perf
			perf_end=rte_rdtsc()-perf_start;

			if(perf_end>timer_perform_max[my_lcore])
				timer_perform_max[my_lcore]=perf_end;

#endif
		}
}


int main_loop_sum_ip(void)
{
	int my_lcore;
	int i,j,k;
	struct lcore_info_s *local;
	uint64_t cur_tsc, prev_tsc,diff_tsc, hz;
	uint64_t start,end,count=0;
	struct hash_array *ip_hash;
	struct hash_array *remote_burst[MAX_CPU];
	struct hash_array *remote_back[MAX_CPU];
	struct hash_array local_rcv[MAX_CPU];
	struct hash_array *local_snd;
	struct hash_array local_alloced_list;
	int io_cnt;
	int tmp;
	struct hash_array *local_ip_pool;
	struct ip_g_s2 *ipm,*ipmtmp;
	struct wd_pack *localwd;
	uint32_t tick=0;
	char json_buf[20000];
	uint32_t nat_bandwidth[NAT_MAX_DSTNUM];
	uint32_t dst_pl_cfg_pre = viptoa_curr;
//	struct l4_port_g_b *tk;

	my_lcore=rte_lcore_id();
	local=&lcore[my_lcore];
	ip_hash=local->sum.sum_hash;
#ifdef WF_NAT
	io_cnt=__builtin_popcountll(me.io_in_mask|me.io_out_mask);
#else
	io_cnt=__builtin_popcountll(me.io_in_mask);
#endif
	rte_memcpy(remote_burst,local->sum.sum_ip_io2sum_burst,sizeof(struct hash_array *)*io_cnt);
	rte_memcpy(remote_back,local->sum.sum_ip_sum2io_burst,sizeof(struct hash_array *)*io_cnt);
	local_ip_pool=&local->sum.ip_sum_pool;
	local_snd=local->sum.sum_sum2io_pending;
	INIT_LIST_HEAD(&local_alloced_list.header);
	local_alloced_list.load=0;

	if (g_dst_pl != NULL){
		for (i = 0; i < NAT_MAX_DSTNUM; i++) {
//			nat_bandwidth[i] = g_dst_pl[i].ip.tcp_bps;
			if (g_dst_pl)
				{
				if (g_dst_pl[i].ip.tcp_bps)
					nat_bandwidth[i] = g_dst_pl[i].ip.tcp_bps;
				else
					nat_bandwidth[i] = 1000;
				}
			else
				nat_bandwidth[i] = 1000;
		}
	}

//	tk=local->sum.netport_tbl[0];

	for(i=0;i<io_cnt;i++)
		{
		INIT_LIST_HEAD(&local_rcv[i].header);
		local_rcv[i].load=0;
		}
	localwd=local->sum.wd;

	RUNNING_LOG_INFO("core %d :%s\n",my_lcore,__FUNCTION__);

	while(1){
		count++;
		start=rte_rdtsc();

		for(i=0;i<io_cnt;i++)//rcv
			{
			if(remote_burst[i]->load)
				{
				list_splice_tail_init(&remote_burst[i]->header,&local_rcv[i].header);
				tmp=remote_burst[i]->load;
				rte_smp_wmb();
				remote_burst[i]->load=0;
				rte_smp_wmb();
				local_rcv[i].load+=tmp;

#if 0//test
{
				int x=0;
				struct ip_g_s2 *ipm,*iptmp;

				list_for_each_entry_safe(ipm, iptmp, &local_rcv[i].header, pending_list)
					{
					x++;
					RUNNING_LOG_DEBUG("%s: core<%d> rcv test ip=%x cnt=%d\n",__FUNCTION__,rte_lcore_id(),ipm->addr,
						x);
					}
}
#endif

				RUNNING_LOG_DEBUG("core %d :remote_burst[%d]->load=%d local_rcv.load=%d\n",
					my_lcore,i,tmp,local_rcv[i].load);

				}
			}

		for(i=0;i<io_cnt;i++)//process
			{
			if(local_rcv[i].load)
				{
				RUNNING_LOG_DEBUG("core %d :local_rcv[%d]->load=%d local_snd.load=%d\n",
					my_lcore,i,local_rcv[i].load,local_snd[i].load);

				list_for_each_entry_safe(ipm,ipmtmp,&local_rcv[i].header,pending_list)
					{
					process_sum_dstip(local_ip_pool,ip_hash,&local_alloced_list,
						ipm,&local->sum);
					list_del_init(&ipm->pending_list);
					list_add_tail(&ipm->list,&local_snd[i].header);
					local_snd[i].load++;
					local_rcv[i].load--;
					}
//				local_snd[i].load+=local_rcv[i].load;
//				local_rcv[i].load=0;

				RUNNING_LOG_DEBUG("core %d :deal local_snd[%d].load=%d local_rcv[i].load=%d\n",
					my_lcore,i,local_snd[i].load,local_rcv[i].load);

				}
			}

		for(i=0;i<io_cnt;i++)//free back
			{
			//ip
			if((!remote_back[i]->load)&&(local_snd[i].load))
				{
				list_splice_tail_init(&local_snd[i].header,&remote_back[i]->header);
				rte_smp_wmb();
				remote_back[i]->load=local_snd[i].load;
				rte_smp_wmb();
				local_snd[i].load=0;

				RUNNING_LOG_DEBUG("core %d :push back remote_back[%d]->load=%d\n",
					my_lcore,i,remote_back[i]->load);
				}
			}

		if(unlikely(local->timer_flag))
		{
			struct ip_sum_b *ppx;
			struct ip_sum_b *ips,*ipstmp;
			int idx = 0;

			local->timer_flag=0;
			memset(nat_flow_limit, 0, sizeof(nat_flow_limit));

			if (dst_pl_cfg_pre != viptoa_curr) {
				dst_pl_cfg_pre = viptoa_curr;

				for (i = 0; i < NAT_MAX_DSTNUM; i++) {
					if (g_dst_pl)
						{
						if (g_dst_pl[i].ip.tcp_bps)
							nat_bandwidth[i] = g_dst_pl[i].ip.tcp_bps;
						else
							nat_bandwidth[i] = 1000;
						}
					else
						nat_bandwidth[i] = 1000;
				}
			}

			if(!list_empty(&local_alloced_list.header))
			{
				list_for_each_entry_safe(ips, ipstmp, &local_alloced_list.header, alloc_list)
				{
					if (((ips->ip_sum[0].ip.bps )>>17) > nat_bandwidth[ips->ip_idx]
						||((ips->ip_sum[1].ip.bps)>>17) > nat_bandwidth[ips->ip_idx])  // Byte per s => Mbps
					{
						RUNNING_LOG_INFO("core %d :ip=0x%x,bps=%d=>%d,idx=%d, bandwidth=%d,nat flow limit!\n",my_lcore,ips->addr,
							(ips->ip_sum[0].ip.bps),(ips->ip_sum[1].ip.bps),ips->ip_idx,nat_bandwidth[ips->ip_idx]);

						idx = (ips->ip_idx)>>5; //uint32_t, 32bit
						nat_flow_limit[idx] |= 1ULL<<((ips->ip_idx)&0x1f);
					}

//					if( ips->ip_idx ==234)
//					RUNNING_LOG_INFO("core %d :ip=0x%x,bps=%d %d,idx=%d, bandwidth=%d,linkcount=%d!\n",my_lcore,ips->addr,
//							(ips->ip_sum[0].ip.bps),(ips->ip_sum[1].ip.bps),ips->ip_idx,nat_bandwidth[ips->ip_idx],nat_linkcount[ips->ip_idx]);

					format_json_dstip_sum(ips,json_buf);
				}
				rte_smp_wmb();

				list_splice_tail_init(&local_alloced_list.header,&local_ip_pool->header);
				local_ip_pool->load+=local_alloced_list.load;
				local_alloced_list.load=0;
			}

			for(i=0;i<IP_HASH_ARRAY_SZ;i++)
				{
				INIT_LIST_HEAD(&ip_hash[i].header);
				}

			rte_smp_wmb();
		}

		end=rte_rdtsc()-start;

#if 1//perform test

		if(end>timer_perform_max[my_lcore])
			timer_perform_max[my_lcore]=end;
		if((end<timer_perform_min[my_lcore])||!timer_perform_min[my_lcore])
			timer_perform_min[my_lcore]=end;

		if(timer_perform_aver[my_lcore]==0)
			timer_perform_aver[my_lcore]=end;
		else
			timer_perform_aver[my_lcore]=((count-1)*timer_perform_aver[my_lcore]+end)/count;

//		RUNNING_LOG_INFO("core %d :sum perform min=%llu aver=%llu max=%llu\n",
//			my_lcore,timer_perform_min[my_lcore],timer_perform_aver[my_lcore],timer_perform_max[my_lcore]);

#endif

		}
}
static inline uint32_t csum_tcpudp_nofold (uint32_t saddr, uint32_t daddr,
	uint16_t len, uint8_t proto, uint32_t sum)
{
    asm("addl %1, %0\n"    /* 累加daddr */
        "adcl %2, %0\n"    /* 累加saddr */
        "adcl %3, %0\n"    /* 累加len(2字节), proto, 0*/
        "adcl $0, %0\n"    /*加上进位 */
        : "=r" (sum)
        : "g" (daddr), "g" (saddr), "g" ((ntohs(len) << 16) + proto*256), "0" (sum));
    return sum;
}

static inline uint16_t csum_tcpudp_magic(__be32 saddr, __be32 daddr,
	uint16_t len, uint8_t proto,  uint32_t sum)
{
    return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

/*
 * Calculate(/check) TCP checksum
 */
static inline __sum16 tcp_v4_check(int len, __be32 saddr,
				   __be32 daddr, uint32_t base)
{
	return csum_tcpudp_magic(saddr,daddr,len,IPPROTO_TCP,base);
}

uint16_t get_ip_checksum( uint16_t * addr, int count )
{
       /* Compute Internet Checksum for "count" bytes
        * beginning at location "addr".
       */
       uint32_t sum = 0;

       while ( count > 1 )

       {
           /* This is the inner loop */
           sum += *addr++;
           count -=2;
        }

       /* Add left-over byte, if any */
       if ( count > 0 )
           sum += * ( unsigned char * ) addr;

	/* Fold 32-bit sum to 16 bits */
	sum=(sum>>16)+(sum&0xffff);  //把高位的进位，加到低八位，其实是32位加法
	sum+=(sum>>16);  //add carry

       return (uint16_t)~sum;
}

static inline int __attribute__((always_inline))
nat_create_srcdstip_list(struct snat_item *snattable, struct dnat_item *dnattable,
		struct hash_array *ip_hash, struct hash_array * ip_pool,
		struct hash_array *srcip_alloclist,int reset)
{
	int i,j,k;
	uint32_t hash_idx = 0;
	uint32_t tmp_ip = 0;
	int num = 0;
	int hit = 0;
	struct srcip_nat *srcipnat,*ipnat,*ipnattmp;

	if (reset)
	{
		RUNNING_LOG_INFO("core %d :%s reset list!\n",rte_lcore_id(), __FUNCTION__);
		if(!list_empty(&srcip_alloclist->header))
		{
			list_for_each_entry_safe(ipnat, ipnattmp, &srcip_alloclist->header, alloc_list)
			{
				list_del_init(&ipnat->tbl_list);
				list_move_tail(&ipnat->alloc_list,&ip_pool->header);
				ip_pool->load++;

			}
		}
	}

	//add vip
	for( i = 0; i < NAT_MAX_DSTNUM; i++)
	{
		hit = 0;
		if (0 != dnattable[i].dst_ip)
		{
			tmp_ip = dnattable[i].dst_ip;
			hash_idx = tmp_ip & (IP_HASH_ARRAY_SZ - 1);
			if(!list_empty(&ip_hash[hash_idx].header))
			{
				list_for_each_entry_safe(ipnat, ipnattmp, &ip_hash[hash_idx].header, tbl_list)
				{
					if((ipnat->self == tmp_ip) && (ipnat->dstip== dnattable[i].dst_ip))
					{
						hit = 1;
						break;
					}
				}
			}

			if(hit == 0)
			{
				if(ip_pool->load)
				{
					srcipnat = list_first_entry(&ip_pool->header, struct srcip_nat, alloc_list);
					srcipnat->self= dnattable[i].dst_ip;
					srcipnat->dstip = dnattable[i].dst_ip;
					srcipnat->dstip_idx= dnattable[i].dstip_idx;

					INIT_LIST_HEAD(&srcipnat->tbl_list);
					list_add_tail(&srcipnat->tbl_list, &ip_hash[hash_idx].header);
					list_del_init(&srcipnat->alloc_list);
					list_add_tail(&srcipnat->alloc_list, &srcip_alloclist->header);
					ip_pool->load--;
					num++;
				}else{
					RUNNING_LOG_INFO("core %d :%s ip_pool->load=0!\n",rte_lcore_id(), __FUNCTION__);
					return 0;
				}
			}
		}else{
			break;
		}
	}
#if 0

	//add realip
	for( i = 0; i < NAT_MAX_DSTNUM; i++)
	{
		if (0 != dnattable[i].dst_ip)
		{
			for( j = 0; j < NAT_MAX_RULENUM; j++)
			{
				if (0 == dnattable[i].rule[j].proto)
					break;
				for( k = 0; k < NAT_MAX_NATIPNUM; k++)
				{
					hit = 0;
					if( 0 != dnattable[i].rule[j].nat_ip[k])
					{
						tmp_ip = dnattable[i].rule[j].nat_ip[k];
						hash_idx = tmp_ip & (IP_HASH_ARRAY_SZ - 1);
						if(!list_empty(&ip_hash[hash_idx].header))
						{
							list_for_each_entry_safe(ipnat, ipnattmp, &ip_hash[hash_idx].header, tbl_list)
							{
								if((ipnat->self == tmp_ip) && (ipnat->dstip== dnattable[i].dst_ip))
								{
									hit = 1;
									break;
								}
							}
						}

						if(hit == 0)
						{
							if(ip_pool->load)
							{
								srcipnat = list_first_entry(&ip_pool->header, struct srcip_nat, alloc_list);
								srcipnat->self= tmp_ip;
								srcipnat->dstip = dnattable[i].dst_ip;
								srcipnat->dstip_idx= dnattable[i].dstip_idx;

								INIT_LIST_HEAD(&srcipnat->tbl_list);
								list_add_tail(&srcipnat->tbl_list, &ip_hash[hash_idx].header);
								list_del_init(&srcipnat->alloc_list);
								list_add_tail(&srcipnat->alloc_list, &srcip_alloclist->header);
								ip_pool->load--;
								num++;
							}else{
								RUNNING_LOG_INFO("core %d :%s ip_pool->load=0!\n",rte_lcore_id(), __FUNCTION__);
								return 0;
							}
						}
					}else{
						break;
					}
				}

			}
		}
		else{
			break;
		}
	}
#endif

	//add srcip
	for( i = 0; i < NAT_MAX_DSTNUM; i++)
	{
		if (0 != snattable[i].dst_ip)
		{
			for( j = 0; j < snattable[i].sip_num; j++)
			{
                hit = 0;
				tmp_ip = snattable[i].snat_ip[j];
				hash_idx = tmp_ip & (IP_HASH_ARRAY_SZ - 1);
				if(!list_empty(&ip_hash[hash_idx].header))
				{
					list_for_each_entry_safe(ipnat, ipnattmp, &ip_hash[hash_idx].header, tbl_list)
					{
						if((ipnat->self == tmp_ip) && (ipnat->dstip== snattable[i].dst_ip))
						{
							hit = 1;
							break;
						}
					}
				}

				if(hit == 0)
				{
					if(ip_pool->load)
					{
						srcipnat = list_first_entry(&ip_pool->header, struct srcip_nat, alloc_list);
						srcipnat->self= tmp_ip;
						srcipnat->dstip = snattable[i].dst_ip;
						srcipnat->dstip_idx= i;

						INIT_LIST_HEAD(&srcipnat->tbl_list);
						list_add_tail(&srcipnat->tbl_list, &ip_hash[hash_idx].header);
						list_del_init(&srcipnat->alloc_list);
						list_add_tail(&srcipnat->alloc_list, &srcip_alloclist->header);
						ip_pool->load--;
						num++;
					}else{
						RUNNING_LOG_INFO("core %d :%s ip_pool->load=0!\n",rte_lcore_id(), __FUNCTION__);
						return 0;
					}
				}
			}
		}else{
			break;
		}
	}

	return num;
}

static inline int __attribute__((always_inline))
nat_create_snatip_list(struct snat_item *snattable,
		struct hash_array *ip_hash, struct hash_array * ip_pool,
		struct hash_array *srcip_alloclist)
{
	int i,j,k;
	uint32_t hash_idx = 0;
	uint32_t tmp_ip = 0;
	int num = 0;
	int hit = 0;
	struct snat_ip*srcipnat,*ipnat,*ipnattmp;

	if(!list_empty(&srcip_alloclist->header))
	{
		list_for_each_entry_safe(ipnat, ipnattmp, &srcip_alloclist->header, alloc_list)
		{
			list_del_init(&ipnat->tbl_list);
			list_move_tail(&ipnat->alloc_list,&ip_pool->header);
			ip_pool->load++;
		}
	}

	//add srcip
	for( i = 0; i < NAT_MAX_DSTNUM; i++)
	{
		if (0 != snattable[i].dst_ip)
		{
			if(ip_pool->load)
			{
				hash_idx = snattable[i].dst_ip & (IP_HASH_ARRAY_SZ - 1);
				srcipnat = list_first_entry(&ip_pool->header, struct snat_ip, alloc_list);
				memset(srcipnat->snat_ip, 0, sizeof(uint32_t)*NAT_MAX_SIPNUM);
				rte_memcpy(srcipnat->snat_ip, snattable[i].snat_ip, sizeof(uint32_t)*snattable[i].sip_num);
				srcipnat->dstip = snattable[i].dst_ip;
				srcipnat->sip_sum=snattable[i].sip_num;
				srcipnat->deadtime= snattable[i].vip_deadtime;

//				RUNNING_LOG_DEBUG("core %d :%s dst_ip:%u.%u.%u.%u\n",rte_lcore_id(), __FUNCTION__, srcipnat->dstip>>24,(srcipnat->dstip>>16) & 0xff,
//					(srcipnat->dstip>>8) & 0xff, (srcipnat->dstip) & 0xff);
//				{
//					int k;
//					for (k=0;k<NAT_MAX_SIPNUM;k++){
//						RUNNING_LOG_DEBUG("core %d :%s snat_ip:%u.%u.%u.%u\n",rte_lcore_id(), __FUNCTION__,
//							srcipnat->snat_ip[k]>>24,
//							(srcipnat->snat_ip[k]>>16) & 0xff,
//							(srcipnat->snat_ip[k]>>8) & 0xff,
//							srcipnat->snat_ip[k] & 0xff);
//					}
//				}

				INIT_LIST_HEAD(&srcipnat->tbl_list);
				list_add_tail(&srcipnat->tbl_list, &ip_hash[hash_idx].header);
				list_del_init(&srcipnat->alloc_list);
				list_add_tail(&srcipnat->alloc_list, &srcip_alloclist->header);
				ip_pool->load--;
				num++;
			}else{
				RUNNING_LOG_INFO("core %d :%s ip_pool->load=0!\n",rte_lcore_id(), __FUNCTION__);
				return 0;
			}

		}else{
			break;
		}
	}
	if (2 == rte_lcore_id())
		RUNNING_LOG_INFO("core %d :%s num=%d\n",rte_lcore_id(), __FUNCTION__, num);

	return num;
}

static inline int __attribute__((always_inline))
nat_create_toavip_list(uint32_t *toaviptable,
		struct hash_array *viptoa_hash, struct hash_array * viptoa_pool,
		struct hash_array *viptoa_alloclist)
{
	int i,j,k;
	uint32_t hash_idx = 0;
	int num = 0;
	struct toa_vip*toa,*viptoa,*viptoatmp;

	if(!list_empty(&viptoa_alloclist->header))
	{
		list_for_each_entry_safe(viptoa, viptoatmp, &viptoa_alloclist->header, alloc_list)
		{
			list_del_init(&viptoa->tbl_list);
			list_move_tail(&viptoa->alloc_list,&viptoa_pool->header);
			viptoa_pool->load++;
		}
	}

	//add vip
	for( i = 0; i < NAT_MAX_DSTNUM; i++)
	{
		if (0 != toaviptable[i])
		{
			if(viptoa_pool->load)
			{
				hash_idx = toaviptable[i] & (TOA_IP_HASH_ARRAY_SZ - 1);
				toa = list_first_entry(&viptoa_pool->header, struct toa_vip, alloc_list);
				toa->vip = toaviptable[i];

				INIT_LIST_HEAD(&toa->tbl_list);
				list_add_tail(&toa->tbl_list, &viptoa_hash[hash_idx].header);
				list_del_init(&toa->alloc_list);
				list_add_tail(&toa->alloc_list, &viptoa_alloclist->header);
				viptoa_pool->load--;
				num++;
			}else{
				RUNNING_LOG_INFO("core %d :%s ip_pool->load==0!\n",rte_lcore_id(), __FUNCTION__);
				return 0;
			}

		}
	}

	return num;
}

static inline int __attribute__((always_inline))
nat_create_dnatconfig_list(struct dnat_item *dnattable,
		struct hash_array *dnatconfig_hash, struct hash_array * dnatconfig_pool,
		struct hash_array *dnatconfig_alloclist)
{
	int i,j,k;
	uint32_t hash_idx = 0;
	uint32_t data[3];
	int num = 0;
	struct dnat_config *dconfig,*dantconfig,*dantconfigtmp;

	if(!list_empty(&dnatconfig_alloclist->header))
	{
		list_for_each_entry_safe(dantconfig, dantconfigtmp, &dnatconfig_alloclist->header, alloc_list)
		{
			list_del_init(&dantconfig->tbl_list);
			list_move_tail(&dantconfig->alloc_list,&dnatconfig_pool->header);
			dnatconfig_pool->load++;
		}
	}

	//add
	for( i = 0; i < NAT_MAX_DSTNUM; i++)
	{
		if (0 != dnattable[i].dst_ip)
		{
			for (j = 0; j < NAT_MAX_RULENUM; j++)
			{
				if (0 != dnattable[i].rule[j].dst_port)
				{
					if(dnatconfig_pool->load)
					{
//			if(rte_lcore_id()==3)
//			RUNNING_LOG_INFO("core %d :%s vip=0x%x,port=%d\n",rte_lcore_id(), __FUNCTION__,dnattable[i].dst_ip,dnattable[i].rule[j].dst_port);

						dconfig = list_first_entry(&dnatconfig_pool->header, struct dnat_config, alloc_list);
						dconfig->dstip = dnattable[i].dst_ip;
						dconfig->rule = dnattable[i].rule[j];
//						memcpy(dconfig->rule,dnattable[i].rule[j],sizeof(struct dnat_rule));
						dconfig->index_dstip = dnattable[i].dstip_idx;
						dconfig->index_rule = j;
#ifdef BOND_2DIR
						dconfig->forward_level = g_dst_pl ? g_dst_pl[dnattable[i].dstip_idx].fwd_level : 4;
#endif
						dconfig->fwd_realip_mode = dnattable[i].fwd_realip_mode;

//						RUNNING_LOG_DEBUG("core %d :%s vip=%u.%u.%u.%u,port=%d\n",rte_lcore_id(), __FUNCTION__,
//							dnattable[i].dst_ip>>24,(dnattable[i].dst_ip>>16)&0xff,(dnattable[i].dst_ip>>8)&0xff,dnattable[i].dst_ip & 0xff,
//							dnattable[i].rule[j].dst_port);
//						{
//							int k;
//							for (k=0;k<NAT_MAX_NATIPNUM;k++)
//								RUNNING_LOG_INFO("nat ip=%u.%u.%u.%u\n",dconfig->rule.nat_ip[k]>>24,(dconfig->rule.nat_ip[k]>>16)&0xff,
//									(dconfig->rule.nat_ip[k]>>8) & 0xff, dconfig->rule.nat_ip[k] & 0xff);
//						}

						data[0] = dnattable[i].dst_ip;
						data[1] = dnattable[i].rule[j].dst_port;
						data[2] = 0;
						hash_idx = rte_jhash_3words(data[0], data[1], data[2], PRIME_VALUE);
						hash_idx = hash_idx & (DNAT_CONFIG_HASH_ARRAY_SZ - 1);
						INIT_LIST_HEAD(&dconfig->tbl_list);
						list_add_tail(&dconfig->tbl_list, &dnatconfig_hash[hash_idx].header);
						list_del_init(&dconfig->alloc_list);
						list_add_tail(&dconfig->alloc_list, &dnatconfig_alloclist->header);
						dnatconfig_pool->load--;
						num++;
					}else{
						RUNNING_LOG_ERROR("core %d :%s pool->load=0!\n",rte_lcore_id(), __FUNCTION__);
						return 0;
					}
				}else{
					break;
				}
			}

		}else{
			break;
		}
	}

	return num;
}


/*
 * remove tcp timestamp opt in one packet, just set it to TCPOPT_NOP
 * return 1 if success
 */
static inline int __attribute__((always_inline))
tcp_opt_replace_timestamp(struct tcp_hdr *tcph, struct pp_info ptk_info)
{
	unsigned char *ptr;
	__be32 oldbuf[4], newbuf[4];
        struct toa_data *toa;
	int length;
	int i;

	ptr = (unsigned char *)(tcph + 1);
	length = ((tcph->data_off & 0xf0) >> 2) - sizeof(struct tcp_hdr);

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return 0;
		case TCPOPT_NOP:	/* Ref: RFC 793 section 3.1 */
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2)	/* "silly options" */
				return;
			if (opsize > length)
				return;	/* don't parse partial options */
			if ((opcode == TCPOPT_TIMESTAMP)
			    && (opsize == TCPOLEN_TIMESTAMP))
			{
				/* the length of buf is 16Byte,
				 * but data is 10Byte. zero the buf
				 */
				memset((__u8*)oldbuf, 0, sizeof(oldbuf));
				memcpy((__u8*)oldbuf, ptr - 2, TCPOLEN_TIMESTAMP);

				for (i = 0; i < TCPOLEN_TIMESTAMP; i++) {
					*(ptr - 2 + i) = TCPOPT_NOP;	/* TCPOPT_NOP replace timestamp opt */
				}

                                toa =  (struct toa_data *)(ptr - 2);
                                toa->opcode = TCPOPT_ADDR;
                        	toa->opsize = TCPOLEN_ADDR;
                        	toa->port = rte_cpu_to_be_16(ptk_info.sport);
                        	toa->ip = rte_cpu_to_be_32(ptk_info.srcip);

				memset((__u8*)newbuf, 0, sizeof(newbuf));
				memcpy((__u8*)newbuf, ptr - 2, TCPOLEN_TIMESTAMP);
                                csum_replace16(&tcph->cksum, oldbuf, newbuf);

				return 1;
			}

			ptr += opsize - 2;
			length -= opsize;
		}
	}
        return 0;
}

/*
 * add client (ip and port) in tcp option
 * return 1 if success
 */
static inline int __attribute__((always_inline))
tcp_opt_add_toa(struct rte_mbuf *mbuf, struct tcp_hdr *tcph, struct pp_info ptk_info)
{
        struct toa_data *toa;
        uint8_t *p, *q;

        struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
        struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)((uint8_t *)eth_hdr + sizeof(struct ether_hdr));

        /* skb length and tcp option length checking */
        if (mbuf->pkt_len > 1000)
            return 0;

        /* the maximum length of TCP head is 60 bytes, so only 40 bytes for options */
	if (((tcph->data_off & 0xf0) >> 2) + sizeof(struct toa_data) > 60) {
		return 0;
	}

        p = (uint8_t *)eth_hdr + mbuf->pkt_len;
	q = p + sizeof(struct toa_data);

	/* move data down, offset is sizeof(struct toa_data) */
	while (p >= ((uint8_t *) tcph + sizeof(struct tcp_hdr))) {
		*q = *p;
		p--;
		q--;
	}

    	/* put client ip opt , ptr point to opts */
	toa = (struct toa_data *)(tcph + 1);
	toa->opcode = TCPOPT_ADDR;
	toa->opsize = TCPOLEN_ADDR;
	toa->port = rte_cpu_to_be_16(ptk_info.sport);
	toa->ip = rte_cpu_to_be_32(ptk_info.srcip);

	/* reset tcp header length */
	tcph->data_off += (sizeof(struct toa_data) / 4)<<4;
	/* reset ip header totoal length */
	ip_hdr->total_length =
	    htons(ntohs(ip_hdr->total_length) + sizeof(struct toa_data));

	/* reset skb length */
	mbuf->pkt_len += sizeof(struct toa_data);
        mbuf->data_len += sizeof(struct toa_data);

	/* re-calculate tcp csum, if no csum_offload */
	{
	        int ipv4_hdr_len = (ip_hdr->version_ihl & IPV4_HDR_IHL_MASK)<<2;
	        int len = rte_be_to_cpu_16(ip_hdr->total_length) -  ipv4_hdr_len;
		tcph->cksum = 0;
		tcph->cksum = tcp_v4_check(len, ip_hdr->src_addr, ip_hdr->dst_addr,
			 csum_partial(tcph, len, 0));
	}

	/* re-calculate ip head csum, tot_len has been adjusted */
	ip_hdr->hdr_checksum = 0;
        ip_hdr->hdr_checksum = get_ip_checksum((uint16_t *)ip_hdr, sizeof(struct ipv4_hdr));
}

static inline int __attribute__((always_inline))
nat_toavip_find(uint32_t dstip, struct hash_array *vip_hash)
{
	uint32_t hash_idx = 0;
	uint32_t tmp_ip = 0;
	struct toa_vip *viptoa,*viptoatmp;

//	RUNNING_LOG_INFO("core %d :%s dstip=0x%x\n",rte_lcore_id(), __FUNCTION__, dstip);

	//check dstip
	tmp_ip = dstip;
	hash_idx = tmp_ip & (TOA_IP_HASH_ARRAY_SZ - 1);

	if(!list_empty(&vip_hash[hash_idx].header))
	{
		list_for_each_entry_safe(viptoa, viptoatmp, &vip_hash[hash_idx].header, tbl_list)
		{
			if(tmp_ip == viptoa->vip)
			{
				return 1;
			}
		}
	}

	return 0;
}

void
initialize_eth_header(struct ether_hdr *eth_hdr, struct ether_addr *src_mac,
		struct ether_addr *dst_mac, uint16_t ether_type,
		uint8_t vlan_enabled, uint16_t van_id)
{
	ether_addr_copy(dst_mac, &eth_hdr->d_addr);
	ether_addr_copy(src_mac, &eth_hdr->s_addr);

	if (vlan_enabled) {
		struct vlan_hdr *vhdr = (struct vlan_hdr *)((uint8_t *)eth_hdr +
				sizeof(struct ether_hdr));

		eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_VLAN);

		vhdr->eth_proto =  rte_cpu_to_be_16(ether_type);
		vhdr->vlan_tci = van_id;
	} else {
		eth_hdr->ether_type = rte_cpu_to_be_16(ether_type);
	}
}

void
initialize_arp_header(struct arp_hdr *arp_hdr, struct ether_addr *src_mac,
		struct ether_addr *dst_mac, uint32_t src_ip, uint32_t dst_ip,
		uint32_t opcode)
{
	arp_hdr->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
	arp_hdr->arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	arp_hdr->arp_hln = ETHER_ADDR_LEN;
	arp_hdr->arp_pln = sizeof(uint32_t);
	arp_hdr->arp_op = rte_cpu_to_be_16(opcode);
	ether_addr_copy(src_mac, &arp_hdr->arp_data.arp_sha);
	arp_hdr->arp_data.arp_sip = src_ip;
	ether_addr_copy(dst_mac, &arp_hdr->arp_data.arp_tha);
	arp_hdr->arp_data.arp_tip = dst_ip;
}

static inline void __attribute__((always_inline))
do_create_arp_req(struct rte_mbuf *created_pkt,int port,
	uint32_t sip,uint32_t tip)
{
	struct ether_hdr *eth_hdr;
	struct arp_hdr *arp_hdr;
	size_t pkt_size;

	pkt_size = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
	created_pkt->data_len = pkt_size;
	created_pkt->pkt_len = pkt_size;

	eth_hdr = rte_pktmbuf_mtod(created_pkt, struct ether_hdr *);
	ether_addr_copy(rte_eth_devices[port].data->mac_addrs,
			&eth_hdr->s_addr);
	memset(&eth_hdr->d_addr, 0xFF, ETHER_ADDR_LEN);
	eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_ARP);

	arp_hdr = (struct arp_hdr *)((char *)eth_hdr + sizeof(struct ether_hdr));
	arp_hdr->arp_hrd = rte_cpu_to_be_16(ARP_HRD_ETHER);
	arp_hdr->arp_pro = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	arp_hdr->arp_hln = ETHER_ADDR_LEN;
	arp_hdr->arp_pln = sizeof(uint32_t);
	arp_hdr->arp_op = rte_cpu_to_be_16(ARP_OP_REQUEST);

	ether_addr_copy(rte_eth_devices[port].data->mac_addrs,
			&arp_hdr->arp_data.arp_sha);
	arp_hdr->arp_data.arp_sip =sip;
	memset(&arp_hdr->arp_data.arp_tha, 0, ETHER_ADDR_LEN);
	arp_hdr->arp_data.arp_tip =tip;

	return;
}

#define PRINT_MAC(ADDR) 	\
	RUNNING_LOG_INFO("%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8"\n", \
										ADDR[0], ADDR[1], ADDR[2],ADDR[3], ADDR[4], ADDR[5]);

static inline uint16_t __attribute__((always_inline))
ipv4_hdr_cksum(struct ipv4_hdr *ip_h)
{
	uint16_t *v16_h;
	uint32_t ip_cksum;

	/*
	 * Compute the sum of successive 16-bit words of the IPv4 header,
	 * skipping the checksum field of the header.
	 */
	v16_h = (unaligned_uint16_t *) ip_h;
	ip_cksum = v16_h[0] + v16_h[1] + v16_h[2] + v16_h[3] +
		v16_h[4] + v16_h[6] + v16_h[7] + v16_h[8] + v16_h[9];

	/* reduce 32 bit checksum to 16 bits and complement it */
	ip_cksum = (ip_cksum & 0xffff) + (ip_cksum >> 16);
	ip_cksum = (ip_cksum & 0xffff) + (ip_cksum >> 16);
	ip_cksum = (~ip_cksum) & 0x0000FFFF;
	return (ip_cksum == 0) ? 0xFFFF : (uint16_t) ip_cksum;
}

#define is_multicast_ipv4_addr(ipv4_addr) \
	(((rte_be_to_cpu_32((ipv4_addr)) >> 24) & 0x000000FF) == 0xE0)

struct rte_mbuf *gen_icmp_pkt(struct rte_mbuf *m)
{
	int offset = 0;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct icmp_hdr *icmp_h;
	uint32_t ip_addr;
	uint32_t cksum;

	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)((uint8_t *)eth_hdr + sizeof(struct ether_hdr) + offset);
	icmp_h = (struct icmp_hdr *) ((char *)ipv4_hdr + sizeof(struct ipv4_hdr));
	if((icmp_h->icmp_type == IP_ICMP_ECHO_REQUEST) && (icmp_h->icmp_code == 0))
	{
		ip_addr = ipv4_hdr->src_addr;
		if (is_multicast_ipv4_addr(ipv4_hdr->dst_addr)) {
			uint32_t ip_src;

			ip_src = rte_be_to_cpu_32(ip_addr);
			if ((ip_src & 0x00000003) == 1)
				ip_src = (ip_src & 0xFFFFFFFC) | 0x00000002;
			else
				ip_src = (ip_src & 0xFFFFFFFC) | 0x00000001;
			ipv4_hdr->src_addr = rte_cpu_to_be_32(ip_src);
			ipv4_hdr->dst_addr = ip_addr;
			ipv4_hdr->hdr_checksum = ipv4_hdr_cksum(ipv4_hdr);
		} else {
			ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
			ipv4_hdr->dst_addr = ip_addr;
		}
		icmp_h->icmp_type = IP_ICMP_ECHO_REPLY;
		cksum = ~icmp_h->icmp_cksum & 0xffff;
		cksum += ~htons(IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
		cksum += htons(IP_ICMP_ECHO_REPLY << 8);
		cksum = (cksum & 0xffff) + (cksum >> 16);
		cksum = (cksum & 0xffff) + (cksum >> 16);
		icmp_h->icmp_cksum = ~cksum;
	}

	return m;
}

int main_loop_distribute(void)
{
	int my_lcore;
	int i,j,k,nb_rx,nb_tx;
	uint8_t port_arr[MAX_DEV];
	uint16_t queue_arr[MAX_DEV];
	struct rte_mbuf *pkts_burst[BURST_SZ];
	struct lcore_info_s *local;
#ifdef __MAIN_LOOP_KNI__
	struct rte_ring *ring_kni[MAX_DEV];
#endif
//	struct dnat_item local_dtable[NAT_MAX_DSTNUM] = {0};
	struct dnat_item *local_dtable;
//	struct snat_item local_stable[NAT_MAX_DSTNUM] = {0};
	struct snat_item *local_stable;

	struct rte_ring *ring_dist[MAX_CPU][MAX_DEV];
	struct lcore_info_s *io_core[MAX_CPU]={NULL};

	struct out_buf_s out[MAX_DEV];
	struct out_buf_s *pout;
	int pos = 0;
	int num_dstip = 0;

	struct hash_array *local_srcipnat_pool,*local_srcipnat_hash;
	struct hash_array local_srcip_alloclist;
	struct srcip_nat *srcipnat;

	uint64_t cur_tsc, prev_tsc,diff_tsc, hz;
	uint64_t mask;
	uint64_t tick0,tick1,tick2,tick3,tick4;
	int port_cnt = 0;
	int port_id = 0;
	int io_cnt = 0;
	int ret=0;
	uint32_t pre_dtable = dnatconfig_curr;
	uint32_t pre_stable = snatconfig_curr;
	int flag_inout[MAX_DEV];
    uint32_t mon_ip = me.mon_vip;
#ifdef __INTER_CONN_IP__
	uint32_t idx_ring_conn_ip=0;
#endif
	struct ether_hdr *eth_hdr;
	struct ether_addr d_addr;

//	uint32_t if_ip[]={rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.in_ip & me.settle_setting.gw_bonding_inoutvlan.in_ipmask),
//		rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.out_ip & me.settle_setting.gw_bonding_inoutvlan.out_ipmask)};
	uint32_t if_ip[]={rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.in_ip),rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.out_ip)};
	uint32_t if_ipmask[]={rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.in_ipmask),
		rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.out_ipmask)};
	uint32_t gw_ip[]={rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.in_gw_ip),rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.out_gw_ip)};

	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1)/US_PER_S * TIME_DPI;//100us
	uint32_t tsc_cnt_10s=0;

	my_lcore=rte_lcore_id();

	local=&lcore[my_lcore];
	port_cnt=local->port_cnt;
	local_srcipnat_pool = &local->distribute.srcipnat_pool;
	local_srcipnat_hash = local->distribute.io_srcip_hash;
	INIT_LIST_HEAD(&local_srcip_alloclist.header);

//	RUNNING_LOG_INFO("core %d :%s %d\n",my_lcore, __FUNCTION__, port_cnt);

#ifdef WF_NAT
			io_cnt=__builtin_popcountll(me.io_in_mask|me.io_out_mask);
#else
			io_cnt=__builtin_popcountll(me.io_in_mask);
#endif

	rte_memcpy(port_arr, local->port_id, sizeof(local->port_id[0])*MAX_DEV);
	rte_memcpy(queue_arr, local->queue_id, sizeof(local->queue_id[0])*MAX_DEV);
#ifdef __MAIN_LOOP_KNI__
	rte_memcpy(ring_kni, local->distribute.kni_ring, sizeof(struct rte_ring *)*MAX_DEV);
#endif

	local_dtable = (struct dnat_item *)rte_zmalloc_socket(NULL, sizeof(struct dnat_item)*NAT_MAX_DSTNUM,
			8,rte_lcore_to_socket_id(my_lcore));
	if (!local_dtable)
	{
		RUNNING_LOG_ERROR("%s core<%u> can not malloc local_dtable\n", __FUNCTION__, my_lcore);
		return -1;
	}
	local_stable = (struct snat_item *)rte_zmalloc_socket(NULL, sizeof(struct snat_item)*NAT_MAX_DSTNUM,
			8,rte_lcore_to_socket_id(my_lcore));
	if (!local_stable)
	{
		RUNNING_LOG_ERROR("%s core<%u> can not malloc local_stable\n", __FUNCTION__, my_lcore);
		return -1;
	}

	if (dnatconfig_curr)
		rte_memcpy(local_dtable, &dtable[NAT_MAX_DSTNUM], sizeof(struct dnat_item) * NAT_MAX_DSTNUM);
	else
		rte_memcpy(local_dtable, &dtable[0], sizeof(struct dnat_item) * NAT_MAX_DSTNUM);

	if (snatconfig_curr)
		rte_memcpy(local_stable, &stable[NAT_MAX_DSTNUM], sizeof(struct snat_item) * NAT_MAX_DSTNUM);
	else
		rte_memcpy(local_stable, &stable[0], sizeof(struct snat_item) * NAT_MAX_DSTNUM);

//	num_dstip = nat_get_dstip_num(local_dtable);
	ret = nat_create_srcdstip_list(local_stable, local_dtable, local_srcipnat_hash, local_srcipnat_pool, &local_srcip_alloclist, 0);
	RUNNING_LOG_INFO("core %d :%s srcdstip_list=%d\n",my_lcore, __FUNCTION__, ret);

	mask=me.io_in_mask |me.io_out_mask;
	io_cnt=__builtin_popcountl(mask);
	j = 0;
	do
	{
		i=__builtin_ffsll(mask)-1;
		mask &= ~(1ULL<<i);

		rte_memcpy(ring_dist[j], lcore[i].io_in.ring_input, sizeof(struct rte_ring *)*MAX_DEV);
		io_core[j]=&lcore[i];
		j++;
	}while(mask);

	for( i = 0; i < port_cnt; i++)
	{
//		for( j = 0; j < MAX_DEV; j++)
        for( j = 0; j < me.port_cnt; j++)
		{
			if(port_arr[i] == me.settle_setting.gw_bonding_inoutvlan.in_port[j])
			{
				flag_inout[i] = DIR_IN;
				break;
			}
		}
//		if (MAX_DEV == j)
        if (me.port_cnt == j)
			flag_inout[i] = DIR_OUT;

		RUNNING_LOG_DEBUG("core %d :%s port_cnt=%d,port %d index(%d) is %s\n",my_lcore, __FUNCTION__, port_cnt, port_arr[i],i,(flag_inout[i]==DIR_IN)?"DIR_IN":"DIR_OUT");
	}

#ifndef __MAIN_LOOP_KNI__
	struct rte_mempool *arp_pkt_pool=local->distribute.io_buf;

	uint32_t local_link_status_map;
	uint32_t local_arp_need[MAX_DEV]={0};
#endif

	prev_tsc=cur_tsc=rte_rdtsc();
	while(1){

		cur_tsc=rte_rdtsc();
                mon_ip = me.mon_vip;

		for(i=0;i<port_cnt;i++)
		{
//			if(my_lcore == 14)
//			RUNNING_LOG_DEBUG("core %d :%s %d %d\n",my_lcore, __FUNCTION__, port_arr[i],queue_arr[i]);

			nb_rx = rte_eth_rx_burst(port_arr[i], queue_arr[i], pkts_burst,BURST_SZ);

			port_id = local->port_id[i];
			pout=&out[i];
//			if(my_lcore == 0)
//				RUNNING_LOG_DEBUG("core %d :%s %d %d nb_rx(%d)\n",my_lcore, __FUNCTION__, port_arr[i],queue_arr[i],nb_rx);

			if(nb_rx)
			{
				for(j=0;j<nb_rx;j++)
				{
//				tick0 = rte_rdtsc();
//				RUNNING_LOG_INFO("core %d :%s j=%d,tick=%i\n",rte_lcore_id(), __FUNCTION__, j,tick0-tick3);
//				tick0 = rte_rdtsc();
					static uint32_t idx_ring = 0;
					uint32_t idx_dstip = 0;
					struct pp_info p_info={0};
					ret=pkt_getip(pkts_burst[j], &p_info, if_ip,if_ipmask);

//					if (my_lcore == 0 )
//				tick1 = rte_rdtsc();

//				if ((p_info.srcip == IPv4(211,140,62,234)) || (p_info.dstip == IPv4(211,140,62,234)))
//				if (p_info.packet_info & FLAG(F_IPV4))
//					RUNNING_LOG_DEBUG("%s:core <%d> port:%d nat =>src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u\n",__FUNCTION__,my_lcore,port_arr[i],
//						p_info.srcip>>24, (p_info.srcip>>16)&0xff,(p_info.srcip>>8)&0xff,(p_info.srcip)&0xff,p_info.sport,
//						p_info.dstip>>24, (p_info.dstip>>16)&0xff,(p_info.dstip>>8)&0xff,(p_info.dstip)&0xff,p_info.dport);

					if (unlikely(mon_ip && (mon_ip == p_info.srcip || mon_ip == p_info.dstip)))
						    RUNNING_LOG_INFO("core<%d> %s get the packet, %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",rte_lcore_id(), __FUNCTION__,
						    	p_info.srcip>>24, (p_info.srcip>>16)&0xff,(p_info.srcip>>8)&0xff,(p_info.srcip)&0xff,p_info.sport,
						    	p_info.dstip>>24, (p_info.dstip>>16)&0xff,(p_info.dstip>>8)&0xff,(p_info.dstip)&0xff,p_info.dport);
					if (unlikely(ret & FLAG(POLICY_ACT_KERNEL)))
					{
#ifdef __MAIN_LOOP_KNI__
						RUNNING_LOG_DEBUG("%s: core<%d> enqueue pkt to kni\n",__FUNCTION__,rte_lcore_id());

						eth_hdr = rte_pktmbuf_mtod(pkts_burst[j], struct ether_hdr *);
						struct arp_hdr *arp_hdr = (struct arp_hdr *)((char *)(eth_hdr + 1));
						uint16_t arp_op = rte_be_to_cpu_16(arp_hdr->arp_op);
						uint16_t arp_pro = rte_be_to_cpu_16(arp_hdr->arp_pro);

						RUNNING_LOG_DEBUG("%s: core<%d> AAAAAAAAAAAAAAAAAAAAAAARP src_ip:%#x -> dst_ip:%#x\n",__FUNCTION__,rte_lcore_id(),
							arp_hdr->arp_data.arp_sip, arp_hdr->arp_data.arp_tip);


//						rte_pktmbuf_dump(running_log_fp,pkts_burst[j],pkts_burst[j]->data_len);
						if(rte_ring_mp_enqueue(ring_kni[i],(void *)pkts_burst[j]))
						{
							RUNNING_LOG_DEBUG("%s: core<%d> enqueue to kni fail \n",__FUNCTION__, my_lcore);
						}
#else
						{
							struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkts_burst[j], struct ether_hdr *);
							struct arp_hdr *arp_hdr = (struct arp_hdr *)((char *)(eth_hdr + 1));
							uint16_t arp_op = rte_be_to_cpu_16(arp_hdr->arp_op);
							uint16_t arp_pro = rte_be_to_cpu_16(arp_hdr->arp_pro);

							RUNNING_LOG_DEBUG("%s: core<%d> port[%d] AAAAAAAAAAAAAAAAAAAAAAARP src_ip:%#x -> dst_ip:%#x if_ip=%#x\n",__FUNCTION__,
								rte_lcore_id(),port_arr[i],
								arp_hdr->arp_data.arp_sip, arp_hdr->arp_data.arp_tip,
								if_ip[port_arr[i]]);
//							rte_pktmbuf_dump(running_log_fp,pkts_burst[j],pkts_burst[j]->data_len);
//							save_pcap_file(pkts_burst[j]);

							if ((rte_be_to_cpu_16(arp_hdr->arp_hrd) != ARP_HRD_ETHER) ||
								(arp_pro != ETHER_TYPE_IPv4) ||	(arp_hdr->arp_hln != 6) ||(arp_op != ARP_OP_REQUEST)||
								(arp_hdr->arp_pln != 4)) {

								RUNNING_LOG_DEBUG("%d  DROP ARP:	hrd=%d proto=0x%04x hln=%d "
									   "pln=%d op=%u sip=%x tip=%x\n",rte_lcore_id(),
									   rte_be_to_cpu_16(arp_hdr->arp_hrd),
									   arp_pro, arp_hdr->arp_hln,
									   arp_hdr->arp_pln, arp_op,arp_hdr->arp_data.arp_sip,arp_hdr->arp_data.arp_tip);

								rte_pktmbuf_free(pkts_burst[j]);
							} else if (((rte_cpu_to_be_32(arp_hdr->arp_data.arp_sip)==gw_ip[0])&&(rte_cpu_to_be_32(arp_hdr->arp_data.arp_tip)==if_ip[0]))||
								((rte_cpu_to_be_32(arp_hdr->arp_data.arp_sip)==gw_ip[1])&&(rte_cpu_to_be_32(arp_hdr->arp_data.arp_tip)==if_ip[1])))
							{
								if (arp_hdr->arp_op == rte_cpu_to_be_16(ARP_OP_REQUEST)) {

									uint32_t arp_r_sip = arp_hdr->arp_data.arp_tip;

									RUNNING_LOG_DEBUG("%s: core<%d> ARP_OP_REPLY\n",__FUNCTION__,rte_lcore_id());

									/* reply arp */
									arp_hdr->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);

									/* Switch src and dst data and set bonding MAC */
									ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);

									rte_eth_macaddr_get(port_arr[i], &eth_hdr->s_addr);

									ether_addr_copy(&arp_hdr->arp_data.arp_sha, &arp_hdr->arp_data.arp_tha);

									/* Switch ip */
									arp_hdr->arp_data.arp_tip = arp_hdr->arp_data.arp_sip;

									if (flag_inout[i] == DIR_IN)
										rte_eth_macaddr_get(me.settle_setting.gw_bonding_inoutvlan.in_port[0], &d_addr);
									else
										rte_eth_macaddr_get(me.settle_setting.gw_bonding_inoutvlan.out_port[0], &d_addr);

//									RUNNING_LOG_INFO("%s: core<%d> port(%d) bondp(%d)=====AAAAAAAAAAAAAAAARRRRRRPPPPPPPP========\n",
//										__FUNCTION__,rte_lcore_id(), i,port_arr[i]);
//									PRINT_MAC(d_addr.addr_bytes);

									ether_addr_copy(&d_addr, &arp_hdr->arp_data.arp_sha);
									arp_hdr->arp_data.arp_sip = arp_r_sip;

//									save_pcap_file(pkts_burst[j]);
									/* send */
									if (1 != rte_eth_tx_burst(port_arr[i], 0, &pkts_burst[j], 1)) {
										rte_eth_tx_burst(port_arr[i], 0, NULL, 0);
									}
								} else {
									RUNNING_LOG_DEBUG("%d  DROP ARP22222:	hrd=%d proto=0x%04x hln=%d "
									   "pln=%d op=%u sip=%x tip=%x\n",rte_lcore_id(),
									   rte_be_to_cpu_16(arp_hdr->arp_hrd),
									   arp_pro, arp_hdr->arp_hln,
									   arp_hdr->arp_pln, arp_op,arp_hdr->arp_data.arp_sip,arp_hdr->arp_data.arp_tip);

									rte_eth_tx_burst(port_arr[i], 0, NULL, 0);
								}
							}
						}
#endif
					}
					else if (unlikely(ret & FLAG(POLICY_ACT_DROP)))
					{
						if (p_info.packet_info & FLAG(F_IPV4))
							RUNNING_LOG_DEBUG("%s: core<%d> POLICY_ACT_DROP pkt\n",__FUNCTION__,my_lcore);

						rte_pktmbuf_free(pkts_burst[j]);
					}
//					else if (nat_dstip_find(p_info.srcip, p_info.dstip, local_srcipnat_hash, &idx_ring, &idx_dstip))
					else if (
#ifdef BOND_2DIR
						((flag_inout[i]==DIR_OUT) && nat_dstip_find(p_info.srcip, p_info.dstip, local_srcipnat_hash, &idx_ring, &idx_dstip))||
#endif
						(nat_dstip_find(dist_snat_find_vip(p_info.dstip,local_stable), p_info.dstip, local_srcipnat_hash, &idx_ring, &idx_dstip)))
					{
//				tick2 = rte_rdtsc();
						RUNNING_LOG_DEBUG("core %d :%s dstip found!!!ring[%d] %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u %s\n",rte_lcore_id(), __FUNCTION__,idx_dstip,
							p_info.srcip>>24, (p_info.srcip>>16)&0xff,(p_info.srcip>>8)&0xff,(p_info.srcip)&0xff,p_info.sport,
							p_info.dstip>>24, (p_info.dstip>>16)&0xff,(p_info.dstip>>8)&0xff,(p_info.dstip)&0xff,p_info.dport,
							flag_inout[i]?"OUT":"IN");

						pkts_burst[j]->seqn = (flag_inout[i]<<16) |idx_dstip;

						idx_ring = (idx_ring & 0xff)%io_cnt;
//						idx_ring++;
//						idx_ring %= io_cnt;


                        if (unlikely(mon_ip && (mon_ip == p_info.srcip || mon_ip == p_info.dstip  || (mon_ip == dist_snat_find_vip(p_info.dstip,local_stable))))){
						    RUNNING_LOG_INFO("core<%d> enqueue pkt to ring[%d], %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",rte_lcore_id(), idx_ring,
						    	p_info.srcip>>24, (p_info.srcip>>16)&0xff,(p_info.srcip>>8)&0xff,(p_info.srcip)&0xff,p_info.sport,
						    	p_info.dstip>>24, (p_info.dstip>>16)&0xff,(p_info.dstip>>8)&0xff,(p_info.dstip)&0xff,p_info.dport);
						}

						pos=pout->queue_buf[idx_ring].buf_pos;
						pout->queue_buf[idx_ring].buf[pos]=(void *)pkts_burst[j];
						pout->queue_buf[idx_ring].buf_pos++;
						if(unlikely(pout->queue_buf[idx_ring].buf_pos >= BURST_SZ))
						{
//							RUNNING_LOG_INFO("%s: core<%d> enqueue pkt to ring[%d] BURST\n",__FUNCTION__,rte_lcore_id(), idx_ring);

							nb_tx=rte_ring_sp_enqueue_bulk(ring_dist[idx_ring][port_id],(void* const*)&pout->queue_buf[idx_ring].buf,BURST_SZ);
							if (unlikely(nb_tx == -ENOBUFS))
							{
								RUNNING_LOG_ERROR("%s: core<%d> BURST enqueue pkt to ring[%d][%d] return ENOBUFS\n",__FUNCTION__,rte_lcore_id(),idx_ring,port_id);
								for(nb_tx = 0; nb_tx<BURST_SZ; nb_tx++)
								{
									rte_pktmbuf_free(pout->queue_buf[idx_ring].buf[nb_tx]);
								}
							}
							pout->queue_buf[idx_ring].buf_pos=0;
						}
//				tick3 = rte_rdtsc();
//						RUNNING_LOG_DEBUG("%s: core<%d> enqueue pkt to ring[%d],tick=%d %d %d,dst=0x%x\n",__FUNCTION__,rte_lcore_id(),
//							idx_ring,tick1-tick0,tick2-tick1,tick3-tick2,p_info.dstip);
//						if(rte_ring_sp_enqueue(ring_dist[idx_ring][port_id],(void *)pkts_burst[j]))
//						{
//							RUNNING_LOG_DEBUG("%s: core<%d> enqueue pkt to core fail \n",__FUNCTION__, my_lcore);
//							rte_pktmbuf_free(pkts_burst[j]);
//						}
					}
#ifdef __INTER_CONN_IP__
					else if (unlikely(ret & FLAG(POLICY_ACT_PING_REPLY)))
					{
						RUNNING_LOG_DEBUG("core %d :%s PING conn_ip %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",rte_lcore_id(), __FUNCTION__,
							p_info.srcip>>24, (p_info.srcip>>16)&0xff,(p_info.srcip>>8)&0xff,(p_info.srcip)&0xff,p_info.sport,
							p_info.dstip>>24, (p_info.dstip>>16)&0xff,(p_info.dstip>>8)&0xff,(p_info.dstip)&0xff,p_info.dport);

						pkts_burst[j]->seqn = (DIR_IN<<16);
						idx_ring = (idx_ring_conn_ip & 0xff)%io_cnt;
						idx_ring_conn_ip++;

						pos=pout->queue_buf[idx_ring].buf_pos;
						pout->queue_buf[idx_ring].buf[pos]=(void *)pkts_burst[j];
						pout->queue_buf[idx_ring].buf_pos++;
						if(unlikely(pout->queue_buf[idx_ring].buf_pos >= BURST_SZ))
						{
							nb_tx=rte_ring_sp_enqueue_bulk(ring_dist[idx_ring][port_id],(void* const*)&pout->queue_buf[idx_ring].buf,BURST_SZ);
							if (unlikely(nb_tx == -ENOBUFS))
							{
								RUNNING_LOG_WARN("%s: core<%d> BURST enqueue pkt to ring[%d][%d] return ENOBUFS\n",__FUNCTION__,rte_lcore_id(),idx_ring,port_id);
								for(nb_tx = 0; nb_tx<BURST_SZ; nb_tx++)
								{
									rte_pktmbuf_free(pout->queue_buf[idx_ring].buf[nb_tx]);
								}
							}
							pout->queue_buf[idx_ring].buf_pos=0;
						}
					}
#endif
					else
					{
//						RUNNING_LOG_DEBUG("%s: core<%d> drop pkt\n",__FUNCTION__,my_lcore);
						rte_pktmbuf_free(pkts_burst[j]);
						if (unlikely(mon_ip && ((mon_ip == p_info.srcip || mon_ip == p_info.dstip) || (mon_ip == dist_snat_find_vip(p_info.dstip,local_stable)))))
							RUNNING_LOG_INFO("core<%d> %s: %s drop pkt %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",my_lcore,__FUNCTION__,flag_inout[i]?"OUT":"IN",
								p_info.srcip>>24, (p_info.srcip>>16)&0xff,(p_info.srcip>>8)&0xff,(p_info.srcip)&0xff,p_info.sport,
						    	p_info.dstip>>24, (p_info.dstip>>16)&0xff,(p_info.dstip>>8)&0xff,(p_info.dstip)&0xff,p_info.dport);
					}
				}
#ifndef __MAIN_LOOP_KNI__
				local_arp_need[port_arr[i]]=0;
#endif
			}

		}

		//process timer
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc))
		{
			for(i=0;i<port_cnt;i++)
			{
				for(j=0;j<io_cnt;j++)
				{
					if(unlikely(pout->queue_buf[j].buf_pos))
					{
//						RUNNING_LOG_INFO("%s: core<%d> 100us burst ring_idx=%d, cnt=%d\n",
//							__FUNCTION__,rte_lcore_id(), j, pout->queue_buf[j].buf_pos);
//						rte_pktmbuf_dump(running_log_fp,(struct rte_mbuf *)pout->queue_buf[j].buf[0],((struct rte_mbuf *)(pout->queue_buf[j].buf[0]))->data_len);

						nb_tx=rte_ring_sp_enqueue_bulk(ring_dist[j][local->port_id[i]], (void* const*)&pout->queue_buf[j].buf, pout->queue_buf[j].buf_pos);
						if (unlikely(nb_tx == -ENOBUFS))
						{
							RUNNING_LOG_INFO("%s: core<%d> enqueue pkt to ring[%d][%d] return ENOBUFS\n",__FUNCTION__,rte_lcore_id(),j,local->port_id[i]);
							for(nb_tx = 0; nb_tx<pout->queue_buf[j].buf_pos; nb_tx++)
							{
								rte_pktmbuf_free(pout->queue_buf[j].buf[nb_tx]);
							}
						}
						pout->queue_buf[j].buf_pos=0;
					}
				}
			}

			if(unlikely(pre_dtable != dnatconfig_curr))
			{
				int reset_list = 1;
				int num_list=0;
				int num=0;
				if (dnatconfig_curr)
					rte_memcpy(local_dtable, &dtable[NAT_MAX_DSTNUM], sizeof(struct dnat_item) * NAT_MAX_DSTNUM);
				else
					rte_memcpy(local_dtable, &dtable[0], sizeof(struct dnat_item) * NAT_MAX_DSTNUM);

				pre_dtable=dnatconfig_curr;

//				num = nat_get_dstip_num(local_dtable);
//				if (num < num_dstip)
//					reset_list = 1;
//				else
//					reset_list = 0;
//				num_dstip = num;
				num_list = nat_create_srcdstip_list(local_stable, local_dtable, local_srcipnat_hash, local_srcipnat_pool, &local_srcip_alloclist, reset_list);
				if (my_lcore == 0)
				RUNNING_LOG_DEBUG("core %d :%s dnatconfig change,nat_create_srcdstip_list=%d\n",rte_lcore_id(), __FUNCTION__,num_list);
			}

			if(unlikely(pre_stable != snatconfig_curr))
			{
				int reset_list = 1;
				int num_list=0;
				int num=0;
				if (snatconfig_curr)
					rte_memcpy(local_stable, &stable[NAT_MAX_DSTNUM], sizeof(struct snat_item) * NAT_MAX_DSTNUM);
				else
					rte_memcpy(local_stable, &stable[0], sizeof(struct snat_item) * NAT_MAX_DSTNUM);

				pre_stable=snatconfig_curr;

				num_list = nat_create_srcdstip_list(local_stable, local_dtable, local_srcipnat_hash, local_srcipnat_pool, &local_srcip_alloclist, reset_list);
				if (my_lcore == 0)
				RUNNING_LOG_DEBUG("core %d :%s snatconfig change,nat_create_srcdstip_list=%d\n",rte_lcore_id(), __FUNCTION__,num_list);
			}

			if (++tsc_cnt_10s > TIME_1S_US/TIME_DPI)
			{
#ifndef __MAIN_LOOP_KNI__
				struct rte_mempool *m;

				local_link_status_map = link_status_map;

				for (i=0;i<port_cnt;i++)
				{
					local_arp_need[port_arr[i]]++;
					if (local_arp_need[port_arr[i]]==10 && (0 != (local_link_status_map & (1 << port_arr[i]))))
					{
						RUNNING_LOG_DEBUG("(%d) : ARP REQ port=%d que=%d\n", my_lcore,port_arr[i],queue_arr[i]);

						struct rte_mbuf *m = rte_pktmbuf_alloc(arp_pkt_pool);
						if(m==NULL){
							RUNNING_LOG_ERROR("core %d :%s cannot alloc arp pkt mbuf port(%d)\n",rte_lcore_id(), __FUNCTION__, port_arr[i]);
							rte_eth_tx_burst(port_arr[i], 0, NULL, 0);
							break;
						}

						do_create_arp_req(m,port_arr[i],if_ip[port_arr[i]],gw_ip[port_arr[i]]);

//						save_pcap_file(m);

						pout->queue_buf[0].buf[pout->queue_buf[0].buf_pos]=(void *)m;
						pout->queue_buf[0].buf_pos++;

						local_arp_need[port_arr[i]]=0;
					}

					if(unlikely(pout->queue_buf[0].buf_pos != 0))
					{
						nb_tx=rte_eth_tx_burst(port_arr[i],0,(struct rte_mbuf **)&pout->queue_buf[0].buf,pout->queue_buf[0].buf_pos);
						if (unlikely(nb_tx < pout->queue_buf[0].buf_pos))
							{
							rte_eth_tx_burst(port_arr[i], 0, NULL, 0);
							}
						pout->queue_buf[0].buf_pos=0;
					}
				}
#endif

			tsc_cnt_10s=0;
			}

			prev_tsc = cur_tsc;
		}
	}

	if (local_stable)
	{
		free(local_stable);
		local_stable = NULL;
	}
	if (local_dtable)
	{
		free(local_dtable);
		local_dtable = NULL;
	}
}
#if 0
static inline void __attribute__((always_inline))
io_pcap(struct rte_mbuf *m,
	struct hash_array *pcap_pool,struct hash_array *pcap_snd_pending)
{
	struct pcap_ship *p;
	struct local_pcap_pkthdr *hdr;
        struct timeval tv;
	unsigned char *pt,*pd;

	if(!list_empty(&pcap_pool->header))
	{
		p=list_first_entry(&pcap_pool->header,struct pcap_ship,list);

		list_del_init(&p->list);
		list_add_tail(&p->list,&pcap_snd_pending->header);
		pcap_snd_pending->load++;
		pcap_pool->load--;

		hdr=(struct local_pcap_pkthdr *)(&p->buf[0]);
                gettimeofday(&tv,0);
		pt = rte_pktmbuf_mtod(m, unsigned char *);
		hdr->ts.tv_sec = tv.tv_sec;
		hdr->ts.tv_usec = tv.tv_usec;
		hdr->caplen = m->data_len;
		hdr->len = m->data_len;

		p->len=sizeof(struct local_pcap_pkthdr)+hdr->len;
		pd=(unsigned char *)(hdr+1);
		rte_memcpy(pd,pt,m->data_len);

		RUNNING_LOG_DEBUG("core %d: PPPPPPAP len=%d tlen=%d pcappool=%d pending=%d\n",
			rte_lcore_id(),hdr->len,p->len,pcap_pool->load,pcap_snd_pending->load);
	}
}
#endif

static inline int __attribute__((always_inline))
sumsrc_stat(struct pp_info *packet_info, uint16_t *flow_state, struct src_sum_tmp *srcip_sum)
{
	uint32_t srcip_idx;
	int r;

	memset(srcip_sum, 0, sizeof(struct src_sum_tmp));
	if(packet_info->packet_info & FLAG(F_TCP))
		{
		if(packet_info->packet_info & (FLAG(F_TCP_SYN)))
			{
			srcip_sum->halfreq_flow++;
			*flow_state = FLOW_STATE_TCP_SYN;
			}
		if(packet_info->packet_info & (FLAG(F_TCP_SYN_ACK)))
			{
			srcip_sum->halfreq_flow++;
			*flow_state = FLOW_STATE_TCP_SYNACK;
			}
		else if(packet_info->packet_info & (FLAG(F_TCP_FIN)|FLAG(F_TCP_RST)))
			{
			srcip_sum->finish_tcp_flow++;
			*flow_state = FLOW_STATE_TCP_FIN;
			}
		else//ack
			{
				if (*flow_state == FLOW_STATE_TCP_SYN){
					srcip_sum->new_build_tcp_flow++;
//					*flow_state = FLOW_STATE_TCP_ACK;
				}
			}
		}
	else if(packet_info->packet_info & FLAG(F_UDP))
		{
			if (*flow_state != FLOW_STATE_UDP)
				srcip_sum->new_build_udp_flow++;

		}

	return 0;
}

#ifdef __SRC_SUM__
static inline void __attribute__((always_inline))
srcipalldst_dyn_policy_io_setting(struct hash_array *src_p_pool,struct hash_array *src_p_hash,struct sum_msg *msg, uint32_t timer_index)
{
	uint32_t srcip_idx;
	struct io_src_policy *src_p,*src_ptmp;
//	int i;

	srcip_idx=(msg->ip)&(IP_HASH_ARRAY_SZ-1);

	if(!list_empty(&src_p_hash[srcip_idx].header))
		{
		list_for_each_entry_safe(src_p, src_ptmp, &src_p_hash[srcip_idx].header, tbl_list)
			{
			if((msg->ip==src_p->srcip)&&(msg->ip2==src_p->dstip))
				{

				src_p->flag=msg->msg;

				src_p->timer_index = timer_index;

//				RUNNING_LOG_INFO("core %d :FIND policy io setting ip=%x ip2=%x\n",rte_lcore_id(), msg->ip,msg->ip2);

				return;
				}
			}
		}

//alloc_x:
	//alloc src policy dyn
	if(!list_empty(&src_p_pool->header))
		{
		src_p=list_first_entry(&src_p_pool->header,struct io_src_policy,list);
		list_del_init(&src_p->list);
		INIT_LIST_HEAD(&src_p->tbl_list);
		src_p->srcip=msg->ip;
		src_p->dstip=msg->ip2;
		list_add(&src_p->tbl_list,&src_p_hash[srcip_idx].header);
		src_p_pool->load--;

		src_p->timer_index = timer_index;

		src_p->flag=msg->msg;

		src_p->bl_freeze_time_s = 60;
//		RUNNING_LOG_INFO("core %d :NEW policy io setting ip=%x ip2=%x\n",rte_lcore_id(), msg->ip,msg->ip2);

		}
	else
		{
		RUNNING_LOG_WARN("src policy pool empty!\n");
		return;
		}
}

static inline int __attribute__((always_inline))
srcipa_policy_io_check(struct hash_array *src_p_pool,struct hash_array *src_p_hash,struct ipv4_4tuple *tuple, uint32_t timer_index)
{
	uint32_t srcip_idx;
	uint32_t srcip = tuple->a.pair.l3;
	uint32_t dstip = tuple->b.pair.l3;
	struct io_src_policy *src_p,*src_ptmp;

	srcip_idx=srcip&(IP_HASH_ARRAY_SZ-1);

	if(!list_empty(&src_p_hash[srcip_idx].header))
		{
		list_for_each_entry_safe(src_p, src_ptmp, &src_p_hash[srcip_idx].header, tbl_list)
			{
			if((srcip==src_p->srcip)&&(dstip==src_p->dstip))
				{
//					RUNNING_LOG_INFO("core %d: FIND policy io setting %#x->%#x\n", rte_lcore_id(), srcip, dstip);

					if (timer_index < src_p->timer_index)
						timer_index += TIMER_LOOP_SZ;

					if (timer_index - src_p->timer_index < src_p->bl_freeze_time_s * (TIME_1S_US/TIME_DPI))
					{
						if (src_p->flag)
							src_p->timer_index = timer_index;

						return 1;
					}
					else
					{
//						RUNNING_LOG_INFO("core %d: freeze the bl policy io setting %#x->%#x\n", rte_lcore_id(), srcip, dstip);

						list_del_init(&src_p->tbl_list);

						INIT_LIST_HEAD(&src_p->list);
						list_add(&src_p->list, &src_p_pool->header);
						src_p_pool->load++;

						return 0;
					}

				}
			}
		}

	return 0;
}
#endif

#ifdef __SYNC_FLOW_TABLE__
static inline int __attribute__((always_inline))
flow_nat_sync_msg_snd(struct hash_array *snd_pending, struct hash_array *pool, struct flow_nat *flow_nat, int io_cnt, uint8_t is_add)
{
	struct flow_nat_msg *flow_msg_snd;
	int i;

		for (i=0;i<(io_cnt-1);i++)
		{
			if(!list_empty(&pool->header))
			{
				flow_msg_snd=list_first_entry(&pool->header,struct flow_nat_msg,list);

				list_del_init(&flow_msg_snd->list);

				flow_msg_snd->snat=flow_nat->snat;
				flow_msg_snd->vip_idx=flow_nat->vip_idx;
				flow_msg_snd->first_ack_seq_no=flow_nat->first_ack_seq_no;
				flow_msg_snd->is_add_flow=is_add;

				flow_msg_snd->nat_tuplehash[CT_DIR_ORIGINAL].dir = flow_nat->nat_tuplehash[CT_DIR_ORIGINAL].dir;
				flow_msg_snd->nat_tuplehash[CT_DIR_ORIGINAL].proto = flow_nat->nat_tuplehash[CT_DIR_ORIGINAL].proto;
				flow_msg_snd->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.all = flow_nat->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.all;
				flow_msg_snd->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.all = flow_nat->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.all;

				flow_msg_snd->nat_tuplehash[CT_DIR_REPLY].dir = flow_nat->nat_tuplehash[CT_DIR_REPLY].dir;
				flow_msg_snd->nat_tuplehash[CT_DIR_REPLY].proto = flow_nat->nat_tuplehash[CT_DIR_REPLY].proto;
				flow_msg_snd->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.all = flow_nat->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.all;
				flow_msg_snd->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.all = flow_nat->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.all;
					
				pool->load--;

				list_add_tail(&flow_msg_snd->list,&snd_pending[i].header);

				snd_pending[i].load++;

				RUNNING_LOG_DEBUG("core %u :flow sync msg cnt %u hashx idx=%llx\n",rte_lcore_id(),
					pool->load,i);
			}
			else
			{
				RUNNING_LOG_WARN("sync flow msg pool empty!\n");
				return MM_FAIL;
			}

		}

		return MM_SUCCESS;
}

uint61_t aaa_min[MAX_CPU]={0}, aaa_max[MAX_CPU]={0}, ddd_min[MAX_CPU]={0}, ddd_max[MAX_CPU]={0};
#endif /* #ifdef __SYNC_FLOW_TABLE__ */

int main_loop_nat(void)
{

	int my_lcore;
	int i,j,k,dist_idx,nb_rx,nb_tx;
	int loop_10ms_cnt=0;
	int loop_cnt=0;
	int port_cnt;
	uint8_t port_arr[MAX_DEV];
	uint8_t txport_arr[MAX_DEV];
	uint16_t queue_arr[MAX_DEV];
	struct rte_mbuf *pkts_burst[BURST_SZ];
	int prev_req,curr_req;
	struct hash_array *ip_hash;
	struct hash_array *flow_hash;
	struct lcore_info_s *local;
	uint64_t cur_tsc, prev_tsc,diff_tsc, hz;
	uint64_t local_mask;
	int sum_cnt, io_cnt/*, pcap_cnt*/;
	struct ip_g_s2 *ipdst;
	uint64_t start,end,count=0;
	int i_vlan,o_vlan;
	int flag_inout;
	uint32_t mon_ip = me.mon_vip;
//        int deadtime = me.natconfig.deadtime;
    int deadtime_rst = me.natconfig.deadtime_rst;
//	int local_pcap_flag = do_pcap_flag;

	//src sum
#ifdef __SRC_SUM__
	struct hash_array *local_sumsrc_srcip_hash;
#endif
	struct hash_array *local_srcip_sum_pool;
	struct hash_array *local_sumsrc_snd,*local_sumsrc_back;
	struct hash_array local_sumsrc_snd_pending[MAX_CPU];
	int sumsrc_cnt;
	struct src_sum_tmp ipsrctmp={0};

	struct hash_array *local_msgfrom_srcsum_send[MAX_CPU];
	struct hash_array *local_msgfrom_srcsum_back[MAX_CPU];
	struct hash_array local_msgfrom_srcsum_back_pending[MAX_CPU];
	struct hash_array local_msgfrom_srcsum_handler[MAX_CPU];
	struct sum_msg *ms,*mstmp;

#ifdef __SYNC_FLOW_TABLE__
	/* snd flow msg to other nat core */
	struct hash_array *local_flow_nat_sync_pool;
	struct hash_array local_flow_nat_sync_snd_pending[MAX_CPU];
	struct hash_array *local_flow_nat_sync_snd[MAX_CPU];
	struct hash_array *local_flow_nat_sync_snd_back[MAX_CPU];

	/* rcv flow msg from other nat core */
	struct hash_array *local_flow_nat_sync_rcv[MAX_CPU]={NULL};
	struct hash_array *local_flow_nat_sync_rcv_back[MAX_CPU]={NULL};
	struct hash_array local_flow_nat_sync_rcv_backpending[MAX_CPU];
	struct hash_array local_flow_nat_sync_rcv_handler[MAX_CPU];
#endif

#ifdef __SRC_SUM__
	struct hash_array *local_srcip_policy_hash;
	struct hash_array *local_srcip_policy_pool;
#endif

#if defined(BOND_2DIR)
	uint32_t if_ip[]={rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.in_ip),
		rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.out_ip)};
	uint32_t if_ipmask[]={rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.in_ipmask),
		rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.out_ipmask)};
#else
	uint32_t if_ip[]={rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.in_ip & me.settle_setting.gw_bonding_inoutvlan.in_ipmask),
		rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.out_ip & me.settle_setting.gw_bonding_inoutvlan.out_ipmask)};
	uint32_t if_ipmask[]={rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.in_ipmask),
		rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.out_ipmask)};
#endif

	char l2_data[16]={0};
	int l2_data_valid=0;
	int *l2_sig;
	char *l2_pdata;

	my_lcore=rte_lcore_id();
	local_mask=(1ULL<<my_lcore);
	local=&lcore[my_lcore];

	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1)/US_PER_S * TIME_DPI; //100us
//	const uint64_t drain_1s_tsc = (rte_get_tsc_hz() + US_PER_S - 1)/US_PER_S * IN_TIMER_1S; // 1s

	struct hash_array *local_ip_pool,*local_ip_burst,*local_ip_burstcache,*local_ip_back;
	struct hash_array *local_netport_pool,*local_netport_back;

//	struct hash_array *local_pcap_pool,*local_pcap_burst,*local_pcap_back;
//	struct hash_array *local_flow_pool,*local_flowtag_pool;
	struct port_info_sum *port_stat;
	int ready_port_sum;
	int mystate=0;
	uint32_t prev_policy=0;
	struct policy mydefaultpolicy;
//	struct core_timer *timer;
	struct port_push *port_snd;
	struct rte_ring *ring_input[MAX_DEV];
	int ret=0;
#ifdef IN_OUT_IN1_MODE
	struct out_buf_s out[MAX_DEV];
	struct out_buf_s *pout;
	int out_queue[MAX_DEV][MAX_TX_QUEUE]={0};
	int out_queue_sz[MAX_DEV]={0};
#endif

	uint32_t hash_idx = 0;
	static uint16_t tcp_port_rover[NAT_MAX_DSTNUM];
//	static uint16_t udp_port_rover[NAT_MAX_DSTNUM];
#ifdef	__SRCP_BIT_MAP__
	struct bitmap_s *port_bitmap;
#endif
	int tupleidx = 0;
	int fresh_tupleidx = 0;
	int pos = 0;
	struct nat_map_tuple *nat_tuplepair, *fresh_tuplepair;
	struct hash_array *local_flownat_pool,*local_flownat_hash, *local_srcnat_hash;
	struct hash_array *local_dnatconfig_pool,*local_dnatconfig_hash;
	struct hash_array *local_srcipnat_pool, *local_srcipnat_hash;
    struct hash_array *local_viptoa_pool, *local_viptoa_hash;
	struct hash_array local_dnatconfig_alloclist, local_srcip_alloclist, local_viptoa_alloclist;
	int distribute_cnt=0;
//	struct dnat_item local_dtable[NAT_MAX_DSTNUM] = {0};
	struct dnat_item *local_dtable;
//	struct snat_item local_stable[NAT_MAX_DSTNUM] = {0};
	struct snat_item *local_stable;
	uint32_t local_flow_limit[(NAT_MAX_DSTNUM>>5)+1] = {0};
	uint32_t pre_dtable=0;
	uint32_t pre_stable=0;
	uint32_t data[3];
	int num=0;
	uint64_t tick0,tick1,tick2,tick3;
	uint32_t pre_viptoa=0;
	uint32_t local_viptoa[NAT_MAX_DSTNUM] = {0};
	uint32_t timer_curr_idx=0;
	struct hash_array *local_timer;
	uint32_t flow_deadtime;
#ifdef __FIRTST_ACK_SEQ__
	uint32_t first_ack_seq_no=0;
#endif
	local_timer=local->io_in.flowtimer;
//	flow_deadtime=me.natconfig.deadtime;

	l2_sig=&local->io_in.l2_sig;
#ifdef BOND_2DIR
	l2_pdata=&local->io_in.l2_data_out[0];
#endif
//	timer=&local->localtimer;
	port_cnt=local->port_cnt;
	if(me.settle_setting.mode==INTERFACE_MODE_GW_BONDING)
	{
		i_vlan=me.settle_setting.gw_bonding_inoutvlan.in_vlanid;
		o_vlan=me.settle_setting.gw_bonding_inoutvlan.out_vlanid;
	}

	rte_memcpy(&local_flow_limit, nat_flow_limit, sizeof(nat_flow_limit) );
	memset(out,0,sizeof(out[0])*MAX_DEV);
	for(i=0;i<local->port_cnt;i++)
	{
		out_queue_sz[i]=local->io_in.out_queue_sz[i];
		rte_memcpy(out_queue[i],local->io_in.out_queue[i],sizeof(int)*MAX_TX_QUEUE);
	}

	rte_memcpy(port_arr,local->port_id,sizeof(local->port_id[0])*MAX_DEV);
	rte_memcpy(txport_arr,local->txport_id,sizeof(local->txport_id[0])*MAX_DEV);
	rte_memcpy(queue_arr,local->queue_id,sizeof(local->queue_id[0])*MAX_DEV);
	ip_hash=local->io_in.io_in_hash;
	hz = rte_get_timer_hz();

	local_ip_pool=&local->io_in.ip_pool;
	local_ip_burst=local->io_in.ip_io2sum_burst;
	local_ip_burstcache=local->io_in.ip_io2sum_pending;
	local_ip_back=local->io_in.ip_sum2io_burst;
	local_netport_pool=&local->io_in.netport_pool;
	local_netport_back=local->io_in.netport_sum2io_burst;

	sumsrc_cnt=__builtin_popcountll(me.sum_src_mask);
#ifdef __SRC_SUM__
	local_sumsrc_srcip_hash=local->io_in.sumsrc_srcip_hash;
#endif
	local_srcip_sum_pool=&local->io_in.srcsum_pool;
	local_sumsrc_snd=local->io_in.ip_io2sumsrc_burst;
	local_sumsrc_back=local->io_in.ip_sumsrc2io_burst;
	for(i=0;i<MAX_CPU;i++)
		{
		INIT_LIST_HEAD(&local_sumsrc_snd_pending[i].header);
		local_sumsrc_snd_pending[i].load=0;

		INIT_LIST_HEAD(&local_msgfrom_srcsum_back_pending[i].header);
		local_msgfrom_srcsum_back_pending[i].load=0;

		INIT_LIST_HEAD(&local_msgfrom_srcsum_handler[i].header);
		local_msgfrom_srcsum_handler[i].load=0;
		}

	rte_memcpy(local_msgfrom_srcsum_send,local->io_in.msg_sumsrc2io_send,
		sizeof(local->io_in.msg_sumsrc2io_send[0])*MAX_CPU);
	rte_memcpy(local_msgfrom_srcsum_back,local->io_in.msg_sumsrc2io_back,
		sizeof(local->io_in.msg_sumsrc2io_back[0])*MAX_CPU);

//	local_pcap_pool=&local->io_in.pcap_pool;
//	local_pcap_burst=local->io_in.pcap2io_burst;
//	local_pcap_back=local->io_in.io2pcap_burst;

//	local_flow_pool=&local->io_in.flow_pool;
//	local_flowtag_pool=&local->io_in.flowtag_pool;
//	flow_hash=local->io_in.io_flow_hash;
	sum_cnt=__builtin_popcountll(me.sum_mask);
//	pcap_cnt=__builtin_popcountll(me.pcap_mask);
	port_stat=&local->io_in.port_sub[local->io_in.port_sum_curr];
	ready_port_sum=0;
	port_snd=local->io_in.port_do_push;
	rte_memcpy(ring_input,local->io_in.ring_input,sizeof(struct rte_ring *)*MAX_DEV);

	local_flownat_pool=&local->io_in.flownat_pool;
	local_flownat_hash = local->io_in.io_flownat_hash;
//	local_srcnat_hash = local->io_in.io_srcnat_hash;
	local_dnatconfig_pool=&local->io_in.dnatconfig_pool;
	local_dnatconfig_hash = local->io_in.dnat_config_hash;
	local_srcipnat_pool = &local->io_in.srcipnat_pool;
	local_srcipnat_hash = local->io_in.io_srcip_hash;
	INIT_LIST_HEAD(&local_srcip_alloclist.header);
	INIT_LIST_HEAD(&local_dnatconfig_alloclist.header);
	local_dnatconfig_alloclist.load=0;
    local_viptoa_pool = &local->io_in.viptoa_pool;
	local_viptoa_hash = local->io_in.io_viptoa_hash;
	INIT_LIST_HEAD(&local_viptoa_alloclist.header);
    local_viptoa_alloclist.load=0;

#ifdef BOND_2DIR
	int txport_out = me.settle_setting.gw_bonding_inoutvlan.out_port_num ?
			me.settle_setting.gw_bonding_inoutvlan.out_port[my_lcore%me.settle_setting.gw_bonding_inoutvlan.out_port_num] :
			0;
#endif
	int txport_in = me.settle_setting.gw_bonding_inoutvlan.in_port[my_lcore%me.settle_setting.gw_bonding_inoutvlan.in_port_num];
#ifdef __SRC_SUM__
	local_srcip_policy_hash=local->io_in.srcip_policy_hash;
	local_srcip_policy_pool=&local->io_in.srcip_policy_pool;
#endif

#ifdef	__SRCP_BIT_MAP__
	port_bitmap=(struct bitmap_s *)rte_zmalloc_socket(NULL, sizeof(struct bitmap_s)*NAT_MAX_DSTNUM*NAT_MAX_SIPNUM,
		8,rte_lcore_to_socket_id(my_lcore));
	if (!port_bitmap)
	{
		RUNNING_LOG_ERROR("%s core<%u> can not malloc the memory for srcip_port\n", __FUNCTION__, my_lcore);
		return 0;
	}
	for (i=0; i < NAT_MAX_DSTNUM; i++)
	{
		for (j=0; j < NAT_MAX_SIPNUM; j++)
		{
			bitmap_init(port_bitmap + i*NAT_MAX_SIPNUM + j);
		}
		tcp_port_rover[i]=1001;
	}

#endif

	local_dtable = (struct dnat_item *)rte_zmalloc_socket(NULL, sizeof(struct dnat_item)*NAT_MAX_DSTNUM,
		8,rte_lcore_to_socket_id(my_lcore));
	if (!local_dtable)
	{
		RUNNING_LOG_ERROR("%s core<%u> can not malloc local_dtable\n", __FUNCTION__, my_lcore);
		return -1;
	}
	local_stable = (struct snat_item *)rte_zmalloc_socket(NULL, sizeof(struct snat_item)*NAT_MAX_DSTNUM,
		8,rte_lcore_to_socket_id(my_lcore));
	if (!local_stable)
	{
		RUNNING_LOG_ERROR("%s core<%u> can not malloc local_stable\n", __FUNCTION__, my_lcore);
		return -1;
	}
sleep(1);
	if(2 == my_lcore)
	RUNNING_LOG_INFO("core %d :%s HZ=%u\n", my_lcore, __FUNCTION__, hz);

	core_stat[my_lcore]=0;
	core_prev[my_lcore]=0;
	memcpy(&mydefaultpolicy,&default_policy[default_curr],sizeof(mydefaultpolicy));
	prev_policy=default_curr;

	if (dnatconfig_curr)
		rte_memcpy(local_dtable, &dtable[NAT_MAX_DSTNUM], sizeof(struct dnat_item) * NAT_MAX_DSTNUM);
	else
		rte_memcpy(local_dtable, &dtable[0], sizeof(struct dnat_item) * NAT_MAX_DSTNUM);

	pre_dtable=dnatconfig_curr;

	if (snatconfig_curr)
		rte_memcpy(local_stable, &stable[NAT_MAX_DSTNUM], sizeof(struct snat_item) * NAT_MAX_DSTNUM);
	else
		rte_memcpy(local_stable, &stable[0], sizeof(struct snat_item) * NAT_MAX_DSTNUM);

	pre_stable=snatconfig_curr;

	nat_create_dnatconfig_list(local_dtable, local_dnatconfig_hash, local_dnatconfig_pool, &local_dnatconfig_alloclist);
	nat_create_snatip_list(local_stable, local_srcipnat_hash, local_srcipnat_pool, &local_srcip_alloclist);

    pre_viptoa = viptoa_curr;
//    rte_memcpy(local_viptoa, nat_viptoa, sizeof(local_viptoa[0]) * NAT_MAX_DSTNUM);
	if (g_dst_pl) {
		for (i=0;i<NAT_MAX_DSTNUM;i++)
			local_viptoa[i] = g_dst_pl[i].toa_flag ? g_dst_pl[i].dstip : 0;
	} else {
		for (i=0;i<NAT_MAX_DSTNUM;i++)
			local_viptoa[i] = 0;

		RUNNING_LOG_ERROR("core<%d> %s: nooooo vip\n", my_lcore, __FUNCTION__);
	}
    nat_create_toavip_list(local_viptoa, local_viptoa_hash, local_viptoa_pool, &local_viptoa_alloclist);

 #ifdef __SYNC_FLOW_TABLE__
 #ifdef BOND_2DIR
 			io_cnt=__builtin_popcountll(me.io_in_mask|me.io_out_mask);
 #else
 			io_cnt=__builtin_popcountll(me.io_in_mask);
 #endif

 		/* snd to other nat core */
 		for(i=0;i<(io_cnt-1);i++)
 			{
 			local_flow_nat_sync_snd[i]=&local->io_in.flow_nat_sync_snd[i];
 			local_flow_nat_sync_snd_back[i]=&local->io_in.flow_nat_sync_snd_back[i];

 			INIT_LIST_HEAD(&local_flow_nat_sync_snd_pending[i].header);
 			local_flow_nat_sync_snd_pending[i].load=0;
 			}
 		local_flow_nat_sync_pool=&local->io_in.flow_nat_sync_pool;

 		/* rcv from other nat core */
 		rte_memcpy(local_flow_nat_sync_rcv,local->io_in.flow_nat_sync_rcv,sizeof(struct hash_array *) * (io_cnt-1));
 		rte_memcpy(local_flow_nat_sync_rcv_back,local->io_in.flow_nat_sync_rcv_back,sizeof(struct hash_array *) * (io_cnt-1));
 		for(i=0;i<MAX_CPU;i++)
 			{
 			INIT_LIST_HEAD(&local_flow_nat_sync_rcv_backpending[i].header);
 			local_flow_nat_sync_rcv_backpending[i].load=0;

 			INIT_LIST_HEAD(&local_flow_nat_sync_rcv_handler[i].header);
 			local_flow_nat_sync_rcv_handler[i].load=0;
 			}
 #endif	// #ifdef __SYNC_FLOW_TABLE__

	prev_tsc=cur_tsc=rte_rdtsc();

	while(1){
//     tick0 = rte_rdtsc();
		cur_tsc = rte_rdtsc();
		mon_ip = me.mon_vip;

		if(unlikely(*l2_sig))
		{
#ifdef BOND_2DIR
			rte_memcpy(l2_data,l2_pdata,14);
#endif
			*l2_sig=0;
			l2_data_valid=1;
			rte_wmb();
#ifdef BOND_2DIR
			RUNNING_LOG_DEBUG("core<%d>: dump out mac %x:%x:%x:%x:%x:%x <- %x:%x:%x:%x:%x:%x type=%x%x\n",
				rte_lcore_id(),(uint8_t)l2_data[0], (uint8_t)l2_data[1], (uint8_t)l2_data[2],
				(uint8_t)l2_data[3], (uint8_t)l2_data[4], (uint8_t)l2_data[5],
				(uint8_t)l2_data[6], (uint8_t)l2_data[7], (uint8_t)l2_data[8],
				(uint8_t)l2_data[9],(uint8_t)l2_data[10],(uint8_t)l2_data[11],
				l2_data[12],l2_data[13]);
#endif
		}

		//process pkts
//		for(i=0;i<port_cnt;i++)
//		{
		i = 0;
		for(k=0;k<me.port_cnt;k++)
//                for(k=0;k<MAX_DEV;k++)
		{
			nb_rx = rte_ring_sc_dequeue_burst(ring_input[k], (void **)pkts_burst, BURST_SZ);
			pout=&out[i];
			if(nb_rx)
			{
			start = rte_rdtsc();
			count++;
//			tick1 = rte_rdtsc();
				core_stat[my_lcore]+=nb_rx;
				for(j=0;j<nb_rx;j++)
				{
					struct pp_info p_info={0};
					struct flow_nat *natflow;
					enum nat_manip_type maniptype = NAT_MANIP_NULL;
					struct ipv4_4tuple curr_tuple, new_tuple,tmp_tuple;
					enum nat_manip_type type;
					uint32_t ip_tmp = 0;
					struct flow_nat *flownat = NULL;
					uint16_t dstip_idx = 0, srcip_idx=0;

					ret=pkt_get_ipport(pkts_burst[j], &p_info);
					flag_inout = (pkts_burst[j]->seqn) >>16;
					dstip_idx = (pkts_burst[j]->seqn) & 0xffff;
					pkts_burst[j]->seqn = p_info.packet_info;

//					if(likely(!(ret & FLAG(POLICY_ACT_KERNEL))))
//						{
//						ipdst=pkt_dstip_handler(pkts_burst[j],&p_info,local_ip_pool,
//							local_ip_burstcache,ip_hash,
//							sum_cnt,&local->io_in);
//						}

					if (unlikely(mon_ip && (mon_ip == p_info.srcip || mon_ip == p_info.dstip)))
					    RUNNING_LOG_INFO("core %d :nat %u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u,packet_info=0x%x\n",rte_lcore_id(),
					    		p_info.srcip>>24, (p_info.srcip>>16)&0xff, (p_info.srcip>>8)&0xff, (p_info.srcip)&0xff, p_info.sport,
								p_info.dstip>>24, (p_info.dstip>>16)&0xff, (p_info.dstip>>8)&0xff, (p_info.dstip)&0xff, p_info.dport,
								p_info.packet_info);

					int queue_idx=0;
					int pos = 0;
					int need_snat = 0;
					int txport_id;
					int idx_ring = 0;

#ifdef VLAN_ON
					char *l2_hdr=rte_pktmbuf_mtod(pkts_burst[j], char *);

					rte_memcpy(l2_hdr,l2_data,16);
#else
					char *l2_hdr=rte_pktmbuf_mtod(pkts_burst[j], char *);
					char l2_tmp[6];
#ifdef BOND_2DIR

					if  (DIR_OUT == flag_inout)
					{
						rte_memcpy(l2_hdr,&local->io_in.l2_data_in[0],14);
					}else
#endif
					{
						rte_memcpy(l2_tmp,l2_hdr,6);
						rte_memcpy(l2_hdr,l2_hdr+6,6);
						rte_memcpy(l2_hdr+6,l2_tmp,6);
					}
#endif

#ifdef WF_NAT
					if((p_info.packet_info & FLAG(F_TCP)) ||(p_info.packet_info & FLAG(F_UDP)))
					{
				        int proto;
				        if(p_info.packet_info & FLAG(F_TCP))
							proto = L4_TYPE_TCP;
						else
							proto = L4_TYPE_UDP;
						curr_tuple.a.pair.l3 = p_info.srcip;
						curr_tuple.a.pair.l4 = p_info.sport;
						curr_tuple.b.pair.l3 = p_info.dstip;
						curr_tuple.b.pair.l4 = p_info.dport;

//					if (p_info.srcip==0xb702ce7f ||p_info.dstip==0xb702ce7f)
//					{
//						RUNNING_LOG_INFO("core %d :sip=0x%x dst=0x%x,sport=%d dport=%d, packet_info=0x%x\n",rte_lcore_id(),
//								p_info.srcip, p_info.dstip, p_info.sport, p_info.dport,p_info.packet_info);
//                                                rte_pktmbuf_dump(running_log_fp,pkts_burst[j],pkts_burst[j]->data_len);
//					}

#if 0
					// debug pcap
                   if (unlikely(local_pcap_flag && mon_ip && (mon_ip == p_info.srcip || mon_ip == p_info.dstip)))
                   {
						if (local_pcap_pool->load != 0)
						{
							io_pcap(pkts_burst[j], local_pcap_pool, local_pcap_burst);
						}

					}
#endif

                    // add TOA
                if ((p_info.packet_info & FLAG(F_TCP)) && (DIR_IN == flag_inout))
				{
                    if((p_info.packet_info & FLAG(F_TCP_SYN))
                        && nat_toavip_find(p_info.dstip, local_viptoa_hash))
					{
						RUNNING_LOG_DEBUG("core %d :sip=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u, packet_info=0x%x add toa\n",rte_lcore_id(),
								p_info.srcip>>24, (p_info.srcip>>16)&0xff, (p_info.srcip>>8)&0xff, (p_info.srcip)&0xff, p_info.sport,
								p_info.dstip>>24, (p_info.dstip>>16)&0xff, (p_info.dstip>>8)&0xff, (p_info.dstip)&0xff, p_info.dport,
								p_info.packet_info);

//					        rte_pktmbuf_dump(running_log_fp,pkts_burst[j],pkts_burst[j]->data_len);

						struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkts_burst[j], struct ether_hdr *);
						struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)((uint8_t *)eth_hdr + sizeof(struct ether_hdr));
						int ipv4_hdr_len = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK)<<2;
						struct tcp_hdr *tcphdr = (struct tcp_hdr *)((uint8_t *)ipv4_hdr + ipv4_hdr_len);
#ifdef __FIRTST_ACK_SEQ__
						first_ack_seq_no = rte_be_to_cpu_32(tcphdr->sent_seq) + 1;
#endif
				        if ((p_info.packet_info & FLAG(F_TCP_OPTION))
				                && tcp_opt_replace_timestamp(tcphdr, p_info)){
//                          rte_pktmbuf_dump(running_log_fp,pkts_burst[j],pkts_burst[j]->data_len);

				        }
                        else{
                                tcp_opt_add_toa(pkts_burst[j], tcphdr, p_info);
                        }

//                      rte_pktmbuf_dump(running_log_fp,pkts_burst[j],pkts_burst[j]->data_len);

                    }
#ifdef __FIRTST_ACK_SEQ__
					else if ((p_info.packet_info & FLAG(F_TCP_SYN_ACK)))
					{
						struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkts_burst[j], struct ether_hdr *);
						struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)((uint8_t *)eth_hdr + sizeof(struct ether_hdr));
						int ipv4_hdr_len = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK)<<2;
						struct tcp_hdr *tcphdr = (struct tcp_hdr *)((uint8_t *)ipv4_hdr + ipv4_hdr_len);

						first_ack_seq_no = rte_be_to_cpu_32(tcphdr->recv_ack);
					}
#endif
            	}

					RUNNING_LOG_DEBUG("core %d :DIR_IN sip=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u, proto=0x%x\n",rte_lcore_id(),
								p_info.srcip>>24, (p_info.srcip>>16)&0xff, (p_info.srcip>>8)&0xff, (p_info.srcip)&0xff, p_info.sport,
								p_info.dstip>>24, (p_info.dstip>>16)&0xff, (p_info.dstip>>8)&0xff, (p_info.dstip)&0xff, p_info.dport,
								proto);

						natflow = nat_flow_find(&curr_tuple, local_flownat_hash, proto);
//						natflow = nat_flow_find(&curr_tuple, local_flownat_hash);

						if (NULL == natflow)
						{
#ifdef BOND_2DIR
//							if  (FUN_IO_IN == local->type)
							if  (DIR_IN == flag_inout)
#endif
							{
								struct dnat_range natrange;
								uint32_t srcip[NAT_MAX_SIPNUM] = {0};

								memset(&natrange, 0, sizeof(struct dnat_range));

//								tick0 = rte_rdtsc();

								maniptype = dnat_rule_find(&curr_tuple, proto, local_dnatconfig_hash, &natrange, &dstip_idx);
#ifdef BOND_2DIR
								if ((p_info.packet_info & FLAG(F_TCP)) && (80 == p_info.dport ||443 == p_info.dport))
									maniptype = NAT_MANIP_FWD;
#endif

								if (NAT_MANIP_DST == maniptype)
								{
									if ((local_flow_limit[dstip_idx>>5] & (1ULL<<(dstip_idx&0x1f))))
									{
										RUNNING_LOG_DEBUG("%s: core<%d> nat_flow_limit drop pkt\n",__FUNCTION__,rte_lcore_id());
										rte_pktmbuf_free(pkts_burst[j]);

										if (unlikely(mon_ip && (mon_ip == p_info.srcip || mon_ip == p_info.dstip)))
											RUNNING_LOG_ERROR("%s: core<%d> nat_flow_limit drop pkt\n",__FUNCTION__,rte_lcore_id());

										continue;
									}
#ifdef __SRC_SUM__
									if (srcipa_policy_io_check(local_srcip_policy_pool,local_srcip_policy_hash, &curr_tuple, timer_curr_idx))
									{
										RUNNING_LOG_DEBUG("%s: core<%d> srcip attack drop pkt because of src_ip attack\n",__FUNCTION__,rte_lcore_id());
										rte_pktmbuf_free(pkts_burst[j]);

									if (unlikely(mon_ip && (mon_ip == p_info.srcip || mon_ip == p_info.dstip)))
										RUNNING_LOG_INFO("core %d :attack sip=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u, packet_info=0x%x\n",
											rte_lcore_id(),
											p_info.srcip>>24, (p_info.srcip>>16)&0xff, (p_info.srcip>>8)&0xff, (p_info.srcip)&0xff, p_info.sport,
											p_info.dstip>>24, (p_info.dstip>>16)&0xff, (p_info.dstip>>8)&0xff, (p_info.dstip)&0xff, p_info.dport,
											p_info.packet_info);

										if (flownat) {
											sumsrc_stat(&p_info, &flownat->state, &ipsrctmp);
											pkt_srcip_handler(&p_info,local_srcip_sum_pool, local_sumsrc_srcip_hash,
												local_sumsrc_snd_pending,sumsrc_cnt,&ipsrctmp);
										}

										continue;
									}
#endif
//									if (my_lcore == 0 ){
//										//num++;
//									if ((p_info.srcip == IPv4(211,140,62,234))&& (p_info.dstip == IPv4(211,140,62,234)))
//										RUNNING_LOG_DEBUG("core %d :nat_rule_find sport=%d dst_port=%d, nat_port=%d,natip=%x num=%d\n",
//										    rte_lcore_id(),p_info.sport,p_info.dport,natrange.nat_port,natrange.nat_ip[0], num);
//									}
									dnat_get_unique_tuple(&new_tuple, &curr_tuple, &natrange, local_flownat_hash);
//								if ((p_info.srcip == IPv4(211,140,62,234))|| (p_info.dstip == IPv4(211,140,62,234)))
									RUNNING_LOG_DEBUG("core %d :dnat_get_unique_tuple ret=%d,sip=%u.%u.%u.%u:%u dip=%u.%u.%u.%u:%u\n",
										rte_lcore_id(),ret,
										new_tuple.a.pair.l3>>24,(new_tuple.a.pair.l3>>16)&0xff,(new_tuple.a.pair.l3>>8)&0xff,new_tuple.a.pair.l3&0xff,new_tuple.a.pair.l4,
										new_tuple.b.pair.l3>>24,(new_tuple.b.pair.l3>>16)&0xff,(new_tuple.b.pair.l3>>8)&0xff,new_tuple.b.pair.l3&0xff,new_tuple.b.pair.l4);

									need_snat = nat_srcip_find(&curr_tuple, local_srcipnat_hash, srcip, &flow_deadtime);
									if (need_snat)
									{
										struct bitmap_s *lbmp;
//										uint64_t ttt1, ttt2, ttt3;

										srcip_idx=(curr_tuple.a.pair.l3)%need_snat;

//										ttt1 = rte_rdtsc();
										new_tuple.a.pair.l3 = srcip[srcip_idx];
										//new_tuple.a.pair.l3 = srcip[0];
#ifdef	__SRCP_BIT_MAP__
										lbmp = port_bitmap + dstip_idx * NAT_MAX_SIPNUM + srcip_idx;
										snat_l4proto_get_port(&new_tuple, local_flownat_hash, &tcp_port_rover[dstip_idx], lbmp);
#else
										snat_l4proto_get_port(&new_tuple, local_flownat_hash, &tcp_port_rover[dstip_idx], lbmp);
#endif
//										ttt2 = rte_rdtsc();

//										ttt3 = ttt2 - ttt1;

//										if (!tmr1 || (tmr1 > ttt3))
//											tmr1 = ttt3;
//										if (!tmr2 || (tmr2 < ttt3))
//											tmr2 = ttt3;


//										RUNNING_LOG_ERROR("sssssrc ip %#x:%d sum:%d\n", new_tuple.a.pair.l3, new_tuple.a.pair.l4, need_snat);
									}

									nat_ipv4_manip_pkt(pkts_burst[j], &p_info, &new_tuple, NAT_MANIP_DST);
									if (need_snat)
										nat_ipv4_manip_pkt(pkts_burst[j], &p_info, &new_tuple, NAT_MANIP_SRC);

									pkt_dstip_handler(pkts_burst[j], &p_info, local_ip_pool, local_ip_burstcache, ip_hash, sum_cnt, &local->io_in,
										DIR_IN, dstip_idx);

//									tick1 = rte_rdtsc();

									//add
									nat_invert_tuple(&tmp_tuple, &new_tuple);

									if(local_flownat_pool->load)
									{
										flownat = list_first_entry(&local_flownat_pool->header, struct flow_nat, alloc_list);
										//memset(&flownat->nat_tuplehash, 0, sizeof(struct ipv4_4tuple)*2);
										flownat->nat_tuplehash[CT_DIR_ORIGINAL].dir=CT_DIR_ORIGINAL;
										flownat->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4=curr_tuple;
                                        flownat->nat_tuplehash[CT_DIR_ORIGINAL].proto=proto;
										flownat->nat_tuplehash[CT_DIR_REPLY].dir=CT_DIR_REPLY;
										flownat->nat_tuplehash[CT_DIR_REPLY].tuple_v4=tmp_tuple;
                                        flownat->nat_tuplehash[CT_DIR_REPLY].proto=proto;
										flownat->last_tick = cur_tsc;
										flownat->snat = need_snat;
										flownat->sip_idx = srcip_idx&0xff;
										flownat->vip_idx = (dstip_idx);
										flownat->deadtime = (uint16_t)flow_deadtime;

										flownat->state=FLOW_STATE_MAX;
#ifdef __FIRTST_ACK_SEQ__
										flownat->first_ack_seq_no=0;

										if (first_ack_seq_no && ((p_info.packet_info & FLAG(F_TCP)) &&
											((p_info.packet_info & FLAG(F_TCP_SYN))||(p_info.packet_info & FLAG(F_TCP_SYN_ACK)))))
										{
											flownat->first_ack_seq_no=first_ack_seq_no;
										}
#endif
#ifdef __SRC_SUM__
										sumsrc_stat(&p_info, &flownat->state, &ipsrctmp);
										pkt_srcip_handler(&p_info,local_srcip_sum_pool, local_sumsrc_srcip_hash,
											local_sumsrc_snd_pending,sumsrc_cnt,&ipsrctmp);
#endif
										/*if(p_info.packet_info & FLAG(F_UDP))
											flownat->state=FLOW_STATE_UDP;
										else if(p_info.packet_info & FLAG(F_TCP_SYN))
											flownat->state=FLOW_STATE_TCP_SYN;
										else if(p_info.packet_info & FLAG(F_TCP_SYN_ACK))
											flownat->state=FLOW_STATE_TCP_SYNACK;*/

//										RUNNING_LOG_ERROR("core %d :original %u.%u.%u.%u:%u --> %u.%u.%u.%u:%u,state=%#x p_info:%#x\n",rte_lcore_id(),
//											curr_tuple.a.pair.l3>>24,(curr_tuple.a.pair.l3>>16)&0xff,(curr_tuple.a.pair.l3>>8)&0xff,curr_tuple.a.pair.l3&0xff,curr_tuple.a.pair.l4,
//											curr_tuple.b.pair.l3>>24,(curr_tuple.b.pair.l3>>16)&0xff,(curr_tuple.b.pair.l3>>8)&0xff,curr_tuple.b.pair.l3&0xff,curr_tuple.b.pair.l4,
//											flownat->state, p_info.packet_info);

										data[0] = curr_tuple.a.pair.l3;
										data[1] = curr_tuple.b.pair.l3;
										data[2] = (curr_tuple.a.pair.l4)<<16 |curr_tuple.b.pair.l4;
										hash_idx = rte_jhash_3words(data[0], data[1], data[2], PRIME_VALUE);
										hash_idx = hash_idx & (FLOWNAT_HASH_ARRAY_SZ - 1);


										INIT_LIST_HEAD(&flownat->nat_tuplehash[CT_DIR_ORIGINAL].listnode);
										list_add_tail(&flownat->nat_tuplehash[CT_DIR_ORIGINAL].listnode, &local_flownat_hash[hash_idx].header);

										/* add this node to src list for src ip of request statistic  */
//										hash_idx = p_info.srcip & (IP_HASH_ARRAY_SZ - 1);
//										INIT_LIST_HEAD(&flownat->nat_tuplehash[CT_DIR_ORIGINAL].src_list);
//										list_add_tail(&flownat->nat_tuplehash[CT_DIR_ORIGINAL].src_list, &local_src_list_hash[].header);

										data[0] = tmp_tuple.a.pair.l3;
										data[1] = tmp_tuple.b.pair.l3;
										data[2] =(tmp_tuple.a.pair.l4)<<16 |tmp_tuple.b.pair.l4;
										hash_idx = rte_jhash_3words(data[0], data[1], data[2], PRIME_VALUE);
										hash_idx = hash_idx & (FLOWNAT_HASH_ARRAY_SZ - 1);


										INIT_LIST_HEAD(&flownat->nat_tuplehash[CT_DIR_REPLY].listnode);
										list_add_tail(&flownat->nat_tuplehash[CT_DIR_REPLY].listnode, &local_flownat_hash[hash_idx].header);

										int timer_idx = (timer_curr_idx + flow_deadtime*TIME_1S_US/TIME_DPI)%TIMER_LOOP_SZ;
										list_move_tail(&flownat->alloc_list,&local_timer[timer_idx].header);
//										pos++;
//										if(pos >= timer->queue_sz)
//											pos=0;
//										list_move_tail(&flownat->alloc_list,&timer->natlist[pos].header);
										nat_linkcount[flownat->vip_idx]++;
										local_flownat_pool->load--;

#ifdef __SYNC_FLOW_TABLE__
										flow_nat_sync_msg_snd(local_flow_nat_sync_snd_pending, local_flow_nat_sync_pool,
													flownat,io_cnt, FLOW_NAT_SYNC_MSG_ADD);
#endif
									}
									else
									{
										RUNNING_LOG_INFO("core %d :local_flownat_pool miss dst=%u.%u.%u.%u:%u src=%u.%u.%u.%u:%u,alloc flownat fail\n",rte_lcore_id(),
											curr_tuple.b.pair.l3>>24,(curr_tuple.b.pair.l3>>16)&0xff,(curr_tuple.b.pair.l3>>8)&0xff,curr_tuple.b.pair.l3&0xff,curr_tuple.b.pair.l4,
											curr_tuple.a.pair.l3>>24,(curr_tuple.a.pair.l3>>16)&0xff,(curr_tuple.a.pair.l3>>8)&0xff,curr_tuple.a.pair.l3&0xff,curr_tuple.a.pair.l4);

										local->io_in.miss_alloced_flownat++;
									}
//									tick1 = rte_rdtsc();
					                if (unlikely(mon_ip && (mon_ip == p_info.srcip || mon_ip == p_info.dstip)))
									    RUNNING_LOG_INFO("%s: core<%d> new natlist, src=%u.%u.%u.%u:%d,repley src=%u.%u.%u.%u:%d dst=%u.%u.%u.%u:%d\n",
									        __FUNCTION__,rte_lcore_id(),
									        curr_tuple.b.pair.l3>>24,(curr_tuple.b.pair.l3>>16)&0xff,(curr_tuple.b.pair.l3>>8)&0xff,curr_tuple.b.pair.l3&0xff,curr_tuple.a.pair.l4,
									        tmp_tuple.a.pair.l3>>24,(tmp_tuple.a.pair.l3>>16)&0xff,(tmp_tuple.a.pair.l3>>8)&0xff,tmp_tuple.a.pair.l3&0xff,tmp_tuple.a.pair.l4,
									        tmp_tuple.b.pair.l3>>24,(tmp_tuple.b.pair.l3>>16)&0xff,(tmp_tuple.b.pair.l3>>8)&0xff,tmp_tuple.b.pair.l3&0xff,tmp_tuple.b.pair.l4);

								}

#ifdef BOND_2DIR
								else if(NAT_MANIP_FWD == maniptype)
								{
									//to nginx

#ifndef __MAIN_LOOP_KNI__
									rte_memcpy(local->io_in.l2_data_out, me.settle_setting.gw_bonding_inoutvlan.out_neigh_mac,ETHER_ADDR_LEN);

									rte_eth_macaddr_get(port_arr[i], (struct ether_addr *)&local->io_in.l2_data_out[6]);

									local->io_in.l2_data_out[12] = 0x08;
									local->io_in.l2_data_out[13] = 0x00;
#endif
									rte_memcpy(l2_hdr,&local->io_in.l2_data_out[0],14);
									pkt_dstip_handler(pkts_burst[j], &p_info, local_ip_pool, local_ip_burstcache, ip_hash, sum_cnt, &local->io_in,
										DIR_IN, dstip_idx);

								}
#endif

								else{
									if (unlikely(mon_ip && (mon_ip == p_info.srcip || mon_ip == p_info.dstip)))
										RUNNING_LOG_INFO("%s: core<%d> DDDDDdrop pkt, maniptype=%d,sip=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u\n",
											__FUNCTION__,rte_lcore_id(),maniptype,
											p_info.srcip>>24, (p_info.srcip>>16)&0xff,(p_info.srcip>>8)&0xff,(p_info.srcip)&0xff, p_info.sport,
											p_info.dstip>>24, (p_info.dstip>>16)&0xff,(p_info.dstip>>8)&0xff,(p_info.dstip)&0xff, p_info.dport);

									rte_pktmbuf_free(pkts_burst[j]);

									continue;
								}
							}
#ifdef BOND_2DIR
							// from nginx
							else{
								RUNNING_LOG_DEBUG("core %d:%s : %u.%u.%u.%u:%u --> %u.%u.%u.%u:%u from NG\n",
                                    rte_lcore_id(), __FUNCTION__,
                                    p_info.srcip>>24, (p_info.srcip>>16)&0xff,(p_info.srcip>>8)&0xff,(p_info.srcip)&0xff, p_info.sport,
									p_info.dstip>>24, (p_info.dstip>>16)&0xff,(p_info.dstip>>8)&0xff,(p_info.dstip)&0xff, p_info.dport);
#ifndef __MAIN_LOOP_KNI__
								rte_memcpy(local->io_in.l2_data_out, me.settle_setting.gw_bonding_inoutvlan.in_neigh_mac,ETHER_ADDR_LEN);

								rte_eth_macaddr_get(port_arr[i], (struct ether_addr *)&local->io_in.l2_data_out[6]);

								local->io_in.l2_data_out[12] = 0x08;
								local->io_in.l2_data_out[13] = 0x00;

								rte_memcpy(l2_hdr,&local->io_in.l2_data_out[0],14);
#endif

								pkt_dstip_handler(pkts_burst[j], &p_info, local_ip_pool, local_ip_burstcache, ip_hash, sum_cnt, &local->io_in,
									DIR_OUT, dstip_idx);
							}

#endif
						}else{

							need_snat = natflow->snat;
#ifdef __SYNC_FLOW_TABLE__
							/* if the flow is sync from other core, ignore it, it should be deleted by the msg from the core who create it */
							if (natflow->deadtime != 0)
								{
#endif
							natflow->last_tick = cur_tsc;
							int timer_idx = (timer_curr_idx + natflow->deadtime*TIME_1S_US/TIME_DPI)%TIMER_LOOP_SZ;
							list_move_tail(&natflow->alloc_list,&local_timer[timer_idx].header);
#ifdef __SYNC_FLOW_TABLE__
								}
#endif							
                           if (unlikely(mon_ip
						   	&& (mon_ip == natflow->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.pair.l3 ||
						   		mon_ip == natflow->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.pair.l3))) {
								RUNNING_LOG_INFO("core %d :%s ori: %u.%u.%u.%u:%u --> %u.%u.%u.%u:%u; reply:%u.%u.%u.%u:%u --> %u.%u.%u.%u:%u l4 forward\n",
									rte_lcore_id(),__FUNCTION__,
									(natflow->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.pair.l3>>24),
									(natflow->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.pair.l3>>16)&0xff,
									(natflow->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.pair.l3>>8)&0xff,
									(natflow->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.pair.l3)&0xff,
									(natflow->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.pair.l4),
									(natflow->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.pair.l3>>24),
									(natflow->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.pair.l3>>16)&0xff,
									(natflow->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.pair.l3>>8)&0xff,
									(natflow->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.pair.l3)&0xff,
									(natflow->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.pair.l4),
									(natflow->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.pair.l3>>24),
									(natflow->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.pair.l3>>16)&0xff,
									(natflow->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.pair.l3>>8)&0xff,
									(natflow->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.pair.l3)&0xff,
									(natflow->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.pair.l4),
									(natflow->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.pair.l3>>24),
									(natflow->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.pair.l3>>16)&0xff,
									(natflow->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.pair.l3>>8)&0xff,
									(natflow->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.pair.l3)&0xff,
									(natflow->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.pair.l4));
					   			}
#ifdef __FIRTST_ACK_SEQ__
							if (first_ack_seq_no && ((p_info.packet_info & FLAG(F_TCP)) &&
								((p_info.packet_info & FLAG(F_TCP_SYN))||(p_info.packet_info & FLAG(F_TCP_SYN_ACK)))))
							{
								natflow->first_ack_seq_no=first_ack_seq_no;
							}
#endif
							if(nat_equal_tuple(&natflow->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4, &curr_tuple)){
								tmp_tuple = natflow->nat_tuplehash[CT_DIR_REPLY].tuple_v4;

								type = NAT_MANIP_DST;
#ifdef __FIRTST_ACK_SEQ__
								if (((p_info.packet_info & FLAG(F_TCP))
				                        && (p_info.packet_info & FLAG(F_TCP_ACK))
				                        && (DIR_IN == flag_inout)))
								{
									struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkts_burst[j], struct ether_hdr *);
									struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)((uint8_t *)eth_hdr + sizeof(struct ether_hdr));
									int ipv4_hdr_len = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK)<<2;
									struct tcp_hdr *tcphdr = (struct tcp_hdr *)((uint8_t *)ipv4_hdr + ipv4_hdr_len);
									int tcp_hdr_len = ((tcphdr->data_off & 0xf0) >> 2);

//									RUNNING_LOG_ERROR("core %u : %s ack add toa\n", rte_lcore_id(),__FUNCTION__);
									if ((rte_be_to_cpu_16(ipv4_hdr->total_length) == (tcp_hdr_len + ipv4_hdr_len))
										&& (rte_be_to_cpu_32(tcphdr->sent_seq)==natflow->first_ack_seq_no))
									{
										if ((p_info.packet_info & FLAG(F_TCP_OPTION))
												&& tcp_opt_replace_timestamp(tcphdr, p_info)){
//									  		rte_pktmbuf_dump(running_log_fp,pkts_burst[j],pkts_burst[j]->data_len);

								        }
				                        else{
				                                tcp_opt_add_toa(pkts_burst[j], tcphdr, p_info);
			                        }
								}
								}
#endif
							}else{
								tmp_tuple = natflow->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4;

								RUNNING_LOG_DEBUG("core %d :%s reply for ORIGINAL %u.%u.%u.%u:%u --> %u.%u.%u.%u:%u\n",
										rte_lcore_id(),__FUNCTION__,
										tmp_tuple.a.pair.l3>>24,(tmp_tuple.a.pair.l3>>16)&0xff,(tmp_tuple.a.pair.l3>>8)&0xff,(tmp_tuple.a.pair.l3)&0xff,tmp_tuple.a.pair.l4,
										tmp_tuple.b.pair.l3>>24,(tmp_tuple.b.pair.l3>>16)&0xff,(tmp_tuple.b.pair.l3>>8)&0xff,(tmp_tuple.b.pair.l3)&0xff,tmp_tuple.b.pair.l4);
								type = NAT_MANIP_SRC;
							}

							nat_invert_tuple(&new_tuple, &tmp_tuple);

#ifdef BOND_2DIR
//							if (FUN_IO_IN == local->type)
//							if  (DIR_IN == flag_inout)
//								type = NAT_MANIP_DST;
//							else
//								type = NAT_MANIP_SRC;

#endif

							if (likely(need_snat))
							{
								nat_ipv4_manip_pkt(pkts_burst[j], &p_info, &new_tuple, NAT_MANIP_DST);
								nat_ipv4_manip_pkt(pkts_burst[j], &p_info, &new_tuple, NAT_MANIP_SRC);
							}
							else
								nat_ipv4_manip_pkt(pkts_burst[j], &p_info, &new_tuple, type);



//#ifdef BOND_2DIR
#if 0
//							if  (FUN_IO_OUT == local->type)
							if  (DIR_IN == flag_inout)
#else
//							ip_tmp = dnat_find_dstip_bynatip(p_info.srcip, local_dtable);
//							if (0 != ip_tmp)
							if (type == NAT_MANIP_SRC)
#endif
							{
								struct pp_info ptk_info=p_info;
								ptk_info.srcip = new_tuple.a.pair.l3;
								ptk_info.sport = new_tuple.a.pair.l4;
								ipdst=pkt_dstip_handler(pkts_burst[j], &ptk_info, local_ip_pool, local_ip_burstcache, ip_hash, sum_cnt, &local->io_in,
									DIR_OUT, natflow->vip_idx);

							}
							else{
#ifdef __SRC_SUM__
								sumsrc_stat(&p_info, &natflow->state, &ipsrctmp);
								pkt_srcip_handler(&p_info,local_srcip_sum_pool, local_sumsrc_srcip_hash,
									local_sumsrc_snd_pending,sumsrc_cnt,&ipsrctmp);
#endif
								ipdst=pkt_dstip_handler(pkts_burst[j], &p_info, local_ip_pool, local_ip_burstcache, ip_hash, sum_cnt, &local->io_in,
									DIR_IN, natflow->vip_idx);
							}

#if 0
							if(p_info.packet_info & FLAG(F_TCP))
							{
								if(process_flow_tcp_state_noseqcheck(p_info.packet_info,&natflow->state))
								{
									natflow->last_tick -= (deadtime - deadtime_rst)*drain_1s_tsc;
#if 0
									if (unlikely(mon_ip && (mon_ip == p_info.srcip || mon_ip == p_info.dstip)))
									    RUNNING_LOG_INFO("core %d: natlist rev reset, srcip=0x%x dstip=0x%x, srcip=0x%x dstip=0x%x,sport=%d\n",
										my_lcore, natflow->nat_tuplehash[0].tuple_v4.a.pair.l3,
										natflow->nat_tuplehash[0].tuple_v4.b.pair.l3,
										natflow->nat_tuplehash[1].tuple_v4.a.pair.l3,
										natflow->nat_tuplehash[1].tuple_v4.b.pair.l3,
										natflow->nat_tuplehash[0].tuple_v4.a.pair.l4);
                                                                        //delete
									if(list_is_singular(&natflow->nat_tuplehash[0].listnode)){
										INIT_LIST_HEAD(natflow->nat_tuplehash[0].listnode.prev);
										INIT_LIST_HEAD(&natflow->nat_tuplehash[0].listnode);
									}else{
										list_del_init(&natflow->nat_tuplehash[0].listnode);
									}

									if(list_is_singular(&natflow->nat_tuplehash[1].listnode)){
										INIT_LIST_HEAD(natflow->nat_tuplehash[1].listnode.prev);
										INIT_LIST_HEAD(&natflow->nat_tuplehash[1].listnode);
									}else{
										list_del_init(&natflow->nat_tuplehash[1].listnode);
									}

									list_del_init(&natflow->alloc_list);
									list_move_tail(&natflow->alloc_list,&local_flownat_pool->header);
									local_flownat_pool->load++;
#endif
								}
							}
#endif

						}
					}
					else if ((p_info.packet_info & FLAG(F_ICMP)) &&(DIR_IN == flag_inout))
					{

						if (nat_is_vip(p_info.dstip, local_srcipnat_hash)) {
							pkts_burst[j] = gen_icmp_pkt(pkts_burst[j]);
						}

#ifdef __INTER_CONN_IP__
#ifdef BOND_2DIR
						else if(((p_info.dstip&if_ipmask[0])==(if_ip[0]&if_ipmask[0])) ||
							((p_info.dstip&if_ipmask[1])==(if_ip[1]&if_ipmask[1])))
						{
							RUNNING_LOG_DEBUG("PING CONN_IP\n");
							pkts_burst[j] = gen_icmp_pkt(pkts_burst[j]);
						}
#else	// #ifdef BOND_2DIR
						else if(unlikely((p_info.dstip&if_ipmask[0])==(if_ip[0]&if_ipmask[0])))
						{
							RUNNING_LOG_DEBUG("PING CONN_IP\n");
							pkts_burst[j] = gen_icmp_pkt(pkts_burst[j]);
						}
#endif	// #ifdef BOND_2DIR
#endif



					}
					else{
						RUNNING_LOG_DEBUG("%s: core<%d> drop pkt other than tcp/udp or icmp\n",__FUNCTION__,rte_lcore_id());
						rte_pktmbuf_free(pkts_burst[j]);

						if (unlikely(mon_ip && ((mon_ip == p_info.dstip) || (mon_ip == dist_snat_find_vip(p_info.dstip,local_stable)))))
							RUNNING_LOG_ERROR("%s: core<%d> drop pkt other than tcp/udp or icmp in_out:%d find(%d)\n",__FUNCTION__,rte_lcore_id(),
								flag_inout, nat_is_vip(p_info.dstip, local_srcipnat_hash));

						continue;
					}

#endif

#ifdef BOND_2DIR
//						txport_id = (flag_inout==DIR_IN)?txport_out:txport_in;
 						if(NAT_MANIP_FWD == maniptype){
							txport_id = txport_out;
							RUNNING_LOG_DEBUG("%s: core<%d> to NGINX port\n",__FUNCTION__,rte_lcore_id());
						}
						else
						{
							txport_id = txport_in;
						}

						pos=pout->queue_buf[txport_id].buf_pos;
						pout->queue_buf[txport_id].buf[pos]=(void *)pkts_burst[j];
						pout->queue_buf[txport_id].buf_pos++;
						RUNNING_LOG_DEBUG("%s: core<%d> send portidx=%d port=%d qidx=%d q=%d pos=%d\n",
							__FUNCTION__,rte_lcore_id(),i,port_arr[i],
							queue_idx,out_queue[i][queue_idx],pout->queue_buf[queue_idx].buf_pos);

						if(unlikely(pout->queue_buf[txport_id].buf_pos >= BURST_SZ))
						{
							RUNNING_LOG_DEBUG("%s: core<%d> burst portidx=%d port=%d qidx=%d q=%d\n",
								__FUNCTION__,rte_lcore_id(),i,txport_arr[i],
								queue_idx,out_queue[i][queue_idx]);

							nb_tx=rte_eth_tx_burst(txport_id, out_queue[i][0],(struct rte_mbuf **)&pout->queue_buf[txport_id].buf,BURST_SZ);
							if (unlikely(nb_tx < BURST_SZ))
							{
							    RUNNING_LOG_WARN("%s: core<%d> BURST tx %d pkts failed.\n",__FUNCTION__,rte_lcore_id(),BURST_SZ-nb_tx);
								port_stat[txport_id].sub[1].bad_ipv4_pkts+=(BURST_SZ-nb_tx);
								for(;nb_tx<BURST_SZ;nb_tx++)
								{
									rte_pktmbuf_free(pout->queue_buf[txport_id].buf[nb_tx]);
								}
							}
							pout->queue_buf[txport_id].buf_pos=0;
						}

						update_port_sum_out(pkts_burst[j],&port_stat[txport_id]);
#else
						queue_idx=(pkts_burst[j]->hash.rss>>4)%out_queue_sz[i];
						pos=pout->queue_buf[queue_idx].buf_pos;
						pout->queue_buf[queue_idx].buf[pos]=(void *)pkts_burst[j];
						pout->queue_buf[queue_idx].buf_pos++;

						if(unlikely(pout->queue_buf[queue_idx].buf_pos >= BURST_SZ))
						{
							nb_tx=rte_eth_tx_burst(port_arr[i],out_queue[i][queue_idx],(struct rte_mbuf **)&pout->queue_buf[queue_idx].buf,BURST_SZ);
							if (unlikely(nb_tx < BURST_SZ))
							{
								RUNNING_LOG_WARN("%s: core<%d> immediately tx %d but %d pkts failed.\n",
									__FUNCTION__,rte_lcore_id(),
									nb_tx, (pout->queue_buf[j].buf_pos-nb_tx));

								port_stat[port_arr[i]].sub[1].bad_ipv4_pkts+=(BURST_SZ-nb_tx);
								for(;nb_tx<BURST_SZ;nb_tx++)
								{
									rte_pktmbuf_free(pout->queue_buf[queue_idx].buf[nb_tx]);
								}
							}
							pout->queue_buf[queue_idx].buf_pos=0;
						}

						update_port_sum_out(pkts_burst[j],&port_stat[port_arr[i]]);
#endif
					}
//                                        tick2 = rte_rdtsc();
//                                        if (my_lcore == 3)
//                                        RUNNING_LOG_INFO("core %d: %llu ticks for %d pkts !==========\n",
//                				my_lcore, tick2-tick1,nb_rx);

				end=rte_rdtsc()-start;
				if(end>timer_perform_max[my_lcore])
					timer_perform_max[my_lcore]=end;
				if((end<timer_perform_min[my_lcore])||!timer_perform_min[my_lcore])
					timer_perform_min[my_lcore]=end;

				if(timer_perform_aver[my_lcore]==0)
					timer_perform_aver[my_lcore]=end;
				else
					timer_perform_aver[my_lcore]=((count-1)*timer_perform_aver[my_lcore]+end)/count;
				}
			}
//			}

		if(unlikely(ready_port_sum))
		{
			if(!local->io_in.port_sum_sig)
			{
				local->io_in.port_sum_curr^=1;
				if(local->io_in.port_sum_curr)
					port_stat=&local->io_in.port_sub[MAX_DEV];
				else
					port_stat=&local->io_in.port_sub[0];

				memset(port_stat,0,sizeof(struct port_info_sum)*MAX_DEV);
				ready_port_sum=0;

				local->io_in.port_sum_sig=1;
				rte_smp_wmb();

//				end=rte_rdtsc()-start;
//				RUNNING_LOG_DEBUG("core %d  switch waste %llu\n",my_lcore,end);

			}
		}

		//process timer
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc))	// 100us
		{
//		        local_pcap_flag = do_pcap_flag;

			for(i=0;i<sum_cnt;i++)
				do_burst(&local_ip_burst[i],&local_ip_burstcache[i],i);

			for(i=0;i<sumsrc_cnt;i++)
				{
					do_burst2(&local_sumsrc_snd[i],&local_sumsrc_snd_pending[i],i);
				}

#ifdef BOND_2DIR
//			for(i=0;i<port_cnt;i++)
			i = 0;
			{
				pout=&out[i];
//				for(j=0;j<out_queue_sz[i];j++)
//				for(j=0;j<MAX_DEV;j++)
                for(j=0;j<me.port_cnt;j++)
				{
					if(unlikely(pout->queue_buf[j].buf_pos))
					{
						RUNNING_LOG_DEBUG("%s: core<%d> 100us burst  port=%d out_q=%d cnt=%d p=%p\n",
							__FUNCTION__,rte_lcore_id(),j,out_queue[i][j%out_queue_sz[i]],pout->queue_buf[j].buf_pos,&pout->queue_buf[j].buf);
//						rte_pktmbuf_dump(running_log_fp,(struct rte_mbuf *)pout->queue_buf[j].buf[0],((struct rte_mbuf *)(pout->queue_buf[j].buf[0]))->data_len);

//						save_pcap_file((struct rte_mbuf *)pout->queue_buf[j].buf[0]);

						nb_tx=rte_eth_tx_burst(j,out_queue[i][0],
							(struct rte_mbuf **)&pout->queue_buf[j].buf,pout->queue_buf[j].buf_pos);
						if (unlikely(nb_tx < pout->queue_buf[j].buf_pos))
						{
						    RUNNING_LOG_WARN("%s: core<%d> timer tx %d but %d pkts failed.\n",__FUNCTION__,rte_lcore_id(),
								nb_tx, (pout->queue_buf[j].buf_pos-nb_tx));
							port_stat[j].sub[1].bad_ipv4_pkts+=(pout->queue_buf[j].buf_pos-nb_tx);
							for(;nb_tx < pout->queue_buf[j].buf_pos;nb_tx++)
							{
								rte_pktmbuf_free(pout->queue_buf[j].buf[nb_tx]);
							}
						}
						pout->queue_buf[j].buf_pos=0;
					}
				}
			}

#else
			for(i=0;i<port_cnt;i++)
			{
				pout=&out[i];
				for(j=0;j<out_queue_sz[i];j++)
				{
					if(unlikely(pout->queue_buf[j].buf_pos))
					{
						nb_tx=rte_eth_tx_burst(port_arr[i],out_queue[i][j],
							(struct rte_mbuf **)&pout->queue_buf[j].buf,pout->queue_buf[j].buf_pos);
						if (unlikely(nb_tx < pout->queue_buf[j].buf_pos))
						{
							port_stat[port_arr[i]].sub[1].bad_ipv4_pkts+=(pout->queue_buf[j].buf_pos-nb_tx);
							for(;nb_tx < pout->queue_buf[j].buf_pos;nb_tx++)
							{
								rte_pktmbuf_free(pout->queue_buf[j].buf[nb_tx]);
							}
						}

						pout->queue_buf[j].buf_pos=0;
					}
				}
			}
#endif
			if(!list_empty(&local_timer[timer_curr_idx].header))
			{
				struct flow_nat *fnat,*fnattmp;
				struct pp_info p_info={0};
#ifdef	__SRCP_BIT_MAP__
				struct bitmap_s *lbmp;
#endif
				list_for_each_entry_safe(fnat, fnattmp, &local_timer[timer_curr_idx].header, alloc_list)
				{
#ifdef	__SRCP_BIT_MAP__

//					RUNNING_LOG_DEBUG("%u %u %u", fnat->vip_idx, fnat->sip_idx, fnat->nat_tuplehash[1].tuple_v4.b.pair.l4);
					lbmp = port_bitmap + fnat->vip_idx * NAT_MAX_SIPNUM + fnat->sip_idx;
#endif
					if (mon_ip && (fnat->nat_tuplehash[0].tuple_v4.b.pair.l3==mon_ip||fnat->nat_tuplehash[1].tuple_v4.a.pair.l3==mon_ip))
					{
						RUNNING_LOG_INFO("core %d: del natlist, src=0x%x:%d vip=0x%x:%d => rip=0x%x sip=0x%x:%d\n",
        						my_lcore,
        						fnat->nat_tuplehash[0].tuple_v4.a.pair.l3,
        						fnat->nat_tuplehash[0].tuple_v4.a.pair.l4,
        						fnat->nat_tuplehash[0].tuple_v4.b.pair.l3,
        						fnat->nat_tuplehash[0].tuple_v4.b.pair.l4,
        						fnat->nat_tuplehash[1].tuple_v4.a.pair.l3,
        						fnat->nat_tuplehash[1].tuple_v4.b.pair.l3,
        						fnat->nat_tuplehash[1].tuple_v4.b.pair.l4);
					}


#ifdef __SYNC_FLOW_TABLE__
					flow_nat_sync_msg_snd(local_flow_nat_sync_snd_pending, local_flow_nat_sync_pool,
								fnat,io_cnt, FLOW_NAT_SYNC_MSG_DEL);

					printf("core %d: del natlist, src=0x%x:%d vip=0x%x:%d => rip=0x%x sip=0x%x:%d\n",
        						my_lcore,
        						fnat->nat_tuplehash[0].tuple_v4.a.pair.l3,
        						fnat->nat_tuplehash[0].tuple_v4.a.pair.l4,
        						fnat->nat_tuplehash[0].tuple_v4.b.pair.l3,
        						fnat->nat_tuplehash[0].tuple_v4.b.pair.l4,
        						fnat->nat_tuplehash[1].tuple_v4.a.pair.l3,
        						fnat->nat_tuplehash[1].tuple_v4.b.pair.l3,
        						fnat->nat_tuplehash[1].tuple_v4.b.pair.l4);
#endif

					//delete
					if(list_is_singular(&fnat->nat_tuplehash[0].listnode)){
						INIT_LIST_HEAD(fnat->nat_tuplehash[0].listnode.prev);
						INIT_LIST_HEAD(&fnat->nat_tuplehash[0].listnode);
					}else{
						list_del_init(&fnat->nat_tuplehash[0].listnode);
					}

//					list_del_init(&fnat->nat_tuplehash[0].src_list);

					RUNNING_LOG_DEBUG("core %d: del natlist, src=%u.%u.%u.%u:%d vip=%u.%u.%u.%u:%d => rip=%u.%u.%u.%u sip=%u.%u.%u.%u:%d\n",
        						my_lcore,
        						fnat->nat_tuplehash[0].tuple_v4.a.pair.l3>>24,(fnat->nat_tuplehash[0].tuple_v4.a.pair.l3>>16)&0xff,(fnat->nat_tuplehash[0].tuple_v4.a.pair.l3>>8)&0xff,fnat->nat_tuplehash[0].tuple_v4.a.pair.l3&0xff,
        						fnat->nat_tuplehash[0].tuple_v4.a.pair.l4,
        						fnat->nat_tuplehash[0].tuple_v4.b.pair.l3>>24,(fnat->nat_tuplehash[0].tuple_v4.b.pair.l3>>16)&0xff,(fnat->nat_tuplehash[0].tuple_v4.b.pair.l3>>8)&0xff,fnat->nat_tuplehash[0].tuple_v4.b.pair.l3&0xff,
        						fnat->nat_tuplehash[0].tuple_v4.b.pair.l4,
        						fnat->nat_tuplehash[1].tuple_v4.a.pair.l3>>24,(fnat->nat_tuplehash[1].tuple_v4.a.pair.l3>>16)&0xff,(fnat->nat_tuplehash[1].tuple_v4.a.pair.l3>>8)&0xff,fnat->nat_tuplehash[1].tuple_v4.a.pair.l3&0xff,
        						fnat->nat_tuplehash[1].tuple_v4.b.pair.l3>>24,(fnat->nat_tuplehash[1].tuple_v4.b.pair.l3>>16)&0xff,(fnat->nat_tuplehash[1].tuple_v4.b.pair.l3>>8)&0xff,fnat->nat_tuplehash[1].tuple_v4.b.pair.l3&0xff,
        						fnat->nat_tuplehash[1].tuple_v4.b.pair.l4);

					if(list_is_singular(&fnat->nat_tuplehash[1].listnode)){
						INIT_LIST_HEAD(fnat->nat_tuplehash[1].listnode.prev);
						INIT_LIST_HEAD(&fnat->nat_tuplehash[1].listnode);
					}else{
						list_del_init(&fnat->nat_tuplehash[1].listnode);
					}

#ifdef	__SRCP_BIT_MAP__

					clear_bitmap(lbmp,fnat->nat_tuplehash[1].tuple_v4.b.pair.l4);
#endif

//					list_del_init(&fnat->alloc_list);
//					list_move_tail(&fnat->alloc_list,&local->io_in.flownat_pool.header);
					nat_linkcount[fnat->vip_idx]--;
					if(unlikely(nat_linkcount[fnat->vip_idx] < 0))
						nat_linkcount[fnat->vip_idx] = 0;
					local->io_in.flownat_pool.load++;

				}

				list_splice_tail_init(&local_timer[timer_curr_idx].header,&local->io_in.flownat_pool.header);

			}

			timer_curr_idx++;
			if(unlikely(timer_curr_idx>=TIMER_LOOP_SZ))
			{
				timer_curr_idx=0;
			}
			
//			if (!(timer_curr_idx%(5*TIME_1S_US/TIME_DPI)))
//			{

//			}

			if (unlikely(++loop_cnt>=(IN_TIMER_RES/10)))	// 0.1s
			{
				rte_memcpy(&local_flow_limit, nat_flow_limit, sizeof(nat_flow_limit) );
				loop_cnt = 0;
				ready_port_sum=1;
//				flow_deadtime=me.natconfig.deadtime;
//				nat_timer_handler(timer, local, drain_1s_tsc*me.natconfig.deadtime);
			}

			prev_tsc = cur_tsc;
		}

		//msg from srcsum
		for(i=0;i<sumsrc_cnt;i++)
			{
			msg_C_rcv_poll(local_msgfrom_srcsum_send[i],&local_msgfrom_srcsum_handler[i]);
			}

		for(i=0;i<sumsrc_cnt;i++)
			{
			if(!list_empty(&local_msgfrom_srcsum_handler[i].header))
				{
				list_for_each_entry_safe(ms, mstmp, &local_msgfrom_srcsum_handler[i].header, list)
					{
//					RUNNING_LOG_INFO("core %d : %d XXXXXXXXXXX msg =%d ip=%x ip2=%x\n",my_lcore,i,
//						ms->msg,ms->ip,ms->ip2);


// 					修改src策略
//					switch(ms->msg)
#ifdef __SRC_SUM__
						{
						srcipalldst_dyn_policy_io_setting(local_srcip_policy_pool,
								local_srcip_policy_hash,ms,timer_curr_idx);
						}
#endif
					}

				list_splice_tail_init(&local_msgfrom_srcsum_handler[i].header,
					&local_msgfrom_srcsum_back_pending[i].header);
				local_msgfrom_srcsum_back_pending[i].load+=local_msgfrom_srcsum_handler[i].load;
				local_msgfrom_srcsum_handler[i].load=0;
				}
			}

		for(i=0;i<sumsrc_cnt;i++)
			{
			msg_C_return_poll(&local_msgfrom_srcsum_back_pending[i],local_msgfrom_srcsum_back[i]);
			}

		for(i=0;i<sum_cnt;i++)
		{
			if(local_ip_back[i].load)
				{

				list_splice_tail_init(&local_ip_back[i].header,&local_ip_pool->header);
				local_ip_pool->load+=local_ip_back[i].load;
				rte_smp_wmb();

				RUNNING_LOG_DEBUG("core %d :get back pool local_ip_back[%d].load=%d local_ip_pool.load=%d\n",
					my_lcore,i,local_ip_back[i].load,local_ip_pool->load);

				local_ip_back[i].load=0;

				rte_smp_wmb();
				}
		}

		/*for(i=0;i<pcap_cnt;i++)
		{
			if(local_pcap_back[i].load)
				{

				list_splice_tail_init(&local_pcap_back[i].header,&local_pcap_pool->header);
				local_pcap_pool->load+=local_pcap_back[i].load;
				rte_smp_wmb();

				RUNNING_LOG_DEBUG("core %d :get back pool local_pcap_back[%d].load=%d local_pcap_pool.load=%d\n",
					my_lcore,i,local_pcap_back[i].load,local_pcap_pool->load);

				local_pcap_back[i].load=0;

				rte_smp_wmb();
				}
		}*/

		for(i=0;i<sumsrc_cnt;i++)
			{
			msg_P_retrieve_poll(&local_sumsrc_back[i],local_srcip_sum_pool);
			}

#ifdef	__SYNC_FLOW_TABLE__
		/* snd to other nat core */
		for(i=0;i<(io_cnt-1);i++)
			{
			msg_P_snd_poll(&local_flow_nat_sync_snd_pending[i],local_flow_nat_sync_snd[i]);
			}

		/* retrieve snding item back from other nat core */
		for(i=0;i<(io_cnt-1);i++)
			{
			msg_P_retrieve_poll(local_flow_nat_sync_snd_back[i],local_flow_nat_sync_pool);
			}

		/* rcv nat flow msg from other nat core */
		for(i=0;i<(io_cnt-1);i++)
			{
			msg_C_rcv_poll(local_flow_nat_sync_rcv[i],&local_flow_nat_sync_rcv_handler[i]);
			}

		/* process the flow msg */
		for(i=0;i<(io_cnt-1);i++)
			{
			if(!list_empty(&local_flow_nat_sync_rcv_handler[i].header))
				{
					/* op */
					struct flow_nat_msg *flow_msg_ss,*flow_msg_sstmp;
					struct flow_nat *flow_nat_rcv=NULL;
					struct flow_nat *fnat_msg,*fnat_msgtmp;
					
					list_for_each_entry_safe(flow_msg_ss, flow_msg_sstmp, &local_flow_nat_sync_rcv_handler[i].header, list)
					{
						if (flow_msg_ss->is_add_flow == FLOW_NAT_SYNC_MSG_ADD)
						{
							if(local_flownat_pool->load)
							{
								uint64_t ttt1 = rte_rdtsc(), ttt2;
								
								flow_nat_rcv = list_first_entry(&local_flownat_pool->header, struct flow_nat, alloc_list);

								list_del_init(&flow_nat_rcv->alloc_list);
								
								//memset(&flownat->nat_tuplehash, 0, sizeof(struct ipv4_4tuple)*2);
								flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].dir=flow_msg_ss->nat_tuplehash[CT_DIR_ORIGINAL].dir;
								flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4=flow_msg_ss->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4;
								flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].proto=flow_msg_ss->nat_tuplehash[CT_DIR_ORIGINAL].proto;
								
								flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].dir=flow_msg_ss->nat_tuplehash[CT_DIR_REPLY].dir;
								flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].tuple_v4=flow_msg_ss->nat_tuplehash[CT_DIR_REPLY].tuple_v4;
								flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].proto=flow_msg_ss->nat_tuplehash[CT_DIR_REPLY].proto;
								flow_nat_rcv->last_tick = 0;
								flow_nat_rcv->snat = flow_msg_ss->snat;
								flow_nat_rcv->sip_idx = 0;
								flow_nat_rcv->vip_idx = flow_msg_ss->vip_idx;
								flow_nat_rcv->deadtime = 0;

								flow_nat_rcv->state=FLOW_STATE_MAX;
#ifdef __FIRTST_ACK_SEQ__
								flow_nat_rcv->first_ack_seq_no=flow_msg_ss->first_ack_seq_no;
#endif
								/* original */
								data[0] = flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.pair.l3;
								data[1] = flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.pair.l3;
								data[2] = (flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.pair.l4)<<16
									| flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.pair.l4;
								hash_idx = rte_jhash_3words(data[0], data[1], data[2], PRIME_VALUE);
								hash_idx = hash_idx & (FLOWNAT_HASH_ARRAY_SZ - 1);

								INIT_LIST_HEAD(&flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].listnode);
								list_add_tail(&flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].listnode, &local_flownat_hash[hash_idx].header);

								/* reply */
								data[0] = flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.pair.l3;
								data[1] = flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.pair.l3;
								data[2] =(flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.pair.l4)<<16 
									| flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.pair.l4;
								hash_idx = rte_jhash_3words(data[0], data[1], data[2], PRIME_VALUE);
								hash_idx = hash_idx & (FLOWNAT_HASH_ARRAY_SZ - 1);

								INIT_LIST_HEAD(&flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].listnode);
								list_add_tail(&flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].listnode, &local_flownat_hash[hash_idx].header);

								local_flownat_pool->load--;

								ttt2 = rte_rdtsc() - ttt1;
								if(ttt2>aaa_max[my_lcore])
									aaa_max[my_lcore]=ttt2;
								if((ttt2<aaa_min[my_lcore])||!aaa_min[my_lcore])
									aaa_min[my_lcore]=ttt2;
								
								printf("core %d : ADD original %u.%u.%u.%u:%u --> %u.%u.%u.%u:%u\n",rte_lcore_id(),
									flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.pair.l3>>24,
									(flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.pair.l3>>16)&0xff,
									(flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.pair.l3>>8)&0xff,
									flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.pair.l3&0xff,
									flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.pair.l4,
									flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.pair.l3>>24,
									(flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.pair.l3>>16)&0xff,
									(flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.pair.l3>>8)&0xff,
									flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.pair.l3&0xff,
									flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.pair.l4);

								printf("core %d : ADD reply %u.%u.%u.%u:%u --> %u.%u.%u.%u:%u\n",rte_lcore_id(),
									flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.pair.l3>>24,
									(flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.pair.l3>>16)&0xff,
									(flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.pair.l3>>8)&0xff,
									flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.pair.l3&0xff,
									flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.pair.l4,
									flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.pair.l3>>24,
									(flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.pair.l3>>16)&0xff,
									(flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.pair.l3>>8)&0xff,
									flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.pair.l3&0xff,
									flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.pair.l4);

							}
						}
						else if (flow_msg_ss->is_add_flow == FLOW_NAT_SYNC_MSG_DEL)
						{
							uint64_t ttttt1 = rte_rdtsc(), ttttt2;
							/* Get the flow to be deleted by original tuple */
							flow_nat_rcv = nat_flow_find(&flow_msg_ss->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4, 
								local_flownat_hash,flow_msg_ss->nat_tuplehash[CT_DIR_ORIGINAL].proto);
							if (flow_nat_rcv){
//								printf("111111\n");
								if(list_is_singular(&flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].listnode)){
									INIT_LIST_HEAD(flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].listnode.prev);
									INIT_LIST_HEAD(&flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].listnode);
								}else{
									list_del_init(&flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].listnode);
								}
								if(list_is_singular(&flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].listnode)){
									INIT_LIST_HEAD(flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].listnode.prev);
									INIT_LIST_HEAD(&flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].listnode);
								}else{
									list_del_init(&flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].listnode);
								}

								INIT_LIST_HEAD(&flow_nat_rcv->alloc_list);
								list_add_tail(&flow_nat_rcv->alloc_list, &local_flownat_pool->header);
								local_flownat_pool->load++;
							} else {
//								printf("222222\n");
								/* Get the flow to be deleted by replied tuple */							
								flow_nat_rcv = nat_flow_find(&flow_msg_ss->nat_tuplehash[CT_DIR_REPLY].tuple_v4, 
											local_flownat_hash,flow_msg_ss->nat_tuplehash[CT_DIR_REPLY].proto);
								if (flow_nat_rcv){
									if(list_is_singular(&flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].listnode)){
										INIT_LIST_HEAD(flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].listnode.prev);
										INIT_LIST_HEAD(&flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].listnode);
									}else{
										list_del_init(&flow_nat_rcv->nat_tuplehash[CT_DIR_ORIGINAL].listnode);
									}
									if(list_is_singular(&flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].listnode)){
										INIT_LIST_HEAD(flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].listnode.prev);
										INIT_LIST_HEAD(&flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].listnode);
									}else{
										list_del_init(&flow_nat_rcv->nat_tuplehash[CT_DIR_REPLY].listnode);
									}

									INIT_LIST_HEAD(&flow_nat_rcv->alloc_list);
									list_add_tail(&flow_nat_rcv->alloc_list, &local_flownat_pool->header);
									local_flownat_pool->load++;
								}
							}

							ttttt2 = rte_rdtsc() -ttttt1;
							if(ttttt2>ddd_max[my_lcore])
								ddd_max[my_lcore]=ttttt2;
							if((ttttt2<ddd_min[my_lcore])||!ddd_min[my_lcore])
								ddd_min[my_lcore]=ttttt2;
							printf("core %d : DELETE original %u.%u.%u.%u:%u --> %u.%u.%u.%u:%u\n",rte_lcore_id(),
								flow_msg_ss->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.pair.l3>>24,
								(flow_msg_ss->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.pair.l3>>16)&0xff,
								(flow_msg_ss->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.pair.l3>>8)&0xff,
								flow_msg_ss->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.pair.l3&0xff,
								flow_msg_ss->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.a.pair.l4,
								flow_msg_ss->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.pair.l3>>24,
								(flow_msg_ss->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.pair.l3>>16)&0xff,
								(flow_msg_ss->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.pair.l3>>8)&0xff,
								flow_msg_ss->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.pair.l3&0xff,
								flow_msg_ss->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4.b.pair.l4);
							
							printf("core %d : DELETE reply %u.%u.%u.%u:%u --> %u.%u.%u.%u:%u\n",rte_lcore_id(),
								flow_msg_ss->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.pair.l3>>24,
								(flow_msg_ss->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.pair.l3>>16)&0xff,
								(flow_msg_ss->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.pair.l3>>8)&0xff,
								flow_msg_ss->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.pair.l3&0xff,
								flow_msg_ss->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.pair.l4,
								flow_msg_ss->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.pair.l3>>24,
								(flow_msg_ss->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.pair.l3>>16)&0xff,
								(flow_msg_ss->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.pair.l3>>8)&0xff,
								flow_msg_ss->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.pair.l3&0xff,
								flow_msg_ss->nat_tuplehash[CT_DIR_REPLY].tuple_v4.b.pair.l4);

						}

					}

////////////////////////

					list_splice_tail_init(&local_flow_nat_sync_rcv_handler[i].header,
						&local_flow_nat_sync_rcv_backpending[i].header);
					local_flow_nat_sync_rcv_backpending[i].load+=local_flow_nat_sync_rcv_handler[i].load;
					local_flow_nat_sync_rcv_handler[i].load=0;
				}
			}
		/* return the msg to other nat core */
		for(i=0;i<(io_cnt-1);i++)
			{
			msg_C_return_poll(&local_flow_nat_sync_rcv_backpending[i],local_flow_nat_sync_rcv_back[i]);
			}
#endif	/* #ifdef __SYNC_FLOW_TABLE__ */


		if(unlikely(pre_dtable != dnatconfig_curr))
		{
		        if (my_lcore == 2)
			RUNNING_LOG_DEBUG("core %d :default dnattable change from %d to %d\n",
				my_lcore, pre_dtable, dnatconfig_curr);
			if (dnatconfig_curr)
				rte_memcpy(local_dtable, &dtable[NAT_MAX_DSTNUM], sizeof(struct dnat_item) * NAT_MAX_DSTNUM);
			else
				rte_memcpy(local_dtable, &dtable[0], sizeof(struct dnat_item) * NAT_MAX_DSTNUM);

			pre_dtable=dnatconfig_curr;
			nat_create_dnatconfig_list(local_dtable, local_dnatconfig_hash, local_dnatconfig_pool, &local_dnatconfig_alloclist);
		}

		if(unlikely(pre_stable != snatconfig_curr))
		{
		        if (my_lcore == 2)
			RUNNING_LOG_DEBUG("core %d :default snattable change from %d to %d\n",
				my_lcore, pre_stable, snatconfig_curr);
			if (snatconfig_curr)
				rte_memcpy(local_stable, &stable[NAT_MAX_DSTNUM], sizeof(struct dnat_item) * NAT_MAX_DSTNUM);
			else
				rte_memcpy(local_stable, &stable[0], sizeof(struct dnat_item) * NAT_MAX_DSTNUM);

			pre_stable=snatconfig_curr;
//			nat_create_dnatconfig_list(local_dtable, local_dnatconfig_hash, local_dnatconfig_pool, &local_dnatconfig_alloclist);
			nat_create_snatip_list(local_stable, local_srcipnat_hash, local_srcipnat_pool, &local_srcip_alloclist);
		}

		if(unlikely(pre_viptoa != viptoa_curr))
		{
			if (my_lcore == 2)
				RUNNING_LOG_DEBUG("core %d :default viptoa change from %d to %d\n",
					my_lcore, pre_viptoa, viptoa_curr);
//			rte_memcpy(local_viptoa, nat_viptoa, sizeof(local_viptoa[0]) * NAT_MAX_DSTNUM);
			if (g_dst_pl) {
				for (i=0;i<NAT_MAX_DSTNUM;i++)
					local_viptoa[i] = g_dst_pl[i].toa_flag ? g_dst_pl[i].dstip : 0;
			} else {
				for (i=0;i<NAT_MAX_DSTNUM;i++)
					local_viptoa[i] = 0;
				RUNNING_LOG_ERROR("core<%d> %s: no vip\n", my_lcore, __FUNCTION__);
			}

			pre_viptoa=viptoa_curr;
            nat_create_toavip_list(local_viptoa, local_viptoa_hash, local_viptoa_pool, &local_viptoa_alloclist);
		}
//        tick3 = rte_rdtsc();
//        if (my_lcore == 3)
//        RUNNING_LOG_INFO("core %d :%llu ticks for 1 while loop!==========\n",
//				my_lcore, tick3-tick0);
	}

	if (local_stable)
	{
		free(local_stable);
		local_stable = NULL;
	}
	if (local_dtable)
	{
		free(local_dtable);
		local_dtable = NULL;
	}

}

#if 0
int main_loop_pcap(void)
{
	int my_lcore;
	int i;
	int io_cnt,tmp;
	int pre_pcap_flag = 0;
	int *new_pcap_flag = &do_pcap_flag;
	struct lcore_info_s *local;
	FILE *local_pcap_fp = NULL;

	struct pcap_ship *pcap, *pcaptmp;

	struct hash_array *remote_burst[MAX_CPU];
	struct hash_array *remote_back[MAX_CPU];
	struct hash_array local_rcv[MAX_CPU];
	struct hash_array local_snd[MAX_CPU];

//	struct hash_array local_alloced_list;

	my_lcore=rte_lcore_id();
	local=&lcore[my_lcore];

#ifdef BOND_2DIR
	io_cnt=__builtin_popcountll(me.io_in_mask|me.io_out_mask);
#else
	io_cnt=__builtin_popcountll(me.io_in_mask);
#endif

	rte_memcpy(remote_burst,local->pcap.pcap_io2pcap_burst,sizeof(struct hash_array *)*io_cnt);
	rte_memcpy(remote_back,local->pcap.pcap_io2pcap_back,sizeof(struct hash_array *)*io_cnt);

	for(i=0;i<io_cnt;i++)
	{
		INIT_LIST_HEAD(&local_rcv[i].header);
		local_rcv[i].load=0;
		INIT_LIST_HEAD(&local_snd[i].header);
		local_snd[i].load=0;
	}

	RUNNING_LOG_INFO("core %d: %s start\n",my_lcore,__FUNCTION__);

	while(1)
	{
		if (unlikely(*new_pcap_flag != pre_pcap_flag))
		{
			RUNNING_LOG_INFO("pcap %s\n", *new_pcap_flag ? "start" : "stop");
			pre_pcap_flag = *new_pcap_flag;

			if (pre_pcap_flag) {
				int fileflag = 0;
				struct tm *p;
				time_t now;
				char timebuf[100] = {0};
				char filepath[100] = {0};
				char pcap_save_file[64];

				time(&now);
				p = localtime(&now);
				sprintf(timebuf,"%d%02d%02d-%02d%02d%02d",(1900+p->tm_year),(1+p->tm_mon),p->tm_mday,p->tm_hour,p->tm_min,p->tm_sec);
				sprintf(pcap_save_file,"%s_cap.pcap", timebuf);
				sprintf(filepath,"%s/%s", me.root_dir,pcap_save_file);


				if(!access(filepath, F_OK))
					fileflag = 1;

				if ((local_pcap_fp = fopen(filepath, "a+")) != NULL) {
					if(!fileflag) {
						if(fwrite(pacp_file_header,1,sizeof(pacp_file_header),local_pcap_fp) != sizeof(pacp_file_header)){
							RUNNING_LOG_INFO("Failed to write pcap file header %s \n", filepath);
							return -1;

						}else{
							RUNNING_LOG_INFO("Success to write pcap file header %s \n", filepath);
							return 0;
						}
					}
				}else{
					RUNNING_LOG_INFO("init_pcap_file failed ! \n");
				}
			}else {
				if (local_pcap_fp) {
					fclose(local_pcap_fp);
					local_pcap_fp = NULL;
				}
			}
		}



		for(i=0;i<io_cnt;i++)//rcv
			{
			if(remote_burst[i]->load)
				{
				list_splice_tail_init(&remote_burst[i]->header,&local_rcv[i].header);
				tmp=remote_burst[i]->load;
				rte_smp_wmb();
				remote_burst[i]->load=0;
				rte_smp_wmb();
				local_rcv[i].load+=tmp;

				RUNNING_LOG_DEBUG("core %d :remote_burst[%d]->load=%d local_rcv.load=%d\n",
					my_lcore,i,tmp,local_rcv[i].load);

				}
			}

		for(i=0;i<io_cnt;i++)//process
			{
			if(local_rcv[i].load)
				{
				RUNNING_LOG_DEBUG("core %d :local_rcv[%d]->load=%d local_snd.load=%d\n",
					my_lcore,i,local_rcv[i].load,local_snd[i].load);

				list_for_each_entry_safe(pcap,pcaptmp,&local_rcv[i].header,list)
				{
					if (unlikely(!local_pcap_fp))
					{
						int fileflag = 0;
						struct tm *p;
						time_t now;
						char timebuf[100] = {0};
						char filepath[100] = {0};
						char pcap_save_file[64];

						time(&now);
						p = localtime(&now);
						sprintf(timebuf,"%d%02d%02d-%02d%02d%02d",(1900+p->tm_year),(1+p->tm_mon),p->tm_mday,p->tm_hour,p->tm_min,p->tm_sec);
						sprintf(pcap_save_file,"%s_cap.pcap", timebuf);
						sprintf(filepath,"%s/%s",me.root_dir, pcap_save_file);


						if(!access(filepath, F_OK))
							fileflag = 1;

						if ((local_pcap_fp = fopen(filepath, "a+")) != NULL) {
							if(!fileflag) {
								if(fwrite(pacp_file_header,1,sizeof(pacp_file_header),local_pcap_fp) != sizeof(pacp_file_header)){
									RUNNING_LOG_INFO("Failed to write pcap file header %s \n", filepath);
									return -1;

								}else{
									RUNNING_LOG_DEBUG("Success to write pcap file header %s \n", filepath);
									return 0;
								}
							}
						}else{
							RUNNING_LOG_INFO("init_pcap_file failed ! \n");
						}
					}

					list_del_init(&pcap->list);
					list_add_tail(&pcap->list,&local_snd[i].header);
					local_snd[i].load++;
					local_rcv[i].load--;
				}

                                if (local_pcap_fp){
        				if ( fwrite((char *)pcap->buf, 1, pcap->len, local_pcap_fp) != (unsigned int)pcap->len)
        					RUNNING_LOG_INFO("%s:Failed to write pcap data info \n", __FUNCTION__);
                                }

				RUNNING_LOG_DEBUG("core %d :deal local_snd[%d].load=%d local_rcv[i].load=%d\n",
					my_lcore,i,local_snd[i].load,local_rcv[i].load);

				}
			}


		for(i=0;i<io_cnt;i++)//free back
		{
		//ip
		if((!remote_back[i]->load)&&(local_snd[i].load))
			{
			list_splice_tail_init(&local_snd[i].header,&remote_back[i]->header);
			rte_smp_wmb();
			remote_back[i]->load=local_snd[i].load;
			rte_smp_wmb();
			local_snd[i].load=0;

			RUNNING_LOG_DEBUG("core %d :push back remote_back[%d]->load=%d\n",
				my_lcore,i,remote_back[i]->load);
			}
		}

	}

}
#endif
#if 0
int main_loop_s0(void)
{
	int my_lcore;
	int i,j,k,nb_rx,nb_tx;
	int loop_10ms_cnt=0;
	int loop_cnt=0;
	int port_cnt;
	uint8_t port_arr[MAX_DEV];
	uint8_t txport_arr[MAX_DEV];
	uint16_t queue_arr[MAX_DEV];
	struct rte_mbuf *pkts_burst[BURST_SZ];
	int prev_req,curr_req;
	struct hash_array *ip_hash;
	struct hash_array *flow_hash;
	struct lcore_info_s *local;
	uint64_t cur_tsc, prev_tsc,diff_tsc, hz;
	uint64_t local_mask;
	int sum_cnt;
	struct ip_g_s2 *ipdst;
	uint64_t start,end;
	int i_vlan=0,o_vlan=0;

#if defined(BOND_2DIR)
	uint32_t if_ip[]={rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.in_ip),
		rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.out_ip)};
	uint32_t if_ipmask[]={rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.in_ipmask),
		rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.out_ipmask)};
#else
	uint32_t if_ip[]={rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.in_ip & me.settle_setting.gw_bonding_inoutvlan.in_ipmask),
		rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.out_ip & me.settle_setting.gw_bonding_inoutvlan.out_ipmask)};
	uint32_t if_ipmask[]={rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.in_ipmask),
		rte_be_to_cpu_32(me.settle_setting.gw_bonding_inoutvlan.out_ipmask)};
#endif

	char l2_data[16]={0};
	int l2_data_valid=0;
	int *l2_sig;
	char *l2_pdata;

	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1)/US_PER_S * 10;//10us
	const uint64_t drain_1s_tsc = (rte_get_tsc_hz() + US_PER_S - 1)/US_PER_S * IN_TIMER_1S;//100us

	struct hash_array *local_ip_pool,*local_ip_burst,*local_ip_burstcache,*local_ip_back;
	struct hash_array *local_netport_pool,*local_netport_back;

	struct hash_array *local_flow_pool,*local_flowtag_pool;
	struct port_info_sum *port_stat;
	int ready_port_sum;
	int mystate=0;
	int prev_policy=0;
	struct policy mydefaultpolicy;
	struct core_timer *timer;
	struct port_push *port_snd;
	struct rte_ring *ring_input[MAX_DEV];
	int ret=0;
#ifdef IN_OUT_IN1_MODE
	struct out_buf_s out[MAX_DEV];
	struct out_buf_s *pout;
	int out_queue[MAX_DEV][MAX_TX_QUEUE]={0};
	int out_queue_sz[MAX_DEV]={0};
#endif
#ifdef PIPE_OUT_LIST_MODE
	struct out_burst_cell *cell;
	struct hash_array out_pending[MAX_CPU];
#endif

	struct flow_nat *flownat;
	uint32_t hash_idx = 0;
	static uint16_t tcp_port_rover;
	static uint16_t udp_port_rover;
	int tupleidx = 0;
	int fresh_tupleidx = 0;
	int pos = 0;
	struct nat_map_tuple *nat_tuplepair, *fresh_tuplepair;
	struct hash_array *local_flownat_pool,*local_flownat_hash, *local_srcnat_hash;
	struct dnat_item local_dtable[NAT_MAX_DSTNUM] = {0};
	int pre_dtable=0;
	uint32_t data[3];
	int num=0;

	my_lcore=rte_lcore_id();
	local_mask=(1ULL<<my_lcore);
	local=&lcore[my_lcore];
	l2_sig=&local->io_in.l2_sig;
	l2_pdata=&local->io_in.l2_data[0];
	timer=&local->localtimer;
	port_cnt=local->port_cnt;
	if(me.settle_setting.mode==INTERFACE_MODE_GW_BONDING)
		{
		i_vlan=me.settle_setting.gw_bonding_inoutvlan.in_vlanid;
		o_vlan=me.settle_setting.gw_bonding_inoutvlan.out_vlanid;
		}

#ifdef IN_OUT_IN1_MODE
	memset(out,0,sizeof(out[0])*MAX_DEV);
	for(i=0;i<local->port_cnt;i++)
		{
		out_queue_sz[i]=local->io_in.out_queue_sz[i];
		rte_memcpy(out_queue[i],local->io_in.out_queue[i],sizeof(int)*MAX_TX_QUEUE);
		}
#endif
	rte_memcpy(port_arr,local->port_id,sizeof(local->port_id[0])*MAX_DEV);
	rte_memcpy(txport_arr,local->txport_id,sizeof(local->txport_id[0])*MAX_DEV);
	rte_memcpy(queue_arr,local->queue_id,sizeof(local->queue_id[0])*MAX_DEV);
	ip_hash=local->io_in.io_in_hash;
	hz = rte_get_timer_hz();

	local_ip_pool=&local->io_in.ip_pool;
	local_ip_burst=local->io_in.ip_io2sum_burst;
	local_ip_burstcache=local->io_in.ip_io2sum_pending;
	local_ip_back=local->io_in.ip_sum2io_burst;
	local_netport_pool=&local->io_in.netport_pool;
	local_netport_back=local->io_in.netport_sum2io_burst;

	local_flow_pool=&local->io_in.flow_pool;
	local_flowtag_pool=&local->io_in.flowtag_pool;
//	flow_hash=local->io_in.io_flow_hash;
	sum_cnt=__builtin_popcountll(me.sum_mask);
	port_stat=&local->io_in.port_sub[local->io_in.port_sum_curr];
	ready_port_sum=0;
	port_snd=local->io_in.port_do_push;
	rte_memcpy(ring_input,local->io_in.kni_ring,sizeof(struct rte_ring *)*MAX_DEV);

	local_flownat_pool=&local->io_in.flownat_pool;
	local_flownat_hash = local->io_in.io_flownat_hash;
//	local_srcnat_hash = local->io_in.io_srcnat_hash;
	nat_tuplepair = &local->io_in.tuplepair[0];
	fresh_tuplepair = &local->io_in.freshtuplepair[0];
	memset(local->io_in.tuplepair, 0, sizeof(struct nat_map_tuple)*MAX_TUPLEPAIR*2);
	memset(local->io_in.totaltuplepair, 0, TOTAL_MAX_TUPLEPAIR*sizeof(struct sum_map_tuple));

#ifdef PIPE_OUT_LIST_MODE
	for(i=0;i<MAX_CPU;i++)
		{
		INIT_LIST_HEAD(&out_pending[i].header);
		out_pending[i].load=0;
		}
#endif

	RUNNING_LOG_INFO("core %d :main_loop_io_s0\n",my_lcore);

	memcpy(&mydefaultpolicy,&default_policy[default_curr],sizeof(mydefaultpolicy));
	prev_policy=default_curr;


	if (dnatconfig_curr)
		rte_memcpy(&local_dtable, &dtable[NAT_MAX_DSTNUM], sizeof(local_dtable[0]) * NAT_MAX_DSTNUM);
	else
		rte_memcpy(&local_dtable, &dtable[0], sizeof(local_dtable[0]) * NAT_MAX_DSTNUM);

	pre_dtable=dnatconfig_curr;

	prev_tsc=cur_tsc=rte_rdtsc();

	while(1){
		cur_tsc = rte_rdtsc();

#ifdef VLAN_ON
		if(unlikely(*l2_sig))
		{
			rte_memcpy(l2_data,l2_pdata,16);
			*l2_sig=0;
			l2_data_valid=1;
			rte_wmb();

			RUNNING_LOG_DEBUG("core<%d>: dump out mac %x:%x:%x:%x:%x:%x <- %x:%x:%x:%x:%x:%x type=%x%x vlan=%d\n",
				my_lcore,l2_data[0],l2_data[1],l2_data[2],
				l2_data[3],l2_data[4],l2_data[5],
				l2_data[6],l2_data[7],l2_data[8],
				l2_data[9],l2_data[10],l2_data[11],
				l2_data[12],l2_data[13],l2_data[14]>>+l2_data[15]);
		}
#else
		if(unlikely(*l2_sig))
		{
			rte_memcpy(l2_data,l2_pdata,14);
			*l2_sig=0;
			l2_data_valid=1;
			rte_wmb();

			RUNNING_LOG_DEBUG("core<%d>: dump out mac %x:%x:%x:%x:%x:%x <- %x:%x:%x:%x:%x:%x type=%x%x\n",
				rte_lcore_id(),(uint8_t)l2_data[0], (uint8_t)l2_data[1], (uint8_t)l2_data[2],
				(uint8_t)l2_data[3], (uint8_t)l2_data[4], (uint8_t)l2_data[5],
				(uint8_t)l2_data[6], (uint8_t)l2_data[7], (uint8_t)l2_data[8],
				(uint8_t)l2_data[9],(uint8_t)l2_data[10],(uint8_t)l2_data[11],
				l2_data[12],l2_data[13]);
		}

#endif


		//process pkts
		for(i=0;i<port_cnt;i++)
		{
			nb_rx = rte_eth_rx_burst(port_arr[i], queue_arr[i], pkts_burst,BURST_SZ);
			pout=&out[i];
			if(nb_rx)
			{
				for(j=0;j<nb_rx;j++)
				{
					struct pp_info p_info={0};
					struct flow_nat *natflow;
					enum nat_manip_type maniptype=NAT_MANIP_NULL;
					struct ipv4_4tuple curr_tuple, new_tuple,tmp_tuple;
					enum nat_manip_type type;
					uint32_t ip_tmp = 0;

					ret=pkt_getinfo(pkts_burst[j],&port_stat[port_arr[i]],&mydefaultpolicy,
							&p_info,local->state,if_ip,if_ipmask,local->port_cnt,i_vlan,o_vlan,
							l2_data_valid,
							local_ip_pool,
							local_ip_burstcache,ip_hash,
							sum_cnt,&local->io_in,&ipdst);


					pkts_burst[j]->seqn = p_info.packet_info;

//					if(likely(!(ret & FLAG(POLICY_ACT_KERNEL))))
//						{
//						ipdst=pkt_dstip_handler(pkts_burst[j],&p_info,local_ip_pool,
//							local_ip_burstcache,ip_hash,
//							sum_cnt,&local->io_in);
//						}

//					if (my_lcore == 0 )
//					RUNNING_LOG_DEBUG("core %d :nat =>src=0x%x dst=0x%x,sport=%d dport=%d\n",rte_lcore_id(),p_info.srcip,  p_info.dstip, p_info.sport, p_info.dport);

					if(unlikely(ret & FLAG(POLICY_ACT_KERNEL)))
						{
						RUNNING_LOG_DEBUG("%s: core<%d> enqueue pkt to ring\n",__FUNCTION__,rte_lcore_id());

//						rte_pktmbuf_dump(running_log_fp,pkts_burst[j],pkts_burst[j]->data_len);

//						if(rte_ring_mp_enqueue(ring_input[i],(void *)pkts_burst[j]))
//							{
//							RUNNING_LOG_DEBUG("%s: core<%d> enqueue fail port %d\n",__FUNCTION__,rte_lcore_id(),i);
//							}
						}
					else if(ret & FLAG(POLICY_ACT_DROP))
						{
						RUNNING_LOG_DEBUG("%s: core<%d> POLICY_ACT_DROP pkt\n",__FUNCTION__,rte_lcore_id());
						rte_pktmbuf_free(pkts_burst[j]);
						}
					else
						{

#ifdef IN_OUT_IN1_MODE
						int queue_idx;
						int pos;
						int dstip_idx;

#ifdef VLAN_ON
						char *l2_hdr=rte_pktmbuf_mtod(pkts_burst[j], char *);

//						rte_pktmbuf_dump(running_log_fp,pkts_burst[j],pkts_burst[j]->data_len);

						rte_memcpy(l2_hdr,l2_data,16);

//						rte_pktmbuf_dump(running_log_fp,pkts_burst[j],pkts_burst[j]->data_len);
//#else
//						char *l2_hdr=rte_pktmbuf_mtod(pkts_burst[j], char *);

//						rte_memcpy(l2_hdr,l2_data,14);
#else
						char *l2_hdr=rte_pktmbuf_mtod(pkts_burst[j], char *);
						char l2_tmp[6];

						rte_memcpy(l2_tmp,l2_hdr,6);
						rte_memcpy(l2_hdr,l2_hdr+6,6);
						rte_memcpy(l2_hdr+6,l2_tmp,6);
#endif



#ifdef WF_NAT
						curr_tuple.a.pair.l3 = p_info.srcip;
						curr_tuple.a.pair.l4 = p_info.sport;
						curr_tuple.b.pair.l3 = p_info.dstip;
						curr_tuple.b.pair.l4 = p_info.dport;

						natflow = nat_flow_find(&curr_tuple, local_flownat_hash);

						if (NULL == natflow)
						{
#ifdef BOND_2DIR
							if  (FUN_IO_IN == local->type)
#endif
							{
								struct dnat_range natrange;
								int ret, proto;

								memset(&natrange, 0, sizeof(struct dnat_range));
								if(p_info.packet_info & FLAG(F_TCP))
									proto = L4_TYPE_TCP;
								else if(p_info.packet_info & FLAG(F_UDP))
									proto = L4_TYPE_UDP;

//								maniptype = dnat_rule_find(&curr_tuple, proto, local_dtable, &natrange, &dstip_idx);
								RUNNING_LOG_INFO("core %d :nat =>maniptype=%d,sip=0x%x dst=0x%x,sport=%d dport=%d\n",rte_lcore_id(),maniptype,
									p_info.srcip, p_info.dstip, p_info.sport, p_info.dport);

								if (NAT_MANIP_DST == maniptype)
								{
//									if (my_lcore == 0 ){
//										//num++;
										RUNNING_LOG_INFO("core %d :nat_rule_find sport=%d dst_port=%d, nat_port=%d,natip=%x num=%d\n",rte_lcore_id(),p_info.sport,p_info.dport,natrange.nat_port,natrange.nat_ip[0], num);
//									}
									ret = dnat_get_unique_tuple(&new_tuple, &curr_tuple, &natrange, local_flownat_hash);
									nat_invert_tuple(&tmp_tuple, &new_tuple);

									if (tupleidx < MAX_TUPLEPAIR){
										nat_tuplepair[tupleidx].tuplepair[CT_DIR_ORIGINAL]=curr_tuple;
										nat_tuplepair[tupleidx].tuplepair[CT_DIR_REPLY]=tmp_tuple;
										tupleidx++;
									}else{
//										RUNNING_LOG_INFO("core %d :too many tupleidx\n",rte_lcore_id(),p_info.dstip,p_info.dport,natrange.nat_port,natrange.nat_ip[0], num);
									}

									//RUNNING_LOG_DEBUG("core %d :nat_get_unique_tuple ret=%d,sip=%x dip=%x,sport=%d dport=%d\n",rte_lcore_id(),ret,tmp_tuple.a.pair.l3,tmp_tuple.b.pair.l3,tmp_tuple.a.pair.l4,tmp_tuple.b.pair.l4);
									nat_ipv4_manip_pkt(pkts_burst[j], &p_info, &new_tuple, maniptype);
									nat_ipv4_manip_pkt(pkts_burst[j], &p_info, &new_tuple, NAT_MANIP_SRC);

								}
								else{
									RUNNING_LOG_DEBUG("%s: core<%d> drop pkt\n",__FUNCTION__,rte_lcore_id());
									rte_pktmbuf_free(pkts_burst[j]);
									continue;
								}
							}
#ifdef BOND_2DIR
							else{
//								RUNNING_LOG_INFO("core %d :sip=0x%x dst=0x%x,sport=%d dport=%d\n",rte_lcore_id(), p_info.srcip,  p_info.dstip, p_info.sport, p_info.dport);

								ip_tmp = dnat_find_dstip_bynatip(p_info.srcip, local_dtable);
								if (likely(0 != ip_tmp))
								{
//								RUNNING_LOG_INFO("%s: core<%d> rebuit pkt by DNAT\n",__FUNCTION__,rte_lcore_id());
									new_tuple = curr_tuple;
									new_tuple.a.pair.l3 = ip_tmp;
									nat_ipv4_manip_pkt(pkts_burst[j], &p_info, &new_tuple, maniptype);
								}else{
//									RUNNING_LOG_INFO("%s: core<%d> DROP pkt by DNAT\n",__FUNCTION__,rte_lcore_id());
									rte_pktmbuf_free(pkts_burst[j]);
									continue;
								}
							}
#endif
						}else{
							natflow->last_tick = cur_tsc;
							RUNNING_LOG_INFO("core %d :nat_flow_find src=0x%x,reply src=0x%x\n",rte_lcore_id(),p_info.srcip,natflow->nat_tuplehash[CT_DIR_REPLY].tuple_v4.a.pair.l3);
							if(nat_equal_tuple(&natflow->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4, &curr_tuple)){
								tmp_tuple = natflow->nat_tuplehash[CT_DIR_REPLY].tuple_v4;
								type = NAT_MANIP_DST;
							}else{
								tmp_tuple = natflow->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4;
								type = NAT_MANIP_SRC;
							}

							nat_invert_tuple(&new_tuple, &tmp_tuple);

							if (fresh_tupleidx < MAX_TUPLEPAIR){
								fresh_tuplepair[fresh_tupleidx].tuplepair[0] = natflow->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4;
								fresh_tuplepair[fresh_tupleidx].tuplepair[1] = natflow->nat_tuplehash[CT_DIR_REPLY].tuple_v4;
								fresh_tupleidx++;
							}
#ifdef BOND_2DIR
							if (FUN_IO_IN == local->type)
								type = NAT_MANIP_DST;
							else
								type = NAT_MANIP_SRC;

							nat_ipv4_manip_pkt(pkts_burst[j], &p_info, &new_tuple, type);
#else
							nat_ipv4_manip_pkt(pkts_burst[j], &p_info, &new_tuple, NAT_MANIP_SRC);
							nat_ipv4_manip_pkt(pkts_burst[j], &p_info, &new_tuple, NAT_MANIP_DST);
#endif


#ifdef BOND_2DIR
							if  (FUN_IO_OUT == local->type)
#else
							ip_tmp = dnat_find_dstip_bynatip(p_info.srcip, local_dtable);
							if (0 != ip_tmp)
#endif
							{
								p_info.srcip = new_tuple.a.pair.l3;
								p_info.sport = new_tuple.a.pair.l4;
								RUNNING_LOG_DEBUG("core %d :pkt_srcip_handler srcip=0x%x,sport=%d\n",rte_lcore_id(),p_info.srcip,p_info.sport);
								ipdst=pkt_dstip_handler(pkts_burst[j], &p_info, local_ip_pool, local_ip_burstcache, ip_hash, sum_cnt, &local->io_in,
									DIR_IN, dstip_idx);
							}
						}



#endif

						queue_idx=(pkts_burst[j]->hash.rss>>4)%out_queue_sz[i];
						pos=pout->queue_buf[queue_idx].buf_pos;
						pout->queue_buf[queue_idx].buf[pos]=(void *)pkts_burst[j];
						pout->queue_buf[queue_idx].buf_pos++;
						//RUNNING_LOG_DEBUG("%s: core<%d> send portidx=%d port=%d qidx=%d q=%d pos=%d\n",
							//__FUNCTION__,rte_lcore_id(),i,port_arr[i],
							//queue_idx,out_queue[i][queue_idx],pout->queue_buf[queue_idx].buf_pos);

						if(unlikely(pout->queue_buf[queue_idx].buf_pos >= BURST_SZ))
							{
//							RUNNING_LOG_DEBUG("%s: core<%d> burst portidx=%d port=%d qidx=%d q=%d\n",
//								__FUNCTION__,rte_lcore_id(),i,txport_arr[i],
//								queue_idx,out_queue[i][queue_idx]);
#ifdef BOND_2DIR
							nb_tx=rte_eth_tx_burst(txport_arr[i],out_queue[i][queue_idx],(struct rte_mbuf **)&pout->queue_buf[queue_idx].buf,BURST_SZ);
							if (unlikely(nb_tx < BURST_SZ))
								{
								port_stat[txport_arr[i]].sub[1].bad_ipv4_pkts+=(BURST_SZ-nb_tx);
								for(;nb_tx<BURST_SZ;nb_tx++)
									{
									rte_pktmbuf_free(pout->queue_buf[queue_idx].buf[nb_tx]);
									}
								}
							pout->queue_buf[queue_idx].buf_pos=0;
							}

						update_port_sum_out(pkts_burst[j],&port_stat[txport_arr[i]]);
#else
							nb_tx=rte_eth_tx_burst(port_arr[i],out_queue[i][queue_idx],(struct rte_mbuf **)&pout->queue_buf[queue_idx].buf,BURST_SZ);
							if (unlikely(nb_tx < BURST_SZ))
								{
								port_stat[port_arr[i]].sub[1].bad_ipv4_pkts+=(BURST_SZ-nb_tx);
								for(;nb_tx<BURST_SZ;nb_tx++)
									{
									rte_pktmbuf_free(pout->queue_buf[queue_idx].buf[nb_tx]);
									}
								}
							pout->queue_buf[queue_idx].buf_pos=0;
							}

						update_port_sum_out(pkts_burst[j],&port_stat[port_arr[i]]);
#endif
#endif

						}
					}
				}
			}

		if(unlikely(ready_port_sum))
		{
			if(!local->io_in.port_sum_sig)
			{
				local->io_in.port_sum_curr^=1;
				if(local->io_in.port_sum_curr)
					port_stat=&local->io_in.port_sub[MAX_DEV];
				else
					port_stat=&local->io_in.port_sub[0];

				memset(port_stat,0,sizeof(struct port_info_sum)*MAX_DEV);
				ready_port_sum=0;

				local->io_in.port_sum_sig=1;
				rte_smp_wmb();

//				end=rte_rdtsc()-start;
//				RUNNING_LOG_DEBUG("core %d  switch waste %llu\n",my_lcore,end);

			}
		}

#ifdef WF_NAT
#if 0
		if(tupleidx)
		{
			if(!local->io_in.nat_tuplepair_sig)
			{
			RUNNING_LOG_DEBUG("core %d: natlist tupleidx=%d\n",my_lcore, tupleidx);
				local->io_in.nat_tuplepair_curr^=1;
				if(local->io_in.nat_tuplepair_curr)
					nat_tuplepair=&local->io_in.tuplepair[MAX_TUPLEPAIR];
				else
					nat_tuplepair=&local->io_in.tuplepair[0];

				memset(nat_tuplepair, 0, sizeof(struct nat_map_tuple)*tupleidx);
				tupleidx = 0;

				local->io_in.nat_tuplepair_sig=1;
				rte_smp_wmb();
			}
		}
#endif

		if(!local->io_in.nat_tuplepair_sig )
		{
			if(tupleidx)
			{
				RUNNING_LOG_DEBUG("core %d: natlist tupleidx=%d\n",my_lcore, tupleidx);
				local->io_in.nat_tuplepair_curr^=1;
				if(local->io_in.nat_tuplepair_curr)
				{
					local->io_in.tuplepair[0].cnt = tupleidx;
					nat_tuplepair=&local->io_in.tuplepair[MAX_TUPLEPAIR];
				}
				else{
					local->io_in.tuplepair[MAX_TUPLEPAIR].cnt = tupleidx;
					nat_tuplepair=&local->io_in.tuplepair[0];
				}

				memset(nat_tuplepair, 0, sizeof(struct nat_map_tuple)*MAX_TUPLEPAIR);
				tupleidx = 0;

				local->io_in.nat_tuplepair_sig=1;
				rte_smp_wmb();
			}
		}

		if(fresh_tupleidx)
		{
			if(!local->io_in.fresh_tuplepair_sig)
			{
				local->io_in.fresh_tuplepair_curr^=1;
				if(local->io_in.fresh_tuplepair_curr)
					fresh_tuplepair=&local->io_in.freshtuplepair[MAX_TUPLEPAIR];
				else
					fresh_tuplepair=&local->io_in.freshtuplepair[0];

				//RUNNING_LOG_DEBUG("core %d :nat fresh =%d\n",rte_lcore_id(),fresh_tupleidx);
				//memset(fresh_tuplepair, 0, sizeof(struct nat_map_tuple)*MAX_TUPLEPAIR);
				fresh_tupleidx = 0;

				local->io_in.fresh_tuplepair_sig=1;
				rte_smp_wmb();
			}
		}

		//for new add tuplepair
		if(!local->io_in.sum_tuplepair_sig)
		{
//			if (0 == my_lcore){
//				num++;
//				RUNNING_LOG_INFO("core %d :sum_tuplepair_sig load=%d,%d\n",my_lcore, local_flownat_pool->load, num);
//				}

			for(i=0; i<TOTAL_MAX_TUPLEPAIR; i++)
			{
				if (local->io_in.totaltuplepair[i].map_tuple.tuplepair[0].a.pair.l3 != 0)
				{
//					if (0 == my_lcore)
//						RUNNING_LOG_INFO("core %d :local_flownat_pool load=%d\n",my_lcore, local_flownat_pool->load);
					//alloc
					if(local_flownat_pool->load)
					{
						flownat = list_first_entry(&local_flownat_pool->header, struct flow_nat, alloc_list);
						//memset(&flownat->nat_tuplehash, 0, sizeof(struct ipv4_4tuple)*2);
						flownat->nat_tuplehash[CT_DIR_ORIGINAL].dir=CT_DIR_ORIGINAL;
						flownat->nat_tuplehash[CT_DIR_ORIGINAL].tuple_v4=local->io_in.totaltuplepair[i].map_tuple.tuplepair[0];
						flownat->nat_tuplehash[CT_DIR_REPLY].dir=CT_DIR_REPLY;
						flownat->nat_tuplehash[CT_DIR_REPLY].tuple_v4=local->io_in.totaltuplepair[i].map_tuple.tuplepair[1];
						flownat->last_tick = cur_tsc;

						//hash_idx = local->io_in.totaltuplepair[i].hashidx_0;
						data[0] =local->io_in.totaltuplepair[i].map_tuple.tuplepair[0].a.pair.l3;
						data[1] = local->io_in.totaltuplepair[i].map_tuple.tuplepair[0].b.pair.l3;
						data[2] = (local->io_in.totaltuplepair[i].map_tuple.tuplepair[0].a.pair.l4)<<16 |local->io_in.totaltuplepair[i].map_tuple.tuplepair[0].b.pair.l4;
						hash_idx = rte_jhash_3words(data[0], data[1], data[2], PRIME_VALUE);
						hash_idx = hash_idx & (FLOW_HASH_ARRAY_SZ - 1);
						INIT_LIST_HEAD(&flownat->nat_tuplehash[CT_DIR_ORIGINAL].listnode);
						list_add_tail(&flownat->nat_tuplehash[CT_DIR_ORIGINAL].listnode, &local_flownat_hash[hash_idx].header);

						//hash_idx = local->io_in.totaltuplepair[i].hashidx_1;
						data[0] = local->io_in.totaltuplepair[i].map_tuple.tuplepair[1].a.pair.l3;
						data[1] = local->io_in.totaltuplepair[i].map_tuple.tuplepair[1].b.pair.l3;
						data[2] =(local->io_in.totaltuplepair[i].map_tuple.tuplepair[1].a.pair.l4)<<16 |local->io_in.totaltuplepair[i].map_tuple.tuplepair[1].b.pair.l4;
						hash_idx = rte_jhash_3words(data[0], data[1], data[2], PRIME_VALUE);
						hash_idx = hash_idx & (FLOW_HASH_ARRAY_SZ - 1);
						INIT_LIST_HEAD(&flownat->nat_tuplehash[CT_DIR_REPLY].listnode);
						list_add_tail(&flownat->nat_tuplehash[CT_DIR_REPLY].listnode, &local_flownat_hash[hash_idx].header);

						pos++;
						if(pos >= timer->queue_sz)
							pos=0;
						list_move_tail(&flownat->alloc_list,&timer->natlist[pos].header);
						local_flownat_pool->load--;
					}
					else
					{
						RUNNING_LOG_INFO("core %d :local_flownat_pool miss dst=%x src=%x,alloc flownat fail\n",rte_lcore_id(),
							local->io_in.totaltuplepair[i].map_tuple.tuplepair[0].b.pair.l3,local->io_in.totaltuplepair[i].map_tuple.tuplepair[0].a.pair.l3);

						local->io_in.miss_alloced_flownat++;
					}
					memset(&local->io_in.totaltuplepair[i], 0, sizeof(struct sum_map_tuple));
				}else{
					break;
				}


			}

			local->io_in.sum_tuplepair_sig=1;
			rte_smp_wmb();
		}

		//for refreshing tuplepair
		if(!local->io_in.sum_freshtuple_sig)
		{
			struct flow_nat *natflow;
			for(i=0; i<TOTAL_MAX_TUPLEPAIR; i++)
			{
				if (local->io_in.totalfreshtuple[i].map_tuple.tuplepair[0].a.pair.l3 != 0)
				{
					natflow = nat_flow_find(&local->io_in.totalfreshtuple[i].map_tuple.tuplepair[0], local_flownat_hash);
					if (natflow != NULL){
						natflow->last_tick = cur_tsc;
						rte_smp_wmb();
//						RUNNING_LOG_DEBUG("core %d: nat fresh last_tick sip=0x%x,sport=%d\n", rte_lcore_id(),
//						local->io_in.totalfreshtuple[i].map_tuple.tuplepair[0].a.pair.l3,
//						local->io_in.totalfreshtuple[i].map_tuple.tuplepair[0].a.pair.l4);
					}
				}
				else{
					break;
				}
				//memset(&local->io_in.totalfreshtuple[i], 0, sizeof(struct sum_map_tuple));
			}

			local->io_in.sum_freshtuple_sig=1;
			rte_smp_wmb();
		}
#endif



		//process timer
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc*20))
		{
			if  (FUN_IO_OUT == local->type){
				for(i=0;i<sum_cnt;i++)
					do_burst(&local_ip_burst[i],&local_ip_burstcache[i],i);
			}

#ifdef IN_OUT_IN1_MODE
			for(i=0;i<port_cnt;i++)
			{
				pout=&out[i];
				for(j=0;j<out_queue_sz[i];j++)
				{
					if(unlikely(pout->queue_buf[j].buf_pos))
					{
						RUNNING_LOG_DEBUG("%s: core<%d> 100us burst portidx=%d port=%d qidx=%d q=%d cnt=%d\n",
							__FUNCTION__,rte_lcore_id(),i,port_arr[i],
							j,out_queue[i][j],pout->queue_buf[j].buf_pos);
//						rte_pktmbuf_dump(running_log_fp,(struct rte_mbuf *)pout->queue_buf[j].buf[0],((struct rte_mbuf *)(pout->queue_buf[j].buf[0]))->data_len);

#if 0
				rte_pktmbuf_dump(running_log_fp,(struct rte_mbuf *)pout->queue_buf[j].buf[0],((struct rte_mbuf *)(pout->queue_buf[j].buf[0]))->data_len);
				struct ether_hdr *eth_hdr = rte_pktmbuf_mtod((struct rte_mbuf *)pout->queue_buf[j].buf[0], struct ether_hdr *);
				struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)((uint8_t *)eth_hdr + sizeof(struct ether_hdr));
				struct tcp_hdr *tcphdr = (struct tcp_hdr *)((uint8_t *)ip_hdr + sizeof(struct ipv4_hdr));
				int len = rte_be_to_cpu_16(ip_hdr->total_length) -  sizeof(struct ipv4_hdr);

				RUNNING_LOG_DEBUG("%s: core<%d> ip checksum=%x\n", __FUNCTION__,rte_lcore_id(),ip_hdr->hdr_checksum);
				RUNNING_LOG_DEBUG("%s: core<%d> tcp checksum=%x\n", __FUNCTION__,rte_lcore_id(),rte_be_to_cpu_16(tcphdr->cksum));
				ip_hdr->hdr_checksum = 0;
				tcphdr->cksum = 0;
				tcphdr->cksum = tcp_v4_check(len, ip_hdr->src_addr, ip_hdr->dst_addr,
					 csum_partial(tcphdr, len, 0));
				uint16_t sum=get_ip_checksum((uint16_t *)ip_hdr, sizeof(struct ipv4_hdr));
				ip_hdr->hdr_checksum = sum;

				RUNNING_LOG_DEBUG("%s: core<%d> get_ip_checksum=%x\n", __FUNCTION__,rte_lcore_id(),ip_hdr->hdr_checksum);
				RUNNING_LOG_DEBUG("%s: core<%d> get_tcp_checksum=%x\n", __FUNCTION__,rte_lcore_id(),rte_be_to_cpu_16(tcphdr->cksum));
#endif
#ifdef BOND_2DIR
						nb_tx=rte_eth_tx_burst(txport_arr[i],out_queue[i][j],
							(struct rte_mbuf **)&pout->queue_buf[j].buf,pout->queue_buf[j].buf_pos);
						if (unlikely(nb_tx < pout->queue_buf[j].buf_pos))
						{
							port_stat[txport_arr[i]].sub[1].bad_ipv4_pkts+=(pout->queue_buf[j].buf_pos-nb_tx);
							for(;nb_tx < pout->queue_buf[j].buf_pos;nb_tx++)
							{
								rte_pktmbuf_free(pout->queue_buf[j].buf[nb_tx]);
							}
						}
#else

						nb_tx=rte_eth_tx_burst(port_arr[i],out_queue[i][j],
							(struct rte_mbuf **)&pout->queue_buf[j].buf,pout->queue_buf[j].buf_pos);
						if (unlikely(nb_tx < pout->queue_buf[j].buf_pos))
						{
							port_stat[port_arr[i]].sub[1].bad_ipv4_pkts+=(pout->queue_buf[j].buf_pos-nb_tx);
							for(;nb_tx < pout->queue_buf[j].buf_pos;nb_tx++)
							{
								rte_pktmbuf_free(pout->queue_buf[j].buf[nb_tx]);
							}
						}
#endif
						pout->queue_buf[j].buf_pos=0;
					}
				}
			}
#endif

			if(++loop_10ms_cnt==(IN_TIMER_RES/100))
			{
				timer->handler(timer,local);
				ready_port_sum=1;
				loop_10ms_cnt=0;
			}

			if (unlikely(++loop_cnt>=(IN_TIMER_RES/10)))
			{
				loop_cnt = 0;
				nat_timer_handler(timer, local, drain_1s_tsc*me.natconfig.deadtime);
			}

//			RUNNING_LOG_DEBUG("core %d triger switch\n",my_lcore);

			prev_tsc = cur_tsc;
		}

		for(i=0;i<sum_cnt;i++)
		{
			if(local_ip_back[i].load)
				{

				list_splice_tail_init(&local_ip_back[i].header,&local_ip_pool->header);
				local_ip_pool->load+=local_ip_back[i].load;
				rte_smp_wmb();

				RUNNING_LOG_DEBUG("core %d :get back pool local_ip_back[%d].load=%d local_ip_pool.load=%d\n",
					my_lcore,i,local_ip_back[i].load,local_ip_pool->load);

				local_ip_back[i].load=0;

				rte_smp_wmb();
				}
		}

		if(unlikely(pre_dtable != dnatconfig_curr))
		{
			RUNNING_LOG_DEBUG("core %d :default dnattable change from %d to %d\n",
				my_lcore, pre_dtable, dnatconfig_curr);
			if (dnatconfig_curr)
				rte_memcpy(&local_dtable, &dtable[NAT_MAX_DSTNUM], sizeof(local_dtable[0]) * NAT_MAX_DSTNUM);
			else
				rte_memcpy(&local_dtable, &dtable[0], sizeof(local_dtable[0]) * NAT_MAX_DSTNUM);

			pre_dtable=dnatconfig_curr;
		}

	}
}
#endif

//uint64_t g_pps;
//uint64_t g_bps;
uint64_t g_pps;
uint64_t g_bps;
uint64_t g_pps_out;
uint64_t g_bps_out;


int main_loop_gather(void)
{
	uint64_t cur_tsc, prev_tsc,diff_tsc,start,end,count=0;
	uint64_t  hz=rte_get_timer_hz();
	int i,j,k;
	int my_lcore;
	struct lcore_info_s *local;
	uint64_t *state[MAX_CPU]={NULL};
	struct port_info_sum port_sum[MAX_DEV]={0};
	struct port_info_sum machine_sum={0};

	struct port_info_sum attack_sum={0};
	int attack_cnt=0;
	struct port_info_sum attack_max={0};

	int state_cnt;
	uint64_t tmp_mask;
	int cnt=0;

	int quick_cnt;
	uint32_t *ti[MAX_CPU]={NULL};
	uint32_t ti_cnt;

	int gpolicy=0;
	int gstate=0;
	int prev_policy=0;
	struct policy mydefaultpolicy;
	int *port_sum_sig[MAX_CPU]={NULL};
	int *port_sum_curr[MAX_CPU]={NULL};
	struct lcore_info_s *port_sum_core[MAX_CPU]={NULL};
	struct lcore_info_s *core;
	int port_idx,port_pos;
	char json_buf[20000];

	const uint64_t drain_tsc = (hz + US_PER_S - 1)/US_PER_S * 1000;  // 1ms

	tmp_mask=me.sum_mask|me.io_in_mask|me.io_out_mask;
	j=0;
	do{
		i=__builtin_ffsll(tmp_mask)-1;
		tmp_mask &= ~(1ULL<<i);

		state[j]=&lcore[i].state;
		j++;
	}while(tmp_mask);
	state_cnt=j;

#ifdef WF_NAT
	tmp_mask=me.io_out_mask |me.io_in_mask;
#else
	tmp_mask=me.io_in_mask;
#endif
	j=0;
	do{
		i=__builtin_ffsll(tmp_mask)-1;
		tmp_mask &= ~(1ULL<<i);

		port_sum_sig[j]=&lcore[i].io_in.port_sum_sig;
		port_sum_curr[j]=&lcore[i].io_in.port_sum_curr;
		port_sum_core[j]=&lcore[i];
		j++;
	}while(tmp_mask);
	quick_cnt=j;


	my_lcore=rte_lcore_id();
	local=&lcore[my_lcore];
	rte_memcpy(ti,local->timer.timer_triger,sizeof(uint32_t *)*local->timer.timer_cnt);
	ti_cnt=local->timer.timer_cnt;
	g_pps=g_bps=0;

//	wait_init_finished();

	RUNNING_LOG_INFO("core %d: %s start\n",my_lcore,__FUNCTION__);
	prev_tsc= rte_rdtsc();

	while(1)
		{
		cur_tsc = rte_rdtsc();

		for(i=0;i<quick_cnt;i++)
			{
			if(unlikely(*port_sum_sig[i]))
				{
				core=port_sum_core[i];
				if(*port_sum_curr[i])
					port_pos=0;
				else
					port_pos=MAX_DEV;

				for(j=0;j<core->port_cnt;j++)
					{
					port_idx=core->port_id[j];
					do_port_sum_dir(&port_sum[port_idx],&core->io_in.port_sub[port_idx+port_pos],0);
					do_port_sum_dir(&port_sum[port_idx],&core->io_in.port_sub[port_idx+port_pos],1);
					g_bps+=core->io_in.port_sub[port_idx+port_pos].sub[0].in_bps;
					g_pps+=core->io_in.port_sub[port_idx+port_pos].sub[0].in_pps;
					g_bps_out+=core->io_in.port_sub[port_idx+port_pos].sub[1].in_bps;
					g_pps_out+=core->io_in.port_sub[port_idx+port_pos].sub[1].in_pps;
					}

				*port_sum_sig[i]=0;

				rte_smp_wmb();

#ifdef FLOOD_SIG_RT
				if(gpolicy)
					{
					if(!(gstate & STATE_FILTER_START))//in mormal mode
						{
						if((g_bps>mydefaultpolicy.th_bps)||(g_pps>mydefaultpolicy.th_pps))
							{
							gstate|=STATE_FILTER_START;
		#ifdef LIMIT_MODE1
							for(i=0;i<state_cnt;i++)
								*state[i]=STATE_POLICY_G|STATE_FILTER_START;
							rte_smp_wmb();
		#endif
							ALERT_LOG(">>>>>>>>>>>>>> gather :start defence mode th_bps=%llu g_bps=%llu th_pps=%llu g_pps=%llu\n",
								mydefaultpolicy.th_bps,g_bps,mydefaultpolicy.th_pps,g_pps);

							//format_json_attack_event_start(json_buf);
							}
						}

		#ifdef LIMIT_MODE1
					else
						{
						if(gstate & STATE_OUT_LIMIT)
							{
							if(*state[0] & STATE_OUT_LIMIT)
								{
								if((g_bps_out <= mydefaultpolicy.limit_bps)&&(g_pps_out <= mydefaultpolicy.limit_pps))
									{
									for(i=0;i<state_cnt;i++)
										*state[i]=STATE_POLICY_G|STATE_FILTER_START;

									ALERT_LOG("<<<<<<<<<<<<<< gather :defence stop limit mode limit_bps=%llu g_limit_bps=%llu limit_pps=%llu g_limit_pps=%llu\n",
										mydefaultpolicy.limit_bps,g_bps_out,mydefaultpolicy.limit_pps,g_pps_out);

									rte_smp_wmb();
									}

								}
							else
								{
								if((g_bps_out > mydefaultpolicy.limit_bps)||(g_pps_out > mydefaultpolicy.limit_pps))
									{
									for(i=0;i<state_cnt;i++)
										*state[i]=STATE_POLICY_G|STATE_FILTER_START|STATE_OUT_LIMIT;

									ALERT_LOG(">>>>>>>>>>>>>> gather :defence start limit mode limit_bps=%llu g_limit_bps=%llu limit_pps=%llu g_limit_pps=%llu\n",
										mydefaultpolicy.limit_bps,g_bps_out,mydefaultpolicy.limit_pps,g_pps_out);

									rte_smp_wmb();
									}
								}
							}

						}
		#endif
					}
#endif
				}
			}


		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc))
			{
//			if(local->state & (STATE_POLICY_G))
//				{
//				g_pps=g_bps=0;
//				for(i=0;i<quick_cnt;i++)
//					{
//					g_bps+=*quick_all_bps[i];
//					g_pps+=*quick_all_pps[i];
//					}
//				}

			cnt++;
			if(unlikely(cnt==1000))
				{
				for(i=0;i<ti_cnt;i++)
					*ti[i]=1;

				rte_smp_wmb();

				memcpy(&machine_sum,&port_sum[0],sizeof(port_sum[0]));
				for(i=1;i<MAX_DEV;i++)
					{
					do_port_sum_dir(&machine_sum,&port_sum[i],0);
					do_port_sum_dir(&machine_sum,&port_sum[i],1);
					}

				if((gpolicy)&&(gstate & STATE_FILTER_START))
					{
					attack_cnt++;

					do_port_sum_dir(&attack_sum,&machine_sum,0);
					do_port_sum_dir(&attack_sum,&machine_sum,1);

					if(machine_sum.sub[0].in_bps > attack_max.sub[0].in_bps)
						memcpy(&attack_max,&machine_sum,sizeof(machine_sum));
					}

#ifdef FLOOD_SIG_RT
				if(gpolicy)
					{
					if(gstate & STATE_FILTER_START)//in def
						{
						if((g_bps<mydefaultpolicy.th_bps)&&(g_pps<mydefaultpolicy.th_pps))
							{
							gstate=0;
							for(i=0;i<state_cnt;i++)
								*state[i]=STATE_POLICY_G;

							rte_smp_wmb();

							ALERT_LOG("<<<<<<<<< gather :back to normal mode th_bps=%llu g_bps=%llu th_pps=%llu g_pps=%llu attack_cnt=%d\n",
								mydefaultpolicy.th_bps,g_bps,mydefaultpolicy.th_pps,g_pps,attack_cnt);
							dump_allport_sum(&attack_sum);
							dump_allport_sum(&attack_max);

							//format_json_attack_event_end(&attack_sum,&attack_max,attack_cnt,json_buf);
							memset(&attack_sum,0,sizeof(attack_sum));
							memset(&attack_max,0,sizeof(attack_max));
							attack_cnt=0;
							}
						}
					}
#endif

				//log output : json
				format_json_machine_sum(&machine_sum,json_buf);

				if(!hw_log_off)
					{
					HW_LOG_TIME("g_bps_out=%llu g_pps_out=%llu\n",g_bps_out,g_pps_out);
//					dump_port_sum(port_sum);
					dump_allport_sum(&machine_sum);
					}

				memset(port_sum,0,sizeof(port_sum[0])*MAX_DEV);
				g_pps=g_bps=g_pps_out=g_bps_out=0;

				cnt=0;
				}

			prev_tsc = cur_tsc;
//			continue;
			}

		if(unlikely(gpolicy!=global_policy))
			{
			gpolicy=global_policy;
			if(gpolicy)
				{
				for(i=0;i<state_cnt;i++)
					*state[i]=STATE_POLICY_G;

				RUNNING_LOG_DEBUG("global policy curr\n");

//				memcpy(&mydefaultpolicy,&default_policy[default_curr],sizeof(mydefaultpolicy));
//				prev_policy=default_curr;
				}
			else
				{
				for(i=0;i<state_cnt;i++)
					*state[i]=0;

				RUNNING_LOG_DEBUG("split policy curr\n");
				}

			rte_smp_wmb();
			}

		if(unlikely(prev_policy!=default_curr))
			{
			memcpy(&mydefaultpolicy,&default_policy[default_curr],sizeof(mydefaultpolicy));
			prev_policy=default_curr;

#ifdef LIMIT_MODE1
			if((mydefaultpolicy.limit_bps != ((uint64_t)-1))||
				(mydefaultpolicy.limit_pps != ((uint64_t)-1)))
				{
				gstate|=STATE_OUT_LIMIT;
				}
#endif

			rte_smp_wmb();

			RUNNING_LOG_DEBUG("gather :default policy change to %d %d gstate=%x\n",
				my_lcore,prev_policy,prev_policy,gstate);

			dump_defaultpolicy(&mydefaultpolicy);
			}


/*
		if(unlikely(mon_netport_sig))
			{
			rte_memcpy(mon_netport_core.arr,mon_netport_arr.arr,sizeof(uint32_t)*mon_netport_arr.max);
			mon_netport_core.curr=mon_netport_arr.curr;
			mon_netport_core.max=mon_netport_arr.max;
			rte_smp_wmb();
			mon_netport_sig=0;
			rte_smp_wmb();

#if 0//debug
{
			for(i=0;i<mon_netport_core.curr;i++)
			{
				RUNNING_LOG_DEBUG("new mon sz=%d port %d\n",
					mon_netport_core.curr,mon_netport_core.arr[i]);
			}
}
#endif
*/
		}
}


int main_loop_natlistsum(void)
{

	uint64_t cur_tsc, prev_tsc,diff_tsc,start,end,count=0;

	int i,j,k;
	int my_lcore;
	struct lcore_info_s *local;
	struct port_info_sum port_sum[MAX_DEV]={0};
	struct port_info_sum machine_sum={0};

	struct port_info_sum attack_sum={0};
	int attack_cnt=0;
	struct port_info_sum attack_max={0};

	uint32_t in_cnt,inout_cnt;
	uint64_t tmp_mask;
	uint32_t tmp_in_mask;
	int num=0;

	int *nat_flowlist_sig[MAX_CPU]={NULL};
	int *nat_flowlist_curr[MAX_CPU]={NULL};
	int *nat_srclist_sig[MAX_CPU]={NULL};
	int *nat_srclist_curr[MAX_CPU]={NULL};
	int *nat_tuplepair_sig[MAX_CPU]={NULL};
	int *nat_tuplepair_curr[MAX_CPU]={NULL};
	int *fresh_tuplepair_sig[MAX_CPU]={NULL};
	int *fresh_tuplepair_curr[MAX_CPU]={NULL};
	int *nat_sum_tuplepair_sig[MAX_CPU]={NULL};
	int *nat_sum_freshtuple_sig[MAX_CPU]={NULL};
	struct hash_array *nat_flowlist_hash[MAX_CPU]={0};
	struct hash_array *nat_srclist_hash[MAX_CPU]={0};
	struct hash_array *local_flownat_hash;
	struct hash_array *local_srcnat_hash;
	struct hash_array *local_flownat_pool;
	struct nat_map_tuple local_tuplepair[TOTAL_MAX_TUPLEPAIR]={0};
	struct sum_map_tuple totaltuplepair[TOTAL_MAX_TUPLEPAIR]={0};
	struct flow_nat *flownat;
	uint32_t hash_idx;
	uint32_t data[3];

	struct core_timer *timer[MAX_CPU]={NULL};

	struct lcore_info_s *in_core[MAX_CPU]={NULL};
	struct lcore_info_s *io_core[MAX_CPU]={NULL};
	struct lcore_info_s *core;
	int port_idx,pos;
	uint8_t *ptuplepair;
	uint32_t iomask,needcopy;

	my_lcore=rte_lcore_id();
	local=&lcore[my_lcore];

	memset(local_tuplepair, 0, sizeof(struct nat_map_tuple)*TOTAL_MAX_TUPLEPAIR);
	memset(totaltuplepair, 0, sizeof(struct sum_map_tuple)*TOTAL_MAX_TUPLEPAIR);


	tmp_mask = me.io_in_mask |me.io_out_mask;
#ifdef BOND_2DIR
	tmp_in_mask = me.io_in_mask;
#else
	tmp_in_mask = me.io_in_mask |me.io_out_mask;
#endif
	in_cnt=__builtin_popcountl(tmp_in_mask);
	inout_cnt=__builtin_popcountl(tmp_mask);

	RUNNING_LOG_INFO("core %d: natlistsum start %x %d\n",my_lcore, tmp_in_mask, in_cnt);

	j=0;
	do{
		i=__builtin_ffsll(tmp_in_mask)-1;
		tmp_in_mask &= ~(1ULL<<i);

		nat_tuplepair_sig[j]=&lcore[i].io_in.nat_tuplepair_sig;
		nat_tuplepair_curr[j]=&lcore[i].io_in.nat_tuplepair_curr;

		in_core[j]=&lcore[i];
		j++;
	}while(tmp_in_mask);

	j=0;
	do{
		i=__builtin_ffsll(tmp_mask)-1;
		tmp_mask &= ~(1ULL<<i);

//		nat_tuplepair_sig[j]=&lcore[i].io_in.nat_tuplepair_sig;
//		nat_tuplepair_curr[j]=&lcore[i].io_in.nat_tuplepair_curr;
//		nat_flowlist_hash[j] = lcore[i].io_in.io_flownat_hash;
//		nat_srclist_hash[j] = lcore[i].io_in.io_srcnat_hash;
		nat_sum_tuplepair_sig[j] = &lcore[i].io_in.sum_tuplepair_sig;

		io_core[j]=&lcore[i];
		iomask |= 1ULL<<j;
		j++;
	}while(tmp_mask);


//	local_flownat_hash =local->io_in.io_flownat_hash;
//	local_srcnat_hash = local->io_in.io_srcnat_hash;
//	local_flownat_pool=&local->io_in.flownat_pool;


	while(1)
	{
		uint32_t n = 0;
		int cnt = 0;
		//RUNNING_LOG_DEBUG("core %d: total natlistsum \n", rte_lcore_id());

		//for new add tuplepair
		ptuplepair = (uint8_t *)local_tuplepair;

//		memset(local_tuplepair, 0, sizeof(struct nat_map_tuple)*MAX_TUPLEPAIR*MAX_CPU);
//		memset(totaltuplepair, 0, sizeof(struct sum_map_tuple)*MAX_TUPLEPAIR*MAX_CPU);

		n = 0;
		for(i=0;i<in_cnt;i++)
		{
			if(likely(*nat_tuplepair_sig[i]))
			{
				core = in_core[i];

				if(*nat_tuplepair_curr[i])
					pos = 0;
				else
					pos = MAX_TUPLEPAIR;

				cnt = core->io_in.tuplepair[pos].cnt;
//			        RUNNING_LOG_INFO("core %d: total natlistsum core=%d,  cnt=%d,ptuplepair=%p,size=%d\n",
//						rte_lcore_id(),core->core_id, cnt,  ptuplepair,sizeof(struct nat_map_tuple));

				rte_memcpy(ptuplepair, (uint8_t *)&core->io_in.tuplepair[pos], sizeof(struct nat_map_tuple)*cnt);
				ptuplepair += cnt * sizeof(struct nat_map_tuple);
				n+=cnt;

				*nat_tuplepair_sig[i]=0;
				rte_smp_wmb();
			}

		}

//		for(i=0; i<tuplepair_cnt; i++)
//		{
//			for(j=i+1; j<tuplepair_cnt; j++)
//			{
//				if ((local_tuplepair[i].tuplepair[0].a.pair.l3 != 0) &&
//					nat_equal_tuple(&local_tuplepair[i].tuplepair[0], &local_tuplepair[j].tuplepair[0]) &&
//					nat_equal_tuple(&local_tuplepair[i].tuplepair[1], &local_tuplepair[j].tuplepair[1]))
//				{
//					memset(&local_tuplepair[i].tuplepair[0], 0, sizeof(struct nat_map_tuple));
//				}
//			}
//		}

#if 0
		n = 0;
		for(i=0; i<TOTAL_MAX_TUPLEPAIR; i++)
		{
			if (local_tuplepair[i].tuplepair[0].a.pair.l3 != 0)
			{
				totaltuplepair[n].map_tuple=local_tuplepair[i];
				memset(&local_tuplepair[i], 0, sizeof(struct nat_map_tuple));
//				data[0] = local_tuplepair[i].tuplepair[CT_DIR_ORIGINAL].a.pair.l3;
//				data[1] = local_tuplepair[i].tuplepair[CT_DIR_ORIGINAL].b.pair.l3;
//				data[2] = (local_tuplepair[i].tuplepair[CT_DIR_ORIGINAL].a.pair.l4)<<16 | local_tuplepair[i].tuplepair[CT_DIR_ORIGINAL].b.pair.l4;
//				hash_idx = rte_jhash_3words(data[0], data[1], data[2], PRIME_VALUE);
//				totaltuplepair[j].hashidx_0 = hash_idx & (FLOW_HASH_ARRAY_SZ - 1);
//
//				data[0] = local_tuplepair[i].tuplepair[CT_DIR_REPLY].a.pair.l3;
//				data[1] = local_tuplepair[i].tuplepair[CT_DIR_REPLY].b.pair.l3;
//				data[2] = (local_tuplepair[i].tuplepair[CT_DIR_REPLY].a.pair.l4)<<16 | local_tuplepair[i].tuplepair[CT_DIR_REPLY].b.pair.l4;
//				hash_idx = rte_jhash_3words(data[0], data[1], data[2], PRIME_VALUE);
//				totaltuplepair[j].hashidx_1 = hash_idx & (FLOW_HASH_ARRAY_SZ - 1);

				n++;

			}else{
				break;
			}
		}
#endif

		needcopy = iomask;
		if(n !=0)
		{
//		num++;
			RUNNING_LOG_INFO("core %d: total natlist tuplepair=%d,num=%d\n", rte_lcore_id(), n,num);

			//while(needcopy)
			{
				for(i=inout_cnt-1;i>=0;i--)
				//for(i=0;i<inout_cnt;i++)
				{
					if(/*(needcopy &(1ULL<<i)) &&*/ (*nat_sum_tuplepair_sig[i]))
					{
						//needcopy &= ~(1ULL<<i);
						//RUNNING_LOG_INFO("core %d: total natlist tuplepair=%d,i=%d\n", rte_lcore_id(), n, i);
						core = io_core[i];
						rte_memcpy(core->io_in.totaltuplepair, local_tuplepair, n*sizeof(struct sum_map_tuple));

						*nat_sum_tuplepair_sig[i] = 0;
						rte_smp_wmb();

					}
				}
			}

			memset(local_tuplepair, 0, n*sizeof(struct sum_map_tuple));
		}

	}

}

int main_loop_natlistsum2(void)
{

	int i,j,k;
	int my_lcore;
	struct lcore_info_s *local;

	uint32_t out_cnt,inout_cnt;
	uint64_t tmp_mask;
	uint32_t tmp_out_mask;
	int cnt=0;

	int *nat_tuplepair_sig[MAX_CPU]={NULL};
	int *nat_tuplepair_curr[MAX_CPU]={NULL};
	int *nat_sum_tuplepair_sig[MAX_CPU]={NULL};
	int *nat_sum_freshtuple_sig[MAX_CPU]={NULL};
	struct nat_map_tuple local_tuplepair[TOTAL_MAX_TUPLEPAIR]={0};
	struct sum_map_tuple totaltuplepair[TOTAL_MAX_TUPLEPAIR]={0};
	struct flow_nat *flownat;
	uint32_t hash_idx;
	uint32_t data[3];

	struct lcore_info_s *out_core[MAX_CPU]={NULL};
	struct lcore_info_s *core;
	int port_idx,pos;
	uint8_t *ptuplepair;
	uint32_t outmask=0;
	uint32_t needcopy=0;

//	memset(local_tuplepair, 0, sizeof(struct nat_map_tuple)*TOTAL_MAX_TUPLEPAIR);
//	memset(totaltuplepair, 0, sizeof(struct sum_map_tuple)*TOTAL_MAX_TUPLEPAIR);

	tmp_out_mask = me.io_out_mask;
	out_cnt=__builtin_popcountl(tmp_out_mask);

	j=0;
	do{
		i=__builtin_ffsll(tmp_out_mask)-1;
		tmp_out_mask &= ~(1ULL<<i);

		nat_sum_tuplepair_sig[j] = &lcore[i].io_in.sum_tuplepair_sig;

		out_core[j]=&lcore[i];
		outmask |= 1ULL<<j;
		j++;
	}while(tmp_out_mask);

	my_lcore=rte_lcore_id();
	local=&lcore[my_lcore];

	RUNNING_LOG_INFO("core %d: natlistsum2 start 0x%x\n",my_lcore, me.io_out_mask);


	while(1)
	{
		//for new add tuplepair

		needcopy = outmask;
		if(!local->io_in.sum_tuplepair_sig)
		{
			RUNNING_LOG_INFO("core %d: total natlist sum_tuplepair_sig \n", my_lcore);

			while(needcopy)
			{

				for(i=0;i<out_cnt;i++)
				{
					if((needcopy &(1ULL<<i)) && (*nat_sum_tuplepair_sig[i]))
					{
						needcopy &= ~(1ULL<<i);
						core = out_core[i];
						rte_memcpy(core->io_in.totaltuplepair, local->io_in.totaltuplepair, TOTAL_MAX_TUPLEPAIR*sizeof(struct sum_map_tuple));
					RUNNING_LOG_INFO("core %d: total natlist needcopy=0x%x\n", my_lcore,needcopy);
						*nat_sum_tuplepair_sig[i] = 0;
						rte_smp_wmb();
					}
				}
			}
			RUNNING_LOG_INFO("core %d: total natlist needcopy2=0x%x\n", my_lcore,needcopy);
			memset(local->io_in.totaltuplepair, 0, TOTAL_MAX_TUPLEPAIR*sizeof(struct sum_map_tuple));
			local->io_in.sum_tuplepair_sig=1;
			rte_smp_wmb();
		}

	}


}

int main_loop_natlistfresh(void)
{

	uint64_t cur_tsc, prev_tsc,diff_tsc,start,end,count=0;

	int i,j,k;
	int my_lcore;
	struct lcore_info_s *local;
	struct port_info_sum port_sum[MAX_DEV]={0};
	struct port_info_sum machine_sum={0};

	struct port_info_sum attack_sum={0};
	int attack_cnt=0;
	struct port_info_sum attack_max={0};

	uint32_t in_cnt,out_cnt;
	uint64_t tmp_mask;
	int cnt=0;

	int *nat_flowlist_sig[MAX_CPU]={NULL};
	int *nat_flowlist_curr[MAX_CPU]={NULL};
	int *nat_srclist_sig[MAX_CPU]={NULL};
	int *nat_srclist_curr[MAX_CPU]={NULL};
	int *nat_tuplepair_sig[MAX_CPU]={NULL};
	int *nat_tuplepair_curr[MAX_CPU]={NULL};
	int *fresh_tuplepair_sig[MAX_CPU]={NULL};
	int *fresh_tuplepair_curr[MAX_CPU]={NULL};
	int *nat_sum_tuplepair_sig[MAX_CPU]={NULL};
	int *nat_sum_freshtuple_sig[MAX_CPU]={NULL};
	struct hash_array *nat_flowlist_hash[MAX_CPU]={0};
	struct hash_array *nat_srclist_hash[MAX_CPU]={0};
	struct hash_array *local_flownat_hash;
//	struct hash_array *local_srcnat_hash;
	struct hash_array *local_flownat_pool;
	struct nat_map_tuple local_tuplepair[TOTAL_MAX_TUPLEPAIR]={0};
	struct sum_map_tuple totaltuplepair[TOTAL_MAX_TUPLEPAIR]={0};
	struct flow_nat *flownat;
	uint32_t hash_idx;
	uint32_t data[3];

	struct core_timer *timer[MAX_CPU]={NULL};

	struct lcore_info_s *io_core[MAX_CPU]={NULL};
	struct lcore_info_s *core;
	int port_idx,pos;
	uint8_t *ptuplepair;
	int needcopy = 0;

	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1)/US_PER_S * 1000;
	const uint64_t drain_1s_tsc = (rte_get_tsc_hz() + US_PER_S - 1)/US_PER_S * IN_TIMER_1S;

	tmp_mask = me.io_in_mask |me.io_out_mask;
	j=0;
	do{
		i=__builtin_ffsll(tmp_mask)-1;
		tmp_mask &= ~(1ULL<<i);

		nat_tuplepair_sig[j]=&lcore[i].io_in.nat_tuplepair_sig;
		nat_tuplepair_curr[j]=&lcore[i].io_in.nat_tuplepair_curr;
		fresh_tuplepair_sig[j]=&lcore[i].io_in.fresh_tuplepair_sig;
		fresh_tuplepair_curr[j]=&lcore[i].io_in.fresh_tuplepair_curr;
		nat_flowlist_hash[j] = lcore[i].io_in.io_flownat_hash;
//		nat_srclist_hash[j] = lcore[i].io_in.io_srcnat_hash;
		nat_sum_tuplepair_sig[j] = &lcore[i].io_in.sum_tuplepair_sig;
		nat_sum_freshtuple_sig[j] = &lcore[i].io_in.sum_freshtuple_sig;
		timer[j]=&lcore[i].localtimer;

		io_core[j]=&lcore[i];
		j++;
	}while(tmp_mask);
	in_cnt=j;

	my_lcore=rte_lcore_id();
	local=&lcore[my_lcore];
	local_flownat_hash =local->io_in.io_flownat_hash;
//	local_srcnat_hash = local->io_in.io_srcnat_hash;
	local_flownat_pool=&local->io_in.flownat_pool;

	RUNNING_LOG_INFO("core %d: natlistfresh start %d\n",my_lcore, sizeof(int),sizeof(char),sizeof(uint8_t));

	prev_tsc = rte_rdtsc();
	while(1)
	{
		cur_tsc = rte_rdtsc();
		//RUNNING_LOG_DEBUG("core %d: total natlistfresh \n", rte_lcore_id());

		//for tuplepair refresh
		needcopy = 0;
		ptuplepair = (uint8_t *)local_tuplepair;

		memset(local_tuplepair, 0, sizeof(struct nat_map_tuple)*TOTAL_MAX_TUPLEPAIR);
		memset(totaltuplepair, 0, sizeof(struct sum_map_tuple)*TOTAL_MAX_TUPLEPAIR);

		for(i=0;i<in_cnt;i++)
		{
			if(unlikely(*fresh_tuplepair_sig[i]))
			{
				needcopy |= (1<<i);
				core = io_core[i];
				if(*fresh_tuplepair_curr[i])
					pos = 0;
				else
					pos = MAX_TUPLEPAIR;

				rte_memcpy(ptuplepair, (uint8_t *)&core->io_in.freshtuplepair[pos], sizeof(struct nat_map_tuple)*MAX_TUPLEPAIR);
				memset((uint8_t *)&core->io_in.freshtuplepair[pos], 0, sizeof(struct nat_map_tuple)*MAX_TUPLEPAIR);
				ptuplepair += MAX_TUPLEPAIR * sizeof(struct nat_map_tuple);

				*fresh_tuplepair_sig[i]=0;

				rte_smp_wmb();
			}

		}

//		for(i=0; i<tuplepair_cnt; i++)
//		{
//			for(j=i+1; j<tuplepair_cnt; j++)
//			{
//				if ((local_tuplepair[i].tuplepair[0].a.pair.l3 != 0) &&
//					nat_equal_tuple(&local_tuplepair[i].tuplepair[0], &local_tuplepair[j].tuplepair[0]) &&
//					nat_equal_tuple(&local_tuplepair[i].tuplepair[1], &local_tuplepair[j].tuplepair[1]))
//				{
//					memset(&local_tuplepair[i].tuplepair[0], 0, sizeof(struct nat_map_tuple));
//				}
//			}
//		}

		j = 0;
		for(i=0; i<TOTAL_MAX_TUPLEPAIR; i++)
		{
			if (local_tuplepair[i].tuplepair[0].a.pair.l3 != 0)
			{
				totaltuplepair[j].map_tuple=local_tuplepair[i];
				j++;
			}
		}

		if(j !=0)
		{
			RUNNING_LOG_DEBUG("core %d: total refresh=%d\n", rte_lcore_id(), j);

			while(needcopy)
			{
				for(i=0;i<in_cnt;i++)
				{
					if(*nat_sum_freshtuple_sig[i])
					{
						needcopy &= ~(1ULL<<i);
						core = io_core[i];
						memset(core->io_in.totalfreshtuple, 0, TOTAL_MAX_TUPLEPAIR*sizeof(struct sum_map_tuple));
						rte_memcpy(core->io_in.totalfreshtuple, totaltuplepair, TOTAL_MAX_TUPLEPAIR*sizeof(struct sum_map_tuple));

						*nat_sum_freshtuple_sig[i] = 0;
						rte_smp_wmb();
					}
				}
			}
		}

	}

}

#endif
