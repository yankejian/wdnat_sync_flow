#include "all.h"

#if 0
const char * rtm_type2str(u_int16_t type)
{
	static char dflt[] = "RTM_[DDDDD]";
	char * str;
	switch(type) {
	_PF(RTM_NEWLINK)
	_PF(RTM_DELLINK)
	_PF(RTM_GETLINK)
	_PF(RTM_NEWADDR)
	_PF(RTM_DELADDR)
	_PF(RTM_GETADDR)
	_PF(RTM_NEWROUTE)
	_PF(RTM_DELROUTE)
	_PF(RTM_GETROUTE)
	_PF(RTM_NEWNEIGH)
	_PF(RTM_DELNEIGH)
	_PF(RTM_GETNEIGH)

	default:
	snprintf(dflt, sizeof(dflt), "RTM_[%u]", type);
	str = dflt;
	break;
	}

	return(str);
}

void nl_parse_rtattr (struct rtattr **tb, int max, struct rtattr *rta, int len, int family)
{
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;

		rta = RTA_NEXT(rta,len);
	}
}
static void nl_l2(struct nlmsghdr *h) 
{
	struct ndmsg *neigh;  
	struct rtattr *tb[NDA_MAX + 1];
	uint32_t dst;
	char * mac=NULL ;
	uint16_t old_state;
	char ip_str[32];
	int len, ifindex;
	uint8_t portid;

	len = h->nlmsg_len - NLMSG_SPACE (sizeof (struct ndmsg));
	if (len < 0) {
		RUNNING_LOG_DEBUG("%s: %s bad length %d\n",
			__FUNCTION__, rtm_type2str(h->nlmsg_type), len);
		return ;
	}
	neigh = NLMSG_DATA (h);

//	RTE_LOG(DEBUG, SYNC, "ndm_family=0x%x ndm_flags=0x%x ndm_type=%d ndm_ifindex=%d ndm_state=0x%x tick=%ld\n",
//			neigh->ndm_family,neigh->ndm_flags,neigh->ndm_type,neigh->ndm_ifindex,neigh->ndm_state,get_time());//kickit

    if ((neigh->ndm_family != AF_INET)||(neigh->ndm_type != RTN_UNICAST))
        return ;

	memset (tb, 0, sizeof tb);
	nl_parse_rtattr (tb, NDA_MAX, NDA_RTA (neigh), len, MSG_FAMILY_NEIGH);

	if (!tb[NDA_DST]) {
		RUNNING_LOG_DEBUG("No Destination IP Address in netlink message\n");
		return;
	}
  	dst = *(uint32_t *)RTA_DATA(tb[NDA_DST]);

	if (tb[NDA_LLADDR]) {
		mac = (char *)RTA_DATA(tb[NDA_LLADDR]);
		
		RUNNING_LOG_DEBUG("%s:Recv ndmsg[nlmsg_type=%d, type=%u state=0x%04x "
		"flags=0x%02x ifindex=%u, dst=%s,%x, mac=%02X:%02X:%02X:%02X:%02X:%02X:\n",
			__FUNCTION__,h->nlmsg_type, neigh->ndm_type, neigh->ndm_state, 
			neigh->ndm_flags, neigh->ndm_ifindex, ip2str(ip_str, dst),dst,
			mac[0]&0xff, mac[1]&0xff, mac[2]&0xff, mac[3]&0xff, mac[4]&0xff, mac[5]&0xff);
	} else {
		RUNNING_LOG_DEBUG("no MAC found for %s\n", ip2str(ip_str, dst));		
	}

//#ifdef CONFIG_BONDING_SUPPORT
//	if(filter_cfg.bond_info.bond_onoff)
//		port_arr=&bond_port_param_array[0];			
//#endif

//	if (!ifindex2portid(neigh->ndm_ifindex, &portid)) {		
//		if (h->nlmsg_type == RTM_NEWNEIGH) {
//			if((neigh->ndm_state!=NUD_FAILED)&&
//				(neigh->ndm_state!=NUD_INCOMPLETE))
//				nh_hash_add(dst, mac, neigh->ndm_state, neigh->ndm_ifindex, portid, port_arr);
//			else
//				{
//				RTE_LOG(WARNING, SYNC, "ERROR : found state %x\n", neigh->ndm_state); 	
//				
//				}
//#ifdef CONFIG_KEEP_NH_ALIVE_MODE_NL	//kickit
//			//keep_nh_alive(h,neigh,&dst,mac);
//#endif			
//		} else if (h->nlmsg_type == RTM_DELNEIGH){
//			nh_hash_del(dst);
//		}
//	}		

	return;
}

static void nl_link (struct nlmsghdr *h)
{
	int len, i;
	struct ifinfomsg *ifi;
	struct rtattr *tb [IFLA_MAX + 1];
	char *name;
	char *p;
	
	ifi = NLMSG_DATA (h);

	RUNNING_LOG_DEBUG("%s: Recv ifinfomsg: type=%hu index=%d flags=%08x change=%08x\n",
		 __FUNCTION__,ifi->ifi_type, ifi->ifi_index, ifi->ifi_flags, ifi->ifi_change);

	len = h->nlmsg_len - NLMSG_SPACE (sizeof (struct ifinfomsg));
	if (len < 0) {
		RUNNING_LOG_ERROR("%s: %s bad nl msg length %d\n",
			__FUNCTION__, rtm_type2str(h->nlmsg_type), len);
		return;
	}
	memset (tb, 0, sizeof tb);
	nl_parse_rtattr(tb, IFLA_MAX, IFLA_RTA (ifi), len, MSG_FAMILY_IFACE);

	if (tb[IFLA_IFNAME] == NULL) {
		RUNNING_LOG_ERROR("%s: %s no IFLA_IFNAME attribute\n",
			__FUNCTION__, rtm_type2str(h->nlmsg_type));
		return;
	}
	name = (char *)RTA_DATA(tb[IFLA_IFNAME]);

	if(strncmp(name, BOND_IF_NAME,strlen(BOND_IF_NAME)))
		{
		RUNNING_LOG_DEBUG("Ignoring interface %s %s\n", name);
		return;
		}

	/* identify interface type */
	if (ifi->ifi_type != ARPHRD_ETHER)
		return;

	if (h->nlmsg_type == RTM_NEWLINK) {
			/*
			 * Ignore I/F with NO MAC address, or at least
			 * wait for them to have acquired one (have bnet 
			 * in mind ..)
			 */
			if (tb[IFLA_ADDRESS] == NULL) {
				RUNNING_LOG_DEBUG("%s: "
					"%s no IFLA_ADDRESS attribute for %s\n",
					__FUNCTION__, rtm_type2str(h->nlmsg_type), name);
				return;
			}
			if (RTA_PAYLOAD(tb[IFLA_ADDRESS]) == 0) {
				RUNNING_LOG_DEBUG("%s: "
					"%s empty IFLA_ADDRESS field for %s\n",
					__FUNCTION__, rtm_type2str(h->nlmsg_type), name);
				return;
			}

			RUNNING_LOG_DEBUG("%s: newlink msg %s with if %s\n",
				__FUNCTION__, rtm_type2str(h->nlmsg_type), name);

			p=strchr(name,'.');
			if(p)
				{
				i=atoi(++p);
				if(i==me.settle_setting.gw_bonding_inoutvlan.in_vlanid)
					{
					RUNNING_LOG_DEBUG("%s: get in vlan %d mac\n",
						__FUNCTION__, i);
					}
				else if(i==me.settle_setting.gw_bonding_inoutvlan.out_vlanid)
					{
					RUNNING_LOG_DEBUG("%s: get out vlan %d mac\n",
						__FUNCTION__, i);
					}
				else
					{
					RUNNING_LOG_DEBUG("%s: error vlan %d mac\n",
						__FUNCTION__, i);
					}
				}
			
			RUNNING_LOG_DEBUG("mac=0x%02X:%02X:%02X:%02X:%02X:%02X\n", 
				(*((char *)RTA_DATA(tb[IFLA_ADDRESS]) + 0)) & 0xFF, 
				(*((char *)RTA_DATA(tb[IFLA_ADDRESS]) + 1)) & 0xFF, 
				(*((char *)RTA_DATA(tb[IFLA_ADDRESS]) + 2)) & 0xFF, 
				(*((char *)RTA_DATA(tb[IFLA_ADDRESS]) + 3)) & 0xFF, 
				(*((char *)RTA_DATA(tb[IFLA_ADDRESS]) + 4)) & 0xFF, 
				(*((char *)RTA_DATA(tb[IFLA_ADDRESS]) + 5)) & 0xFF);

//			memcpy(port_param[port_id].if_mac, RTA_DATA(tb[IFLA_ADDRESS]), ETH_ALEN);
//			port_param[port_id].flag|=F_IF_PORT_VALID;

	} else {
		/*
	 	 * DELETE case
	 	 */
//	 	 memset(&port_param[port_id],0,sizeof(port_param[0]));
	}
	return;
}

static int netlink_recv(const struct sockaddr_nl *who, struct nlmsghdr *h, void * arg)
{
	switch (h->nlmsg_type) {
		case RTM_NEWNEIGH:
		case RTM_DELNEIGH:
			nl_l2 (h);
			break;
		case RTM_NEWLINK:
		case RTM_DELLINK:
			nl_link (h);
			break;
		default:
			break;
	}
	return 0;
}

static struct nlsock netlink_listen = {
	.name = "netlink-listen",
	.recv = (rtnl_filter_t)netlink_recv,
};

static void netlink_recv_event (int fd, short event, void *data)
{
	struct nlsock *s = data;
	rtnl_listen(&s->rtnl, s->recv, NULL);
}

static int
netlink_sock_open(int proto, struct nlsock *cmn, long groups, int listen)
{
	if (rtnl_open_byproto(&cmn->rtnl, groups, proto) < 0) {
		RUNNING_LOG_ERROR("Unable to open netlink socket\n");
		return MM_FAIL;
	}

	if (listen) {
		event_set (&cmn->ev, cmn->rtnl.fd,
		           EV_READ | EV_PERSIST,
	        	   netlink_recv_event, cmn);
		event_add (&cmn->ev, NULL);
	}
	return MM_SUCCESS;
}



static void *nl_thread(void *args)
{
	int rc;

	rc = event_dispatch();
}

int init_nl(void)
{
	int rc;

	if(netlink_sock_open (NETLINK_ROUTE, &netlink_listen,
			(RTMGRP_NEIGH | RTMGRP_LINK), 1)==MM_FAIL)
		{
		RUNNING_LOG_ERROR("netlink_sock_open Fail\n");
		return MM_FAIL;
		}

	rc = pthread_create(&nl_thread_id, NULL, &nl_thread, NULL);
	if (rc != 0) {
		RUNNING_LOG_ERROR("Failed to create nl thread\n");
		return MM_FAIL;
	}

	RUNNING_LOG_INFO("nl init Success\n");
	return MM_SUCCESS;
}
#endif

pthread_t ping_thread_id;
pthread_t nl_thread_id;
int ping_thread_stop=0;
int ping_thread_start=0;

static int getResultFromSystemCall(const char* pCmd, char* pResult, int size)
{
   int fd[2];
   pid_t status;  
   
   if(pipe(fd))   {
   	RUNNING_LOG_DEBUG( "pipe error!\n");
      return -1;
   }

   //prevent content in stdout affect result
   fflush(stdout);

   //hide stdout
   int bak_fd = dup(STDOUT_FILENO);
   int new_fd = dup2(fd[1], STDOUT_FILENO);


   //the output of `pCmd` is write into fd[1]
   status = system(pCmd);
   if (0 == WEXITSTATUS(status)) {
	   read(fd[0], pResult, size-1);
	   pResult[strlen(pResult)-1] = 0;
   }

   //resume stdout
   dup2(bak_fd, new_fd);

   return 0;
}

#if defined(VLAN_ON)
static void *ping_thread(void *args)
{
//	pthread_cond_t cond;
//   	pthread_mutex_t mutex;   
	char cmd[256];
	char ipstr_out[64];
//	struct timeval now;
//	struct timespec timeout;   
	uint32_t gw_ip[]={	
		me.settle_setting.gw_bonding_inoutvlan.in_gw_ip,
		me.settle_setting.gw_bonding_inoutvlan.out_gw_ip
		};
	int idx=0;
	
//	pthread_cond_init(&cond,NULL);
//	pthread_mutex_init(&mutex,NULL);

	while(!ping_thread_stop){
//		 pthread_mutex_lock(&mutex);  

//		 gettimeofday(&now, NULL);

//		timeout.tv_sec = now.tv_sec + 1;
//		timeout.tv_nsec = now.tv_usec * 1000;		 

		 sprintf(cmd,"ping %s -q -c 1 -W1",ip2str(ipstr_out,gw_ip[idx]));
		 RUNNING_LOG_DEBUG( "running cmd %s\n",cmd);
		 system(cmd);

//		 pthread_cond_timedwait(&cond, &mutex, &timeout);

//		 pthread_mutex_unlock(&mutex);

		 if(++idx>=(sizeof(gw_ip)/sizeof(gw_ip[0])))
		 	idx=0;

		 sleep(1);
	}
	ping_thread_stop++;
	RUNNING_LOG_DEBUG( "ping_thread exit now\n");
}
#else

static void *ping_thread(void *args)
{
//	pthread_cond_t cond;
//   	pthread_mutex_t mutex;   
	char cmd[256];
	char ipstr_out[64];
	char str_ret[32];

	int idx=0;
	int i, j, k;
	int   ret;
	int is_run = 0;
//	struct dnat_item local_dtable[NAT_MAX_DSTNUM];
	struct dnat_item *local_dtable;
	int pre_dtable=0;
	int loop_cnt = 0;

	uint32_t gw_ip[2]={me.settle_setting.gw_bonding_inoutvlan.in_gw_ip,
		me.settle_setting.gw_bonding_inoutvlan.out_gw_ip};

	local_dtable = malloc(sizeof(struct dnat_item )*NAT_MAX_DSTNUM);
	memset(local_dtable, 0, sizeof(local_dtable[0]) * NAT_MAX_DSTNUM);
	pre_dtable=dnatconfig_curr;
	
//	pthread_cond_init(&cond,NULL);
//	pthread_mutex_init(&mutex,NULL);
//	memset(dnat_linkstate, 0xff, sizeof(dnat_linkstate));

	while(!ping_thread_stop){
		if(!ping_thread_start)
			{
			sleep(1);
			continue;
			}
		
//		 pthread_mutex_lock(&mutex);  

//		 gettimeofday(&now, NULL);

//		timeout.tv_sec = now.tv_sec + 1;
//		timeout.tv_nsec = now.tv_usec * 1000;		 

#ifdef WF_NAT
		 

	 	if (++loop_cnt>=10)	// 
		{
			sprintf(cmd,"ping %s -q -c 1 -W1",ip2str(ipstr_out,gw_ip[0]));
			RUNNING_LOG_DEBUG( "running cmd %s\n",cmd);
			system(cmd);
			sleep(1);	
#ifdef BOND_2DIR		 
			 sprintf(cmd,"ping %s -q -c 1 -W1",ip2str(ipstr_out,gw_ip[1]));
			 RUNNING_LOG_DEBUG( "running cmd %s\n",cmd);
			 system(cmd);
#endif
			
			loop_cnt = 0;
		}

		 if (!is_run)
		 {
			is_run= 1;
		 
//			sprintf(cmd,"ip route add default via %s",
//				ip2str(ipstr_out, me.settle_setting.gw_bonding_inoutvlan.in_gw_ip));
//			system(cmd);
			sprintf(cmd,"ping %s -q -c 1 -W1",ip2str(ipstr_out,gw_ip[0]));
			RUNNING_LOG_DEBUG( "running cmd %s\n",cmd);
			system(cmd);
		 
#ifdef BOND_2DIR		 
			 sprintf(cmd,"ping %s -q -c 1 -W1",ip2str(ipstr_out,gw_ip[1]));
			 RUNNING_LOG_DEBUG( "running cmd %s\n",cmd);
			 system(cmd);
			 sleep(10);
#endif
		 }

//		 sprintf(cmd,"arp -s %s 68:a8:28:27:ba:dc",ip2str(ipstr_out,gw_ip[0]));
//		 RUNNING_LOG_DEBUG( "running cmd %s\n",cmd);
//		 system(cmd);

//		sprintf(cmd,"nc --proxy-type socks4 --proxy 127.0.0.1:10001 -n --send-only -w1 -i0.01 -v 121.40.125.206 8080 2>&1|sed -n 2p|grep -o -E  'Timedout|Connected'");
//		if (0 == getResultFromSystemCall(cmd, str_ret, 32))
//		{
//			RUNNING_LOG_INFO("%s test result is %s\n",__FUNCTION__,  str_ret);
//		}

	 

//		if(unlikely(pre_dtable != dnatconfig_curr))
//		{
//			pre_dtable=dnatconfig_curr;
//			if (dnatconfig_curr)
//				rte_memcpy(&local_dtable, &dtable[NAT_MAX_DSTNUM], sizeof(local_dtable[0]) * NAT_MAX_DSTNUM);		
//			else
//				rte_memcpy(&local_dtable, &dtable[0], sizeof(local_dtable[0]) * NAT_MAX_DSTNUM);
//		}


//		for( i = 0; i < NAT_MAX_DSTNUM; i++)
//		{
//			if(0 != local_dtable[i].dst_ip)
//			{
//				for( j = 0; j < NAT_MAX_RULENUM; j++)
//				{
//					if (0 != local_dtable[i].rule[j].nat_ip[0])
//					{
//						for( k = 0; k < NAT_MAX_NATIPNUM; k++)
//						{
//							if (0 != local_dtable[i].rule[j].nat_ip[k])
//							{
//								memset(str_ret, 0, sizeof(str_ret));
//								sprintf(cmd,"nc --proxy-type socks4 --proxy 127.0.0.1:10001 -n --send-only -w1 -i0.01 -v %s %d 2>&1|sed -n 2p|grep -o -E  'Timedout|Connected'", 
//									ip2str(ipstr_out, rte_cpu_to_be_32(local_dtable[i].rule[j].nat_ip[k])), 
//									local_dtable[i].rule[j].nat_port);
//								if (0 == getResultFromSystemCall(cmd, str_ret, 32))
//								{
//									if (!strcmp(str_ret, "Connected"))
//										dnat_linkstate[i][j] |= (1ULL<<k);
//									RUNNING_LOG_INFO("%s test %s result is %s\n",__FUNCTION__, ipstr_out, str_ret);
//								}
//								//usleep(100000);
//								sleep(1);
//							}
//						}
//					}
//				}
//			}
//		}
		
		sleep(60);
#endif

	}

	if (local_dtable)
	{
		free(local_dtable);
		local_dtable=NULL;
	}
	
	ping_thread_stop++;
	RUNNING_LOG_DEBUG( "ping_thread exit now\n");
}

#endif


int init_ping(void)
{
	int rc;
	
	rc = pthread_create(&ping_thread_id, NULL,  &ping_thread, NULL);
	if (rc != 0) {
		RUNNING_LOG_ERROR("Failed to create ping_thread thread\n");
		return MM_FAIL;
	}

	return MM_SUCCESS;
}

