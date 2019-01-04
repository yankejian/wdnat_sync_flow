#include "all.h"
#include "cJSON.h"

struct mon_cell_arr mon_netport_core;
int mon_netport_sig;

struct mon_file file_mon[FILE_MON_CNT]={
	{DEFAULT_MODE_FILE,/*parser_mode*/NULL,0,0,0,0,0},
	{DEFAULT_CONFIG_FILE,parser_config/*NULL*/,0,0,0,0,0},
	{DEFAULT_SERVER_LIST_FILE,parser_server_list,0,0,0,0,0},
	{DEFAULT_MON_IP_FILE,parser_mon_ip,0,0,0,0,0},
	{DEFAULT_MON_NETPORT_FILE,parser_mon_netport,0,0,0,0,0},
	{DEFAULT_DEFAULT_POLICY_FILE,parser_defaultpolicy,0,0,0,0,0},
	{DEFAULT_SNAT_CONFIG_FILE, parser_snatconfig, 0, 0, 0, 0, 0},
	{DEFAULT_DNAT_CONFIG_FILE, parser_dnatconfig, 0, 0, 0, 0, 0}
};


struct mmb mm_conf={
	.name="m_conf",
	.preinit=m_conf_preinit,
	.init=m_conf_init,
	.deinit=m_conf_deinit,
};

int hw_log_off;
int mon_log_off;
//int do_pcap_flag;

struct mon_cell_arr mon_ip_arr;
struct mon_cell_arr mon_netport_arr;

struct policy default_policy[2];
uint32_t default_curr;
uint32_t global_policy;
uint32_t dnatconfig_curr;
uint32_t snatconfig_curr;
uint32_t viptoa_curr = 0;

struct nat_item snat_table[MAX_NAT_RULENUM];
struct nat_item dnat_table[MAX_NAT_RULENUM];
struct nonat_item nonat_table[MAX_NAT_RULENUM];

struct snat_item stable[NAT_MAX_DSTNUM*2];
struct dnat_item dtable[NAT_MAX_DSTNUM*2];
uint32_t rip_linkstate[NAT_MAX_DSTNUM][NAT_MAX_RULENUM];
//uint32_t nat_bandwidth[NAT_MAX_DSTNUM]; 	//default for not limit
//uint32_t nat_forwardlevel[NAT_MAX_DSTNUM];
//uint32_t nat_viptoa[NAT_MAX_DSTNUM];
int nat_linkcount[NAT_MAX_DSTNUM];

struct dst_pl_s *g_dst_pl = NULL;

//FUN_IO_IN,
//FUN_SUM,
//FUN_CALC,
//FUN_TIMER,
int main_null(void)
{
	RUNNING_LOG_ERROR("core < %d> in NULL loop\n",rte_lcore_id());

	while(1)
	{
		sleep(1);
	}
}

int (*funmap[])(void)={
	main_null,
#ifdef __MAIN_LOOP_KNI__
	main_loop_kni,
#else
	main_null,
#endif
	main_loop_nat, //main_loop_s0,//main_loop_out,
	main_loop_nat,//main_loop_s0,//main_loop_io_sj,//main_loop_io_in_mode0,//main_loop_io_rtc,
	main_loop_sum_ip,//main_loop_sum	//FUN_SUM
	main_null,
	main_loop_gather,//main_loop_timer,	//FUN_TIMER
//	main_loop_flow,
//	main_loop_timer_split,//main_loop_timer,
//	main_loop_reaper,
	main_null, //main_loop_pcap,	//FUN_PCAP
	main_loop_sum_src,				//FUN_SUM_SRC
	//main_loop_natlistsum2,
	//main_loop_natlistfresh,
	main_loop_distribute, //FUN_DISTRIBUTE
	main_null,
	main_null
};

pthread_t conf_thread_id=(pthread_t)0;
pthread_t natconf_thread_id=(pthread_t)0;
pthread_t nat_dstip_p_det_thread_id=(pthread_t)0;	//dstip policy detected
pthread_t nat_ripstatus_thread_id=(pthread_t)0;
pthread_cond_t conf_cond;
pthread_mutex_t conf_mutex;

int parser_zk_conf(char *name)
{
	int r;
	cJSON *t,*tt;
	struct stat buf;
	cJSON * pJson;
	FILE *fp;
	char *buffer_ptr;
	int len;
	char cbuf[1024];
	struct in_addr inp;

	r=stat(name, &buf);
	if((r)||!(buf.st_mode & S_IFREG))
		{
		EARLY_LOG_INFO("%s:stat file %s fail\n",__FUNCTION__,name);
		return MM_FAIL;
		}
	/*

	if((fp=fopen(name,"r"))!=NULL)
		{
		cbuf[0]=0;
		while (!feof(fp))
			{
				char *port_spec;

				fgets(cbuf, sizeof(cbuf), fp);
				port_spec = strrchr(cbuf, ':');
				*port_spec=0;
				if(!inet_aton(cbuf,&inp))
					{
					EARLY_LOG_ERROR("%s: ip= %s is bad\n",,tt->valuestring);
					}

			}

		fclose(fp);
		}
*/

	if((fp = fopen(name, "r")) == NULL)
		{
		EARLY_LOG_INFO("Failed to fopen '%s', err=%s\n", name, strerror(errno));
		return MM_FAIL;
		}

	if((buffer_ptr = malloc(buf.st_size)) == NULL)
		{
		fclose(fp);
		return MM_FAIL;
		}

	if((len = fread(buffer_ptr, 1, buf.st_size, fp)) != buf.st_size)
		{
		free(buffer_ptr);
		fclose(fp);
		return MM_FAIL;
		}

	fclose(fp);

	pJson = cJSON_Parse(buffer_ptr);

	if(pJson == NULL)
		{
		EARLY_LOG_ERROR("%s : cJSON_Parse file %s fail\n",__FUNCTION__,name);
		return MM_FAIL;
		}

	t = cJSON_GetObjectItem(pJson,"server");
	if(t)
		{
		cJSON* pArrayItem = NULL;
		int i;
		int nCount;

		nCount = cJSON_GetArraySize ( t );
		for( i = 0; i < nCount; i++)
			{
			pArrayItem = cJSON_GetArrayItem(t, i);
			if(pArrayItem)
				{
				tt = cJSON_GetObjectItem(pArrayItem,"ip");
				if(tt)
					{
					struct zk_s_list *d;
					struct in_addr inp;

					if(!inet_aton(tt->valuestring,&inp))
						{
						EARLY_LOG_ERROR("%s: ip= %s is bad\n",__FUNCTION__,tt->valuestring);
						}
					else
						{
						cJSON *ttt=cJSON_GetObjectItem(pArrayItem,"port");
						if(ttt)
							{
							if((ttt->valueint > 0)&&(ttt->valueint < 65536))
								{
									d=(struct zk_s_list *)malloc(sizeof(struct zk_s_list));
									if(d)
										{
										INIT_LIST_HEAD(&d->list);
										d->ip=mystrdup(tt->valuestring);
										if(d->ip==NULL)
											{
											cJSON_Delete(pJson);
											free(buffer_ptr);
											return MM_FAIL;
											}
										d->port=ttt->valueint;
										list_add_tail(&d->list,&zk_server_list);
										EARLY_LOG_INFO("%s: ip= %s:%d\n",__FUNCTION__,d->ip,d->port);
										}
								}
							}
						}
					}
				}
			}
		}

	cJSON_Delete(pJson);

	free(buffer_ptr);

	return MM_SUCCESS;
}


int parser_id(char *name)
{
	char cbuf[PATH_MAX];
	struct stat buf;
	int r;
	FILE *fp;

	r=stat(name, &buf);
	if((r)||!(buf.st_mode & S_IFREG))
		{
		EARLY_LOG_ERROR("%s:stat file %s fail\n",__FUNCTION__,name);
		return MM_FAIL;
		}

	r = buf.st_mode & S_IFREG;
	if(r == S_IFREG)
		{
		if((fp=fopen(name,"r"))!=NULL)
			{
			cbuf[0]=0;
			while (!feof(fp))
				{
					fgets(cbuf, sizeof(cbuf), fp);
					if(cbuf[0])
						{
						int lastc=strlen(cbuf)-1;
						if(cbuf[lastc]=='\n')
							cbuf[lastc]=0;
						me.id=mystrdup(cbuf);
						if(me.id==NULL)
							{
							EARLY_LOG_INFO("alloc id fail\n");
							return MM_FAIL;
							}
						EARLY_LOG_INFO("id = %s\n",me.id);
						break;
						}
					else
						{
						return MM_FAIL;
						}
				}

			fclose(fp);
			}
		}
	else
		return MM_FAIL;

	return MM_SUCCESS;
}


int parser_server_list(char *name)
{
	EARLY_LOG_DEBUG("%s : %s\n",__FUNCTION__,name);

	return MM_SUCCESS;
}


int parser_mode(char *name)
{
	char cbuf[PATH_MAX];
	struct stat buf;
	int r;
	FILE *fp;

	me.mode=MODE_LOCAL;
	me.type=TYPE_FW;

	stat(name, &buf);
	r = buf.st_mode & S_IFREG;
	if(r == S_IFREG)
		{
		if((fp=fopen(name,"r"))!=NULL)
			{
			cbuf[0]=0;
			while (!feof(fp))
				{
					fgets(cbuf, sizeof(cbuf), fp);
					if(!strncmp(cbuf, M_CLUSTER_TOKEN_ZK, strlen(M_CLUSTER_TOKEN_ZK)))
						me.mode=MODE_CLUSTER_ZK;

					if(!strncmp(cbuf, T_FW_TOKEN, strlen(T_FW_TOKEN)))
						me.type=TYPE_FW;
					else if(!strncmp(cbuf, T_SJ_TOKEN, strlen(T_SJ_TOKEN)))
						me.type=TYPE_SJ;
					else if(!strncmp(cbuf, T_KD_TOKEN, strlen(T_KD_TOKEN)))
						me.type=TYPE_KD;
				}

			fclose(fp);
			}
		}

	EARLY_LOG_INFO("%s : mode=%d type=%d\n",__FUNCTION__,me.mode,me.type);

	return MM_SUCCESS;
}


int parser_mon_netport(char *name)
{
	char cbuf[PATH_MAX];
	struct stat buf;
	int r;
	FILE *fp;
	int port;
	int tmp=0;
	uint32_t tmp_ip;

	stat(name, &buf);
	r = buf.st_mode & S_IFREG;
	if(r == S_IFREG)
		{
		if((fp=fopen(name,"r"))!=NULL)
			{
			cbuf[0]=0;
			while (!feof(fp))
				{
					if(fgets(cbuf, sizeof(cbuf), fp)!=NULL)
						{
						port=atoi(cbuf);
						if ((port>0)&&(port<65536))
							{
							tmp++;
							EARLY_LOG_DEBUG("%s : get port=%d\n",__FUNCTION__,port);
							if(tmp>mon_netport_arr.max)
								{
								EARLY_LOG_DEBUG("%s : to more cnt=%d port=%d,cut it\n",__FUNCTION__,tmp,port);
								break;
								}
							}

						if(tmp)
							{
							// not check if ip repeat
							mon_netport_arr.curr=tmp;
							mon_netport_arr.arr[mon_netport_arr.curr-1]=rte_cpu_to_be_16(port);
							}
						}
				}

			fclose(fp);
			}
		}

#if 1//debug
	for(r=0;r<mon_netport_arr.curr;r++)
	{
		EARLY_LOG_INFO("%s : r=%d port=%d\n",__FUNCTION__,r,mon_netport_arr.arr[r]);
	}
#endif

	mon_netport_sig=1;
	rte_smp_wmb();

	return MM_SUCCESS;
}


int parser_mon_ip(char *name)
{
	char cbuf[PATH_MAX];
	struct stat buf;
	int r;
	FILE *fp;
	struct in_addr addr;
	int tmp=0;
	uint32_t tmp_ip;

	stat(name, &buf);
	r = buf.st_mode & S_IFREG;
	if(r == S_IFREG)
		{
		if((fp=fopen(name,"r"))!=NULL)
			{
			cbuf[0]=0;
			while (!feof(fp))
				{
					if(fgets(cbuf, sizeof(cbuf), fp)!=NULL)
						{
						if (inet_aton(cbuf, &addr))
							{
							tmp++;
							EARLY_LOG_DEBUG("%s : get ip=%x\n",__FUNCTION__,addr.s_addr);
							if(tmp>mon_ip_arr.max)
								{
								EARLY_LOG_DEBUG("%s : to more cnt=%d ip=%x,cut it\n",__FUNCTION__,tmp,addr.s_addr);
								break;
								}
							}

						if(tmp)
							{
							// not check if ip repeat
							mon_ip_arr.curr=tmp;
							mon_ip_arr.arr[mon_ip_arr.curr-1]=(uint32_t)addr.s_addr;
							}
						}
				}

			fclose(fp);
			}
		}

#if 0//debug
	for(r=0;r<mon_ip_arr.curr;r++)
	{
		EARLY_LOG_INFO("%s : r=%d ip=%x\n",__FUNCTION__,r,mon_ip_arr.arr[r]);
	}
#endif

	int i,j,k;
	uint64_t mask;
	struct mon_cell_arr *sum_arr[MAX_CPU];
	int sum_cnt=__builtin_popcountll(me.sum_mask);

	mask=me.sum_mask;
	j=0;
	do
		{
			i=__builtin_ffsll(mask)-1;
			mask &= ~(1ULL<<i);
			k=lcore[i].sum.mon_ip_idx^1;
			sum_arr[j]=&lcore[i].sum.mon_ip_core[k];
			lcore[i].sum.mon_ip_core[k].curr=0;
			j++;
#if 0//debug
{
		EARLY_LOG_INFO("%s : sumcore=%d idx=%d j=%d\n",__FUNCTION__,i,k,j);

}
#endif
		}while(mask);

	for(j=0;j<mon_ip_arr.curr;j++)
		{
		k=rte_be_to_cpu_32(mon_ip_arr.arr[j])&(sum_cnt-1);
		sum_arr[k]->arr[sum_arr[k]->curr++]=mon_ip_arr.arr[j];

#if 0//debug
{
		EARLY_LOG_INFO("%s : put ip=%x to k=%d\n",__FUNCTION__,mon_ip_arr.arr[j],k);

}
#endif
		}

	rte_smp_wmb();

	mask=me.sum_mask;
	do
		{
			i=__builtin_ffsll(mask)-1;
			mask &= ~(1ULL<<i);
			lcore[i].sum.mon_ip_switch=1;
		}while(mask);

	rte_smp_wmb();

	return MM_SUCCESS;
}

void dump_defaultpolicy(struct policy *p)
{
	EARLY_LOG_INFO("<%d> ------------->  default policy dumping\n",rte_lcore_id());
	EARLY_LOG_INFO("land_action=%d smurf_action=%d fraggle_action=%d nuker_action=%d\n",
		p->land_action,p->smurf_action,
		p->fraggle_action,p->nuker_action);
	EARLY_LOG_INFO("ip_option_action=%d ttl0_action=%d tcp_bad_action=%d\n",
		p->ip_option_action,p->ttl0_action,
		p->tcp_bad_action);
	EARLY_LOG_INFO("th_pps=%llu th_bps=%llu limit_pps=%llu limit_bps=%llu\n",
		p->th_pps,p->th_bps,
		p->limit_pps,p->limit_bps);
}

int parser_defaultpolicy(char *name)
{
	int r;
	cJSON *t,*tt,*ttt,*tttt,*ttttt,*tttttt;
	struct stat buf;
	cJSON * pJson;
    FILE *fp;
	char *buffer_ptr;
	int len;
	int ret=MM_SUCCESS;
	struct policy tmp_policy={0};
	int i,j;


	r=stat(name, &buf);
	if((r)||!(buf.st_mode & S_IFREG))
	{
		if (ENOENT == errno)  //not exist
	        {
	                EARLY_LOG_INFO("%s:defaultpolicy file is not exist!\n",__FUNCTION__);
                        return MM_SUCCESS;
	        }
		EARLY_LOG_INFO("%s:stat file %s fail\n",__FUNCTION__,name);
		return MM_FAIL;
	}

    if((fp = fopen(name, "r")) == NULL)
		{
       	EARLY_LOG_INFO("Failed to fopen '%s', err=%s\n", name, strerror(errno));
		return MM_FAIL;
		}

    if((buffer_ptr = malloc(buf.st_size)) == NULL)
		{
        fclose(fp);
        return MM_FAIL;
    	}

    if((len = fread(buffer_ptr, 1, buf.st_size, fp)) != buf.st_size)
		{
        free(buffer_ptr);
        fclose(fp);
        return MM_FAIL;
    	}

    fclose(fp);

	pJson = cJSON_Parse(buffer_ptr);

	if(pJson == NULL)
		{
		EARLY_LOG_ERROR("%s : cJSON_Parse file %s fail\n",__FUNCTION__,name);
		return MM_FAIL;
		}

	t = cJSON_GetObjectItem(pJson,"type");
	if(t)
		{
			if (!strcmp(t->valuestring,"global"))
				{
				if(!global_policy)
					{
					global_policy=1;
					rte_smp_wmb();
					EARLY_LOG_INFO("policy change to global\n");
					}
				}
			else
				{
				if(global_policy)
					{
					global_policy=0;
					rte_smp_wmb();
					EARLY_LOG_INFO("policy change to split\n");
					}
				}
		}

	t = cJSON_GetObjectItem(pJson,"flood_th");
	if(t)
		{
			tt = cJSON_GetObjectItem(t,"pps");
			if(tt)
				{
				tmp_policy.th_pps=(uint64_t)tt->valueint;

				EARLY_LOG_INFO("th_pps is %llu\n",tt->valueint);
				}

			tt = cJSON_GetObjectItem(t,"bps");
			if(tt)
				{
				tmp_policy.th_bps=((uint64_t)tt->valueint)>>3;

				EARLY_LOG_INFO("th_bps is %llu\n",tt->valueint);
				}
		}

	t = cJSON_GetObjectItem(pJson,"limit");
	if(t)
		{
			tt = cJSON_GetObjectItem(t,"pps");
			if(tt)
				{
				tmp_policy.limit_pps=(uint64_t)tt->valueint;

				EARLY_LOG_INFO("limit_pps is %llu\n",tt->valueint);
				}

			tt = cJSON_GetObjectItem(t,"bps");
			if(tt)
				{
				tmp_policy.limit_bps=((uint64_t)tt->valueint)>>3;

				EARLY_LOG_INFO("limit_bps is %llu\n",tt->valueint);
				}
		}

	t = cJSON_GetObjectItem(pJson,"land");
	if(t)
		{
			tt = cJSON_GetObjectItem(t,"action");
			if(tt)
				{
					if (!strcmp(tt->valuestring,"drop"))
						{
						tmp_policy.land_action=FLAG(POLICY_ACT_DROP);
						}
					else
						{
						tmp_policy.land_action=FLAG(POLICY_ACT_FORWARD);
						}

				EARLY_LOG_INFO("land is %x\n",tmp_policy.land_action);
				}

			tt = cJSON_GetObjectItem(t,"cap");
			if(tt)
				{
					if (!strcmp(tt->valuestring,"true"))
						{
						tmp_policy.land_action|=FLAG(POLICY_ACT_PCAP);
						}

				EARLY_LOG_INFO("land cap is %x\n",tmp_policy.land_action);
				}
		}

	t = cJSON_GetObjectItem(pJson,"smurf");
	if(t)
		{
			tt = cJSON_GetObjectItem(t,"action");
			if(tt)
				{
					if (!strcmp(tt->valuestring,"drop"))
						{
						tmp_policy.smurf_action=FLAG(POLICY_ACT_DROP);
						}
					else
						{
						tmp_policy.smurf_action=FLAG(POLICY_ACT_FORWARD);
						}

				EARLY_LOG_INFO("smurf_action is %x\n",tmp_policy.smurf_action);
				}

			tt = cJSON_GetObjectItem(t,"cap");
			if(tt)
				{
					if (!strcmp(tt->valuestring,"true"))
						{
						tmp_policy.smurf_action|=FLAG(POLICY_ACT_PCAP);
						}

				EARLY_LOG_INFO("smurf_action cap is %x\n",tmp_policy.smurf_action);
				}
		}

	t = cJSON_GetObjectItem(pJson,"fraggle");
	if(t)
		{
			tt = cJSON_GetObjectItem(t,"action");
			if(tt)
				{
					if (!strcmp(tt->valuestring,"drop"))
						{
						tmp_policy.fraggle_action=FLAG(POLICY_ACT_DROP);
						}
					else
						{
						tmp_policy.fraggle_action=FLAG(POLICY_ACT_FORWARD);
						}

				EARLY_LOG_INFO("fraggle_action is %x\n",tmp_policy.fraggle_action);
				}

			tt = cJSON_GetObjectItem(t,"cap");
			if(tt)
				{
					if (!strcmp(tt->valuestring,"true"))
						{
						tmp_policy.fraggle_action|=FLAG(POLICY_ACT_PCAP);
						}

				EARLY_LOG_INFO("fraggle_action cap is %x\n",tmp_policy.fraggle_action);
				}
		}

	t = cJSON_GetObjectItem(pJson,"ipoption");
	if(t)
		{
			tt = cJSON_GetObjectItem(t,"action");
			if(tt)
				{
					if (!strcmp(tt->valuestring,"drop"))
						{
						tmp_policy.ip_option_action=FLAG(POLICY_ACT_DROP);
						}
					else
						{
						tmp_policy.ip_option_action=FLAG(POLICY_ACT_FORWARD);
						}

				EARLY_LOG_INFO("ip_option_action is %x\n",tmp_policy.ip_option_action);
				}

			tt = cJSON_GetObjectItem(t,"cap");
			if(tt)
				{
					if (!strcmp(tt->valuestring,"true"))
						{
						tmp_policy.ip_option_action|=FLAG(POLICY_ACT_PCAP);
						}

				EARLY_LOG_INFO("ip_option_action cap is %x\n",tmp_policy.ip_option_action);
				}
		}

	t = cJSON_GetObjectItem(pJson,"tracert");
	if(t)
		{
			tt = cJSON_GetObjectItem(t,"action");
			if(tt)
				{
					if (!strcmp(tt->valuestring,"drop"))
						{
						tmp_policy.ttl0_action=FLAG(POLICY_ACT_DROP);
						}
					else
						{
						tmp_policy.ttl0_action=FLAG(POLICY_ACT_FORWARD);
						}

				EARLY_LOG_INFO("ttl0_action is %x\n",tmp_policy.ttl0_action);
				}

			tt = cJSON_GetObjectItem(t,"cap");
			if(tt)
				{
					if (!strcmp(tt->valuestring,"true"))
						{
						tmp_policy.ttl0_action|=FLAG(POLICY_ACT_PCAP);
						}

				EARLY_LOG_INFO("ttl0_action cap is %x\n",tmp_policy.ttl0_action);
				}
		}

	t = cJSON_GetObjectItem(pJson,"tcpbad");
	if(t)
		{
			tt = cJSON_GetObjectItem(t,"action");
			if(tt)
				{
					if (!strcmp(tt->valuestring,"drop"))
						{
						tmp_policy.tcp_bad_action=FLAG(POLICY_ACT_DROP);
						}
					else
						{
						tmp_policy.tcp_bad_action=FLAG(POLICY_ACT_FORWARD);
						}

				EARLY_LOG_INFO("tcp_bad_action is %x\n",tmp_policy.tcp_bad_action);
				}

			tt = cJSON_GetObjectItem(t,"cap");
			if(tt)
				{
					if (!strcmp(tt->valuestring,"true"))
						{
						tmp_policy.tcp_bad_action|=FLAG(POLICY_ACT_PCAP);
						}

				EARLY_LOG_INFO("tcp_bad_action cap is %x\n",tmp_policy.tcp_bad_action);
				}
		}

	t = cJSON_GetObjectItem(pJson,"nuker");
	if(t)
		{
			tt = cJSON_GetObjectItem(t,"action");
			if(tt)
				{
					if (!strcmp(tt->valuestring,"drop"))
						{
						tmp_policy.nuker_action=FLAG(POLICY_ACT_DROP);
						}
					else
						{
						tmp_policy.nuker_action=FLAG(POLICY_ACT_FORWARD);
						}

				EARLY_LOG_INFO("nuker_action is %x\n",tmp_policy.nuker_action);
				}

			tt = cJSON_GetObjectItem(t,"cap");
			if(tt)
				{
					if (!strcmp(tt->valuestring,"true"))
						{
						tmp_policy.nuker_action|=FLAG(POLICY_ACT_PCAP);
						}

				EARLY_LOG_INFO("nuker_action cap is %x\n",tmp_policy.nuker_action);
				}
		}

	if(!tmp_policy.limit_bps)
		{
		tmp_policy.limit_bps=(uint64_t)-1;
#ifdef LIMIT_MODE2
		tmp_policy.per_limit_bps=(uint64_t)-1;
#endif
		}
#ifdef LIMIT_MODE2
	else
		tmp_policy.per_limit_bps=tmp_policy.limit_bps/__builtin_popcountll(me.io_in_mask);
#endif

	if(!tmp_policy.limit_pps)
		{
		tmp_policy.limit_pps=(uint64_t)-1;
#ifdef LIMIT_MODE2
		tmp_policy.per_limit_bps=(uint64_t)-1;
#endif
		}
#ifdef LIMIT_MODE2
	else
		tmp_policy.per_limit_pps=tmp_policy.limit_pps/__builtin_popcountll(me.io_in_mask);
#endif

	if(!tmp_policy.th_bps)
		tmp_policy.th_bps=(uint64_t)-1;
	if(!tmp_policy.th_pps)
		tmp_policy.th_pps=(uint64_t)-1;

	if(memcmp(&tmp_policy,&default_policy[default_curr],sizeof(default_policy[0])))
		{
		memcpy(&default_policy[default_curr^1],&tmp_policy,sizeof(default_policy[0]));

		default_curr^=1;

		rte_smp_wmb();

		EARLY_LOG_INFO("curr default policy %d\n",default_curr);
		dump_defaultpolicy(&default_policy[default_curr]);
		}

conf_out:
	cJSON_Delete(pJson);

	free(buffer_ptr);

	return ret;
}

void cjson_parse_kafka(cJSON *t)
{
	cJSON *tt,*ttt,*tttt;

	tt = cJSON_GetObjectItem(t,"event_kafka");
	if(tt)
		{
		ttt = cJSON_GetObjectItem(tt,"brokers_list");
		if(ttt)
			{
			me.ch_kafka.brokers_list = mystrdup(ttt->valuestring);
			}

		ttt = cJSON_GetObjectItem(tt,"machine_stat_event");
		if(ttt)
			{
			tttt = cJSON_GetObjectItem(ttt,"topic_name");
			me.ch_kafka.channel_kafka[TOPIC_MACHINE_STAT].topic_name = mystrdup(tttt->valuestring);
			}

		ttt = cJSON_GetObjectItem(tt,"dstip_stat_event");
		if(ttt)
			{
			tttt = cJSON_GetObjectItem(ttt,"topic_name");
			me.ch_kafka.channel_kafka[TOPIC_DSTIP_STAT].topic_name = mystrdup(tttt->valuestring);
			}

		ttt = cJSON_GetObjectItem(tt,"attack_event");
		if(ttt)
			{
			tttt = cJSON_GetObjectItem(ttt,"topic_name");
			me.ch_kafka.channel_kafka[TOPIC_ATTACK_EVENT].topic_name = mystrdup(tttt->valuestring);
			}

		ttt = cJSON_GetObjectItem(tt,"src_station_event");
		if(ttt)
			{
			tttt = cJSON_GetObjectItem(ttt,"topic_name");
			me.ch_kafka.channel_kafka[TOPIC_SRC_STATION_EVENT].topic_name = mystrdup(tttt->valuestring);
			}
		}

}

int my_htoi(char s[])
{
    int i;
    int n = 0;
    if (s[0] == '0' && (s[1]=='x' || s[1]=='X'))
    {
        i = 2;
    }
    else
    {
        i = 0;
    }

    for (; (s[i] >= '0' && s[i] <= '9') || ((s[i]|0x20) >= 'a' && (s[i]|0x20) <= 'z');++i)
    {
        if (s[i] > '9')
        {
            n = 16 * n + (10 + (s[i] | 0x20) - 'a');
        }
        else
        {
            n = 16 * n + (s[i] - '0');
        }
    }
    return n;
}

int parser_config(char *name)
{
	int r;
	cJSON *t,*tt,*ttt,*tttt,*ttttt,*tttttt;
	struct stat buf;
	cJSON * pJson;
    FILE *fp;
	char *buffer_ptr;
	int len;
	int ret=MM_SUCCESS;
	int inout_in1=0;
	int lcore_msk=0,lcore_msk_cfg=0;

	r=stat(name, &buf);
	if((r)||!(buf.st_mode & S_IFREG))
		{
		EARLY_LOG_INFO("%s:stat file %s fail\n",__FUNCTION__,name);
		return MM_FAIL;
		}

	if((fp = fopen(name, "r")) == NULL)
		{
       	EARLY_LOG_INFO("Failed to fopen '%s', err=%s\n", name, strerror(errno));
		return MM_FAIL;
		}

	if((buffer_ptr = malloc(buf.st_size)) == NULL)
		{
        fclose(fp);
        return MM_FAIL;
    	}

	if((len = fread(buffer_ptr, 1, buf.st_size, fp)) != buf.st_size)
		{
        free(buffer_ptr);
        fclose(fp);
        return MM_FAIL;
    	}

	fclose(fp);

	pJson = cJSON_Parse(buffer_ptr);

	if(pJson == NULL)
		{
		EARLY_LOG_ERROR("%s : cJSON_Parse file %s fail\n",__FUNCTION__,name);
		return MM_FAIL;
		}

	if(!(me.flag & FLAG_CONFIGED))
		{
			t = cJSON_GetObjectItem(pJson,"type");
			if(t)
				{
				EARLY_LOG_INFO("type is %s\n",t->valuestring);
				}

//			t = cJSON_GetObjectItem(pJson,"settle_mode");
//			if(t)
//				{
//				if (!strcmp(t->valuestring,"full"))
//					{
//					me.settle_mode=SETTLE_MODE_FULL;
//					}
//				else//default to half
//					{
//					me.settle_mode=SETTLE_MODE_HALF;
//					}
//
//				EARLY_LOG_INFO("settle_mode is %s\n",t->valuestring);
//				}

			t = cJSON_GetObjectItem(pJson,"base");
			if(t)
				{
				char buf[256];

				tt = cJSON_GetObjectItem(t,"root");
				if(tt)
					{
					me.root_dir=mystrdup(tt->valuestring);
					if(me.root_dir==NULL)
						{
						cJSON_Delete(pJson);
						free(buffer_ptr);
						EARLY_LOG_INFO("root_dir alloc fail\n");
						return MM_FAIL;
						}

					EARLY_LOG_INFO("root_dir is %s\n",tt->valuestring);
					}

				tt = cJSON_GetObjectItem(t,"running_log");
				if(tt)
					{
					me.runnning_log_file=mystrdup(tt->valuestring);
					if(me.runnning_log_file==NULL)
						{
						cJSON_Delete(pJson);
						free(buffer_ptr);
						EARLY_LOG_INFO("runnning_log_file alloc fail\n");
						return MM_FAIL;
						}

					EARLY_LOG_INFO("running_log is %s\n",tt->valuestring);
					}

				tt = cJSON_GetObjectItem(t,"hw_log");
				if(tt)
					{
					me.hw_log_file=mystrdup(tt->valuestring);
					if(me.hw_log_file==NULL)
						{
						cJSON_Delete(pJson);
						free(buffer_ptr);
						EARLY_LOG_INFO("hw_log_file alloc fail\n");
						return MM_FAIL;
						}
					EARLY_LOG_INFO("hw_log is %s\n",tt->valuestring);
					}

				tt = cJSON_GetObjectItem(t,"flow_log");
				if(tt)
					{
					me.flow_log_file=mystrdup(tt->valuestring);
					if(me.flow_log_file==NULL)
						{
						cJSON_Delete(pJson);
						free(buffer_ptr);
						EARLY_LOG_INFO("flow_log_file alloc fail\n");
						return MM_FAIL;
						}
					EARLY_LOG_INFO("flow_log is %s\n",tt->valuestring);
					}

				tt = cJSON_GetObjectItem(t,"alert_log");
				if(tt)
					{
					me.alert_log_file=mystrdup(tt->valuestring);
					if(me.alert_log_file==NULL)
						{
						cJSON_Delete(pJson);
						free(buffer_ptr);
						EARLY_LOG_INFO("alert_log_file alloc fail\n");
						return MM_FAIL;
						}
					EARLY_LOG_INFO("alert_log is %s\n",tt->valuestring);
					}

				tt = cJSON_GetObjectItem(t,"mon_ip_max");
				if(tt)
					{
					mon_ip_arr.max=tt->valueint;
					EARLY_LOG_INFO("mon_ip_max is %d\n",mon_ip_arr.max);
					}

				tt = cJSON_GetObjectItem(t,"mon_netport_max");
				if(tt)
					{
					mon_netport_arr.max=tt->valueint;
					EARLY_LOG_INFO("mon_netport_max is %d\n",mon_netport_arr.max);
					}
				}

			t = cJSON_GetObjectItem(pJson,"debug");
			if(t)
			{
				tt = cJSON_GetObjectItem(t,"hwlog");
				if(tt)
					{
					if (!strcmp(tt->valuestring,"off"))
						hw_log_off=1;
					else
						hw_log_off=0;
					}

				tt = cJSON_GetObjectItem(t,"monlog");
				if(tt)
					{
					if (!strcmp(tt->valuestring,"off"))
						mon_log_off=1;
					else
						mon_log_off=0;
					}

        			tt = cJSON_GetObjectItem(t,"monitor_vip");
        		        if(tt)
        			{
        			        struct in_addr ip;
                			if(inet_aton(tt->valuestring,&ip))
                			{
                				me.mon_vip = rte_be_to_cpu_32(ip.s_addr);
                				EARLY_LOG_INFO("mon_ip=0x%x\n",me.mon_vip);
                			}
                			else
                			{
                			        me.mon_vip = 0;
                				EARLY_LOG_ERROR("mon_ip intput error,please check it!=>%s\n",tt->valuestring);
                			}
        			}else{
        			    me.mon_vip = 0;
        			}

				tt = cJSON_GetObjectItem(t,"log_level");
				if(tt)
				{
					running_log_level = (LogLevel)tt->valueint;
					EARLY_LOG_INFO("log_level = %d\n", tt->valueint);
				}

//				tt = cJSON_GetObjectItem(t,"do_pcap");
//				if(tt)
//				{
//					if (!strcmp(tt->valuestring,"on")) {
//						do_pcap_flag=1;

//					} else {
//						do_pcap_flag=0;
//					}
//				}
			}

			t = cJSON_GetObjectItem(pJson,"plat");
			if(t)
				{
				tt = cJSON_GetObjectItem(t,"eal_args");
				if(tt)
					{
					int i;
					int nb_token=0;
					char *token;
					char *start=tt->valuestring;

					EARLY_LOG_INFO("eal_args is %s \n",tt->valuestring);

					me.param.argc = 1;
					while((token = strsep(&tt->valuestring, " ")) != NULL)
					{
						strcpy(me.param.argv_buf[me.param.argc],token);
						me.param.argv[me.param.argc] = me.param.argv_buf[me.param.argc];
						EARLY_LOG_DEBUG( "%s %d\n", me.param.argv[me.param.argc],me.param.argc );

						if ((*token == '-') && (*(token+1) == 'c'))
							lcore_msk_cfg = my_htoi(token+2);

						me.param.argc++;
					}

					EARLY_LOG_INFO(" argc=%d\n",me.param.argc);
					}

				tt = cJSON_GetObjectItem(t,"hugepage_size");
				if(tt)
					{
					if (!strcmp(tt->valuestring,"1G"))
						{
						me.param.hugepage_size=PAGE_1G;
						}
					else//default to 2M
						{
						me.param.hugepage_size=PAGE_2M;
						}

					EARLY_LOG_INFO("hugepage_size is %s 0x%llx\n",tt->valuestring,me.param.hugepage_size);
					}

				tt = cJSON_GetObjectItem(t,"nr_hugepages");
				if(tt)
					{
					me.param.nr_hugepages =(uint32_t)tt->valueint;
					if(me.param.nr_hugepages<2)
						me.param.nr_hugepages = 2;//less 2 for 2 socket
					EARLY_LOG_INFO("nr_hugepages is %d\n",tt->valueint);
					}

				}

//#ifndef WF_NAT
			t = cJSON_GetObjectItem(pJson,"dev");
			if(t)
				{
		        cJSON* pArrayItem = NULL;
				int i;
		        int nCount;

				nCount = cJSON_GetArraySize ( t );
		        for( i = 0; i < nCount; i++)
		       		{
		            pArrayItem = cJSON_GetArrayItem(t, i);
					if(pArrayItem)
						{
						tt = cJSON_GetObjectItem(pArrayItem,"pci");
						if(tt)
							{
							struct dev_list *d;

							EARLY_LOG_INFO("dev <%d> is %s\n",i,tt->valuestring);
							d=(struct dev_list *)malloc(sizeof(struct dev_list));
							if(d)
								{
								memset(d,0,sizeof(struct dev_list));
								d->dev_id=mystrdup(tt->valuestring);
								if(d->dev_id==NULL)
									{
									cJSON_Delete(pJson);
									free(buffer_ptr);
									EARLY_LOG_INFO("dev_id alloc fail\n");
									return MM_FAIL;
									}
								INIT_LIST_HEAD(&d->list);
								list_add_tail(&d->list,&port_list);
								me.port_cnt++;
								me.port_mask|=(1<<(me.port_cnt-1));
								}
							else
								return MM_FAIL;
							}

						tt = cJSON_GetObjectItem(pArrayItem,"max_queue");
						if(tt)
							printf("max_queue=%d\n",i,tt->valueint);

						}
		        	}
				}
//#endif	/* n def WF_NAT */

			t = cJSON_GetObjectItem(pJson,"settle_mode");
			if(t)
				{
				tt = cJSON_GetObjectItem(t,"mode");
				if(tt)
					{
					if (!strcmp(tt->valuestring,"gw-bonding"))
						me.settle_setting.mode=INTERFACE_MODE_GW_BONDING;
					else
						me.settle_setting.mode=INTERFACE_MODE_GW_NOBONDING;
					}

				if(me.settle_setting.mode==INTERFACE_MODE_GW_BONDING)
					{
					struct in_addr inp;
					int i;
		       			int nCount;

					tt = cJSON_GetObjectItem(t,"in_port");
					if(tt)
					{
						ttt = cJSON_GetObjectItem(tt,"port_no");
						if(ttt)
						{
							nCount = cJSON_GetArraySize ( ttt );
							me.settle_setting.gw_bonding_inoutvlan.in_port_num = nCount;
							for( i = 0; i < nCount; i++)
							{
								if (i >= MAX_DEV)
									break;
								tttt = cJSON_GetArrayItem(ttt, i);
								if((tttt->valueint < MAX_DEV) && (tttt->valueint >= 0))
									me.settle_setting.gw_bonding_inoutvlan.in_port[i] = tttt->valueint ;
								else
									me.settle_setting.gw_bonding_inoutvlan.in_port[i] = 0;
								EARLY_LOG_DEBUG("get in_port no: %d\n",tttt->valueint);
							}
							for( i = nCount; i < MAX_DEV; i++)
								me.settle_setting.gw_bonding_inoutvlan.in_port[i] = MAX_DEV;
						}

						ttt = cJSON_GetObjectItem(tt,"ip");
						if(ttt)
							{
							if(inet_aton(ttt->valuestring,&inp))
								{
								me.settle_setting.gw_bonding_inoutvlan.in_ip=inp.s_addr;
								EARLY_LOG_DEBUG("get bonding in ip %x\n",me.settle_setting.gw_bonding_inoutvlan.in_ip);
								}
							else
								{
								EARLY_LOG_ERROR("bonding ip intput error %s\n",ttt->valuestring);
								}
							}

						ttt = cJSON_GetObjectItem(tt,"gwip");
						if(ttt)
							{
							if(inet_aton(ttt->valuestring,&inp))
								{
								me.settle_setting.gw_bonding_inoutvlan.in_gw_ip=inp.s_addr;
								EARLY_LOG_DEBUG("get gw in ip %x\n",me.settle_setting.gw_bonding_inoutvlan.in_gw_ip);
								}
							else
								{
								EARLY_LOG_ERROR("bonding gw inip intput error %s\n",ttt->valuestring);
								}
							}

                                                ttt = cJSON_GetObjectItem(tt,"neigh_mac");
        					if(ttt)
        					{
        						int i;
        						char mac[64];
        						strcpy(mac, ttt->valuestring);
        						char *str;
        						char *p = mac;
        						for(i=0;i<6;i++,p+=3)
        						{
        							*(p+2)=0;
        							me.settle_setting.gw_bonding_inoutvlan.in_neigh_mac[i]=(int)strtol(p, &str, 16);
        						}
								EARLY_LOG_DEBUG("%s, in_neigh_mac: %#x:%#x:%#x:%#x:%#x:%#x\n", __FUNCTION__,
									me.settle_setting.gw_bonding_inoutvlan.in_neigh_mac[0],
									me.settle_setting.gw_bonding_inoutvlan.in_neigh_mac[1],
									me.settle_setting.gw_bonding_inoutvlan.in_neigh_mac[2],
									me.settle_setting.gw_bonding_inoutvlan.in_neigh_mac[3],
									me.settle_setting.gw_bonding_inoutvlan.in_neigh_mac[4],
									me.settle_setting.gw_bonding_inoutvlan.in_neigh_mac[5]);
        					}

						ttt = cJSON_GetObjectItem(tt,"netmask");
						if(ttt)
							{
							if(inet_aton(ttt->valuestring,&inp))
								{
								me.settle_setting.gw_bonding_inoutvlan.in_ipmask=inp.s_addr;
								EARLY_LOG_DEBUG("get bonding in ipmask %x\n",me.settle_setting.gw_bonding_inoutvlan.in_ipmask);
								}
							else
								{
								EARLY_LOG_ERROR("bonding ipmask intput error %s\n",ttt->valuestring);
								}
							}

						ttt = cJSON_GetObjectItem(tt,"vlanid");
						if(ttt)
							{
							if((ttt->valueint <4096) && (ttt->valueint > 0))
								{
								me.settle_setting.gw_bonding_inoutvlan.in_vlanid=ttt->valueint;
								EARLY_LOG_DEBUG("get bonding in vlanid %d\n",me.settle_setting.gw_bonding_inoutvlan.in_vlanid);
								}
							else
								{
								EARLY_LOG_ERROR("bonding vlanid intput error %d\n",ttt->valueint);
								}
							}
						}
#ifdef BOND_2DIR
					tt = cJSON_GetObjectItem(t,"out_port");
					if(tt)
						{
						ttt = cJSON_GetObjectItem(tt,"port_no");
						if(ttt)
						{
							nCount = cJSON_GetArraySize ( ttt );
							me.settle_setting.gw_bonding_inoutvlan.out_port_num = nCount;
							for( i = 0; i < nCount; i++)
							{
								if (i >= MAX_DEV)
									break;
								tttt = cJSON_GetArrayItem(ttt, i);
								if((tttt->valueint < MAX_DEV) && (tttt->valueint >= 0))
									me.settle_setting.gw_bonding_inoutvlan.out_port[i] = tttt->valueint ;
								else
									me.settle_setting.gw_bonding_inoutvlan.out_port[i] = 0;
								EARLY_LOG_DEBUG("get out_port no: %d\n",tttt->valueint);
							}
							for( i = nCount; i < MAX_DEV; i++)
								me.settle_setting.gw_bonding_inoutvlan.out_port[i] = MAX_DEV;

						}

						ttt = cJSON_GetObjectItem(tt,"ip");
						if(ttt)
							{
							if(inet_aton(ttt->valuestring,&inp))
								{
								me.settle_setting.gw_bonding_inoutvlan.out_ip=inp.s_addr;
								EARLY_LOG_DEBUG("get bonding out ip %x\n",me.settle_setting.gw_bonding_inoutvlan.out_ip);
								}
							else
								{
								EARLY_LOG_ERROR("bonding ip out error %s\n",ttt->valuestring);
								}
							}

						ttt = cJSON_GetObjectItem(tt,"gwip");
						if(ttt)
							{
							if(inet_aton(ttt->valuestring,&inp))
								{
								me.settle_setting.gw_bonding_inoutvlan.out_gw_ip=inp.s_addr;
								EARLY_LOG_DEBUG("get gw out ip %x\n",me.settle_setting.gw_bonding_inoutvlan.out_gw_ip);
								}
							else
								{
								EARLY_LOG_ERROR("bonding gw outip intput error %s\n",ttt->valuestring);
								}
							}

                                                ttt = cJSON_GetObjectItem(tt,"neigh_mac");
        					if(ttt)
        					{
        						int i;
        						char mac[64]={0};
        						strcpy(mac, ttt->valuestring);
        						char *str;
        						char *p = mac;
        						for(i=0;i<6;i++,p+=3)
        						{
        							*(p+2)=0;
        							me.settle_setting.gw_bonding_inoutvlan.out_neigh_mac[i]=(int)strtol(p, &str, 16);
        						}
								EARLY_LOG_DEBUG("%s, out_neigh_mac: %#x:%#x:%#x:%#x:%#x:%#x\n", __FUNCTION__,
									me.settle_setting.gw_bonding_inoutvlan.out_neigh_mac[0],
									me.settle_setting.gw_bonding_inoutvlan.out_neigh_mac[1],
									me.settle_setting.gw_bonding_inoutvlan.out_neigh_mac[2],
									me.settle_setting.gw_bonding_inoutvlan.out_neigh_mac[3],
									me.settle_setting.gw_bonding_inoutvlan.out_neigh_mac[4],
									me.settle_setting.gw_bonding_inoutvlan.out_neigh_mac[5]);
        					}

						ttt = cJSON_GetObjectItem(tt,"netmask");
						if(ttt)
							{
							if(inet_aton(ttt->valuestring,&inp))
								{
								me.settle_setting.gw_bonding_inoutvlan.out_ipmask=inp.s_addr;
								EARLY_LOG_DEBUG("get bonding out ipmask %x\n",me.settle_setting.gw_bonding_inoutvlan.out_ipmask);
								}
							else
								{
								EARLY_LOG_ERROR("bonding ipmask out error %s\n",ttt->valuestring);
								}
							}

						ttt = cJSON_GetObjectItem(tt,"vlanid");
						if(ttt)
							{
							if((ttt->valueint <4096) && (ttt->valueint > 0))
								{
								me.settle_setting.gw_bonding_inoutvlan.out_vlanid=ttt->valueint;
								EARLY_LOG_DEBUG("get bonding out vlanid %d\n",me.settle_setting.gw_bonding_inoutvlan.out_vlanid);
								}
							else
								{
								EARLY_LOG_ERROR("bonding vlanid out error %d\n",ttt->valueint);
								}
							}
						}
#endif
					}
				else
					{
					tt = cJSON_GetObjectItem(t,"ip_on_port");
					if(tt)
						{
						cJSON* pArrayItem = NULL;
						int i,j;
						int nCount;
						int port_no;
						struct in_addr inp;

						nCount = cJSON_GetArraySize ( tt );
						for( j = 0; j < nCount; j++)
							{
							pArrayItem = cJSON_GetArrayItem(tt, j);
							if(pArrayItem)
								{
								ttt = cJSON_GetObjectItem(pArrayItem,"port");
								if(ttt)
									{
									port_no=ttt->valueint;
									tttt = cJSON_GetObjectItem(pArrayItem,"ip");
									if(tttt)
										{
										if(inet_aton(tttt->valuestring,&inp))
											{
											me.interface_ip[port_no]=ntohl(inp.s_addr);
											EARLY_LOG_DEBUG("get port %d ip %x\n",port_no,me.interface_ip[port_no]);
											}
										else
											{
											EARLY_LOG_ERROR("ip intput error %s\n",tttt->valuestring);
											}
										}

									tttt = cJSON_GetObjectItem(pArrayItem,"netmask");
									if(tttt)
										{
										if(inet_aton(tttt->valuestring,&inp))
											{
											me.interface_ipmask[port_no]=ntohl(inp.s_addr);
											EARLY_LOG_DEBUG("get port %d ip netmask %x\n",port_no,me.interface_ipmask[port_no]);
											}
										else
											{
											EARLY_LOG_ERROR("ip intput error %s\n",tttt->valuestring);
											}
										}
									}
								}
							}
						}
					}
				}

			t = cJSON_GetObjectItem(pJson,"nat_config");
			if(t)
			{
				tt = cJSON_GetObjectItem(t,"remoteconfig_addr");
				if(tt)
				{
					strncpy(me.natconfig.addr, tt->valuestring, sizeof(me.natconfig.addr));
				}else{
					strcpy(me.natconfig.addr, "192.168.50.118");
				}

				tt = cJSON_GetObjectItem(t,"remoteconfig_port");
				if(tt)
				{
					me.natconfig.port = tt->valueint;
				}else{
					me.natconfig.port = 8080;
				}

				tt = cJSON_GetObjectItem(t,"remoteconfig_usrname");
				if(tt)
				{
					strncpy(me.natconfig.usrname, tt->valuestring, sizeof(me.natconfig.usrname));
				}else{
					strcpy(me.natconfig.usrname, "admin");
				}
				tt = cJSON_GetObjectItem(t,"remoteconfig_password");
				if(tt)
				{
					strncpy(me.natconfig.password, tt->valuestring, sizeof(me.natconfig.password));
				}else{
					strcpy(me.natconfig.password, "admin");
				}
                                tt = cJSON_GetObjectItem(t,"config_region_tag");
				if(tt)
				{
					strncpy(me.natconfig.region_tag, tt->valuestring, sizeof(me.natconfig.region_tag));
				}else{
					strcpy(me.natconfig.region_tag, "dg");
				}

                                tt = cJSON_GetObjectItem(t,"config_pool_tag");
				if(tt)
				{
					strncpy(me.natconfig.pool_tag, tt->valuestring, sizeof(me.natconfig.pool_tag));
				}else{
					strcpy(me.natconfig.pool_tag, "default");
				}
				EARLY_LOG_INFO("region is %s,pool is %s\n", me.natconfig.region_tag, me.natconfig.pool_tag);
			}

			t = cJSON_GetObjectItem(pJson,"layout");
			if(t)
				{
				int type=FUN_NULL;
				tt = cJSON_GetObjectItem(t,"pipe_io");
				if(tt)
					{
					type=FUN_IO_IN;

//					ttt = cJSON_GetObjectItem(tt,"function");
//					if(ttt)
//						{
//						if (!strcmp(ttt->valuestring,"io_in"))
//							type=FUN_IO_IN;
//						}

					ttt = cJSON_GetObjectItem(tt,"ippool_num");
					if(ttt)
						{
						me.io_ip_pool_cnt=ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"netportpool_num");
					if(ttt)
						{
						me.io_netport_pool_cnt=ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"dn1_pool_num");
					if(ttt)
						{
						me.io_dn1_pool_cnt=ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"flow_num");
					if(ttt)
						{
						me.io_flow_pool_cnt=ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"flowtag_num");
					if(ttt)
						{
						me.io_flowtag_pool_cnt=ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"flownat_num");
					if(ttt)
					{
						me.io_flownat_pool_cnt=ttt->valueint;
					}

					ttt = cJSON_GetObjectItem(tt,"output_num");
					if(ttt)
						{
						me.io_output_pool_cnt=ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"srcsum_num");
					if(ttt)
						{
						me.io_srcsum_pool_cnt=ttt->valueint;
						}
					else
						me.io_srcsum_pool_cnt=5000000;

					ttt = cJSON_GetObjectItem(tt,"io2dis_num");
					if(ttt)
						{
						me.io_flow_nat_sync_msg_cnt=ttt->valueint;
						}
					else
						me.io_flow_nat_sync_msg_cnt=500000;
#ifdef __SRC_SUM__
					ttt = cJSON_GetObjectItem(tt,"srcip_policy_pool");
					if(ttt)
						{
						me.io_srcip_policy_pool_cnt=ttt->valueint;
						}
					else
						me.io_srcip_policy_pool_cnt=10000000;
#endif

					me.io_in_mask=0;
#ifdef IN_OUT_IN1_MODE
					{
					ttt = cJSON_GetObjectItem(tt,"core_map");
					if(ttt)
						{
						cJSON* pArrayItem = NULL;
						int i,j,k,l,h;;
						int nCount,nCount_1;
						int core_no,port_no;
						cJSON* pArrayItem_1 = NULL;
						uint64_t queue_mask;

						nCount = cJSON_GetArraySize ( ttt );
						for( j = 0; j < nCount; j++)
							{
							pArrayItem = cJSON_GetArrayItem(ttt, j);
							if(pArrayItem)
								{
								tttt = cJSON_GetObjectItem(pArrayItem,"core_no");
								if(tttt)
									{
									core_no=tttt->valueint;

									tttt = cJSON_GetObjectItem(pArrayItem,"port_map");
									if(tttt)
										{
										nCount_1 = cJSON_GetArraySize ( tttt );
										for( k = 0; k < nCount_1; k++)
											{
											pArrayItem_1= cJSON_GetArrayItem(tttt, k);
											if(pArrayItem_1)
												{
												ttttt = cJSON_GetObjectItem(pArrayItem_1,"port_no");
												if(ttttt)
													{
													port_no=ttttt->valueint;

													me.port2core_mask_in[port_no]|=(1ULL<<core_no);

													lcore[core_no].port_id[lcore[core_no].port_cnt]=port_no;

													ttttt = cJSON_GetObjectItem(pArrayItem_1,"txport_no");
													if(ttttt)
													{
														lcore[core_no].txport_id[lcore[core_no].port_cnt]=ttttt->valueint;
													}

													ttttt = cJSON_GetObjectItem(pArrayItem_1,"in_q");
													if(ttttt)
														{
														queue_mask=strtoull(ttttt->valuestring,NULL,16);

														lcore[core_no].queue_id[lcore[core_no].port_cnt]=__builtin_ffsll(queue_mask)-1;
														}

													ttttt = cJSON_GetObjectItem(pArrayItem_1,"out_q");
													if(ttttt)
														{
														queue_mask=strtoull(ttttt->valuestring,NULL,16);
														h=0;

														do
															{
																l=__builtin_ffsll(queue_mask)-1;
																queue_mask &= ~(1ULL<<l);
																lcore[core_no].io_in.out_queue[lcore[core_no].port_cnt][h]=l;
																lcore[core_no].io_in.out_queue_sz[lcore[core_no].port_cnt]++;
																h++;
															}while(queue_mask);
														}


													lcore[core_no].port_cnt++;
													}

												}
											}
										}

									lcore[core_no].socket_id=rte_lcore_to_socket_id(core_no);
									lcore[core_no].type=type;
									lcore[core_no].run=funmap[type];

									//me.io_out_mask|=(1ULL<<core_no);
									me.io_in_mask|=(1ULL<<core_no);
									lcore_msk |=(1ULL<<core_no);
									}
								}
							}
						}
					}

#endif

#if 0
					ttt = cJSON_GetObjectItem(tt,"port_map");
					if(ttt)
						{
				        cJSON* pArrayItem = NULL;
						int i,j;
				        int nCount;
						int port_no;

						nCount = cJSON_GetArraySize ( ttt );
				        for( j = 0; j < nCount; j++)
				       		{
				            pArrayItem = cJSON_GetArrayItem(ttt, j);
							if(pArrayItem)
								{
								tttt = cJSON_GetObjectItem(pArrayItem,"port_no");
								if(tttt)
									{
									port_no=tttt->valueint;
									ttttt = cJSON_GetObjectItem(pArrayItem,"core_mask");
									if(ttttt)
										{
										uint64_t m=1;
										uint64_t mask=strtoull(ttttt->valuestring,NULL,16);
										int queue_cnt=0;
										int a,b,c,d;

										me.port2core_mask_in[port_no]=mask;

									#ifdef IN_OUT_IN1_MODE
										a=__builtin_popcountll(me.port2core_mask_in[port_no]);
										b=MAX_TX_QUEUE/a;
										d=0;
									#endif

										do
											{
												i=__builtin_ffsll(mask)-1;
												mask &= ~(1ULL<<i);

									#ifdef IN_OUT_IN1_MODE
												lcore[i].io_in.out_queue_sz[lcore[i].port_cnt]=b;
												for(c=0;c<b;c++)
													{
													lcore[i].io_in.out_queue[lcore[i].port_cnt][c]=d+c*a;
													}
												d++;
									#endif

									#ifdef PIPE_OUT_LIST_MODE
												lcore[i].io_in.port_do_push[lcore[i].port_cnt].port_id=port_no;
									#endif

												lcore[i].port_id[lcore[i].port_cnt]=port_no;
												lcore[i].queue_id[lcore[i].port_cnt]=queue_cnt++;
												lcore[i].socket_id=rte_lcore_to_socket_id(i);
												lcore[i].type=type;
												lcore[i].port_cnt++;
												lcore[i].run=funmap[type];

												me.io_in_mask|=(1ULL<<i);

											}while(mask);

										}
									}

								}
				        	}
						}
#endif
				}


#ifdef WF_NAT
				tt = cJSON_GetObjectItem(t,"pipe_io_out");
				if(tt)
				{
					type=FUN_IO_OUT;

					ttt = cJSON_GetObjectItem(tt,"ippool_num");
					if(ttt)
					{
						me.io_ip_pool_cnt=ttt->valueint;
					}

					ttt = cJSON_GetObjectItem(tt,"netportpool_num");
					if(ttt)
					{
						me.io_netport_pool_cnt=ttt->valueint;
					}

					ttt = cJSON_GetObjectItem(tt,"dn1_pool_num");
					if(ttt)
					{
						me.io_dn1_pool_cnt=ttt->valueint;
					}

					ttt = cJSON_GetObjectItem(tt,"flow_num");
					if(ttt)
					{
						me.io_flow_pool_cnt=ttt->valueint;
					}

					ttt = cJSON_GetObjectItem(tt,"flowtag_num");
					if(ttt)
					{
						me.io_flowtag_pool_cnt=ttt->valueint;
					}

					ttt = cJSON_GetObjectItem(tt,"flownat_num");
					if(ttt)
					{
						me.io_flownat_pool_cnt=ttt->valueint;
					}

					ttt = cJSON_GetObjectItem(tt,"output_num");
					if(ttt)
					{
						me.io_output_pool_cnt=ttt->valueint;
					}

					me.io_out_mask=0;

					ttt = cJSON_GetObjectItem(tt,"core_map");
					if(ttt)
					{
						cJSON* pArrayItem = NULL;
						int i,j,k,l,h;
						int nCount,nCount_1;
						int core_no,port_no;
						cJSON* pArrayItem_1 = NULL;
						uint64_t queue_mask;

						nCount = cJSON_GetArraySize ( ttt );
						for( j = 0; j < nCount; j++)
						{
							pArrayItem = cJSON_GetArrayItem(ttt, j);
							if(pArrayItem)
							{
								tttt = cJSON_GetObjectItem(pArrayItem,"core_no");
								if(tttt)
								{
									core_no=tttt->valueint;

									tttt = cJSON_GetObjectItem(pArrayItem,"port_map");
									if(tttt)
									{
										nCount_1 = cJSON_GetArraySize ( tttt );
										for( k = 0; k < nCount_1; k++)
										{
											pArrayItem_1= cJSON_GetArrayItem(tttt, k);
											if(pArrayItem_1)
											{
												ttttt = cJSON_GetObjectItem(pArrayItem_1,"port_no");
												if(ttttt)
												{
													port_no=ttttt->valueint;

													me.port2core_mask_out[port_no]|=(1ULL<<core_no);

													lcore[core_no].port_id[lcore[core_no].port_cnt]=port_no;

													ttttt = cJSON_GetObjectItem(pArrayItem_1,"txport_no");
													if(ttttt)
													{
														lcore[core_no].txport_id[lcore[core_no].port_cnt]=ttttt->valueint;
													}

													ttttt = cJSON_GetObjectItem(pArrayItem_1,"in_q");
													if(ttttt)
													{
														queue_mask=strtoull(ttttt->valuestring,NULL,16);

														lcore[core_no].queue_id[lcore[core_no].port_cnt]=__builtin_ffsll(queue_mask)-1;
													}

													ttttt = cJSON_GetObjectItem(pArrayItem_1,"out_q");
													if(ttttt)
													{
														queue_mask=strtoull(ttttt->valuestring,NULL,16);
														h=0;

														do
														{
															l=__builtin_ffsll(queue_mask)-1;
															queue_mask &= ~(1ULL<<l);
															lcore[core_no].io_in.out_queue[lcore[core_no].port_cnt][h]=l;
															lcore[core_no].io_in.out_queue_sz[lcore[core_no].port_cnt]++;
															h++;
														}while(queue_mask);
													}

													lcore[core_no].port_cnt++;
												}
											}
										}
									}

									lcore[core_no].socket_id=rte_lcore_to_socket_id(core_no);
									lcore[core_no].type=type;
									lcore[core_no].run=funmap[type];

									me.io_out_mask|=(1ULL<<core_no);
									lcore_msk |=(1ULL<<core_no);
								}
							}
						}
					}
				}

				tt = cJSON_GetObjectItem(t,"pipe_distribute");
				if(tt)
				{
					type=FUN_DISTRIBUTE;

					ttt = cJSON_GetObjectItem(tt,"dist_ring_cnt");
					if(ttt)
					{
						me.dist_ring_cnt=ttt->valueint;
					}else{
					        me.dist_ring_cnt=DIST_RING_SZ;
					}

					ttt = cJSON_GetObjectItem(tt,"deadtime");
					if(ttt)
					{
						me.natconfig.deadtime= ttt->valueint;
						EARLY_LOG_INFO("nat linklist deadtime=%d\n", me.natconfig.deadtime);
					}else{
						me.natconfig.deadtime= FLOW_NAT_DEAD_TIME_DEF;
					}

                                        ttt = cJSON_GetObjectItem(tt,"deadtime_reset");
					if(ttt)
					{
						me.natconfig.deadtime_rst= ttt->valueint;
						EARLY_LOG_INFO("natlistfresh deadtime_rst=%d\n", me.natconfig.deadtime_rst);
					}else{
						me.natconfig.deadtime_rst= 10;
					}

					me.distribute_mask=0;

					ttt = cJSON_GetObjectItem(tt,"core_map");
					if(ttt)
					{
						cJSON* pArrayItem = NULL;
						int i,j,k,l,h;
						int nCount,nCount_1;
						int core_no,port_no;
						cJSON* pArrayItem_1 = NULL;
						uint64_t queue_mask;

						nCount = cJSON_GetArraySize ( ttt );
						for( j = 0; j < nCount; j++)
						{
							pArrayItem = cJSON_GetArrayItem(ttt, j);
							if(pArrayItem)
							{
								tttt = cJSON_GetObjectItem(pArrayItem,"core_no");
								if(tttt)
								{
									core_no=tttt->valueint;

									tttt = cJSON_GetObjectItem(pArrayItem,"port_map");
									if(tttt)
									{
										nCount_1 = cJSON_GetArraySize ( tttt );
										for( k = 0; k < nCount_1; k++)
										{
											pArrayItem_1= cJSON_GetArrayItem(tttt, k);
											if(pArrayItem_1)
											{
												ttttt = cJSON_GetObjectItem(pArrayItem_1,"port_no");
												if(ttttt)
												{
													port_no=ttttt->valueint;

													me.port2core_mask_out[port_no]|=(1ULL<<core_no);

													lcore[core_no].port_id[lcore[core_no].port_cnt]=port_no;

													ttttt = cJSON_GetObjectItem(pArrayItem_1,"txport_no");
													if(ttttt)
													{
														lcore[core_no].txport_id[lcore[core_no].port_cnt]=ttttt->valueint;
													}

													ttttt = cJSON_GetObjectItem(pArrayItem_1,"in_q");
													if(ttttt)
													{
														queue_mask=strtoull(ttttt->valuestring,NULL,16);

														lcore[core_no].queue_id[lcore[core_no].port_cnt]=__builtin_ffsll(queue_mask)-1;
													}

													lcore[core_no].port_cnt++;
												}
											}
											EARLY_LOG_DEBUG("core %d port_cnt=%d, port=%d\n",core_no,lcore[core_no].port_cnt, lcore[core_no].port_id[0]);
										}
									}

									lcore[core_no].socket_id=rte_lcore_to_socket_id(core_no);
									lcore[core_no].type=type;
									lcore[core_no].run=funmap[type];

									me.distribute_mask|=(1ULL<<core_no);
									lcore_msk |=(1ULL<<core_no);
								}
							}
						}
					}
				}
#endif

#ifdef __MAIN_LOOP_KNI__
				tt = cJSON_GetObjectItem(t,"pipe_linux");
				if(tt)
					{
					int core_id = 12;

					ttt = cJSON_GetObjectItem(tt,"core_no");
					if(ttt)
						{
						core_id=ttt->valueint;
						lcore[core_id].type=FUN_KNI;
						lcore[core_id].run=funmap[FUN_KNI];
						me.kni_no=core_id;
						lcore_msk |=(1ULL<<core_id);
						}

					ttt = cJSON_GetObjectItem(tt,"port_map");
					if(ttt)
						{
				        cJSON* pArrayItem = NULL;
						int i,j;
				        int nCount;
						int port_no;

						nCount = cJSON_GetArraySize ( ttt );
				        for( j = 0; j < nCount; j++)
				       		{
				            pArrayItem = cJSON_GetArrayItem(ttt, j);
							if(pArrayItem)
								{
								tttt = cJSON_GetObjectItem(pArrayItem,"port_no");
								if(tttt)
									{
									port_no=tttt->valueint;
									ttttt = cJSON_GetObjectItem(pArrayItem,"queue_no");
									if(ttttt)
										{
										lcore[core_id].kni.queue_id[port_no]=ttttt->valueint;
										}
									}

								}
				        	}
						}
					}
#endif

#ifdef PIPE_OUT_LIST_MODE
					{
					tt = cJSON_GetObjectItem(t,"pipe_out");
					if(tt)
						{
						ttt = cJSON_GetObjectItem(tt,"core_map");
						if(ttt)
							{
							cJSON* pArrayItem = NULL;
							int i,j,k,l,h;;
							int nCount,nCount_1;
							int core_no,port_no;
							cJSON* pArrayItem_1 = NULL;
							uint64_t queue_mask;

							me.io_out_mask=0;
							type=FUN_IO_OUT;

							nCount = cJSON_GetArraySize ( ttt );
							for( j = 0; j < nCount; j++)
								{
								pArrayItem = cJSON_GetArrayItem(ttt, j);
								if(pArrayItem)
									{
									tttt = cJSON_GetObjectItem(pArrayItem,"core_no");
									if(tttt)
										{
										core_no=tttt->valueint;

										tttt = cJSON_GetObjectItem(pArrayItem,"port_map");
										if(tttt)
											{
											nCount_1 = cJSON_GetArraySize ( tttt );
											for( k = 0; k < nCount_1; k++)
												{
												pArrayItem_1= cJSON_GetArrayItem(tttt, k);
												if(pArrayItem_1)
													{
													ttttt = cJSON_GetObjectItem(pArrayItem_1,"port_no");
													if(ttttt)
														{
														port_no=ttttt->valueint;
														lcore[core_no].io_out.port_do_pop[lcore[core_no].port_cnt].port_id=port_no;
														lcore[core_no].port_id[lcore[core_no].port_cnt]=port_no;
														me.port2core_mask_out[port_no]|=(1ULL<<core_no);

														ttttt = cJSON_GetObjectItem(pArrayItem_1,"queue_mask");
														if(ttttt)
															{
															queue_mask=strtoull(ttttt->valuestring,NULL,16);

															h=0;
															do
																{
																	l=__builtin_ffsll(queue_mask)-1;
																	queue_mask &= ~(1ULL<<l);
																	lcore[core_no].io_out.port_do_pop[lcore[core_no].port_cnt].port_queue_arr[h++]=l;
															}while(queue_mask);

															lcore[core_no].io_out.port_do_pop[lcore[core_no].port_cnt].port_queue_arr_sz=h;
															}

														lcore[core_no].port_cnt++;
														}
													}
												}
											}


										lcore[core_no].type=type;
										lcore[core_no].run=funmap[type];

										me.io_out_mask|=(1ULL<<core_no);
										lcore_msk |=(1ULL<<core_no);
										}
									}
								}
							}

//						ttt = cJSON_GetObjectItem(tt,"port_map");
//						if(ttt)
//							{
//					        cJSON* pArrayItem = NULL;
//							int i,j;
//					        int nCount;
//							int port_no;

//							nCount = cJSON_GetArraySize ( ttt );
//					        for( j = 0; j < nCount; j++)
//					       		{
//					            pArrayItem = cJSON_GetArrayItem(ttt, j);
//								if(pArrayItem)
//									{
//									tttt = cJSON_GetObjectItem(pArrayItem,"port_no");
//									if(tttt)
//										{
//										port_no=tttt->valueint;
//										ttttt = cJSON_GetObjectItem(pArrayItem,"core_mask");
//										if(ttttt)
//											{
//											uint64_t m=1;
//											uint64_t mask=strtoull(ttttt->valuestring,NULL,16);
//											int queue_cnt=0;

//											me.port2core_mask_out[port_no]=mask;

//											do
//												{
//													i=__builtin_ffsll(mask)-1;
//													mask &= ~(1ULL<<i);
//													lcore[i].port_id[lcore[i].port_cnt]=port_no;
//													lcore[i].type=type;
//													lcore[i].run=funmap[type];
//													lcore[i].port_cnt++;
//													me.io_out_mask|=(1ULL<<i);
//												}while(mask);

//											}
//										}

//									}
//					        	}
//							}
						}
					}
#endif

				tt = cJSON_GetObjectItem(t,"pipe_sum");
				if(tt)
					{
//					ttt = cJSON_GetObjectItem(tt,"mp_type");
//					if(ttt)
//						{
//						if (!strcmp(ttt->valuestring,"socket"))
//							me.sum_mp_type=MP_TYPE_SOCKET;
//						else if(!strcmp(ttt->valuestring,"cores"))
//							me.sum_mp_type=MP_TYPE_CORES;
//						else
//							me.sum_mp_type=MP_TYPE_PERCORE;
//						}

					ttt = cJSON_GetObjectItem(tt,"sum_ippool_cnt");
					if(ttt)
						{
						me.sum_ip_pool_cnt=ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"sum_netportpool_num");
					if(ttt)
						{
						me.sum_netport_pool_cnt=ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"sum_dn1pool_num");
					if(ttt)
						{
						me.sum_dn1_pool_cnt=ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"sum_map");
					if(ttt)
						{
						cJSON* pArrayItem = NULL;
						int i,j;
						int nCount;
						int core_no;

						type=FUN_SUM;
						me.sum_mask=0;
						nCount = cJSON_GetArraySize ( ttt );
						for( j = 0; j < nCount; j++)
							{
							pArrayItem = cJSON_GetArrayItem(ttt, j);
							if(pArrayItem)
								{
								tttt = cJSON_GetObjectItem(pArrayItem,"core_no");
								if(tttt)
									{
									core_no=tttt->valueint;

									ttttt = cJSON_GetObjectItem(pArrayItem,"core_mask");
									if(ttttt)
										{
										uint64_t mask=strtoull(ttttt->valuestring,NULL,16);

										lcore[core_no].type=type;
										lcore[core_no].run=funmap[type];
//										lcore[core_no].sum.sum2io_map=mask;
//										lcore[core_no].sum.sum2io_cnt=__builtin_popcountll(mask);
										me.sum_mask|=(1ULL<<core_no);
										lcore_msk |=(1ULL<<core_no);
										}
									}
								}
							}
						}

					}

				tt = cJSON_GetObjectItem(t,"pipe_gather");
				if(tt)
					{
					ttt = cJSON_GetObjectItem(tt,"timer_dn1pool_num");
					if(ttt)
						{
						me.timer_dn1_pool_cnt=ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"core_map");
					if(ttt)
						{
						cJSON* pArrayItem = NULL;
						int i,j;
						int nCount;
						int core_no;

						type=FUN_TIMER;
						nCount = cJSON_GetArraySize ( ttt );
						for( j = 0; j < nCount; j++)
							{
							pArrayItem = cJSON_GetArrayItem(ttt, j);
							if(pArrayItem)
								{
								tttt = cJSON_GetObjectItem(pArrayItem,"core_no");
								if(tttt)
									{
									core_no=tttt->valueint;

									ttttt = cJSON_GetObjectItem(pArrayItem,"core_mask");
									if(ttttt)
										{
										uint64_t mask=strtoull(ttttt->valuestring,NULL,16);

										lcore[core_no].type=type;
										lcore[core_no].run=funmap[type];
										lcore[core_no].timer.timer_map=mask;
										lcore[core_no].timer.timer_cnt=0;

										lcore_msk |=(1ULL<<core_no);
										}
									}
								}
							}
						}

					}
				else{
					EARLY_LOG_INFO("%s:core for pipe_gather is not configured,please check it\n", __FUNCTION__);
					return MM_FAIL;
				}

//			tt = cJSON_GetObjectItem(t,"pipe_natsum");
//			if(tt)
//			{
//				int core_id;
//				ttt = cJSON_GetObjectItem(tt,"core_no");
//				if(ttt)
//				{
//					core_id = ttt->valueint;
//					lcore[core_id].type = FUN_NAT_LISTSUM;
//					lcore[core_id].run = funmap[FUN_NAT_LISTSUM];
//					EARLY_LOG_INFO("core %d:for natlist\n", core_id);
//				}

//			}
/*
			type=FUN_PCAP;
			me.pcap_mask=0;
			tt = cJSON_GetObjectItem(t,"pipe_pcap");
			if(tt)
				{
				int core_id;

				ttt = cJSON_GetObjectItem(tt,"pcap_pool_cnt");
				if(ttt)
					{
					me.pcap_pool_cnt=ttt->valueint;
					}

				ttt = cJSON_GetObjectItem(tt,"core_no");
				if(ttt)
					{
					core_id=ttt->valueint;
					lcore[core_id].type=type;
					lcore[core_id].run=funmap[type];
					me.pcap_mask=(1ULL<<core_id);
					EARLY_LOG_INFO("core %d:for pcap\n", core_id);
					}
				}
*/
				tt = cJSON_GetObjectItem(t,"pipe_sum_src");
				if(tt)
					{
					ttt = cJSON_GetObjectItem(tt,"dstip_policy_pool");
					if(ttt)
						{
						me.sumsrc_dst_policy_pool_cnt=ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"sum_srcippool_cnt");
					if(ttt)
						{
						me.sum_srcip_pool_cnt=ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"msg_pool_cnt");
					if(ttt)
						{
						me.msg_srcsum2io_pool_cnt=ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"core_map");
					if(ttt)
						{
						cJSON* pArrayItem = NULL;
						int i,j;
						int nCount;
						int core_no;

						type=FUN_SUM_SRC;
						me.sum_src_mask=0;
						nCount = cJSON_GetArraySize ( ttt );
						for( j = 0; j < nCount; j++)
							{
							pArrayItem = cJSON_GetArrayItem(ttt, j);
							if(pArrayItem)
								{
								tttt = cJSON_GetObjectItem(pArrayItem,"core_no");
								if(tttt)
									{
									core_no=tttt->valueint;

									ttttt = cJSON_GetObjectItem(pArrayItem,"core_mask");
									if(ttttt)
										{
										uint64_t mask=strtoull(ttttt->valuestring,NULL,16);

										lcore[core_no].type=type;
										lcore[core_no].run=funmap[type];
//										lcore[core_no].sum.sum2io_map=mask;
//										lcore[core_no].sum.sum2io_cnt=__builtin_popcountll(mask);
										me.sum_src_mask|=(1ULL<<core_no);
										lcore_msk |=(1ULL<<core_no);
										}
									}
								}
							}
						}

					}
//			tt = cJSON_GetObjectItem(t,"pipe_natsum2");
//			if(tt)
//			{
//				int core_id;
//				ttt = cJSON_GetObjectItem(tt,"core_no");
//				if(ttt)
//				{
//					core_id = ttt->valueint;
//					me.natsum2_mask|=(1ULL<<core_id);
//					lcore[core_id].type = FUN_NAT_LISTSUM2;
//					lcore[core_id].run = funmap[FUN_NAT_LISTSUM2];
//					EARLY_LOG_INFO("core %d:for natlistsum2\n", core_id);
//				}

//			}

//			tt = cJSON_GetObjectItem(t,"pipe_natfresh");
//			if(tt)
//			{
//				int core_id;
//				ttt = cJSON_GetObjectItem(tt,"core_no");
//				if(ttt)
//				{
//					core_id = ttt->valueint;
//					lcore[core_id].type = FUN_NAT_LISTFRESH;
//					lcore[core_id].run = funmap[FUN_NAT_LISTFRESH];
//					EARLY_LOG_INFO("core %d:for natlistfresh\n", core_id);
//				}
//				ttt = cJSON_GetObjectItem(tt,"deadtime");
//				if(ttt)
//				{
//					me.natconfig.deadtime= ttt->valueint;
//					EARLY_LOG_INFO("natlistfresh deadtime=%d\n", me.natconfig.deadtime);
//				}else{
//					me.natconfig.deadtime= 10;
//				}

//			}


			cjson_parse_kafka(t);

#if 1
{
				int k;


				for(k=0;k<MAX_DEV;k++)
					{
					EARLY_LOG_INFO("port %d inmask=%llx outmask=%llx\n",k,
						me.port2core_mask_in[k],me.port2core_mask_out[k]);
					}

				for(k=0;k<MAX_CPU;k++)
					{
					if(lcore[k].type!=FUN_NULL)
						{
						EARLY_LOG_INFO("lcore[%d] type=%d %p\n",
							k,lcore[k].type,lcore[k].run);

						/*
						int h;

						for(h=0;h<lcore[k].port_cnt;h++)
							{
							EARLY_LOG_INFO("lcore[%d] port %d queue %d type=%d\n",
								k,lcore[k].port_id[h],lcore[k].queue_id[h],lcore[k].type);
							}
							*/
						}
					}
}
#endif
				}

			if (lcore_msk != lcore_msk_cfg){
				EARLY_LOG_INFO("EEEEEEEEEEEEEEE lcore_mask=%#x cfg lcore mask:%#x\n",lcore_msk,lcore_msk_cfg);
				return MM_FAIL;
			}

		}
	else
	{
		t = cJSON_GetObjectItem(pJson,"debug");
		if(t)
		{
			tt = cJSON_GetObjectItem(t,"hwlog");
			if(tt)
				{
				if (!strcmp(tt->valuestring,"off"))
					hw_log_off=1;
				else
					hw_log_off=0;
				}

			tt = cJSON_GetObjectItem(t,"monlog");
			if(tt)
				{
				if (!strcmp(tt->valuestring,"off"))
					mon_log_off=1;
				else
					mon_log_off=0;
				}

			tt = cJSON_GetObjectItem(t,"monitor_vip");
		        if(tt)
			{
			        struct in_addr ip;
        			if(inet_aton(tt->valuestring,&ip))
        			{
        				me.mon_vip = rte_be_to_cpu_32(ip.s_addr);
        				EARLY_LOG_INFO("mon_ip=0x%x\n",me.mon_vip);
        			}
        			else
        			{
        			        me.mon_vip = 0;
        				EARLY_LOG_ERROR("mon_ip intput error,please check it!=>%s\n",tt->valuestring);
        			}
			}else{
			    me.mon_vip = 0;
			}

			tt = cJSON_GetObjectItem(t,"log_level");
			if(tt)
			{
				running_log_level = (LogLevel)tt->valueint;
				EARLY_LOG_INFO("log_level = %d\n", tt->valueint);
				printf("WD_NAT:log_level = %d\n", tt->valueint);

//				//test
//				int port_id=tt->valueint;
//				/* Stop device */
//				rte_eth_dev_stop(port_id);

//				printf("%s : stop port %d ...\n",__FUNCTION__,(unsigned)port_id);
//				RUNNING_LOG_ERROR("%s : stop port %d ...\n",__FUNCTION__,(unsigned)port_id);
			}else{
				running_log_level=LOG_LEVEL_INFO;
			}
//			tt = cJSON_GetObjectItem(t,"do_pcap");
//			if(tt)
//			{
//				if (!strcmp(tt->valuestring,"on")) {
//					do_pcap_flag=1;
//				} else {
//					do_pcap_flag=0;
//				}
//			}

		}

		t = cJSON_GetObjectItem(pJson,"nat_config");
		if(t)
		{
			tt = cJSON_GetObjectItem(t,"remoteconfig_addr");
			if(tt)
			{
				strncpy(me.natconfig.addr, tt->valuestring, NAT_API_LEN);
				me.natconfig.addr[NAT_API_LEN-1] = 0;
			}else{
				strcpy(me.natconfig.addr, "192.168.50.118");
			}

			tt = cJSON_GetObjectItem(t,"remoteconfig_port");
			if(tt)
			{
				me.natconfig.port = tt->valueint;
			}else{
				me.natconfig.port = 8080;
			}

			tt = cJSON_GetObjectItem(t,"remoteconfig_usrname");
			if(tt)
			{
				strncpy(me.natconfig.usrname, tt->valuestring, sizeof(me.natconfig.usrname));
				me.natconfig.usrname[NAT_API_LEN-1] = 0;
			}else{
				strcpy(me.natconfig.usrname, "admin");
			}
			tt = cJSON_GetObjectItem(t,"remoteconfig_password");
			if(tt)
			{
				strncpy(me.natconfig.password, tt->valuestring, sizeof(me.natconfig.password));
				me.natconfig.password[NAT_API_LEN-1] = 0;
			}else{
				strcpy(me.natconfig.password, "admin");
			}
                        tt = cJSON_GetObjectItem(t,"config_region_tag");
			if(tt)
			{
				strncpy(me.natconfig.region_tag, tt->valuestring, sizeof(me.natconfig.region_tag));
				me.natconfig.region_tag[NAT_API_LEN/2-1] = 0;
			}else{
				strcpy(me.natconfig.region_tag, "dg");
			}

                        tt = cJSON_GetObjectItem(t,"config_pool_tag");
			if(tt)
			{
				strncpy(me.natconfig.pool_tag, tt->valuestring, sizeof(me.natconfig.pool_tag));
				me.natconfig.pool_tag[NAT_API_LEN/2-1] = 0;
			}else{
				strcpy(me.natconfig.pool_tag, "default");
			}
			EARLY_LOG_INFO("region is %s,pool is %s\n", me.natconfig.region_tag, me.natconfig.pool_tag);
			tt = cJSON_GetObjectItem(t,"natconfig_ver");
			if(tt)
			{
				strncpy(me.natconfig.natconfig_ver, tt->valuestring, sizeof(me.natconfig.natconfig_ver));
				me.natconfig.natconfig_ver[NAT_API_LEN-1] = 0;
			}else{
				strcpy(me.natconfig.natconfig_ver, DEFAULT_NATCONFIG_VER_PATH);
			}
			tt = cJSON_GetObjectItem(t,"natconfig");
			if(tt)
			{
				strncpy(me.natconfig.natconfig, tt->valuestring, sizeof(me.natconfig.natconfig));
				me.natconfig.natconfig[NAT_API_LEN-1] = 0;
			}else{
				strcpy(me.natconfig.natconfig, DEFAULT_NATCONFIG_PATH);
			}
			tt = cJSON_GetObjectItem(t,"bandwidth_ver");
			if(tt)
			{
				strncpy(me.natconfig.bandwidth_ver, tt->valuestring, sizeof(me.natconfig.bandwidth_ver));
				me.natconfig.bandwidth_ver[NAT_API_LEN-1] = 0;
			}else{
				strcpy(me.natconfig.bandwidth_ver, DEFAULT_BANDWIDTH_VER_PATH);
			}
			tt = cJSON_GetObjectItem(t,"bandwidth");
			if(tt)
			{
				strncpy(me.natconfig.bandwidth, tt->valuestring, sizeof(me.natconfig.bandwidth));
				me.natconfig.bandwidth[NAT_API_LEN-1] = 0;
			}else{
				strcpy(me.natconfig.bandwidth, DEFAULT_BANDWIDTH_PATH);
			}
			tt = cJSON_GetObjectItem(t,"rip_linkstatus");
			if(tt)
			{
				strncpy(me.natconfig.rip_linkstatus, tt->valuestring, sizeof(me.natconfig.rip_linkstatus));
				me.natconfig.rip_linkstatus[NAT_API_LEN-1] = 0;
			}else{
				strcpy(me.natconfig.rip_linkstatus, DEFAULT_RIP_LINKSTAT_PATH);
			}
		}
	}

	me.flag|=FLAG_CONFIGED;

conf_out:
	cJSON_Delete(pJson);

	free(buffer_ptr);

	return ret;
}

#if 0
int parser_natconfig(char *name)
{
	int r, len;
	cJSON *t,*tt;
	struct stat buf;
	cJSON * pJson;
	FILE *fp;
	char *buffer_ptr;
	int ret=MM_SUCCESS;
	struct in_addr addr;
	struct nat_item tmp_nattable[MAX_NAT_RULENUM] = {0};
	struct nonat_item tmp_nonattable[MAX_NAT_RULENUM] = {0};

	r=stat(name, &buf);
	if((r) || !(buf.st_mode & S_IFREG))
	{
		EARLY_LOG_INFO("%s:stat file %s fail\n",__FUNCTION__,name);
		return MM_FAIL;
	}

	if((fp = fopen(name, "r")) == NULL)
	{
       		EARLY_LOG_INFO("Failed to fopen '%s', err=%s\n", name, strerror(errno));
		return MM_FAIL;
	}

	if((buffer_ptr = malloc(buf.st_size)) == NULL)
	{
        	fclose(fp);
        	return MM_FAIL;
    	}

	if((len = fread(buffer_ptr, 1, buf.st_size, fp)) != buf.st_size)
	{
	        free(buffer_ptr);
	        fclose(fp);
	        return MM_FAIL;
    	}

	fclose(fp);

	pJson = cJSON_Parse(buffer_ptr);
	if(pJson == NULL)
	{
		EARLY_LOG_ERROR("%s : cJSON_Parse file %s fail\n",__FUNCTION__,name);
		return MM_FAIL;
	}

	t = cJSON_GetObjectItem(pJson,"dnat");
	if( t )
	{
	        cJSON* pArrayItem = NULL;
		int i, nCount;

		nCount = cJSON_GetArraySize ( t );
		EARLY_LOG_INFO("%s:%d dnat items\n", __FUNCTION__, nCount);

	        for( i = 0; i < nCount; i++)
	       	{
	         	pArrayItem = cJSON_GetArrayItem(t, i);
			if(pArrayItem)
			{
				tt = cJSON_GetObjectItem(pArrayItem, "protocol");
				if(tt)
				{
					tmp_nattable[i].proto= tt->valueint;
				}

				tt = cJSON_GetObjectItem(pArrayItem, "src_minip");
				if(tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_nattable[i].src_minip = rte_be_to_cpu_32(addr.s_addr);
				}

				tt = cJSON_GetObjectItem(pArrayItem, "src_maxip");
				if(tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_nattable[i].src_maxip = rte_be_to_cpu_32(addr.s_addr);
					if (tmp_nattable[i].src_maxip == 0)
						tmp_nattable[i].src_maxip = 0xffffffff;
				}

				tt = cJSON_GetObjectItem(pArrayItem, "src_minport");
				if(tt && (tt->valueint >= 0) && (tt->valueint <= 65535))
				{
					tmp_nattable[i].src_minport = tt->valueint;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"src_maxport");
				if(tt)
				{
					tmp_nattable[i].src_maxport = tt->valueint;
					if (tt->valueint <= 0 || tt->valueint > 65535)
						tmp_nattable[i].src_maxport = 65536;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"dst_minip");
				if(tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_nattable[i].dst_minip = rte_be_to_cpu_32(addr.s_addr);
				}

				tt = cJSON_GetObjectItem(pArrayItem,"dst_maxip");
				if(tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_nattable[i].dst_maxip = rte_be_to_cpu_32(addr.s_addr);
					if (tmp_nattable[i].dst_maxip == 0)
						tmp_nattable[i].dst_maxip = 0xffffffff;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"dst_minport");
				if(tt && (tt->valueint >= 0) && (tt->valueint <= 65535))
				{
					tmp_nattable[i].dst_minport = tt->valueint;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"dst_maxport");
				if(tt)
				{
					tmp_nattable[i].dst_maxport = tt->valueint;
					if (tt->valueint <= 0 || tt->valueint > 65535)
						tmp_nattable[i].dst_maxport = 65535;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"nat_minip");
				if(tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_nattable[i].nat_minip = rte_be_to_cpu_32(addr.s_addr);
				}

				tt = cJSON_GetObjectItem(pArrayItem,"nat_maxip");
				if(tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_nattable[i].nat_maxip = rte_be_to_cpu_32(addr.s_addr);
					if (tmp_nattable[i].nat_maxip == 0)
						tmp_nattable[i].nat_maxip = 0xffffffff;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"nat_minport");
				if(tt && (tt->valueint > 0) && (tt->valueint <= 65535))
				{
					tmp_nattable[i].nat_minport = tt->valueint;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"nat_maxport");
				if(tt)
				{
					tmp_nattable[i].nat_maxport = tt->valueint;
					if (tt->valueint <= 0 || tt->valueint > 65535)
						tmp_nattable[i].nat_maxport = 65535;
				}

			}
	        }

		memcpy(dnat_table,  &tmp_nattable, sizeof(tmp_nattable[0]) * nCount);
		rte_smp_wmb();
	}

	t = cJSON_GetObjectItem(pJson,"snat");
	if( t )
	{
	        cJSON* pArrayItem = NULL;
		int i, nCount;

		memset(tmp_nattable, 0, sizeof(tmp_nattable[0]) * MAX_NAT_RULENUM);

		nCount = cJSON_GetArraySize ( t );
		EARLY_LOG_INFO("%s:%d snat items\n", __FUNCTION__, nCount);

	        for( i = 0; i < nCount; i++)
	       	{
	         	pArrayItem = cJSON_GetArrayItem(t, i);
			if(pArrayItem)
			{
				tt = cJSON_GetObjectItem(pArrayItem, "protocol");
				if(tt)
				{
					tmp_nattable[i].proto= tt->valueint;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"src_minip");
				if(tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_nattable[i].src_minip = addr.s_addr;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"src_maxip");
				if(tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_nattable[i].src_maxip = addr.s_addr;
					if (tmp_nattable[i].src_maxip == 0)
						tmp_nattable[i].src_maxip = 0xffffffff;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"src_minport");
				if(tt && (tt->valueint > 0) && (tt->valueint < 65536))
				{
					tmp_nattable[i].src_minport = tt->valueint;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"src_maxport");
				if(tt)
				{
					tmp_nattable[i].src_maxport = tt->valueint;
					if (tt->valueint <= 0 || tt->valueint > 65535)
						tmp_nattable[i].src_maxport = 65535;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"dst_minip");
				if(tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_nattable[i].dst_minip = addr.s_addr;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"dst_maxip");
				if(tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_nattable[i].dst_maxip = addr.s_addr;
					if (tmp_nattable[i].dst_maxip == 0)
						tmp_nattable[i].dst_maxip = 0xffffffff;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"dst_minport");
				if(tt && (tt->valueint > 0) && (tt->valueint < 65536))
				{
					tmp_nattable[i].dst_minport = tt->valueint;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"dst_maxport");
				if(tt)
				{
					tmp_nattable[i].dst_maxport = tt->valueint;
					if (tt->valueint <= 0 || tt->valueint > 65535)
						tmp_nattable[i].dst_maxport = 65535;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"nat_minip");
				if(tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_nattable[i].nat_minip = addr.s_addr;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"nat_maxip");
				if(tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_nattable[i].nat_maxip = addr.s_addr;
					if (tmp_nattable[i].nat_maxip == 0)
						tmp_nattable[i].nat_maxip = 0xffffffff;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"nat_minport");
				if(tt && (tt->valueint > 0) && (tt->valueint < 65536))
				{
					tmp_nattable[i].nat_minport = tt->valueint;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"nat_maxport");
				if(tt)
				{
					tmp_nattable[i].nat_maxport = tt->valueint;
					if (tt->valueint <= 0 || tt->valueint > 65535)
						tmp_nattable[i].nat_maxport = 65535;
				}

			}
	        }
		memcpy(snat_table,  &tmp_nattable, sizeof(tmp_nattable[0]) * nCount);
		rte_smp_wmb();
	}

	t = cJSON_GetObjectItem(pJson,"nonat");
	if( t )
	{
	        cJSON* pArrayItem = NULL;
		int i, nCount;

		memset(tmp_nonattable, 0, sizeof(tmp_nonattable[0]) * MAX_NAT_RULENUM);

		nCount = cJSON_GetArraySize ( t );
		EARLY_LOG_INFO("%s:%d nonat items\n", __FUNCTION__, nCount);

	        for( i = 0; i < nCount; i++)
	       	{
	         	pArrayItem = cJSON_GetArrayItem(t, i);
			if(pArrayItem)
			{
				tt = cJSON_GetObjectItem(pArrayItem, "protocol");
				if(tt)
				{
					tmp_nattable[i].proto= tt->valueint;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"src_minip");
				if(tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_nonattable[i].src_minip = addr.s_addr;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"src_maxip");
				if(tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_nonattable[i].src_maxip = addr.s_addr;
					if (tmp_nattable[i].src_maxip == 0)
						tmp_nattable[i].src_maxip = 0xffffffff;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"src_minport");
				if(tt && (tt->valueint > 0) && (tt->valueint < 65536))
				{
					tmp_nonattable[i].src_minport = tt->valueint;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"src_maxport");
				if(tt)
				{
					tmp_nonattable[i].src_maxport = tt->valueint;
					if (tt->valueint <= 0 || tt->valueint > 65535)
						tmp_nonattable[i].src_maxport = 65535;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"dst_minip");
				if(tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_nonattable[i].dst_minip = addr.s_addr;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"dst_maxip");
				if(tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_nonattable[i].dst_maxip = addr.s_addr;
					if (tmp_nattable[i].dst_maxip == 0)
						tmp_nattable[i].dst_maxip = 0xffffffff;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"dst_minport");
				if(tt && (tt->valueint > 0) && (tt->valueint < 65536))
				{
					tmp_nonattable[i].dst_minport = tt->valueint;
				}

				tt = cJSON_GetObjectItem(pArrayItem,"dst_maxport");
				if(tt)
				{
					tmp_nonattable[i].dst_maxport = tt->valueint;
					if (tt->valueint <= 0 || tt->valueint > 65535)
						tmp_nonattable[i].dst_maxport = 65535;
				}

			}
	        }
		memcpy(nonat_table,  &tmp_nonattable, sizeof(tmp_nonattable[0]) * nCount);
		rte_smp_wmb();
	}

	cJSON_Delete(pJson);
	free(buffer_ptr);

	return ret;
}
#endif
int nat_is_local_vip(uint32_t ip,struct snat_item *snattable)
{
        int i;
	for( i = 0; i < NAT_MAX_DSTNUM; i++)
	{
		if (0 != snattable[i].dst_ip)
		{
			if(ip == snattable[i].dst_ip)
			{
				return i;
			}

		}else{
			break;
		}
	}

//	RUNNING_LOG_DEBUG("core %d :%s ip 0x%x is not local vip!\n",rte_lcore_id(), __FUNCTION__,ip);

	return 0xFFFF;
}

int parser_snatconfig(char *name)
{
	int r, len;
	cJSON *t,*tt, *ttt;
	struct stat buf;
	cJSON * pJson;
	FILE *fp;
	char *buffer_ptr;
	char *p;
	int ret=MM_SUCCESS;
	struct in_addr addr;
//	struct snat_item tmp_snattable[NAT_MAX_DSTNUM] = {0};
	struct snat_item *tmp_snattable;

	tmp_snattable = (struct snat_item *)malloc(sizeof(struct snat_item) * NAT_MAX_DSTNUM);
	if (!tmp_snattable)
	{
		EARLY_LOG_ERROR("%s: Failed to malloc snat_item '%s', err=%s\n", __FUNCTION__, name, strerror(errno));
		return -1;
	}
	memset(tmp_snattable, 0, sizeof(struct snat_item) * NAT_MAX_DSTNUM);

	r=stat(name, &buf);
	if((r) || !(buf.st_mode & S_IFREG))
	{
		EARLY_LOG_INFO("%s:stat file %s fail\n",__FUNCTION__,name);
		return MM_FAIL;
	}

	if((fp = fopen(name, "r")) == NULL)
	{
       		EARLY_LOG_INFO("Failed to fopen '%s', err=%s\n", name, strerror(errno));
		return MM_FAIL;
	}

	if((buffer_ptr = malloc(buf.st_size)) == NULL)
	{
        	fclose(fp);
        	return MM_FAIL;
    	}

	if((len = fread(buffer_ptr, 1, buf.st_size, fp)) != buf.st_size)
	{
	        free(buffer_ptr);
	        fclose(fp);
	        return MM_FAIL;
    	}

	fclose(fp);

	pJson = cJSON_Parse(buffer_ptr);
	if(pJson == NULL)
	{
		EARLY_LOG_ERROR("%s : cJSON_Parse file %s fail\n",__FUNCTION__,name);
		return MM_FAIL;
	}

	t = cJSON_GetObjectItem(pJson,"snat");
	if( t )
	{
	    cJSON* pArrayItem = NULL;
		cJSON* pArrayItem_1 = NULL;
		int i, j, k, nCount,nCount_1;
		char *p = NULL;

		nCount = cJSON_GetArraySize ( t );
		EARLY_LOG_INFO("%s:%d snat items, snatconfig_curr=%d\n", __FUNCTION__, nCount, snatconfig_curr);

	        for( i = 0; i < nCount; i++)
	       	{
	       		if(i >= NAT_MAX_DSTNUM)
				break;
	         	pArrayItem = cJSON_GetArrayItem(t, i);
			if(pArrayItem)
			{
				tt = cJSON_GetObjectItem(pArrayItem, "dst_ip");
				if(tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_snattable[i].dst_ip = rte_be_to_cpu_32(addr.s_addr);
				}
				else{
					EARLY_LOG_INFO("%s: the %dth snat_config wrong\n", __FUNCTION__, i);
					continue;
				}

//				EARLY_LOG_INFO("%s: the %dth snat_config ip:%u.%u.%u.%u\n", __FUNCTION__, i,
//						tmp_snattable[i].dst_ip>>24, (tmp_snattable[i].dst_ip>>16)&0xff,
//						(tmp_snattable[i].dst_ip>>8)&0xff,(tmp_snattable[i].dst_ip)&0xff);

				tt = cJSON_GetObjectItem(pArrayItem, "dead_time");
				if(tt && (tt->type == cJSON_Number) && (tt->valueint > 0) && (tt->valueint < 65536))
				{
					tmp_snattable[i].vip_deadtime = tt->valueint;
				}else{
					tmp_snattable[i].vip_deadtime = me.natconfig.deadtime;  // default
				}

				tt = cJSON_GetObjectItem(pArrayItem,"snat_map");
				if(tt)
				{
					k = 0;
					p = strtok(tt->valuestring, ", ");
					do
					{
						if (p != NULL && inet_aton(p, &addr)){
							tmp_snattable[i].snat_ip[k] = rte_be_to_cpu_32(addr.s_addr);

//							EARLY_LOG_INFO("%s: the %dth snat_config sip:%u.%u.%u.%u\n", __FUNCTION__, i,
//								tmp_snattable[i].snat_ip[k]>>24, (tmp_snattable[i].snat_ip[k]>>16)&0xff,
//								(tmp_snattable[i].snat_ip[k]>>8)&0xff,(tmp_snattable[i].snat_ip[k])&0xff);

							k++;

						}
						p = strtok(NULL, ", ");
					}while(p != NULL && k < NAT_MAX_SIPNUM);
					tmp_snattable[i].sip_num = (uint32_t)k;
				}

			}
	        }

		if (snatconfig_curr)
			p = (char*) &stable[0];
		else
			p = (char*) &stable[NAT_MAX_DSTNUM];

//		rte_memcpy(p, &tmp_snattable, sizeof(tmp_snattable[0]) * NAT_MAX_DSTNUM);
		rte_memcpy(p, tmp_snattable, sizeof(struct snat_item) * NAT_MAX_DSTNUM);

		snatconfig_curr^=1;

		rte_smp_wmb();
		EARLY_LOG_INFO("%s:%d snat dstip, snatconfig_curr=%d\n", __FUNCTION__, nCount, snatconfig_curr);
	}

	cJSON_Delete(pJson);
	free(buffer_ptr);
	if (tmp_snattable)
	{
		free(tmp_snattable);
		tmp_snattable=NULL;
	}

	return ret;
}

int parser_dnatconfig(char *name)
{
	int r, len;
	cJSON *t,*tt, *ttt;
	struct stat buf;
	cJSON * pJson;
	FILE *fp;
	char *buffer_ptr;
	char *p;
	int ret=MM_SUCCESS;
	int ret_idx;
	struct in_addr addr;

//	struct dnat_item tmp_dnattable[NAT_MAX_DSTNUM] = {0};
//	struct snat_item local_stable[NAT_MAX_DSTNUM] = {0};

	struct dnat_item *tmp_dnattable;
	struct snat_item *local_stable;


	tmp_dnattable = (struct dnat_item *)malloc(NAT_MAX_DSTNUM * sizeof(struct dnat_item));
	if (!tmp_dnattable)
	{
		EARLY_LOG_INFO("%s: Failed to malloc dnat_item '%s', err=%s\n", __FUNCTION__, name, strerror(errno));
		return -1;
	}

//	if (snatconfig_curr)
//		rte_memcpy(&local_stable, &stable[NAT_MAX_DSTNUM], sizeof(local_stable[0]) * NAT_MAX_DSTNUM);
//	else
//		rte_memcpy(&local_stable, &stable[0], sizeof(local_stable[0]) * NAT_MAX_DSTNUM);
	if (snatconfig_curr)
		local_stable = &stable[NAT_MAX_DSTNUM];
	else
		local_stable = &stable[0];

	memset(tmp_dnattable, 0, sizeof(struct dnat_item) * NAT_MAX_DSTNUM);

	r=stat(name, &buf);
	if((r) || !(buf.st_mode & S_IFREG))
	{
		EARLY_LOG_INFO("%s:stat file %s fail\n",__FUNCTION__,name);
		return MM_FAIL;
	}

	if((fp = fopen(name, "r")) == NULL)
	{
       		EARLY_LOG_INFO("Failed to fopen '%s', err=%s\n", name, strerror(errno));
			if (tmp_dnattable){
				free(tmp_dnattable);
				tmp_dnattable = NULL;
			}
		return MM_FAIL;
	}

	if((buffer_ptr = malloc(buf.st_size)) == NULL)
	{
        	fclose(fp);
			if (tmp_dnattable){
				free(tmp_dnattable);
				tmp_dnattable = NULL;
			}
        	return MM_FAIL;
    	}

	if((len = fread(buffer_ptr, 1, buf.st_size, fp)) != buf.st_size)
	{
	        free(buffer_ptr);
	        fclose(fp);
			if (tmp_dnattable){
				free(tmp_dnattable);
				tmp_dnattable = NULL;
			}
	        return MM_FAIL;
    	}

	fclose(fp);

	pJson = cJSON_Parse(buffer_ptr);
	if(pJson == NULL)
	{
		EARLY_LOG_ERROR("%s : cJSON_Parse file %s fail\n",__FUNCTION__,name);
		if (tmp_dnattable){
				free(tmp_dnattable);
				tmp_dnattable = NULL;
			}
		return MM_FAIL;
	}

	t = cJSON_GetObjectItem(pJson,"dnat");
	if( t )
	{
	        cJSON* pArrayItem = NULL;
		cJSON* pArrayItem_1 = NULL;
		int i, j, k, m,nCount,nCount_1;
		char *p = NULL;
		uint32_t tmp_ip;

		nCount = cJSON_GetArraySize ( t );
		EARLY_LOG_INFO("%s:%d dnat items dnatconfig_curr=%d\n", __FUNCTION__, nCount, dnatconfig_curr);
		memset(rip_linkstate, 0, sizeof(rip_linkstate[0][0])*(NAT_MAX_DSTNUM)*NAT_MAX_RULENUM);

	        for( i = 0; i < nCount; i++)
	       	{
	       		if(i >= NAT_MAX_DSTNUM)
				break;
	         	pArrayItem = cJSON_GetArrayItem(t, i);
			if(pArrayItem)
			{
				tt = cJSON_GetObjectItem(pArrayItem, "dst_ip");
				if(tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_ip = rte_be_to_cpu_32(addr.s_addr);

					ret_idx = nat_is_local_vip(tmp_ip, local_stable);
					if (0xffff == ret_idx ) //is not local vip
					{
						EARLY_LOG_INFO("%s:can not find vip 0x%x in snat_config, please check it\n", __FUNCTION__, tmp_ip);
						continue;
					}
					tmp_dnattable[i].dst_ip = tmp_ip;
					tmp_dnattable[i].dstip_idx = ret_idx;
				}
				else{
					continue;
				}
				tt = cJSON_GetObjectItem(pArrayItem,"port_map");
				if(tt)
				{
					nCount_1 = cJSON_GetArraySize ( tt );
//					for(m=nCount_1; m<NAT_MAX_RULENUM; m++)
//						rip_linkstate[i][m] = 0;
					for( j = 0; j < nCount_1; j++)
					{
						if(j >= NAT_MAX_RULENUM)
							break;
						pArrayItem_1= cJSON_GetArrayItem(tt, j);
						if(pArrayItem_1)
						{
							ttt = cJSON_GetObjectItem(pArrayItem_1, "protocol");
							if(ttt && (ttt->type == cJSON_Number))
							{
								tmp_dnattable[i].rule[j].proto = ttt->valueint;
							}

							ttt = cJSON_GetObjectItem(pArrayItem_1,"src_sel_alg");
							if (ttt && (ttt->type == cJSON_String))
							{
								EARLY_LOG_DEBUG("%s:source station select algorithm %s\n", __FUNCTION__, ttt->valuestring);

								if (!strcmp(ttt->valuestring,"dsh")) {
									tmp_dnattable[i].fwd_realip_mode = REALIP_SEL_DSH;
								} else if (!strcmp(ttt->valuestring,"rr")) {
									tmp_dnattable[i].fwd_realip_mode = REALIP_SEL_RR;
								}  else if (!strcmp(ttt->valuestring,"wrr")) {
									tmp_dnattable[i].fwd_realip_mode = REALIP_SEL_WRR;
								} else {
									tmp_dnattable[i].fwd_realip_mode = REALIP_SEL_DEF;
								}
							} else {
								tmp_dnattable[i].fwd_realip_mode = REALIP_SEL_DEF;
							}

							ttt = cJSON_GetObjectItem(pArrayItem_1,"dst_port");
							if(ttt && (ttt->type == cJSON_Number) && ttt->valueint >= 0 && ttt->valueint <= 65535)
							{
								tmp_dnattable[i].rule[j].dst_port= ttt->valueint;
							}

							ttt = cJSON_GetObjectItem(pArrayItem_1,"nat_port");
							if(ttt && (ttt->type == cJSON_Number) && ttt->valueint >= 0 && ttt->valueint <= 65535)
							{
								tmp_dnattable[i].rule[j].nat_port= ttt->valueint;
							}

							ttt = cJSON_GetObjectItem(pArrayItem_1,"nat_ip");
							if(ttt)
							{
								k = 0;
								p = strtok(ttt->valuestring, ", ");
								do
								{
									if (p != NULL && inet_aton(p, &addr)){
										tmp_dnattable[i].rule[j].nat_debouncing[k] = NAT_DEBOUNCING_TIMER_DEF;

										tmp_dnattable[i].rule[j].nat_ip[k++] = rte_be_to_cpu_32(addr.s_addr);
										rip_linkstate[ret_idx][j] |= (1ULL<<(k-1));
									}
									p = strtok(NULL, ", ");
								}while(p != NULL && k < NAT_MAX_NATIPNUM);

								tmp_dnattable[i].rule[j].rip_sum=k;

								for(m=k; m<NAT_MAX_NATIPNUM; m++)
									rip_linkstate[ret_idx][j] &= ~(1ULL<<m);
							}
						}

					}
				}

			}
	        }

		if (dnatconfig_curr)
			p = (char*) &dtable[0];
		else
			p = (char*) &dtable[NAT_MAX_DSTNUM];

//		rte_memcpy(p, &tmp_dnattable, sizeof(tmp_dnattable[0]) * NAT_MAX_DSTNUM);
		rte_memcpy(p, tmp_dnattable, sizeof(struct dnat_item) * NAT_MAX_DSTNUM);

		dnatconfig_curr^=1;

		rte_smp_wmb();
		EARLY_LOG_INFO("%s:find %d dnat dstip, dnatconfig_curr=%d\n", __FUNCTION__, nCount,dnatconfig_curr);
	}

	cJSON_Delete(pJson);
	free(buffer_ptr);

	if (tmp_dnattable){
		free(tmp_dnattable);
		tmp_dnattable = NULL;
	}

	return ret;
}
void *conf_thread(void *args)
{
	int i,r,rv;
	struct stat buf;
	struct timeval now;
	struct timespec outtime;

	while(!term_pending)
	{
		gettimeofday(&now, NULL);
		outtime.tv_sec = now.tv_sec + CONF_TIMEOUT;
		outtime.tv_nsec = now.tv_usec * 1000;

//		printf("%s: Ready to wait for condition...\n", __FUNCTION__);
		pthread_mutex_lock(&conf_mutex);
        rv = pthread_cond_timedwait(&conf_cond, &conf_mutex, &outtime);
		pthread_mutex_unlock(&conf_mutex);
		if(rv==EINTR)
			{
			RUNNING_LOG_DEBUG("%s : get interrupt for conf_cond\n",__FUNCTION__);
			continue;
			}

		for(i=0;i<sizeof(file_mon)/sizeof(file_mon[0]);i++)
			{
				r=stat(file_mon[i].name, &buf);
				if(r==0){
					r = buf.st_mode & S_IFREG;
					if((r == S_IFREG)&&(buf.st_mtime!=file_mon[i].lasttime))
						{
						RUNNING_LOG_DEBUG("%s : file %s change old mtime=%ld new mtime=%ld size=%d old_version=%u\n",
							__FUNCTION__,file_mon[i].name,file_mon[i].lasttime,buf.st_mtime,buf.st_size,file_mon[i].version);

						file_mon[i].lasttime=buf.st_mtime;
						if(file_mon[i].parser)
							file_mon[i].parser(file_mon[i].name);
						}
					}
			}

		#if 0
        switch(rv) {
        case ETIMEDOUT:
                /* Handle timeout */
        case EINTR:
                /* Interupted by signal */
        case EBUSY:
        default:
                /* Handle errors */
        case 0:
                /* condition received a condition signal */
        }
		#endif


	}

	RUNNING_LOG_INFO("%s : conf thread exit now\n",__FUNCTION__);

}

int check_module(char *m,char *full,int mode)
{
	char cbuf[PATH_MAX];
	struct stat buf;
	int r;
	FILE *fp;

	if(mode)
		sprintf(cbuf, "modprobe %s",m);
	else
		{
		stat(full, &buf);
		r = buf.st_mode & S_IFREG;
		if(r != S_IFREG)
			{
			EARLY_LOG_ERROR("err type for modules %s\n",full);
			return MM_FAIL;
			}

		sprintf(cbuf, "insmod %s",full);
		}

	system(cbuf);

	r=MM_FAIL;
	if((fp=fopen("/proc/modules","r"))!=NULL)
		{
		cbuf[0]=0;
		while (!feof(fp))
			{
				fgets(cbuf, sizeof(cbuf), fp);
				if(!strncmp(cbuf, m, strlen(m)))
					{
					EARLY_LOG_DEBUG("found modules %s\n",m);
					r=MM_SUCCESS;
					break;
					}
			}

		fclose(fp);
		}

	return r;
}

struct aa{
	struct slist_head list;
	int no;
};

#ifdef WF_NAT

#define GROUP_STANDARD_BYTE (3)
#define GROUP_BASE64_BYTE (4)
static const char *BASE64CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char PADCHAR = '=';
char* encode_base64(const void *src, unsigned int byte)
{
	uint32_t nremainder = byte % GROUP_STANDARD_BYTE;
	uint32_t ngroup = (byte / GROUP_STANDARD_BYTE) + (nremainder > 0 ? 1 : 0);
	uint32_t nsize = ngroup * GROUP_BASE64_BYTE;

	char *dst = (char*)malloc(nsize + 1);
	if (!dst) {
	    return NULL;
	}
	memset(dst, 0, nsize + 1);

	const char *_src = (const char*)src;
	uint32_t offset = 0;
	while (1) {
	    if (1 == ngroup && 0 != nremainder) {
	        if (1 == nremainder) {
	            dst[offset] = BASE64CHARS[_src[0] >> 2];
	            dst[offset + 1] = BASE64CHARS[((_src[0] & 0x03) << 4)];
	            dst[offset + 2] = PADCHAR;
	            dst[offset + 3] = PADCHAR;
	        }
	        else {
	            dst[offset] = BASE64CHARS[_src[0] >> 2];
	            dst[offset + 1] = BASE64CHARS[((_src[0] & 0x03) << 4) | (_src[1] >> 4)];
	            dst[offset + 2] = BASE64CHARS[((_src[1] & 0x0f) << 2)];
	            dst[offset + 3] = PADCHAR;
	        }
	    }
	    else {
	        dst[offset] = BASE64CHARS[_src[0] >> 2];
	        dst[offset + 1] = BASE64CHARS[((_src[0] & 0x03) << 4) | (_src[1] >> 4)];
	        dst[offset + 2] = BASE64CHARS[((_src[1] & 0x0f) << 2) | (_src[2] >> 6)];
	        dst[offset + 3] = BASE64CHARS[_src[2] & 0x3f];
	    }

	    offset += GROUP_BASE64_BYTE;
	    _src += GROUP_STANDARD_BYTE;
	    if (--ngroup < 1) {
	        break;
	    }
	}

	if (offset != nsize) {
	    free(dst);
	    return NULL;
	}

	return dst;
}
/*
const char *chlist = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int encode_string(char* str, unsigned int length, char* stat) {
    char s[103];
    int i,j;
    unsigned temp;
    if(length <= 0)
		return 1;
    if(length > 100)
		return 2;
    str[length] = '\0';
    strcpy(s,str);
    while(strlen(s) % 3)
		strcat(s,"=");
    for(i = 0,j = 0; s[i]; i += 3,j += 4) {
        temp = s[i];
        temp = (temp << 8) + s[i + 1];
        temp = (temp << 8) + s[i + 2];
        stat[j + 3] = chlist[temp & 0X3F];
        temp >>= 6;
        stat[j + 2] = chlist[temp & 0X3F];
        temp >>= 6;
        stat[j + 1] = chlist[temp & 0X3F];
        temp >>= 6;
        stat[j + 0] = chlist[temp & 0X3F];
    }
    stat[j] = '\0';
    return 0;
}
*/

#if 0
int get_natconfig_version(char *hostaddr, int port, char *username, char *password,
		char *rev)
{
	struct sockaddr_in servaddr;
	int sockfd,n;
	int len = 0;
	char request[1024];
	char str[128];
	char recvline[MAXLINE];
	char *pbase = NULL;
	int my_lcore = rte_lcore_id();

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
                RUNNING_LOG_INFO("core %d: %s socket error\n", my_lcore, __FUNCTION__);
                return 0;
        };

	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	if(inet_pton(AF_INET, hostaddr, &servaddr.sin_addr) <= 0) {
		RUNNING_LOG_INFO("core %d:%s inet_pton error\n", my_lcore, __FUNCTION__);
		return 0;
	}

	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0){
		RUNNING_LOG_INFO("core %d:%s connect error\n", my_lcore, __FUNCTION__);
                return 0;
        }

	memset(request, 0, sizeof(request));
	memset(str, 0, sizeof(str));
	sprintf(str, "%s:%s", username, password);
	pbase = encode_base64(str, strlen(str));

	strcat(request, "GET /api/v1.0/version/dnat HTTP/1.1\r\n");
	memset(str, 0, sizeof(str));
	sprintf(str, "Host: %s:%d\r\n", hostaddr, port);
	strcat(request, str);
	memset(str, 0, sizeof(str));
	if (pbase != NULL){
		strcat(str, "Authorization: Basic ");
		strcat(str, pbase);
		strcat(request, str);
		strcat(request, "\r\n");
		free(pbase);
	}
	strcat(request, "Accept: */*\r\n");
	strcat(request, "Accept-Language: zh-cn,zh\r\n");
	strcat(request, "Connection: keep-alive\r\n");
	strcat(request, "Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n");
	strcat(request, "User-Agent: WDNAT_1.0\r\n\r\n");
//	RUNNING_LOG_INFO("core %d:%s\n", my_lcore, request);

	write(sockfd, request, strlen(request));

	while((n = read(sockfd, recvline, MAXLINE)) > 0)
	{
		recvline[n] = 0;
		strcat(rev, recvline);
		len += n;
	}

	rev[MAX_JSON_LEN-1] = 0;
//	RUNNING_LOG_INFO("core %d:rev=%s\n", my_lcore, rev);

	if(n < 0)
	{
		RUNNING_LOG_DEBUG("core %d: %s read error\n", my_lcore, __FUNCTION__);
		return 0;
	}

	return len;
}
#endif

int write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
	if (strlen((char *)stream) + strlen((char *)ptr) > MAX_JSON_LEN)
		return 0;
	strcat(stream, (char *)ptr);

	return size*nmemb;
}

int get_natconfig_version(char *hostaddr, int hostport, char *username, char *password,
		char *rev)
{

	CURL *curl;
	CURLcode res;
	char str[128];
	char url[512]={0};

	int my_lcore = rte_lcore_id();

	sprintf(str, "%s:%d", hostaddr, hostport);
	strcat(url, str);
	strcat(url, me.natconfig.natconfig_ver);
	strcat(url, "?pool=");
//	strcat(url, "/api/v1.0/version/dnat?pool=");
        strcat(url, me.natconfig.pool_tag);
        strcat(url, "&region=");
        strcat(url, me.natconfig.region_tag);
//        strcat(url, "&isp=");
//        strcat(url, me.natconfig.isp_tag);

	curl = curl_easy_init();//对curl进行初始化

	curl_easy_setopt(curl, CURLOPT_URL, url); //设置下载地址
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3);//设置超时时间
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
	sprintf(str, "%s:%s", username, password);
	curl_easy_setopt(curl, CURLOPT_USERPWD, str);

	//设置写数据的函数
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, rev);//设置写数据的变量
	res = curl_easy_perform(curl);//执行下载
	rev[MAX_JSON_LEN-2] = '\0';

	curl_easy_cleanup(curl);//释放curl资源

	if(CURLE_OK != res)
	{
		RUNNING_LOG_INFO("core %d: %s get error\n", my_lcore, __FUNCTION__);
		return 0;
	}
	else
	{
//		RUNNING_LOG_INFO("core %d:rev=%s\n", my_lcore, rev);
		return 1;
	}

}

int get_remote_config(char *hostaddr, int hostport, char *username, char *password,
		char *rev)
{
	CURL *curl;
	CURLcode res;
	char str[128];
	char url[512]={0};

	int my_lcore = rte_lcore_id();

	sprintf(str, "%s:%d", hostaddr, hostport);
	strcat(url, str);
	strcat(url, me.natconfig.natconfig);
	strcat(url, "?pool=");
//	strcat(url, "/api/v1.0/nat/dnat?pool=");
        strcat(url, me.natconfig.pool_tag);
        strcat(url, "&region=");
        strcat(url, me.natconfig.region_tag);
//        strcat(url, "&isp=");
//        strcat(url, me.natconfig.isp_tag);

	curl = curl_easy_init();//对curl进行初始化

	curl_easy_setopt(curl, CURLOPT_URL, url); //设置下载地址
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3);//设置超时时间
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
	sprintf(str, "%s:%s", username, password);
	curl_easy_setopt(curl, CURLOPT_USERPWD, str);

	//设置写数据的函数
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, rev);//设置写数据的变量
	res = curl_easy_perform(curl);//执行下载
	rev[MAX_JSON_LEN-2] = '\0';

	curl_easy_cleanup(curl);//释放curl资源

	if(CURLE_OK != res)
	{
		RUNNING_LOG_INFO("core %d: %s get error\n", my_lcore, __FUNCTION__);
		return 0;
	}
	else
	{
//		RUNNING_LOG_INFO("core %d:rev=%s\n", my_lcore, rev);
		return 1;
	}

}

int get_bandwidth_version(char *hostaddr, int hostport, char *username, char *password,
		char *rev)
{
	CURL *curl;
	CURLcode res;
	char str[128];
	char url[512]={0};

	int my_lcore = rte_lcore_id();

	sprintf(str, "%s:%d", hostaddr, hostport);
	strcat(url, str);
	strcat(url, me.natconfig.bandwidth_ver);
	strcat(url, "?pool=");
//	strcat(url, "/api/v1.0/version/defense_ip?pool=");
        strcat(url, me.natconfig.pool_tag);
        strcat(url, "&region=");
        strcat(url, me.natconfig.region_tag);
//        strcat(url, "&isp=");
//        strcat(url, me.natconfig.isp_tag);

	curl = curl_easy_init();//对curl进行初始化

	curl_easy_setopt(curl, CURLOPT_URL, url); //设置下载地址
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3);//设置超时时间
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
	sprintf(str, "%s:%s", username, password);
	curl_easy_setopt(curl, CURLOPT_USERPWD, str);

	//设置写数据的函数
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, rev);//设置写数据的变量
	res = curl_easy_perform(curl);//执行下载
	rev[MAX_JSON_LEN-2] = '\0';

	curl_easy_cleanup(curl);//释放curl资源

	if(CURLE_OK != res)
	{
		RUNNING_LOG_INFO("core %d: %s return error\n", my_lcore, __FUNCTION__);
		return 0;
	}
	else
	{
//		RUNNING_LOG_INFO("core %d:rev=%s\n", my_lcore, rev);
		return 1;
	}

}

int get_natconfig_bandwidth(char *hostaddr, int hostport, char *username, char *password,
		uint32_t ip, char *rev)
{
	CURL *curl;
	CURLcode res;
	char str[128];
	char url[512]={0};
	char ipstr_out[64];

	int my_lcore = rte_lcore_id();

	sprintf(str, "%s:%d", hostaddr, hostport);
	strcat(url, str);
	strcat(url, me.natconfig.bandwidth);
//	strcat(url, "/api/v1.0/defense_ip/");
	sprintf(str, "/%s", ip2str(ipstr_out, rte_cpu_to_be_32(ip)));
	strcat(url, str);
        strcat(url, "?pool=");
        strcat(url, me.natconfig.pool_tag);
        strcat(url, "&region=");
        strcat(url, me.natconfig.region_tag);
//        strcat(url, "&isp=");
//        strcat(url, me.natconfig.isp_tag);

	curl = curl_easy_init();//对curl进行初始化

	curl_easy_setopt(curl, CURLOPT_URL, url); //设置下载地址
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3);//设置超时时间
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
	sprintf(str, "%s:%s", username, password);
	curl_easy_setopt(curl, CURLOPT_USERPWD, str);

	//设置写数据的函数
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, rev);//设置写数据的变量
	res = curl_easy_perform(curl);//执行下载
	rev[MAX_JSON_LEN-2] = '\0';

	curl_easy_cleanup(curl);//释放curl资源

//	RUNNING_LOG_INFO("core %d:rev=%s\n", my_lcore, rev);

	if(CURLE_OK != res)
	{
		RUNNING_LOG_INFO("core %d: %s return error\n", my_lcore, __FUNCTION__);
		return 0;
	}
	else
	{
		return 1;
	}

}

int get_rip_status(char *hostaddr, int hostport, char *username, char *password,
		uint32_t ip, uint32_t port, int proto, char *rev)
{
	CURL *curl;
	CURLcode res;
	char str[128];
	char url[512]={0};
	char ipstr_out[64];

	int my_lcore = rte_lcore_id();

	sprintf(str, "%s:%d", hostaddr, hostport);
	strcat(url, str);
	strcat(url, me.natconfig.rip_linkstatus);
//	strcat(url, "/api/v1.0/check/port");
	if (L4_TYPE_UDP == proto)
		sprintf(str, "/%s?port=%d&protocol=udp&timeout=2", ip2str(ipstr_out, rte_cpu_to_be_32(ip)), port);
	else
		sprintf(str, "/%s?port=%d&protocol=tcp&timeout=2", ip2str(ipstr_out, rte_cpu_to_be_32(ip)), port);
	strcat(url, str);
        strcat(url, "&pool=");
        strcat(url, me.natconfig.pool_tag);
        strcat(url, "&region=");
        strcat(url, me.natconfig.region_tag);
//        strcat(url, "&isp=");
//        strcat(url, me.natconfig.isp_tag);

//	RUNNING_LOG_INFO("core %d:url=%s\n", my_lcore, url);

	curl = curl_easy_init();//对curl进行初始化

	curl_easy_setopt(curl, CURLOPT_URL, url); //设置下载地址
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3);//设置超时时间
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
	sprintf(str, "%s:%s", username, password);
	curl_easy_setopt(curl, CURLOPT_USERPWD, str);

	//设置写数据的函数
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, rev);//设置写数据的变量
	res = curl_easy_perform(curl);//执行下载
	rev[MAX_JSON_LEN-2] = '\0';

	curl_easy_cleanup(curl);//释放curl资源

	if(CURLE_OK != res)
	{
		RUNNING_LOG_INFO("core %d:%s return error\n", my_lcore, __FUNCTION__);
		return 0;
	}
	else
	{
//		RUNNING_LOG_INFO("core %d:rev=%s\n", my_lcore, rev);
		return 1;
	}
}
#if 0
int get_remote_config(char *hostaddr, int port, char *username, char *password,
		char *rev)
{
	struct sockaddr_in servaddr;
	int sockfd,n;
	int len = 0;
	char request[1024];
	char str[128];
	char recvline[MAXLINE];
	char *pbase = NULL;
	int my_lcore = rte_lcore_id();

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
                RUNNING_LOG_INFO("core %d: %s socket error\n", my_lcore, __FUNCTION__);
                return 0;
        };

	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	if(inet_pton(AF_INET, hostaddr, &servaddr.sin_addr) <= 0) {
		RUNNING_LOG_INFO("core %d:%s inet_pton error\n", my_lcore, __FUNCTION__);
		return 0;
	}

	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0){
		RUNNING_LOG_INFO("core %d:%s connect error\n", my_lcore, __FUNCTION__);
                return 0;
        }
	RUNNING_LOG_INFO("core %d:%s connect %s success\n", my_lcore, __FUNCTION__, hostaddr);

	memset(request, 0, sizeof(request));
	memset(str, 0, sizeof(str));
	//memset(recvline, 0, sizeof(recvline));
	sprintf(str, "%s:%s", username, password);
	pbase = encode_base64(str, strlen(str));
	//RUNNING_LOG_INFO("core %d: encode_base64=%s\n", my_lcore, pbase);

	strcat(request, "GET /api/v1.0/nat/dnat?include_dmz&format=lite HTTP/1.1\r\n");
	memset(str, 0, sizeof(str));
	sprintf(str, "Host: %s:%d\r\n", hostaddr, port);
	strcat(request, str);
	memset(str, 0, sizeof(str));
	if (pbase != NULL){
		strcat(str, "Authorization: Basic ");
		strcat(str, pbase);
		strcat(request, str);
		strcat(request, "\r\n");
		free(pbase);
	}
	strcat(request, "Accept: */*\r\n");
	strcat(request, "Accept-Language: zh-cn,zh\r\n");
	strcat(request, "Connection: keep-alive\r\n");
	strcat(request, "Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n");
	strcat(request, "User-Agent: WDNAT_1.0\r\n\r\n");
	RUNNING_LOG_INFO("core %d:%s\n", my_lcore, request);

	write(sockfd, request, strlen(request));
	RUNNING_LOG_INFO("core %d:%s write success\n", my_lcore, __FUNCTION__);

	while((n = read(sockfd, recvline, MAXLINE)) > 0)
	{
		recvline[n] = 0;
		strcat(rev, recvline);
		len += n;
	}

	rev[MAX_JSON_LEN-1] = 0;
	RUNNING_LOG_INFO("core %d:%s\n", my_lcore, rev);

	if(n < 0)
	{
		RUNNING_LOG_INFO("core %d: %s read error\n", my_lcore, __FUNCTION__);
		return 0;
	}

	return len;
}


int get_bandwidth_version(char *hostaddr, int port, char *username, char *password,
		char *rev)
{
	struct sockaddr_in servaddr;
	int sockfd,n;
	int len = 0;
	char request[1024];
	char str[128];
	char recvline[MAXLINE];
	char *pbase = NULL;
	int my_lcore = rte_lcore_id();

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
                RUNNING_LOG_INFO("core %d: %s socket error\n", my_lcore, __FUNCTION__);
                return 0;
        };

	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	if(inet_pton(AF_INET, hostaddr, &servaddr.sin_addr) <= 0) {
		RUNNING_LOG_INFO("core %d:%s inet_pton error\n", my_lcore, __FUNCTION__);
		return 0;
	}

	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0){
		RUNNING_LOG_INFO("core %d:%s connect error\n", my_lcore, __FUNCTION__);
                return 0;
        }

	memset(request, 0, sizeof(request));
	memset(str, 0, sizeof(str));
	sprintf(str, "%s:%s", username, password);
	pbase = encode_base64(str, strlen(str));

	strcat(request, "GET /api/v1.0/version/defense_ip HTTP/1.1\r\n");
	memset(str, 0, sizeof(str));
	sprintf(str, "Host: %s:%d\r\n", hostaddr, port);
	strcat(request, str);
	memset(str, 0, sizeof(str));
	if (pbase != NULL){
		strcat(str, "Authorization: Basic ");
		strcat(str, pbase);
		strcat(request, str);
		strcat(request, "\r\n");
		free(pbase);
	}
	strcat(request, "Accept: */*\r\n");
	strcat(request, "Accept-Language: zh-cn,zh\r\n");
	strcat(request, "Connection: keep-alive\r\n");
	strcat(request, "Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n");
	strcat(request, "User-Agent: WDNAT_1.0\r\n\r\n");

	write(sockfd, request, strlen(request));

	while((n = read(sockfd, recvline, MAXLINE)) > 0)
	{
		recvline[n] = 0;
		strcat(rev, recvline);
		len += n;
	}

	rev[MAX_JSON_LEN-1] = 0;
//	RUNNING_LOG_DEBUG("%s:%s\n",  __FUNCTION__, rev);

	if(n < 0)
	{
		RUNNING_LOG_DEBUG("core %d: %s read error\n", my_lcore, __FUNCTION__);
		return 0;
	}

	return len;
}

int get_natconfig_bandwidth(char *hostaddr, int port, char *username, char *password,
		uint32_t ip, char *rev)
{
	struct sockaddr_in servaddr;
	int sockfd,n;
	int len = 0;
	char request[1024];
	char str[128];
	char recvline[MAXLINE];
	char *pbase = NULL;
	char ipstr_out[64];
	int my_lcore = rte_lcore_id();

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
                RUNNING_LOG_INFO("core %d: %s socket error\n", my_lcore, __FUNCTION__);
                return 0;
        };

	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	if(inet_pton(AF_INET, hostaddr, &servaddr.sin_addr) <= 0) {
		RUNNING_LOG_INFO("core %d:%s inet_pton error\n", my_lcore, __FUNCTION__);
		return 0;
	}

	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0){
		RUNNING_LOG_INFO("core %d:%s connect error\n", my_lcore, __FUNCTION__);
                return 0;
        }

	memset(request, 0, sizeof(request));
	memset(str, 0, sizeof(str));
	sprintf(str, "%s:%s", username, password);
	pbase = encode_base64(str, strlen(str));

	strcat(request, "GET /api/v1.0/defense_ip/");
	sprintf(str, "%s HTTP/1.1\r\n", ip2str(ipstr_out, rte_cpu_to_be_32(ip)));
	strcat(request, str);
	memset(str, 0, sizeof(str));
	sprintf(str, "Host: %s:%d\r\n", hostaddr, port);
	strcat(request, str);
	memset(str, 0, sizeof(str));
	if (pbase != NULL){
		strcat(str, "Authorization: Basic ");
		strcat(str, pbase);
		strcat(request, str);
		strcat(request, "\r\n");
		free(pbase);
	}
	strcat(request, "Accept: */*\r\n");
	strcat(request, "Accept-Language: zh-cn,zh\r\n");
	strcat(request, "Connection: keep-alive\r\n");
	strcat(request, "Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n");
	strcat(request, "User-Agent: WDNAT_1.0\r\n\r\n");

//	RUNNING_LOG_DEBUG("%s:%s\n",  __FUNCTION__, request);
	write(sockfd, request, strlen(request));

	while((n = read(sockfd, recvline, MAXLINE)) > 0)
	{
		recvline[n] = 0;
		strcat(rev, recvline);
		len += n;
	}

	rev[MAX_JSON_LEN-1] = 0;
//	RUNNING_LOG_DEBUG("%s:%s\n",  __FUNCTION__, rev);

	if(n < 0)
	{
		RUNNING_LOG_DEBUG("core %d: %s read error\n", my_lcore, __FUNCTION__);
		return 0;
	}

	return len;
}

int get_natip_status(char *hostaddr, int hostport, char *username, char *password,
		uint32_t ip, uint32_t port, int proto, char *rev)
{
	struct sockaddr_in servaddr;
	int sockfd,n;
	int len = 0;
	char request[1024];
	char str[128];
	char recvline[MAXLINE];
	char *pbase = NULL;
	char ipstr_out[64];
	int my_lcore = rte_lcore_id();

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
                RUNNING_LOG_INFO("core %d: %s socket error\n", my_lcore, __FUNCTION__);
                return 0;
        };

	bzero(&servaddr,sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(hostport);
	if(inet_pton(AF_INET, hostaddr, &servaddr.sin_addr) <= 0) {
		RUNNING_LOG_INFO("core %d:%s inet_pton error\n", my_lcore, __FUNCTION__);
		return 0;
	}

	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0){
		RUNNING_LOG_DEBUG("core %d:%s connect error\n", my_lcore, __FUNCTION__);
                return 0;
        }

	memset(request, 0, sizeof(request));
	memset(str, 0, sizeof(str));
	sprintf(str, "%s:%s", username, password);
	pbase = encode_base64(str, strlen(str));

	strcat(request, "GET /api/v1.0/check/port/");
	if (L4_TYPE_UDP == proto)
		sprintf(str, "%s?port=%d&protocol=udp&timeout=2 HTTP/1.1\r\n", ip2str(ipstr_out, rte_cpu_to_be_32(ip)), port);
	else
		sprintf(str, "%s?port=%d&protocol=tcp&timeout=2 HTTP/1.1\r\n", ip2str(ipstr_out, rte_cpu_to_be_32(ip)), port);
	strcat(request, str);
	memset(str, 0, sizeof(str));
	sprintf(str, "Host: %s:%d\r\n", hostaddr, hostport);
	strcat(request, str);
	memset(str, 0, sizeof(str));
	if (pbase != NULL){
		strcat(str, "Authorization: Basic ");
		strcat(str, pbase);
		strcat(request, str);
		strcat(request, "\r\n");
		free(pbase);
	}
	strcat(request, "Accept: */*\r\n");
	strcat(request, "Accept-Language: zh-cn,zh\r\n");
	strcat(request, "Connection: keep-alive\r\n");
	strcat(request, "Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n");
	strcat(request, "User-Agent: WDNAT_1.0\r\n\r\n");

//	RUNNING_LOG_DEBUG("%s:%s\n",  __FUNCTION__, request);
	write(sockfd, request, strlen(request));

	while((n = read(sockfd, recvline, MAXLINE)) > 0)
	{
		recvline[n] = 0;
		strcat(rev, recvline);
		len += n;
	}

	rev[MAX_JSON_LEN-1] = 0;
//	RUNNING_LOG_DEBUG("%s:%s\n",  __FUNCTION__, rev);

	if(n < 0)
	{
		RUNNING_LOG_DEBUG("core %d: %s read error\n", my_lcore, __FUNCTION__);
		return 0;
	}

	return len;
}
#endif

int parser_remote_dnatconfig(char *pconfig)
{
	cJSON * pJson = NULL;
	cJSON * pArrayItem = NULL;
	cJSON * pArrayItem_1 = NULL;
	cJSON *t,*tt,*ttt;
	char *p = NULL;
	int i, j, m, idx_dip, idx_rule, idx_rip, nCount,nCount_1;
	struct in_addr addr;
//	struct dnat_item tmp_dnattable[NAT_MAX_DSTNUM];
	struct dnat_item *tmp_dnattable;
	struct dnat_item *ptable = NULL;
	uint32_t tmp_ip;
	int ret_idx;
//	struct snat_item local_stable[NAT_MAX_DSTNUM] = {0};
	struct snat_item *local_stable;

	local_stable = (struct snat_item *)malloc(NAT_MAX_DSTNUM * sizeof(struct snat_item));
	if (!local_stable)
	{
		EARLY_LOG_INFO("%s: Failed to malloc snat_item '%s', err=%s\n", __FUNCTION__, pconfig, strerror(errno));
		return -1;
	}
	memset(local_stable, 0, (NAT_MAX_DSTNUM * sizeof(struct snat_item)));

	if (snatconfig_curr)
		rte_memcpy(local_stable, &stable[NAT_MAX_DSTNUM], sizeof(struct snat_item) * NAT_MAX_DSTNUM);
	else
		rte_memcpy(local_stable, &stable[0], sizeof(struct snat_item) * NAT_MAX_DSTNUM);


	pJson = cJSON_Parse(pconfig);
	if(pJson == NULL)
	{
		RUNNING_LOG_INFO("%s: cJSON_Parse config file fail\n", __FUNCTION__);
		return 0;
	}

	m = 0;
	idx_dip = 0;
	idx_rule = 0;
	idx_rip = 0;

	tmp_dnattable = (struct dnat_item *)malloc(NAT_MAX_DSTNUM * sizeof(struct dnat_item));
	if (!tmp_dnattable)
	{
		RUNNING_LOG_ERROR("%s: Failed to malloc dnat_item err=%s\n", __FUNCTION__, strerror(errno));
		return -1;
	}

	memset(tmp_dnattable, 0, sizeof(tmp_dnattable[0])*NAT_MAX_DSTNUM);
	nCount = cJSON_GetArraySize ( pJson );
	RUNNING_LOG_INFO("%s:GetArraySize=%d\n", __FUNCTION__, nCount);
//	RUNNING_LOG_INFO("%s:pJson=%s\n", __FUNCTION__, pconfig);

	for( i = 0; i < nCount; i++)
	{
		pArrayItem = cJSON_GetArrayItem(pJson, i);
		if(pArrayItem)
		{
			t = cJSON_GetObjectItem(pArrayItem,"nat_pool");  //vip...
			if(t)
			{
				pArrayItem_1= cJSON_GetArrayItem(t, 0);
				tt = cJSON_GetObjectItem(pArrayItem_1,"ip");
				if (tt && inet_aton(tt->valuestring, &addr))
				{
					tmp_ip = rte_be_to_cpu_32(addr.s_addr);
					RUNNING_LOG_DEBUG("%s:dest_ip =0x%x\n", __FUNCTION__, tmp_ip);
					ret_idx = nat_is_local_vip(tmp_ip, local_stable);
					if (0xffff == ret_idx ) //is not local vip
					{
						EARLY_LOG_INFO("%s:vip 0x%x is not local vip\n", __FUNCTION__, tmp_ip);
						continue;
					}

					for (j = 0; j < NAT_MAX_DSTNUM; j++ )
					{
						if (0 != tmp_dnattable[j].dst_ip)
						{
							if (tmp_ip != tmp_dnattable[j].dst_ip)
								continue;
							else{
								idx_dip = j;
								break;
							}
						}else{
							idx_dip = m;
							tmp_dnattable[idx_dip].dst_ip = tmp_ip;
							tmp_dnattable[idx_dip].dstip_idx = ret_idx;
							m++;
							break;
						}
					}
					if (NAT_MAX_DSTNUM == j){
						RUNNING_LOG_INFO("%s:too many dst ip!\n", __FUNCTION__);
						break;
					}
					tt = cJSON_GetObjectItem(pArrayItem_1,"src_sel_alg");
					if (tt && (tt->type == cJSON_String))
					{
						RUNNING_LOG_DEBUG("%s:source station select algorithm %s\n", __FUNCTION__, tt->valuestring);
						if (!strcmp(tt->valuestring,"dsh")){
							tmp_dnattable[idx_dip].fwd_realip_mode = REALIP_SEL_DSH;
						} else if (!strcmp(tt->valuestring,"rr")) {
							tmp_dnattable[idx_dip].fwd_realip_mode = REALIP_SEL_RR;
						}  else if (!strcmp(tt->valuestring,"wrr")) {
							tmp_dnattable[idx_dip].fwd_realip_mode = REALIP_SEL_WRR;
						} else {
							tmp_dnattable[idx_dip].fwd_realip_mode = REALIP_SEL_DEF;
						}
					} else {
						tmp_dnattable[idx_dip].fwd_realip_mode = REALIP_SEL_DEF;
					}

				}else{
					continue;
				}

				tt = cJSON_GetObjectItem(pArrayItem_1,"port");
				if (tt && (tt->type == cJSON_String)){
					RUNNING_LOG_DEBUG("%s:dest_port =%d\n", __FUNCTION__, atoi(tt->valuestring));
					for (j = 0; j < NAT_MAX_RULENUM; j++ )
					{
						if (0 == tmp_dnattable[idx_dip].rule[j].dst_port)
						{
							idx_rule= j;
							break;
						}
					}
					if (NAT_MAX_RULENUM == j){
						RUNNING_LOG_INFO("%s:too many rules for dst ip %x!\n", __FUNCTION__, tmp_dnattable[idx_dip].dst_ip);
						break;
					}
					tmp_dnattable[idx_dip].rule[idx_rule].dst_port = atoi(tt->valuestring);
				}

			}else{
					continue;
			}

			t = cJSON_GetObjectItem(pArrayItem,"dest_pool"); //rip
			if(t)
			{
				idx_rip = 0;
				nCount_1 = cJSON_GetArraySize ( t );
				for (j = 0; j < nCount_1; j++ )
				{
					pArrayItem_1= cJSON_GetArrayItem(t, j);

					tt = cJSON_GetObjectItem(pArrayItem_1,"debouncing");
					if (tt  && (tt->type == cJSON_Number)){
						RUNNING_LOG_DEBUG("%s:nat_debouncing =%d\n", __FUNCTION__, tt->valueint);
						tmp_dnattable[idx_dip].rule[idx_rule].nat_debouncing[idx_rip] =
							(tt->valueint)? (tt->valueint): NAT_DEBOUNCING_TIMER_DEF;
					}else{
						tmp_dnattable[idx_dip].rule[idx_rule].nat_debouncing[idx_rip] = NAT_DEBOUNCING_TIMER_DEF;
					}

					tt = cJSON_GetObjectItem(pArrayItem_1,"ip");
					if (tt && inet_aton(tt->valuestring, &addr))
					{
						RUNNING_LOG_DEBUG("%s:nat_ip =0x%x\n", __FUNCTION__, rte_be_to_cpu_32(addr.s_addr));
						tmp_dnattable[idx_dip].rule[idx_rule].nat_ip[idx_rip++] = rte_be_to_cpu_32(addr.s_addr);
						rip_linkstate[ret_idx][idx_rule] |= (1ULL<<(idx_rip-1));
						if (idx_rip >= NAT_MAX_NATIPNUM)
							break;
					}


					tt = cJSON_GetObjectItem(pArrayItem_1,"port");
					if (tt  && (tt->type == cJSON_String)){
						RUNNING_LOG_DEBUG("%s:nat_port =%d\n", __FUNCTION__, atoi(tt->valuestring));
						tmp_dnattable[idx_dip].rule[idx_rule].nat_port = atoi(tt->valuestring);
					}

				}
				tmp_dnattable[idx_dip].rule[idx_rule].rip_sum=idx_rip;

			}

			t = cJSON_GetObjectItem(pArrayItem,"protocol");
			if(t){
				nCount_1 = cJSON_GetArraySize ( t );
				for (j = 0; j < nCount_1; j++ )
				{
					pArrayItem_1= cJSON_GetArrayItem(t, j);
					if (strstr(pArrayItem_1->valuestring, "UDP") || strstr(pArrayItem_1->valuestring, "udp"))
						tmp_dnattable[idx_dip].rule[idx_rule].proto |= L4_TYPE_UDP;
					else if (strstr(pArrayItem_1->valuestring, "TCP") || strstr(pArrayItem_1->valuestring, "tcp"))
						tmp_dnattable[idx_dip].rule[idx_rule].proto |= L4_TYPE_TCP;
				}
				RUNNING_LOG_DEBUG("%s:protoal =%d\n", __FUNCTION__, tmp_dnattable[idx_dip].rule[idx_rule].proto);
			}
		}
	}

	if (dnatconfig_curr)
		p = (char*) &dtable[0];
	else
		p = (char*) &dtable[NAT_MAX_DSTNUM];

//	rte_memcpy(p, &tmp_dnattable, sizeof(tmp_dnattable[0]) * NAT_MAX_DSTNUM);
	rte_memcpy(p, tmp_dnattable, sizeof(struct dnat_item) * NAT_MAX_DSTNUM);

	dnatconfig_curr^=1;

	rte_smp_wmb();

	if (tmp_dnattable)
	{
		free(tmp_dnattable);
		tmp_dnattable = NULL;
	}
	if (local_stable)
	{
		free(local_stable);
		local_stable = NULL;
	}
	RUNNING_LOG_INFO("%s:vip num=%d, %d items, dnatconfig_curr=%d\n", __FUNCTION__, m,nCount,dnatconfig_curr);

#if 1
sleep(1);
	int fileflag = 0;
	struct tm *t_now;
	time_t now;
	char filebuf[NAT_MAX_RULENUM*128],buf[128];
	char timebuf[128];
	char filepath[128];
	FILE *local_dnatconf_fp = NULL;

	time(&now);
	t_now = localtime(&now);
	sprintf(timebuf,"%04d%02d%02d",(1900+t_now->tm_year),(1+t_now->tm_mon),t_now->tm_mday);
	sprintf(filepath,"%s/dnatconfig_%s", me.root_dir,timebuf);
	if ((local_dnatconf_fp = fopen(filepath, "w+")) == NULL) {
		RUNNING_LOG_INFO("%s:open file failed", __FUNCTION__);
		return 1;
	}

	sprintf(filebuf,"last changed: %04d-%02d-%02d %02d:%02d:%02d\n",(1900+t_now->tm_year),(1+t_now->tm_mon),t_now->tm_mday,t_now->tm_hour,t_now->tm_min,t_now->tm_sec);
	fwrite(filebuf,1,strlen(filebuf), local_dnatconf_fp);

	if (dnatconfig_curr)
		ptable =  &dtable[NAT_MAX_DSTNUM];
	else
		ptable = &dtable[0];
	for (i = 0; i < NAT_MAX_DSTNUM; i++ )
	{
		if (0 != ptable[i].dst_ip)
		{
//			memset(filebuf, 0, sizeof(filebuf));
			sprintf(filebuf, "vip_%03d: %u.%u.%u.%u idx:%03d\n", i,
				ptable[i].dst_ip>>24,(ptable[i].dst_ip>>16)&0xff,(ptable[i].dst_ip>>8)&0xff,(ptable[i].dst_ip)&0xff,
				ptable[i].dstip_idx);

			//RUNNING_LOG_DEBUG("%s:dst_ip =0x%x\n", __FUNCTION__, ptable[i].dst_ip);
			for (j = 0; j < NAT_MAX_RULENUM; j++)
			{
				if (0 != ptable[i].rule[j].dst_port)
				{
//					RUNNING_LOG_DEBUG("%s:i =0x%x\n", __FUNCTION__, i);
//					RUNNING_LOG_DEBUG("%s:j =0x%x\n", __FUNCTION__, j);
//					RUNNING_LOG_INFO("%s:vip =0x%x\n", __FUNCTION__, ptable[i].dst_ip);

					sprintf(buf, "vip=0x%08x,v_port=%05d,real_port=%05d,real_ip=0x%08x,0x%x,0x%x, proto=%d\n",
					ptable[i].dst_ip, ptable[i].rule[j].dst_port, ptable[i].rule[j].nat_port,
					ptable[i].rule[j].nat_ip[0],ptable[i].rule[j].nat_ip[1],ptable[i].rule[j].nat_ip[2],
					ptable[i].rule[j].proto);
					strcat(filebuf, buf);

//					RUNNING_LOG_INFO("%s", buf);
				}
			}
//			RUNNING_LOG_INFO("%s", filebuf);
			fwrite(filebuf,1,strlen(filebuf), local_dnatconf_fp);
		}

	}

	fclose(local_dnatconf_fp);
	local_dnatconf_fp = NULL;

#endif
	return 1;
}

void *natconf_thread(void *args)
{
	char rev[MAX_JSON_LEN];
	char *p = NULL;
	cJSON * pJson = NULL;
	cJSON * pArrayItem = NULL;
	cJSON * pArrayItem_1 = NULL;
	cJSON *t,*tt,*ttt;
	int retry = 1;
	int ret = 0;
	struct in_addr addr;
	int my_lcore;
	int fail_cnt = 0;
	char str_id[33]={0};
//	struct dnat_item tmp_dnattable[NAT_MAX_DSTNUM] = {0};
	struct dnat_item *tmp_dnattable;
	char *ipaddr = me.natconfig.addr;
	int port = me.natconfig.port;
	char *usrname = me.natconfig.usrname;
	char *password = me.natconfig.password;

	RUNNING_LOG_INFO("%s : start\n",__FUNCTION__);

	my_lcore = rte_lcore_id();

	tmp_dnattable = (struct dnat_item *)malloc(NAT_MAX_DSTNUM * sizeof(struct dnat_item));
	if (!tmp_dnattable)
	{
		RUNNING_LOG_ERROR("%s: Failed to malloc dnat_item err=%s\n", __FUNCTION__, strerror(errno));
		return NULL;
	}

	while(!term_pending)
	{
		sleep(2);
		memset(rev, 0, sizeof(rev));
		memset(tmp_dnattable, 0, sizeof(struct dnat_item) * NAT_MAX_DSTNUM);

		ret = get_natconfig_version(ipaddr, port, usrname, password, rev);
		if (0 == ret)
		{
			RUNNING_LOG_INFO("core %d:get_natconfig_version fail\n", my_lcore);
			sleep(18);
			continue;
		}

		p = strchr(rev, '{');
		pJson = cJSON_Parse(p);
		if(pJson == NULL)
		{
			fail_cnt++;
			RUNNING_LOG_INFO("core %d:%s cJSON_Parse fail\n", my_lcore,__FUNCTION__);
			RUNNING_LOG_INFO("core %d:%s rev=%s\n", my_lcore, __FUNCTION__,rev);
			continue;
		}

		t = cJSON_GetObjectItem(pJson,"type");
		if( t )
		{
			if (strcmp(t->valuestring, "dnat"))
			{
				RUNNING_LOG_INFO("core %d:%s check type fail\n", my_lcore, __FUNCTION__);
				fail_cnt++;
				continue;
			}
			t = cJSON_GetObjectItem(pJson,"hash");
			if (t)
			{
				if (strcmp(t->valuestring, str_id))
				{
					strncpy(str_id, t->valuestring, 32);
					RUNNING_LOG_INFO("core %d:%s remote natconfig version change\n", my_lcore, __FUNCTION__);
				}
				else{
					RUNNING_LOG_DEBUG("core %d:%s get the same remote natconfig version\n", my_lcore, __FUNCTION__);
					if (0 == retry)
						continue;
				}

			}else{
				RUNNING_LOG_INFO("core %d:%s get hash fail\n", my_lcore, __FUNCTION__);
				fail_cnt++;
				continue;
			}

		}else{
			RUNNING_LOG_INFO("core %d:%s get_natconfig_version get type fail\n", my_lcore, __FUNCTION__);
			fail_cnt++;
			continue;
		}

		memset(rev, 0, sizeof(rev));
		ret = get_remote_config(ipaddr, port, usrname, password, rev);
		if (ret)
		{
			p = strchr(rev, '[');
			if (NULL != p){
				ret = parser_remote_dnatconfig(p);
			}else{
				retry = 1;
				RUNNING_LOG_INFO("core %d:%s get_remote_config fail\n", my_lcore, __FUNCTION__);
			}
		}

		if (ret)
			retry = 0;
		else
			retry = 1;

		sleep(8);
	}

	if (tmp_dnattable){
		free(tmp_dnattable);
		tmp_dnattable = NULL;
	}

	RUNNING_LOG_INFO("%s : thread exit now\n",__FUNCTION__);
}

//dstip policy detected thread
void *nat_dstip_p_det_thread(void *args)
{
	char rev[MAX_JSON_LEN];
	char *p = NULL;
	cJSON * pJson = NULL;
	cJSON * pArrayItem = NULL;
	cJSON * pArrayItem_1 = NULL;
	cJSON *t,*tt,*ttt;
	int retry = 0;
	int ret = 0;
	int i;
	struct in_addr addr;
	int my_lcore;
	char str_id[33]={0};
//	struct dnat_item tmp_dnattable[NAT_MAX_DSTNUM] = {0};
	struct dnat_item *tmp_dnattable;
	char *ipaddr = me.natconfig.addr;
	int port = me.natconfig.port;
	char *usrname = me.natconfig.usrname;
	char *password = me.natconfig.password;

	struct dst_pl_s *dst_pl;

//	struct dnat_item local_dtable[NAT_MAX_DSTNUM];
	struct dnat_item *local_dtable;
	int pre_dtable=dnatconfig_curr;

	g_dst_pl = (struct dst_pl_s *)malloc(NAT_MAX_DSTNUM * sizeof(struct dst_pl_s));
	if (!g_dst_pl){
		RUNNING_LOG_ERROR("%s: alloc dst_pl_s error\n", __FUNCTION__);
		g_dst_pl = dst_pl = NULL;
	} else {
		memset(g_dst_pl, 0, (NAT_MAX_DSTNUM * sizeof(struct dst_pl_s)));
		dst_pl = g_dst_pl;
	}

	sleep(10);
//	if (dnatconfig_curr)
//		rte_memcpy(&local_dtable, &dtable[NAT_MAX_DSTNUM], sizeof(local_dtable[0]) * NAT_MAX_DSTNUM);
//	else
//		rte_memcpy(&local_dtable, &dtable[0], sizeof(local_dtable[0]) * NAT_MAX_DSTNUM);
	if (dnatconfig_curr)
		local_dtable = &dtable[NAT_MAX_DSTNUM];
	else
		local_dtable = &dtable[0];

	RUNNING_LOG_INFO("%s : start\n",__FUNCTION__);

	tmp_dnattable = (struct dnat_item *)malloc(NAT_MAX_DSTNUM * sizeof(struct dnat_item));
	if (!tmp_dnattable)
	{
		RUNNING_LOG_ERROR("%s: Failed to malloc dnat_item err=%s\n", __FUNCTION__, strerror(errno));
		return NULL;
	}

	my_lcore = rte_lcore_id();

	//memset(nat_bandwidth, 0, sizeof(nat_bandwidth));
	for (i=0; i<NAT_MAX_DSTNUM; i++)
	{
//		nat_bandwidth[i] = 1000;
//		nat_forwardlevel[i] = 4;
//		nat_viptoa[i] = 0;
		nat_linkcount[i] = 0;
	}

	while(!term_pending)
	{
		sleep(10);
		if(unlikely(pre_dtable != dnatconfig_curr))
		{
			RUNNING_LOG_INFO("core %d:%s dnatconfig change to %d\n", my_lcore, __FUNCTION__,dnatconfig_curr);
			retry = 1;
			pre_dtable=dnatconfig_curr;

//			if (dnatconfig_curr)
//				rte_memcpy(&local_dtable, &dtable[NAT_MAX_DSTNUM], sizeof(local_dtable[0]) * NAT_MAX_DSTNUM);
//			else
//				rte_memcpy(&local_dtable, &dtable[0], sizeof(local_dtable[0]) * NAT_MAX_DSTNUM);

			if (dnatconfig_curr)
				local_dtable = &dtable[NAT_MAX_DSTNUM];
			else
				local_dtable = &dtable[0];
		}

		memset(rev, 0, sizeof(rev));

		ret = get_bandwidth_version(ipaddr, port, usrname, password, rev);
		if (0 == ret)
		{
			RUNNING_LOG_INFO("core %d:get_bandwidth_version fail\n", my_lcore);
			continue;
		}

		p = strchr(rev, '{');
		pJson = cJSON_Parse(p);
		if(pJson == NULL)
		{
			RUNNING_LOG_INFO("core %d:%s cJSON_Parse fail\n", my_lcore, __FUNCTION__);
			RUNNING_LOG_INFO("core %d:%s rev=%s\n", my_lcore, __FUNCTION__,rev);
			continue;
		}

		t = cJSON_GetObjectItem(pJson,"type");
		if( t )
		{
			if (strcmp(t->valuestring, "defense_ip"))
			{
				RUNNING_LOG_DEBUG("core %d:%s type fail\n", my_lcore, __FUNCTION__);
				continue;
			}
			t = cJSON_GetObjectItem(pJson,"hash");
			if (t)
			{
				if (strcmp(t->valuestring, str_id))
				{
					strncpy(str_id, t->valuestring, 32);
					RUNNING_LOG_INFO("core %d:%s remote bandwidth version change\n", my_lcore, __FUNCTION__);
				}
				else{
					RUNNING_LOG_DEBUG("core %d:%s get the same remote bandwidth version\n", my_lcore, __FUNCTION__);
					if (0 == retry)
						continue;
				}

			}else{
				continue;
			}

		}else{
			RUNNING_LOG_INFO("core %d:%s get type fail\n", my_lcore, __FUNCTION__);
			continue;
		}

		for( i = 0; i < NAT_MAX_DSTNUM; i++)
		{
			dst_pl[i].ip.tcp_bps = 1000;
			dst_pl[i].dstip = 0;
		}

		for( i = 0; i < NAT_MAX_DSTNUM; i++)
		{
			if(0 != local_dtable[i].dst_ip)
			{
				dst_pl[local_dtable[i].dstip_idx].dstip = local_dtable[i].dst_ip;
#ifdef BOND_2DIR
				dst_pl[local_dtable[i].dstip_idx].fwd_level = 4;
#endif
				memset(rev, 0, sizeof(rev));
				ret = get_natconfig_bandwidth(ipaddr, port, usrname, password, local_dtable[i].dst_ip, rev);
				if (0 == ret)
				{
					RUNNING_LOG_ERROR("core %d:%s:get_natconfig_bandwidth fail\n", my_lcore,__FUNCTION__);
					retry = 1;
					sleep(5);
					continue;
				}

				p = strchr(rev, '{');
				pJson = cJSON_Parse(p);
				if(pJson == NULL)
				{
					RUNNING_LOG_ERROR("core %d:%s:get_natconfig_bandwidth cJSON_Parse fail\n", my_lcore,__FUNCTION__);
					retry = 1;
					sleep(5);
					continue;
				}
//				t = cJSON_GetObjectItem(pJson,"ip");
//				if (t && inet_aton(tt->valuestring, &addr))
//				{
//					if (rte_be_to_cpu_32(addr.s_addr) !=  local_dtable[i].dst_ip)
//					{
//						retry = 1;
//						sleep(1);
//						continue;
//					}
//					tt = cJSON_GetObjectItem(pJson,"bandwidth");
//					if (tt && tt->valueint >= 0 && nat_bandwidth[i] != tt->valueint)
//					{
//						if (0 == tt->valueint)
//							nat_bandwidth[i] = 100000;
//						else
//							nat_bandwidth[i] = tt->valueint;
//						RUNNING_LOG_INFO("%s : nat_bandwidth[%d] =%dM\n",__FUNCTION__, i, nat_bandwidth[i]);
//					}
//				}

				RUNNING_LOG_DEBUG("%s:i(%u) index:%d, ip %u.%u.%u.%u:\n",__FUNCTION__, i, local_dtable[i].dstip_idx,
						local_dtable[i].dst_ip>>24, (local_dtable[i].dst_ip>>16)&0xff,(local_dtable[i].dst_ip>>8)&0xff,
						(local_dtable[i].dst_ip)&0xff);
#ifdef BOND_2DIR
				tt = cJSON_GetObjectItem(pJson,"forward_level");
				if (tt)
				{
					if ( tt->valueint >= 0)
					{
						dst_pl[local_dtable[i].dstip_idx].fwd_level = tt->valueint;
					} else {
						dst_pl[local_dtable[i].dstip_idx].fwd_level = 4;
					}
//					RUNNING_LOG_INFO("%s: ip 0x%x, forward_level[%d] = %d\n",__FUNCTION__,
//						local_dtable[i].dst_ip, local_dtable[i].dstip_idx, nat_forwardlevel[local_dtable[i].dstip_idx]);
					RUNNING_LOG_DEBUG("%s: ip 0x%x, forward_level[%d] = %d\n",__FUNCTION__,
						local_dtable[i].dst_ip, local_dtable[i].dstip_idx, dst_pl[local_dtable[i].dstip_idx].fwd_level);
				}
#endif

				tt = cJSON_GetObjectItem(pJson,"bandwidth");
				if (tt)
				{
					retry = 0;
					if ( tt->valueint >= 0)
					{
						if (0 == tt->valueint) {
							dst_pl[local_dtable[i].dstip_idx].ip.tcp_bps = 100000;
						} else {
							dst_pl[local_dtable[i].dstip_idx].ip.tcp_bps = tt->valueint;
						}
					}else{
						dst_pl[local_dtable[i].dstip_idx].ip.tcp_bps = 100;
					}
//					RUNNING_LOG_INFO("%s:ip 0x%x, nat_bandwidth[%d] = %dM\n",__FUNCTION__,
//						local_dtable[i].dst_ip, local_dtable[i].dstip_idx, nat_bandwidth[local_dtable[i].dstip_idx]);
				}
				else{
					dst_pl[local_dtable[i].dstip_idx].ip.tcp_bps = 100;
					retry = 1;
					sleep(2);
					RUNNING_LOG_DEBUG("core %d:get 0x%x bandwidth fail\n", my_lcore, local_dtable[i].dst_ip);
					RUNNING_LOG_DEBUG("core %d:%s msg=%s\n", my_lcore, __FUNCTION__,p);
				}

                tt = cJSON_GetObjectItem(pJson,"forward_realip");
				if (tt && (tt->type == cJSON_True))
				{
					//retry = 0;
					dst_pl[local_dtable[i].dstip_idx].toa_flag = TRUE;

					RUNNING_LOG_DEBUG("%s: ip %u.%u.%u.%u, need add toa\n",__FUNCTION__,
						local_dtable[i].dst_ip>>24, (local_dtable[i].dst_ip>>16)&0xff,(local_dtable[i].dst_ip>>8)&0xff,(local_dtable[i].dst_ip)&0xff);

				}else{
					dst_pl[local_dtable[i].dstip_idx].toa_flag = FALSE;
				}

				dst_pl[local_dtable[i].dstip_idx].src_bl.tcp_concurrent_new_connections=0;
				dst_pl[local_dtable[i].dstip_idx].src_bl.udp_connections=0;
				dst_pl[local_dtable[i].dstip_idx].src_bl.pps=0;
				dst_pl[local_dtable[i].dstip_idx].src_bl.tcp_and_udp_connections=0;
				dst_pl[local_dtable[i].dstip_idx].src_bl.tcp_concurrent_half=0;
				dst_pl[local_dtable[i].dstip_idx].src_bl.udp_concurrent_new_connections=0;
				dst_pl[local_dtable[i].dstip_idx].src_bl.tcp_connections=0;
				dst_pl[local_dtable[i].dstip_idx].src_bl.bps=0;
				dst_pl[local_dtable[i].dstip_idx].src_bl.icmp=0;
				dst_pl[local_dtable[i].dstip_idx].src_bl.tcp_and_udp_concurrent_new_connections=0;

				tt = cJSON_GetObjectItem(pJson,"threshold");
				if(tt)
				{
					//block
					ttt = cJSON_GetObjectItem(tt,"src_block_tcp_concurrent_new_connections");
					if(ttt)
						{
						dst_pl[local_dtable[i].dstip_idx].src_bl.tcp_concurrent_new_connections=(uint32_t)ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"src_block_udp_connections");
					if(ttt)
						{
						dst_pl[local_dtable[i].dstip_idx].src_bl.udp_connections=(uint32_t)ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"src_block_pps");
					if(ttt)
						{
						dst_pl[local_dtable[i].dstip_idx].src_bl.pps=(uint32_t)ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"src_block_tcp_and_udp_connections");
					if(ttt)
						{
						dst_pl[local_dtable[i].dstip_idx].src_bl.tcp_and_udp_connections=(uint32_t)ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"src_block_tcp_concurrent_half");
					if(ttt)
						{
						dst_pl[local_dtable[i].dstip_idx].src_bl.tcp_concurrent_half=(uint32_t)ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"src_block_udp_concurrent_new_connections");
					if(ttt)
						{
						dst_pl[local_dtable[i].dstip_idx].src_bl.udp_concurrent_new_connections=(uint32_t)ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"src_block_tcp_connections");
					if(ttt)
						{
						dst_pl[local_dtable[i].dstip_idx].src_bl.tcp_connections=(uint32_t)ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"src_block_bps");
					if(ttt)
						{
						dst_pl[local_dtable[i].dstip_idx].src_bl.bps=(uint64_t)ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"src_block_icmp");
					if(ttt)
						{
						dst_pl[local_dtable[i].dstip_idx].src_bl.icmp=(uint64_t)ttt->valueint;
						}

					ttt = cJSON_GetObjectItem(tt,"src_block_tcp_and_udp_concurrent_new_connections");
					if(ttt)
						{
						dst_pl[local_dtable[i].dstip_idx].src_bl.tcp_and_udp_concurrent_new_connections=(uint32_t)ttt->valueint;
						}
//					RUNNING_LOG_INFO("%s: ip %u.%u.%u.%u, thread src_block cfg data:\n",__FUNCTION__,
//						local_dtable[i].dst_ip>>24, (local_dtable[i].dst_ip>>16)&0xff,(local_dtable[i].dst_ip>>8)&0xff,(local_dtable[i].dst_ip)&0xff);
//					RUNNING_LOG_INFO("%s: tcp_concurrent_new_connections: %d\n",__FUNCTION__,dst_pl[local_dtable[i].dstip_idx].src_bl.tcp_concurrent_new_connections);
//					RUNNING_LOG_INFO("%s: udp_connections: %d\n",__FUNCTION__,dst_pl[local_dtable[i].dstip_idx].src_bl.udp_connections);
//					RUNNING_LOG_INFO("%s: pps: %d\n",__FUNCTION__,dst_pl[local_dtable[i].dstip_idx].src_bl.pps);
//					RUNNING_LOG_INFO("%s: tcp_and_udp_connections: %d\n",__FUNCTION__,dst_pl[local_dtable[i].dstip_idx].src_bl.tcp_and_udp_connections);
//					RUNNING_LOG_INFO("%s: tcp_concurrent_half: %d\n",__FUNCTION__,dst_pl[local_dtable[i].dstip_idx].src_bl.tcp_concurrent_half);
//					RUNNING_LOG_INFO("%s: udp_concurrent_new_connections: %d\n",__FUNCTION__,dst_pl[local_dtable[i].dstip_idx].src_bl.udp_concurrent_new_connections);
//					RUNNING_LOG_INFO("%s: tcp_connections: %d\n",__FUNCTION__,dst_pl[local_dtable[i].dstip_idx].src_bl.tcp_connections);
//					RUNNING_LOG_INFO("%s: bps: %d\n",__FUNCTION__,dst_pl[local_dtable[i].dstip_idx].src_bl.bps);
//					RUNNING_LOG_INFO("%s: icmp: %d\n",__FUNCTION__,dst_pl[local_dtable[i].dstip_idx].src_bl.icmp);
//					RUNNING_LOG_INFO("%s: tcp_and_udp_concurrent_new_connections: %d\n",__FUNCTION__,dst_pl[local_dtable[i].dstip_idx].src_bl.tcp_and_udp_concurrent_new_connections);
				}else{

				}

				usleep(100000);
			}
		}
                viptoa_curr++;

	}

	if (g_dst_pl) {
		free(g_dst_pl);
		g_dst_pl = dst_pl = NULL;
	}

	if (tmp_dnattable)
	{
		free(tmp_dnattable);
		tmp_dnattable=NULL;
	}

	RUNNING_LOG_INFO("%s : thread exit now\n",__FUNCTION__);
}

#define __EXCP_LOG_FILE__

static inline void __attribute__((always_inline))
format_json_src_station_event(
	char *buf, uint32_t dst_ip, uint16_t dst_port, uint32_t nat_ip, uint16_t nat_port, int warnning
	)
{
	time_t now;
	int len;

	time(&now);

	sprintf(buf, "{\"timestamp\": %llu,"
		"\"region\":\"%s\","
		"\"nat_ip\":\"%u.%u.%u.%u\","
		"\"nat_port\":\"%u\","
		"\"real_ip\":\"%u.%u.%u.%u\","
		"\"real_port\":\"%u\","
		"\"event\":\"%s\"}",
		(uint64_t)now,me.natconfig.region_tag,
		(dst_ip>>24),(dst_ip>>16)&0xff,(dst_ip>>8)&0xff,(dst_ip)&0xff,
		(dst_port),
		(nat_ip>>24),(nat_ip>>16)&0xff,(nat_ip>>8)&0xff,(nat_ip)&0xff,
		(nat_port),
		warnning ? "Disconnected": "Connected");

#ifndef __EXCP_LOG_FILE__

	len=strlen(buf);
	if (rd_kafka_produce(me.ch_kafka.channel_kafka[TOPIC_SRC_STATION_EVENT].rkt, RD_KAFKA_PARTITION_UA,
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
			rd_kafka_topic_name(me.ch_kafka.channel_kafka[TOPIC_SRC_STATION_EVENT].rkt),
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
#endif /* #ifndef __EXCP_LOG_FILE__ */
}

void *nat_rip_status_thread(void *args)
{
	char rev[MAX_JSON_LEN];
	char *p = NULL;
	cJSON * pJson = NULL;
	cJSON * pArrayItem = NULL;
	cJSON *t;
	int retry = 0;
	int ret = 0;
	int i,j,k,n;
	struct in_addr addr;
	int my_lcore;
	char str_id[33]={0};
	struct dnat_item * tmp_dnattable;
	char *ipaddr = me.natconfig.addr;
	int port = me.natconfig.port;
	char *usrname = me.natconfig.usrname;
	char *password = me.natconfig.password;

	struct dnat_item *local_dtable;
	char buf[512];

#ifdef __EXCP_LOG_FILE__
	char filepath[128];
	FILE *local_rip_excp_fp = NULL;

	sprintf(filepath,"%s/root_station_excp.txt", me.root_dir);
	if ((local_rip_excp_fp = fopen(filepath, "w+")) == NULL) {
		RUNNING_LOG_INFO("%s:open file failed", __FUNCTION__);
	}
#endif	/* #ifdef __EXCP_LOG_FILE__ */

	RUNNING_LOG_INFO("%s : start\n",__FUNCTION__);

	my_lcore = rte_lcore_id();

	tmp_dnattable = (struct dnat_item *)malloc(NAT_MAX_DSTNUM * sizeof(struct dnat_item));
	if (!tmp_dnattable)
	{
		RUNNING_LOG_ERROR("%s: Failed to malloc dnat_item err=%s\n", __FUNCTION__, strerror(errno));
		return NULL;
	}

	//memset(nat_bandwidth, 0, sizeof(nat_bandwidth));
	sleep(10);
	int pre_dtable=dnatconfig_curr;

	if (dnatconfig_curr)
		local_dtable = &dtable[NAT_MAX_DSTNUM];
	else
		local_dtable = &dtable[0];

	//default for not limit
//	memset(rip_linkstate, 0, sizeof(rip_linkstate));

	while(!term_pending)
	{
		sleep(1);
		if(unlikely(pre_dtable != dnatconfig_curr))
		{
			pre_dtable=dnatconfig_curr;

			if (dnatconfig_curr)
				local_dtable = &dtable[NAT_MAX_DSTNUM];
			else
				local_dtable = &dtable[0];
		}

		for( i = 0; i < NAT_MAX_DSTNUM; i++)
		{
			if(0 != local_dtable[i].dst_ip)
			{
				for( j = 0; j < NAT_MAX_RULENUM; j++)
				{
					if (0 != local_dtable[i].rule[j].nat_ip[0])
					{
						for( k = 0; k < NAT_MAX_NATIPNUM; k++)
						{
							if (0 != local_dtable[i].rule[j].nat_ip[k])
							{
								int n;
								uint32_t local_rip_link = (rip_linkstate[local_dtable[i].dstip_idx][j] >> k);

								local_rip_link &= 1;

								for (n=0; n<local_dtable[i].rule[j].nat_debouncing[k];n++)
									{
										memset(rev, 0, sizeof(rev));
										ret = get_rip_status(ipaddr, port, usrname, password,  local_dtable[i].rule[j].nat_ip[k],
											local_dtable[i].rule[j].nat_port, local_dtable[i].rule[j].proto, rev);
										if (0 == ret)
										{
											RUNNING_LOG_INFO("core %d:get_rip_status fail\n", my_lcore);
											sleep(10);
											continue;
										}

										p = strchr(rev, '{');
										pJson = cJSON_Parse(p);
										if(pJson == NULL)
										{
											RUNNING_LOG_INFO("%s cJSON_Parse fail\n", __FUNCTION__);
											RUNNING_LOG_INFO("%s rev=%s\n", __FUNCTION__,rev);
											sleep(10);
											continue;
										}
										t = cJSON_GetObjectItem(pJson,"status");
										if (t)
										{
											if (local_rip_link && ( !strcmp(t->valuestring, "OK")))
												{
													rip_linkstate[local_dtable[i].dstip_idx][j] |= (1ULL<<k);
													break;
												}
											else if (!local_rip_link && !strcmp(t->valuestring, "Fail"))
												{
													rip_linkstate[local_dtable[i].dstip_idx][j] &= ~(1ULL<<k);
													break;
												}
											else if (!local_rip_link && !strcmp(t->valuestring, "OK"))
												{
													if (n == local_dtable[i].rule[j].nat_debouncing[k]-1){

														format_json_src_station_event(buf,
															local_dtable[i].dst_ip,local_dtable[i].rule[j].dst_port,
															local_dtable[i].rule[j].nat_ip[k],local_dtable[i].rule[j].nat_port,NAT_SRC_STATION_OK);

#ifdef __EXCP_LOG_FILE__
														if (local_rip_excp_fp)
															fwrite(buf,1,strlen(buf), local_rip_excp_fp);
#endif	/* #ifdef __EXCP_LOG_FILE__ */


														rip_linkstate[local_dtable[i].dstip_idx][j] |= (1ULL<<k);
														break;
													}
												}
											else if (local_rip_link && !strcmp(t->valuestring, "Fail"))
												{
													if (n == local_dtable[i].rule[j].nat_debouncing[k]-1){

														format_json_src_station_event(buf,
															local_dtable[i].dst_ip,local_dtable[i].rule[j].dst_port,
															local_dtable[i].rule[j].nat_ip[k],local_dtable[i].rule[j].nat_port,NAT_SRC_STATION_ERR);

#ifdef __EXCP_LOG_FILE__
														if (local_rip_excp_fp)
															fwrite(buf,1,strlen(buf), local_rip_excp_fp);
#endif	/* #ifdef __EXCP_LOG_FILE__ */

														rip_linkstate[local_dtable[i].dstip_idx][j] &= ~(1ULL<<k);
														break;
													}
												}

											RUNNING_LOG_DEBUG("%s ping ip 0x%x, result is %s\n",__FUNCTION__,
												local_dtable[i].rule[j].nat_ip[k], t->valuestring);
										}
										else{
											RUNNING_LOG_DEBUG("%s get status fail\n", __FUNCTION__);
										}
										usleep(10000);
										//sleep(1);
									}
							}
						}
					}
					else {
						rip_linkstate[local_dtable[i].dstip_idx][j] = 0;
					}
				}
			}
//			else{
//				for( n = i; n < NAT_MAX_DSTNUM; n++)
//				{
//					memset(&rip_linkstate[n][0], 0, sizeof(rip_linkstate[n][0])*NAT_MAX_RULENUM);
//				}
//			}
		}

		sleep(10);

	}

	if (tmp_dnattable)
	{
		free(tmp_dnattable);
		tmp_dnattable=NULL;
	}

#ifdef __EXCP_LOG_FILE__
	if (local_rip_excp_fp){
		fclose(local_rip_excp_fp);
		local_rip_excp_fp=NULL;
		}
#endif	/* #ifdef __EXCP_LOG_FILE__ */

	RUNNING_LOG_INFO("%s : thread exit now\n",__FUNCTION__);
}
#endif


int m_conf_preinit(__attribute__((unused)) void *m)
{
	char cbuf[PATH_MAX];
	struct stat buf;
	int r;
	FILE *fp;

	EARLY_LOG_DEBUG("%s\n",__FUNCTION__);

#if 0//slist test

	struct slist_header hh,hh2;
	struct slist_head *x;
	struct aa ss[10];

	INIT_SLIST_HEADER(&hh);
	INIT_SLIST_HEADER(&hh2);

	for(r=0;r<10;r++)
		ss[r].no=r+1;

	for(r=0;r<10;r++)
		slist_add_tail(&ss[r].list,&hh);

	slist_for_each(x,&hh,r)
		{
		struct aa *p=list_entry(x,struct aa,list);
		EARLY_LOG_DEBUG("ss[%d]=%d\n",r,p->no);
		}

	for(r=0;r<5;r++)
		{
		x=slist_del_first(&hh);

		slist_add(x,&hh2);
		}

	slist_for_each(x,&hh2,r)
		{
		struct aa *p=list_entry(x,struct aa,list);
		EARLY_LOG_DEBUG("hh2 %d=%d\n",r,p->no);
		}


	slist_splice_tail(&hh2,&hh);

	slist_for_each(x,&hh,r)
		{
		struct aa *p=list_entry(x,struct aa,list);
		EARLY_LOG_DEBUG("splice %d=%d\n",r,p->no);
		}
#endif

/*
	sprintf(cbuf, "rmmod igb_uio");
	r=system(cbuf);
	EARLY_LOG_DEBUG("aaaaaaaaaaaaaaaaaaa r=%d\n",__FUNCTION__,r);

	sprintf(cbuf, "modprobe -r uio");
	r=system(cbuf);
	EARLY_LOG_DEBUG("bbbbbbbbbbbbbbbbbbbbb r=%d\n",__FUNCTION__,r);
*/
	hw_log_off=1;
	mon_log_off=1;

	//get mode
	memset(&me,0,sizeof(me));
	default_curr=0;
	global_policy=0;
	dnatconfig_curr = 0;
	snatconfig_curr = 0;
	memset(default_policy,0,sizeof(default_policy[0])*2);
	memset(lcore,0,sizeof(lcore[0])*MAX_CPU);
	memset(snat_table, 0, sizeof(snat_table[0]) * MAX_NAT_RULENUM);
	memset(dnat_table, 0, sizeof(dnat_table[0]) * MAX_NAT_RULENUM);
	memset(nonat_table, 0, sizeof(nonat_table[0]) * MAX_NAT_RULENUM);
	memset(dtable, 0, sizeof(dtable[0]) * NAT_MAX_DSTNUM*2);
	memset(stable, 0, sizeof(stable[0]) * NAT_MAX_DSTNUM*2);

//	memcpy(me.settle_setting.gw_bonding_inoutvlan.in_mac, "ffffff", 6);

	if(parser_id(DEFAULT_ID_FILE)==MM_FAIL)
		{
		EARLY_LOG_ERROR("id file parser fail\n");
		exit(1);
		}

	//check env
	if(check_module("uio","uio",1)==MM_FAIL)
	{
		EARLY_LOG_ERROR("check_module uio fail\n");
		exit(1);
	}

	if(check_module("igb_uio","./igb_uio.ko",0)==MM_FAIL)
	{
        EARLY_LOG_ERROR("check_module igb_uio fail\n");
		exit(1);
    }
#ifdef __MAIN_LOOP_KNI__
	if(check_module("rte_kni","./rte_kni.ko",0)==MM_FAIL)
	{
        EARLY_LOG_ERROR("check_module rte_kni fail\n");
		exit(1);
    }
#endif
#ifdef CONFIG_BONDING
	if(check_module("8021q","8021q",1)==MM_FAIL)
		exit(1);

	if(check_module("bonding","bonding",1)==MM_FAIL)
		exit(1);
#endif

	INIT_LIST_HEAD(&port_list);
	INIT_LIST_HEAD(&zk_server_list);

#ifdef WF_NAT
//	if (MM_FAIL == wf_get_portdesc(1))
//	{
//        EARLY_LOG_ERROR("check_module rte_kni fail\n");
//		exit(1);
//    }
#endif

	parser_mode(DEFAULT_MODE_FILE);

	// get zk
	if(me.mode==MODE_CLUSTER_ZK)
		{
			if(parser_zk_conf(DEFAULT_ZK_CONF_FILE)==MM_FAIL)
				{
				EARLY_LOG_ERROR("zk_conf file parser fail\n");
				exit(1);
				}

			if(list_empty(&zk_server_list))
				{
				EARLY_LOG_ERROR("zk_server_list empty\n");
				exit(1);
				}

			if(zk_init()!=MM_SUCCESS)
				{

				EARLY_LOG_DEBUG("%s zk_init fail\n",__FUNCTION__);
				return MM_FAIL;
				}
		}

	sprintf(cbuf, "mkdir -p %s -m 777",HUGETLBFS_MOUNT_POINT);
	system(cbuf);

	while(umount(HUGETLBFS_MOUNT_POINT) == 0);

local_config:

	if(parser_config(DEFAULT_CONFIG_FILE)==MM_FAIL)
		{
		EARLY_LOG_ERROR("%s : config parse fail,check it\n",__FUNCTION__);
		term_pending=1;
		exit(1);
		}

	if(parser_defaultpolicy(DEFAULT_DEFAULT_POLICY_FILE)==MM_FAIL)
		{
		EARLY_LOG_ERROR("%s : default policy parse fail,check it\n",__FUNCTION__);
		term_pending=1;
		exit(1);
		}

	if(parser_snatconfig(DEFAULT_SNAT_CONFIG_FILE) == MM_FAIL)
	{
		EARLY_LOG_ERROR("%s : default snat config parse fail,check it\n",__FUNCTION__);
		term_pending=1;
		exit(1);
	}

	if(parser_dnatconfig(DEFAULT_DNAT_CONFIG_FILE) == MM_FAIL)
	{
		EARLY_LOG_ERROR("%s : default dnat config parse fail,check it\n",__FUNCTION__);
		term_pending=1;
		exit(1);
	}

	EARLY_LOG_DEBUG("%s finished\n",__FUNCTION__);

	return MM_SUCCESS;
}

int m_conf_init(__attribute__((unused)) void *m)
{
	int rc;

	EARLY_LOG_DEBUG("%s\n",__FUNCTION__);


	pthread_cond_init(&conf_cond, NULL);
	pthread_mutex_init(&conf_mutex, NULL);

	rc = pthread_create(&conf_thread_id, NULL,  &conf_thread, NULL);
	if (rc != 0) {
		RUNNING_LOG_ERROR("Failed to create conf thread, err=%s\n", strerror(errno));
		//return MM_FAIL;
		exit(1);
	}

	rc = pthread_create(&natconf_thread_id, NULL,  &natconf_thread, NULL);
	if (rc != 0) {
		RUNNING_LOG_ERROR("Failed to create natconf thread, err=%s\n", strerror(errno));
		exit(1);
	}

	rc = pthread_create(&nat_dstip_p_det_thread_id, NULL,  &nat_dstip_p_det_thread, NULL);
	if (rc != 0) {
		RUNNING_LOG_ERROR("Failed to create nat_dstip_p_det_thread, err=%s\n", strerror(errno));
		exit(1);
	}

	rc = pthread_create(&nat_ripstatus_thread_id, NULL,  &nat_rip_status_thread, NULL);
	if (rc != 0) {
		RUNNING_LOG_ERROR("Failed to create nat_natip_status_thread, err=%s\n", strerror(errno));
		exit(1);
	}

#if 0//test
	kafka_init();//kafka test
#endif

	return MM_SUCCESS;
}

int m_conf_deinit(__attribute__((unused)) void *m)
{
//	char cbuf[PATH_MAX];
	EARLY_LOG_DEBUG("%s...\n",__FUNCTION__);
	while(umount(HUGETLBFS_MOUNT_POINT) == 0);
/*
	sprintf(cbuf, "rmmod igb_uio");
	system(cbuf);

	sprintf(cbuf, "modprobe -r uio");
	system(cbuf);
*/
/*
	struct zk_s_list *dd, *temp;

	if(!list_empty(&zk_server_list))
		list_for_each_entry_safe(dd,temp,&zk_server_list,list){
			list_del_init(&dd->list);
			EARLY_LOG_INFO("cleanup zk = %s %d\n",dd->ip,dd->port);
			free(dd->ip);
			free(dd);
		}
*/

	EARLY_LOG_DEBUG("%s finished.\n",__FUNCTION__);

	return MM_SUCCESS;
}

char * mystrdup (const char *s)
{
  size_t len = strlen (s) + 1;
  void *buf = malloc (len);
  memset(buf, 0, len);
  if (buf == NULL)
    return NULL;
  return (char *) memcpy (buf, s, len);
}

int wf_get_portdesc(int verbose)
{
	FILE * fd;
	int	idx, i;
	char buff[PORT_STRING_SIZE], ch[32], *p;
	struct dev_list *d;
	struct rte_pci_addr pciAddr[MAX_DEV];

	// Only parse the Ethernet cards on the PCI bus.
//	fd = popen("lspci -D | grep SFP", "r");
    fd = popen("lspci -D | grep 10-Gigabit", "r");
	if ( fd == NULL )
		EARLY_LOG_DEBUG("*** Unable to do lspci may need to be installed");

	if ( verbose )
		EARLY_LOG_DEBUG("%s: All ports in system\n",__FUNCTION__);

	idx = 0;
	while( fgets(buff, sizeof(buff), fd) ) {
		p = &buff[0];

		// add a null at the end of the string.
		p[strlen(buff)-1] = 0;

		// Decode the 0000:00:00.0 PCI device address.
		pciAddr[idx].domain		= strtol(  p, &p, 16);
		pciAddr[idx].bus		= strtol(++p, &p, 16);
		pciAddr[idx].devid		= strtol(++p, &p, 16);
		pciAddr[idx].function	= strtol(++p, &p, 16);

		i = 0;
		p = &buff[0];
		memset(ch, 0, 32);
		while(*p != ' ' && p!= 0)
		{
			ch[i++] = *p;
			p++;
		}

		d=(struct dev_list *)malloc(sizeof(struct dev_list));
		if(d)
		{
			memset(d,0,sizeof(struct dev_list));
			d->dev_id = mystrdup(ch);
			if(d->dev_id==NULL)
			{
                EARLY_LOG_ERROR("0x%016llx: %s mystrdup fail\n", (1ULL << idx), ch);
				return MM_FAIL;
			}
			INIT_LIST_HEAD(&d->list);
			list_add_tail(&d->list,&port_list);
			me.port_cnt++;
			me.port_mask|=(1<<(me.port_cnt-1));
		}else{
		    EARLY_LOG_ERROR("0x%016llx: %s malloc fail\n", (1ULL << idx), ch);
			return MM_FAIL;
		}

		if ( verbose )
			EARLY_LOG_DEBUG("0x%016llx: %s\n", (1ULL << idx), buff);

		//EARLY_LOG_DEBUG("dev_id:%s\n", d->dev_id);

		if ( ++idx >= MAX_DEV )
			break;
	}

	pclose(fd);
	if ( verbose )
		EARLY_LOG_DEBUG("Found %d ports\n", idx);

	return idx;
}


