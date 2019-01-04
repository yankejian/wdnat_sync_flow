#ifndef __M_CONF_H
#define __M_CONF_H

#define DEFAULT_PID_FILE	"/var/run/fw.pid"

#define DEFAULT_CONFIG_DIR	"./"
#define DEFAULT_ROOT_DIR	"./"

#define DEFAULT_PCAP_DIR	"pcap"
#define DEFAULT_CONFIG_FILE	"./config"
#define DEFAULT_ID_FILE	"./id"
#define DEFAULT_MODE_FILE	"./mode"
#define DEFAULT_ZK_CONF_FILE	"./zk_conf"
#define DEFAULT_SERVER_LIST_FILE	"./server-list"
#define DEFAULT_MON_IP_FILE	"./mon_ip"
#define DEFAULT_MON_NETPORT_FILE	"./mon_netport"
#define DEFAULT_DEFAULT_POLICY_FILE	"./default_policy"
#define DEFAULT_NAT_CONFIG_FILE	"./nat_config"
#define DEFAULT_DNAT_CONFIG_FILE	"./dnat_config"
#define DEFAULT_SNAT_CONFIG_FILE	"./snat_config"

#define HUGETLBFS_MOUNT_POINT 	"/mnt/huge"
#define NR_HUGEPAGE_2M_NODE_0 	"/sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages"
#define NR_HUGEPAGE_2M_NODE_1 	"/sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages"
#define NR_HUGEPAGE_1G_NODE_0 	"/sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages"
#define NR_HUGEPAGE_1G_NODE_1 	"/sys/devices/system/node/node1/hugepages/hugepages-1048576kB/nr_hugepages"

#define DEFAULT_RUNNING_LOG		"running.log"
#define DEFAULT_HW_LOG			"hw.log"
#define DEFAULT_FLOW_LOG		"flow.log"
#define DEFAULT_ALERT_LOG		"alert.log"
#define DEFAULT_MON_LOG			"mon.log"

#define VERSION_NUM				"WD_NAT_V0.2.2.2"
#define VERSION_INFO			"2018102401: 1. fix bug of cannot send pkt through queue 0 based on port0 occasionally"

#define DEFAULT_NATCONFIG_VER_PATH		"/api/v1.0/version/dnat"
#define DEFAULT_NATCONFIG_PATH			"/api/v1.0/nat/dnat"
#define DEFAULT_BANDWIDTH_VER_PATH		"/api/v1.0/version/defense_ip"
#define DEFAULT_BANDWIDTH_PATH			"/api/v1.0/defense_ip"
#define DEFAULT_RIP_LINKSTAT_PATH		"/api/v1.0/check/port"

#define SETTLE_MODE_HALF	0
#define SETTLE_MODE_FULL	1


#define PAGE_2M				(1<<21)
#define PAGE_1G				(1<<30)

#define M_CLUSTER_TOKEN_ZK	"cluster-zk"

#define MODE_LOCAL		0
#define MODE_CLUSTER_ZK	1

#define T_FW_TOKEN	"fw"
#define T_SJ_TOKEN	"sj"
#define T_KD_TOKEN	"kd"

#define TYPE_FW			0
#define TYPE_SJ			1
#define TYPE_KD			2

#define CONF_TIMEOUT	1

#define STATE_POLICY_G	0x80
#define STATE_FILTER_START	0x1
#define STATE_OUT_LIMIT	0x2

#define MAX_NAT_RULENUM	200
#define FILE_MON_CNT	8

#define NAT_MAX_DSTNUM	256
#define NAT_MAX_RULENUM	500		//100
#define NAT_MAX_NATIPNUM	20
#define NAT_MAX_SIPNUM	16

#define PORT_STRING_SIZE	256
#define MAXLINE 1024
#define MAX_JSON_LEN (MAXLINE*1000)

#define FLOW_NAT_DEAD_TIME_DEF	180

enum
{
	NAT_IP_NULL=0,
	NAT_IP_VIP,
	NAT_IP_SRCWEB
};

enum{
	POLICY_ACT_FORWARD=0,
	POLICY_ACT_DROP,
	POLICY_ACT_PCAP,
	POLICY_ACT_KERNEL,
#ifdef __INTER_CONN_IP__
	POLICY_ACT_PING_REPLY,
#endif
//	POLICY_ACT_STOLEN,
	POLICY_ACT_MAX
};

enum
{
	REALIP_SEL_RR = 0,
	REALIP_SEL_DEF = REALIP_SEL_RR,
	REALIP_SEL_WRR,
	REALIP_SEL_DSH,
	REALIP_SEL_MAX
};

struct policy{
	uint32_t land_action;
	uint32_t smurf_action;
	uint32_t fraggle_action;
	uint32_t ip_option_action;
	uint32_t ttl0_action;
	uint32_t tcp_bad_action;
	uint32_t nuker_action;
	uint64_t th_pps;
	uint64_t th_bps;
	uint64_t limit_pps;
	uint64_t limit_bps;
#ifdef LIMIT_MODE2
	uint64_t per_limit_pps;
	uint64_t per_limit_bps;
#endif
};

struct nat_item{
	uint32_t proto;
	uint32_t src_minip;
	uint32_t src_maxip;
	uint32_t src_minport;
	uint32_t src_maxport;
	uint32_t dst_minip;
	uint32_t dst_maxip;
	uint32_t dst_minport;
	uint32_t dst_maxport;
	uint32_t nat_minip;
	uint32_t nat_maxip;
	uint32_t nat_minport;
	uint32_t nat_maxport;
};

#define NAT_DEBOUNCING_TIMER_DEF	3
enum {
	NAT_SRC_STATION_OK,
	NAT_SRC_STATION_ERR
};
struct dnat_rule{
	uint16_t dst_port;
	uint16_t nat_port;
	uint16_t proto;
	uint8_t hitcnt;
	uint8_t rip_sum;
	uint8_t	nat_debouncing[NAT_MAX_NATIPNUM];
	uint32_t nat_ip[NAT_MAX_NATIPNUM];
};
struct dnat_item{
	uint32_t dst_ip;
	uint32_t dstip_idx;
	uint32_t fwd_realip_mode;
	struct dnat_rule rule[NAT_MAX_RULENUM];
};

struct snat_item{
	uint32_t dst_ip;
	uint32_t vip_deadtime;
	uint32_t sip_num;
	uint32_t snat_ip[NAT_MAX_SIPNUM];
};

struct nonat_item{
	uint32_t proto;
	uint32_t src_minip;
	uint32_t src_maxip;
	uint32_t src_minport;
	uint32_t src_maxport;
	uint32_t dst_minip;
	uint32_t dst_maxip;
	uint32_t dst_minport;
	uint32_t dst_maxport;
};

extern struct mon_cell_arr mon_netport_core;
extern int mon_netport_sig;
extern struct mon_cell_arr mon_ip_arr;
extern struct mon_cell_arr mon_netport_arr;
extern struct mmb mm_conf;
extern struct mon_file file_mon[FILE_MON_CNT];
extern pthread_t conf_thread_id;
extern pthread_cond_t conf_cond;
extern pthread_mutex_t conf_mutex;
extern struct policy default_policy[2];
extern uint32_t default_curr;
extern uint32_t global_policy;
extern int hw_log_off;
extern int mon_log_off;
//extern int do_pcap_flag;
extern uint32_t dnatconfig_curr;
extern uint32_t snatconfig_curr;
extern uint32_t viptoa_curr;

extern struct nat_item snat_table[MAX_NAT_RULENUM];
extern struct nat_item dnat_table[MAX_NAT_RULENUM];
extern struct nonat_item nonat_table[MAX_NAT_RULENUM];

extern struct dnat_item dtable[NAT_MAX_DSTNUM*2];
extern struct snat_item stable[NAT_MAX_DSTNUM*2];
extern uint32_t rip_linkstate[NAT_MAX_DSTNUM][NAT_MAX_RULENUM];
//extern uint32_t nat_bandwidth[NAT_MAX_DSTNUM];
//extern uint32_t nat_forwardlevel[NAT_MAX_DSTNUM];
//extern uint32_t nat_viptoa[NAT_MAX_DSTNUM];
extern int nat_linkcount[NAT_MAX_DSTNUM];

extern struct dst_pl_s *g_dst_pl;

int check_module(char *m,char *full,int mode);
int parser_mon_netport(char *name);
int parser_server_list(char *name);
int parser_mode(char *name);
int parser_defaultpolicy(char *name);
int parser_config(char *name);
int parser_mon_ip(char *name);
int m_conf_preinit(void *m);
int m_conf_init(void *m);
int m_conf_deinit( void *m);
int parser_natconfig(char *name);
int parser_dnatconfig(char *name);
int parser_snatconfig(char *name);
int get_rip_status(char *hostaddr, int hostport, char *username, char *password,
		uint32_t ip, uint32_t port, int proto, char *rev);

extern char * mystrdup (const char *s) ;

#endif
