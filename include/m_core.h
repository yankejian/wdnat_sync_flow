#ifndef __M_CORE_H
#define __M_CORE_H

#define LIMIT_MODE1	//sig mode
//#define LIMIT_MODE2		//avg mode

#define BOND_IF_NAME	"bond0"
#define BOND1_IF_NAME	"bond1"
//#define DN1_ON

//#define VLAN_ON
#define WF_NAT
#define WF_NAT_DIST
#define BOND_2DIR
//#define BOND_2DIR_VLAN

//#define PIPE_OUT_LIST_MODE
#define IN_OUT_IN1_MODE
//#define PIPE_OUT_RING_MODE

#define FLOOD_SIG_RT
//#define FLOOD_SIG_1S

#define PRIME_VALUE	0xeaad8405
#define CSUM_MANGLED_0 (0xffff)

#define BURST_SZ     32
#define MAX_TX_QUEUE	16

#define FLOW_HASH_ARRAY_OFF	20
#define SRCNAT_HASH_ARRAY_OFF	16
#define IP_HASH_ARRAY_OFF	14
#define DN1_HASH_ARRAY_OFF	16
#define FLOW_HASH_ARRAY_SZ	(1ULL<<FLOW_HASH_ARRAY_OFF)
#define IP_HASH_ARRAY_SZ	(1ULL<<IP_HASH_ARRAY_OFF)
#define TOA_IP_HASH_ARRAY_SZ	(1ULL<<10)
#define DN1_HASH_ARRAY_SZ	(1ULL<<DN1_HASH_ARRAY_OFF)
#define FLOWNAT_HASH_ARRAY_SZ	(1ULL<<FLOW_HASH_ARRAY_OFF)
#define SRCNAT_HASH_ARRAY_SZ	(1ULL<<SRCNAT_HASH_ARRAY_OFF)
#define DNAT_CONFIG_HASH_ARRAY_SZ (1ULL<<IP_HASH_ARRAY_OFF)
#define MAX_TUPLEPAIR	(BURST_SZ*6)
#define TOTAL_MAX_TUPLEPAIR	(MAX_TUPLEPAIR*(MAX_CPU>>1))

#define DIST_RING_SZ	(1024*1024) //8k is too few

#define DIR_IN			0
#define DIR_OUT			1

#define L4_TYPE_UDP		1
#define L4_TYPE_TCP		2

#define MAX_TOPN_PER	10


#define MAX_FLOW_PERCORE	(8000000)
#define FLOW_POINT	(30)

#define IO_TO_SUM_RING_SZ	(8*1024)

#define IO2SUM_BURST_SZ		(64)

#define FLAG(x)		(1ULL<<(x))

#define SUM_ALLOCED			(63)
#define TIMER_SCANED		(62)

#define L4_SUM_ALLOCED		(0)


#define PPS_SHIFT			(37)
#define PPS_OFFSET			(1ULL<<PPS_SHIFT)

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/
#define NR_ICMP_TYPES		18


/* Codes for UNREACH. */
#define ICMP_NET_UNREACH	0	/* Network Unreachable		*/
#define ICMP_HOST_UNREACH	1	/* Host Unreachable		*/
#define ICMP_PROT_UNREACH	2	/* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH	3	/* Port Unreachable		*/
#define ICMP_FRAG_NEEDED	4	/* Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED		5	/* Source Route failed		*/
#define ICMP_NET_UNKNOWN	6
#define ICMP_HOST_UNKNOWN	7
#define ICMP_HOST_ISOLATED	8
#define ICMP_NET_ANO		9
#define ICMP_HOST_ANO		10
#define ICMP_NET_UNR_TOS	11
#define ICMP_HOST_UNR_TOS	12
#define ICMP_PKT_FILTERED	13	/* Packet filtered */
#define ICMP_PREC_VIOLATION	14	/* Precedence violation */
#define ICMP_PREC_CUTOFF	15	/* Precedence cut off */
#define NR_ICMP_UNREACH		15	/* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET		0	/* Redirect Net			*/
#define ICMP_REDIR_HOST		1	/* Redirect Host		*/
#define ICMP_REDIR_NETTOS	2	/* Redirect Net for TOS		*/
#define ICMP_REDIR_HOSTTOS	3	/* Redirect Host for TOS	*/

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL		0	/* TTL count exceeded		*/
#define ICMP_EXC_FRAGTIME	1	/* Fragment Reass time exceeded	*/

#define TIME_DPI	(100)  // us
#define SRCSUM_TIME_DPI	(1000000)  // 1s
#define TIME_1S_US	(1000000)
#define TIME_100MS_US	(100000)
#define TIME_10MS_US	(10000)
#define TIME_1MS_US	(1000)
#define TIMER_LOOP_SZ	(10*60*TIME_1S_US/TIME_DPI) // 10 min
#define DEFAULT_SUMSRC_TIMEOUT		(5*TIME_1S_US/TIME_DPI)

#define NAT_API_LEN		(64)

enum{
	STEP_STARTED=0,
	STEP_IF_INITED,
	STEP_FAIL,
//	STEP_GW_CHECK,
	STEP_OK,
	STEP_MAX
};

enum{
	ACT_DROP=0,
	ACT_FORWARD,
	ACT_STOLEN,
	ACT_CAP,
	ACT_MAX
};

enum{
	F_IPV4=0,
	F_IPV6,
	F_TCP,  // 2
	F_UDP,
	F_ICMP,
	F_IGMP,
	F_FRAG,
	F_TCP_SYN, // 7
	F_TCP_SYN_ACK, // 8
	F_TCP_ACK, // 9
	F_TCP_RST,
	F_TCP_FIN,
	F_TCP_OPTION,
	F_TCP_FLAG_ERR,
	F_DNS,
	F_SSDP,
//	F_CHARGEN,
	F_SNMP,
	F_NTP,
	F_LAND,
	F_SMURF,
	F_FRAGGLE,
	F_NUKER,
	F_IPOPTION,
	F_IPOPTION_ROUTE,
	F_IPOPTION_SOURCE,
	F_IPOPTION_TIMESTAMP,
	F_TRACERT,
	F_MAX
};

enum{
	INTERFACE_MODE_GW_NOBONDING=0,
	INTERFACE_MODE_GW_BONDING,
	INTERFACE_MODE_MAX
};

enum nat_conntrack_dir {
	CT_DIR_ORIGINAL,
	CT_DIR_REPLY,
	CT_DIR_MAX
};

enum nat_manip_type {
	NAT_MANIP_NOT,
	NAT_MANIP_SRC,
	NAT_MANIP_DST,
	NAT_MANIP_FWD,
	NAT_MANIP_NULL
};

enum{
	FLOW_STATE_TCP_SYN=1,
	FLOW_STATE_TCP_SYNACK,
	FLOW_STATE_TCP_ACK,
	FLOW_STATE_TCP_FIN,
	FLOW_STATE_TCP_END,
	FLOW_STATE_UDP,
	FLOW_STATE_MAX
};

#define TCPHDR_FIN 0x01
#define TCPHDR_SYN 0x02
#define TCPHDR_RST 0x04
#define TCPHDR_PSH 0x08
#define TCPHDR_ACK 0x10
#define TCPHDR_URG 0x20
#define TCPHDR_ECE 0x40
#define TCPHDR_CWR 0x80


//struct ethhdr {
//	uint8_t dest[6];
//	uint8_t src[6];
//	uint16_t type;
//}__attribute__((__packed__));

/*
 *	TCP option
 */

#define TCPOPT_NOP		1	/* Padding */
#define TCPOPT_EOL		0	/* End of options */
#define TCPOPT_MSS		2	/* Segment size negotiating */
#define TCPOPT_WINDOW		3	/* Window scaling */
#define TCPOPT_SACK_PERM        4       /* SACK Permitted */
#define TCPOPT_SACK             5       /* SACK Block */
#define TCPOPT_TIMESTAMP	8	/* Better RTT estimations/PAWS */
#define TCPOPT_MD5SIG		19	/* MD5 Signature (RFC2385) */

/*
 *     TCP option lengths
 */

#define TCPOLEN_MSS            4
#define TCPOLEN_WINDOW         3
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_TIMESTAMP      10
#define TCPOLEN_MD5SIG         18

#define TCPOPT_ADDR  254
#define TCPOLEN_ADDR 8		/* |opcode|size|ip+port| = 1 + 1 + 6 */

struct toa_data
{
    __u8   opcode;
    __u8   opsize;
    __u16  port;
    __u32  ip;
}__attribute__((__packed__));

struct tcphdr {
	uint16_t	source;
	uint16_t	dest;
	uint32_t	seq;
	uint32_t	ack_seq;
	uint8_t dataoff;
	uint8_t flags;
	uint16_t	window;
	uint16_t	check;
	uint16_t	urg_ptr;
}__attribute__((__packed__));

struct udphdr {
	uint16_t	source;
	uint16_t	dest;
	uint16_t	len;
	uint16_t	check;
}__attribute__((__packed__));

struct icmphdr {
  uint8_t		type;
  uint8_t		code;
  uint16_t	checksum;
  union {
	struct {
		uint16_t	id;
		uint16_t	sequence;
	} echo;
	uint32_t	gateway;
	struct {
		uint16_t	__unused;
		uint16_t	mtu;
	} frag;
  } un;
}__attribute__((__packed__));

struct igmphdr {
	uint8_t type;
	uint8_t code;		/* For newer IGMP */
	uint16_t csum;
	uint32_t group;
}__attribute__((__packed__));

struct iphdr {
	uint8_t version_ihl;
	uint8_t	tos;
	uint16_t	tot_len;
	uint16_t	id;
	uint16_t	frag_off;
	uint8_t	ttl;
	uint8_t	protocol;
	uint16_t	check;
	uint32_t	saddr;
	uint32_t	daddr;
	/*The options start here. */
}__attribute__((__packed__));

struct tcp_s{
//	uint64_t cnt;
	uint32_t pps;
	uint32_t bps;
	uint32_t flow;
	uint32_t syn;
	uint32_t syn_ack;
	uint32_t ack;
	uint32_t rst;
	uint32_t fin;
//	uint32_t frag;
}__attribute__((__packed__));

struct tcp_b{
	uint64_t pps;
	uint64_t bps;
	uint64_t flow;
	uint64_t syn;
	uint64_t syn_ack;
	uint64_t ack;
	uint64_t rst;
	uint64_t fin;
//	uint64_t frag;
}__attribute__((__packed__));


// base on pkts cnt ,sum calc
struct tcp_l{
	uint64_t cnt;
	uint64_t flow;
	uint64_t syn;
	uint64_t syn_ack;
	uint64_t ack;
	uint64_t rst;
	uint64_t fin;
//	uint64_t frag;
}__attribute__((__packed__));

struct udp_s{
//	uint64_t cnt;
	uint32_t pps;
	uint32_t bps;
	uint32_t flow;
//	uint32_t frag;
}__attribute__((__packed__));

struct udp_b{
	uint64_t pps;
	uint64_t bps;
	uint64_t flow;
//	uint64_t frag;
}__attribute__((__packed__));


struct udp_l{
	uint64_t cnt;
	uint64_t flow;
//	uint32_t frag;
}__attribute__((__packed__));

struct igmp_s{
//	uint64_t cnt;
	uint32_t pps;
	uint32_t bps;
//	uint32_t frag;
	uint32_t v1;
	uint32_t v2;
	uint32_t v3;
}__attribute__((__packed__));

struct igmp_b{
	uint64_t pps;
	uint64_t bps;
//	uint64_t frag;
	uint64_t v1;
	uint64_t v2;
	uint64_t v3;
}__attribute__((__packed__));

struct igmp_l{
	uint64_t cnt;
//	uint64_t frag;
	uint64_t v1;
	uint64_t v2;
	uint64_t v3;
}__attribute__((__packed__));

struct icmp_s{
//	uint64_t cnt;
	uint32_t pps;
	uint32_t bps;
//	uint64_t frag;
	uint32_t redir;
	uint32_t echo;
	uint32_t unreach;
}__attribute__((__packed__));

struct icmp_b{
	uint64_t pps;
	uint64_t bps;
//	uint64_t frag;
	uint64_t redir;
	uint64_t echo;
	uint64_t unreach;
}__attribute__((__packed__));

struct icmp_l{
	uint64_t cnt;
//	uint64_t frag;
	uint64_t redir;
	uint64_t echo;
	uint64_t unreach;
}__attribute__((__packed__));

struct ip_s{
//	uint32_t cnt;
	uint32_t pps;
	uint32_t bps;
//	uint32_t frag;
	uint32_t ip_option;
//	uint32_t ipv6;
/*
uint32_t ip_option_route;
uint32_t ip_option_srcroute;
uint32_t ip_option_timestamp;
*/
}__attribute__((__packed__));

struct ip_b{
	uint64_t pps;
	uint64_t bps;
	uint64_t frag;
	uint64_t ip_option;
//	uint64_t ipv6;
/*
uint64_t ip_option_route;
uint64_t ip_option_srcroute;
uint64_t ip_option_timestamp;
*/
}__attribute__((__packed__));

struct ip_l{
	uint64_t cnt;
//	uint64_t frag;
	uint64_t ip_option;
//	uint64_t ipv6;
/*
uint32_t ip_option_route;
uint32_t ip_option_srcroute;
uint32_t ip_option_timestamp;
*/
}__attribute__((__packed__));

struct attack_s{
	uint32_t tcp_flag_err;
	uint32_t smurf;
	uint32_t fraggle;
	uint32_t frag;
	uint32_t frag_err;
	uint32_t nuker;
	uint32_t ssdp;
	uint32_t ntp;
	uint32_t dns;
	uint32_t snmp;
//	uint32_t chargen;
	uint32_t tracert;
	uint32_t land;
}__attribute__((__packed__));

struct attack_l{
	uint64_t tcp_flag_err;
	uint64_t smurf;
	uint64_t fraggle;
	uint64_t frag;
	uint64_t frag_err;
	uint64_t nuker;
	uint64_t ssdp;
	uint64_t ntp;
	uint64_t dns;
	uint64_t snmp;
//	uint64_t chargen;
	uint64_t tracert;
	uint64_t land;
}__attribute__((__packed__));


union msg_short {
	uint64_t all;
	struct{
		uint8_t core;
		uint8_t type;
		uint8_t code[6];
	};
}__attribute__((__packed__));

struct ip_sub{
	struct tcp_s tcp;
	struct udp_s udp;
	struct icmp_s icmp;
	struct igmp_s igmp;
	struct ip_s ip;
	struct attack_s attack;
}__attribute__((__packed__));

// only in dir
struct ip_g_s1{
//	union msg_short msg;
	struct list_head list;
	struct list_head timer_list;
	struct ip_s ip_info;
	uint32_t addr;
//	uint32_t flag;
//	uint8_t lcore_id;
}__attribute__((__packed__));

//both 2 dir
struct ip_g_s2{
//	union msg_short msg;
	struct list_head list;
	struct list_head pending_list;
//	struct list_head timer_list;
	struct ip_sub ip_info[2];// 0: in dir 1:out dir
	struct hash_array l4;
	struct hash_array name_http;
	struct hash_array name_dnsreq;
	uint32_t addr;
	uint16_t port;
	uint32_t ip_idx;
//	uint8_t lcore_id;
//	struct rte_mempool *mp;
}__attribute__((__packed__));

struct ip_info_sum_b{
	struct tcp_b tcp;
	struct udp_b udp;
	struct icmp_b icmp;
	struct igmp_b igmp;
	struct ip_b ip;
	struct attack_l attack;
}__attribute__((__packed__));

struct ip_info_sum_s{
	struct tcp_l tcp_sum_pkts;
	struct tcp_l tcp_sum_bytes;
	struct tcp_l tcp_pps;
	struct tcp_l tcp_bps;

	struct udp_l udp_sum_pkts;
	struct udp_l udp_sum_bytes;
	struct udp_l udp_pps;
	struct udp_l udp_bps;

	struct icmp_l icmp_sum_pkts;
	struct icmp_l icmp_sum_bytes;
	struct icmp_l icmp_pps;
	struct icmp_l icmp_bps;

	struct igmp_l igmp_sum_pkts;
	struct igmp_l igmp_sum_bytes;
	struct igmp_l igmp_pps;
	struct igmp_l igmp_bps;

	struct ip_l ip_sum_pkts;
	struct ip_l ip_sum_bytes;
	struct ip_l ip_pps;
	struct ip_l ip_bps;

	struct attack_l attack_sum_pkts;
	struct attack_l attack_sum_bytes;
	struct attack_l attack_pps;
	struct attack_l attack_bps;
}__attribute__((__packed__));

struct ip_sum_s1{
	struct list_head list;
	struct ip_info_sum_s  ip_sum;
	uint32_t addr;
	uint64_t ttl_cnt[4];
}__attribute__((__packed__));

struct ip_sum_s2{
	struct list_head list;
	struct ip_info_sum_s  ip_sum[2];
	uint32_t addr;
//	uint64_t ttl_cnt[4];
}__attribute__((__packed__));

struct l4_port_info{
	uint32_t all[2];
	uint32_t tcp[2];
	uint32_t udp[2];
}__attribute__((__packed__));

struct ip_sum_b{
	struct list_head alloc_list;//use in pool,alloced list
//	struct list_head submit_list;
	struct list_head list;//use only in hash
	struct ip_info_sum_b  ip_sum[2];
	struct hash_array l4;
	struct l4_port_info l4_g;
	struct hash_array dn1;
	struct hash_array dn1_http;
	uint32_t addr;
	uint32_t port;
	uint32_t ip_idx;
	uint64_t flag;
//	struct rte_mempool *mp;
}__attribute__((__packed__));

struct dn1_g_s2{
	struct list_head alloc_list;
	struct list_head list_hash;
	char name[255];
	uint8_t len;
	uint32_t cnt;
//	uint16_t hash_idx;
}__attribute__((__packed__));

struct dn1_sum_b{
	struct list_head list_tbl;//to hash
	struct list_head list_ip;//to ip
	struct list_head alloc_list;//to alloc
	struct ip_sum_b *l3p;
	uint32_t cnt;
	char name[255];
	uint8_t len;
}__attribute__((__packed__));

struct dn1_ti_b{
	struct hash_array chain;
	struct list_head alloc_list;//to alloc
	struct list_head list_hash;
	uint64_t cnt;
	char *name;
	//char name[255];
	uint8_t len;
}__attribute__((__packed__));

struct l4_port_sum_info{
	uint64_t all[2];
	uint64_t tcp[2];
	uint64_t udp[2];
}__attribute__((__packed__));

struct l4_port_g_s2{
	struct list_head alloc_list;
	struct l4_port_info info;
	uint16_t no;
}__attribute__((__packed__));

struct l4_port_g_b{
	struct hash_array chain;
	struct l4_port_sum_info info;
	uint16_t no;
}__attribute__((__packed__));

struct l4_port_sum_b{
	struct list_head list_tbl;//to ip
	struct list_head list_ip;//to ip
	struct list_head alloc_list;//to alloc
	struct ip_sum_b *l3p;
	struct l4_port_info info;
//	uint16_t flag;
	uint16_t no;
}__attribute__((__packed__));

struct port_sub{
	uint64_t in_pps;
	uint64_t in_bps;
	uint64_t bad_ipv4_pkts;
	uint64_t notipv4_pps;
	uint64_t notipv4_bps;

	struct tcp_b tcp;
	struct udp_b udp;
	struct icmp_b icmp;
	struct igmp_b igmp;
	struct ip_b ip;
	struct attack_l attack;
}__attribute__((__packed__));

struct port_info_sum{
//	struct list_head list;
	struct port_sub sub[2];//out bad_ipv4_pkts mean out fail drop
//	struct kni_interface_stats kni_info;

//	int port_id;
}__attribute__((__packed__));


//struct port_sum_per_s{
//	uint64_t in_pps;
//	uint64_t in_bps;
//	uint64_t bad_ipv4_pkts;

//	struct tcp_l tcp_pps;
//	struct tcp_l tcp_bps;
//	struct udp_l udp_pps;
//	struct udp_l udp_bps;
//	struct icmp_l icmp_pps;
//	struct icmp_l icmp_bps;
//	struct igmp_l igmp_pps;
//	struct igmp_l igmp_bps;
//	struct ip_l ip_pps;
//	struct ip_l ip_bps;
//	struct attack_l attack_pps;
//	struct attack_l attack_bps;
//}__attribute__((__packed__));

//struct port_sum_total_s{
//	struct tcp_l tcp_sum_pkts;
//	struct tcp_l tcp_sum_bytes;
//	struct udp_l udp_sum_pkts;
//	struct udp_l udp_sum_bytes;
//	struct icmp_l icmp_sum_pkts;
//	struct icmp_l icmp_sum_bytes;
//	struct igmp_l igmp_sum_pkts;
//	struct igmp_l igmp_sum_bytes;
//	struct ip_l ip_sum_pkts;
//	struct ip_l ip_sum_bytes;
//	struct attack_l attack_sum_pkts;
//	struct attack_l attack_sum_bytes;
//}__attribute__((__packed__));


//struct port_sum_s{
//	struct port_sum_per_s sub;
//	struct port_sum_total_s total;
//}__attribute__((__packed__));

//struct port_all_s1{
//	struct port_sum_s all[1];
//}__attribute__((__packed__));

//struct port_all_s2{
//	struct port_sum_s all[2];
//}__attribute__((__packed__));
struct machine_param{
	char *argv[MAX_ARGV];
	char argv_buf[MAX_ARGV][256];
	int argc;
	uint64_t hugepage_size;
	uint32_t nr_hugepages;
};

enum{
	L2_SELF_MAC_VAILD=0,
	L2_NEIGH_MAC_VAILD,
	L2_STATE_UPDATE,
	L2_STATE_MAX
};

struct settle_mode_gw_bonding_in_out_vlan{
	uint32_t in_ip;
	uint32_t in_gw_ip;
	uint32_t in_ipmask;
	uint32_t out_ip;
	uint32_t out_gw_ip;
	uint32_t out_ipmask;
	int in_vlanid;
	int out_vlanid;
	int in_flag;
	int out_flag;
	char in_mac[6];
	char in_neigh_mac[6];
	char out_mac[6];
	char out_neigh_mac[6];
	int in_port[MAX_DEV];
	int out_port[MAX_DEV];
	int in_port_num;
#ifdef BOND_2DIR
	int out_port_num;
#endif
	int l2_in_state;
	int l2_out_state;

#if defined(VLAN_ON) ||defined(BOND_2DIR_VLAN)
	char l2_in_pending[6+6+4];
	char l2_out_pending[6+6+4];
#else
	char l2_in_pending[6+6+2];
	char l2_out_pending[6+6+2];
#endif
};

struct settle_mode{
	int mode;

	union{
		struct settle_mode_gw_bonding_in_out_vlan gw_bonding_inoutvlan;
	};
};

struct nat_config{
	char addr[NAT_API_LEN];
	char usrname[NAT_API_LEN];
	char password[NAT_API_LEN];
	char natconfig_ver[NAT_API_LEN];
	char natconfig[NAT_API_LEN];
	char bandwidth_ver[NAT_API_LEN];
	char bandwidth[NAT_API_LEN];
	char rip_linkstatus[NAT_API_LEN];
        char region_tag[NAT_API_LEN/2];
//        char isp_tag[32];
        char pool_tag[NAT_API_LEN/2];
	int	port;
	int	deadtime;
        int     deadtime_rst;
};

struct machine{
	//char id[128];
	char *id;
	//char root_dir[256];
	char *root_dir;
	//char config_file[128];
	char *config_file;
	char *runnning_log_file;
	char *hw_log_file;
	char *flow_log_file;
	char *alert_log_file;
	uint32_t interface_ip[MAX_DEV];
	uint32_t interface_ipmask[MAX_DEV];
	struct settle_mode settle_setting;
	int mode;
 	int type;
 	int flag;
 	int port_cnt;
	uint32_t port_mask;
	uint64_t io_in_mask;
	uint64_t io_out_mask;
	uint64_t sum_mask;
	uint64_t sum_src_mask;
//	uint64_t pcap_mask;
	uint64_t kni_no;
	uint32_t natsum2_mask;
	uint32_t distribute_mask;
        uint32_t mon_vip;
	int dist_ring_cnt;
	int io_ip_pool_cnt;
	int io_srcsum_pool_cnt;
	int io_flow_nat_sync_msg_cnt;
	int io_flow_pool_cnt;
	int io_flowtag_pool_cnt;
	int io_flownat_pool_cnt;
	int io_output_pool_cnt;
	int io_netport_pool_cnt;
//	int pcap_pool_cnt;
	int io_dn1_pool_cnt;
//	int sum_mp_type;
	int sum_ip_pool_cnt;
	int sum_netport_pool_cnt;
	int sum_dn1_pool_cnt;
	int timer_dn1_pool_cnt;
	int sum_srcip_pool_cnt;
#ifdef __SRC_SUM__
	int io_srcip_policy_pool_cnt;
#endif
	int sumsrc_dst_policy_pool_cnt;
	int msg_srcsum2io_pool_cnt;
	uint64_t port2core_mask_in[MAX_DEV];
	uint64_t port2core_mask_out[MAX_DEV];
	struct rte_eth_link link[MAX_DEV];
	struct machine_param param;
	struct kafka_info ch_kafka;
	struct nat_config	natconfig;
};


struct machine_sum_s{
	struct tcp_l tcp_sum_pkts;
	struct tcp_l tcp_sum_bytes;
	struct tcp_l tcp_pps;
	struct tcp_l tcp_bps;

	struct udp_l udp_sum_pkts;
	struct udp_l udp_sum_bytes;
	struct udp_l udp_pps;
	struct udp_l udp_bps;

	struct icmp_l icmp_sum_pkts;
	struct icmp_l icmp_sum_bytes;
	struct icmp_l icmp_pps;
	struct icmp_l icmp_bps;

	struct igmp_l igmp_sum_pkts;
	struct igmp_l igmp_sum_bytes;
	struct igmp_l igmp_pps;
	struct igmp_l igmp_bps;

	struct ip_l ip_sum_pkts;
	struct ip_l ip_sum_bytes;
	struct ip_l ip_pps;
	struct ip_l ip_bps;

	struct attack_l attack_sum_pkts;
	struct attack_l attack_sum_bytes;
	struct attack_l attack_pps;
	struct attack_l attack_bps;
};

struct machine_all_s1{
	struct machine_sum_s all;
}__attribute__((__packed__));

struct machine_all_s2{
	struct machine_sum_s all[2];
}__attribute__((__packed__));

union ipv4_5tuple_xmm {
	struct {
		uint8_t  pad0;
		uint8_t  proto;
		uint16_t pad1;
		uint32_t ip_src;
		uint32_t ip_dst;
		uint16_t port_src;
		uint16_t port_dst;
	};
	__m128i xmm;
}__rte_cache_aligned;


struct ipv4_5tuple {
	uint32_t ip_dst;
	uint32_t ip_src;
	uint16_t port_dst;
	uint16_t port_src;
	uint8_t  proto;
} __attribute__((__packed__));

//struct flow_common_s{
//	uint64_t cnt[2];
//	uint32_t index;
//	struct ipv4_5tuple tuple;
//	uint8_t state;
//	uint8_t pt_cnt;
//} __attribute__((__packed__));

/*
struct tcp_flow_s{
	uint32_t wz[2];
	uint32 seq[2];
	uint64_t timestamp[2];//rtt
	uint16_t len[2];
}__attribute__((__packed__));

struct udp_flow_s{
	uint64_t timestamp[2];//rtt
	uint16_t len[2];
}__attribute__((__packed__));
*/

//struct output_cell{
//	struct list_head alloc_list;
//	struct rte_mbuf *pkts_burst[BURST_SZ];
//}__attribute__((__packed__));

#define DIR_BIT		0x8000

struct l34_pair{
	uint32_t l3;
	uint32_t l4;
}__attribute__((__packed__));

struct ipv4_4tuple{
	union {
		uint64_t all;
		struct l34_pair pair;
	}a;
	union {
		uint64_t all;
		struct l34_pair pair;
	}b;
}__attribute__((__packed__));

struct nat_map_tuple{
	struct ipv4_4tuple tuplepair[2];
	uint32_t cnt;
}__attribute__((__packed__));

struct sum_map_tuple{
	struct nat_map_tuple map_tuple;
//	uint32_t hashidx_0;
//	uint32_t hashidx_1;
//	uint32_t srchash;
}__attribute__((__packed__));

struct nat_4tuplehash{
	struct list_head listnode;
	struct list_head src_list;
	struct ipv4_4tuple tuple_v4;
        uint16_t proto;
	/* The direction (for tuplehash) */
	uint16_t  dir;
}__attribute__((__packed__));

struct nat_range{
	unsigned int	flags;
	uint32_t		min_ip;
	uint32_t		max_ip;
	uint32_t		min_port;
	uint32_t		max_port;
}__attribute__((__packed__));

struct dnat_range{
	uint32_t		nat_ip[NAT_MAX_NATIPNUM];
	uint16_t		nat_port;
	uint8_t		index;
	uint8_t		rip_sum;
	uint8_t		fwd_realip_mode;
	uint32_t		link_status;
}__attribute__((__packed__));

#define TYPE_FLOW_TAG	0
#define TYPE_FLOW_STRUCT 1

struct flow_tcp{
	uint32_t seq_start[2];
	uint16_t mss[2];
	uint8_t ws[2];
	//more

}__attribute__((__packed__));

struct flow_tag{
	uint32_t type;
	uint32_t timer_loop;
	struct list_head alloc_list;
	struct list_head tbl_list;
	struct ipv4_4tuple tuple_v4;
	uint64_t last_tick;
}__attribute__((__packed__));

struct flow_s{
	uint32_t type;
	uint32_t timer_loop;
	struct list_head alloc_list;
	struct list_head tbl_list;
	struct ipv4_4tuple tuple_v4;
	uint64_t ts_start;
	uint64_t ts_end;
	uint32_t flag;
	uint32_t state;
	union{
		struct flow_tcp f_tcp;
	};
	uint8_t ttl_max[2];
	uint8_t ttl_avr[2];
	uint8_t ttl_min[2];
}__attribute__((__packed__));

struct flow_nat{
	//uint32_t type;
	//uint32_t timer_loop;
	uint32_t first_ack_seq_no;
	uint16_t state;
#ifdef __SRCP_BIT_MAP__
	uint8_t snat;
	uint8_t sip_idx;
#else
	uint16 snat;
#endif
	uint16_t vip_idx;
	uint16_t deadtime;
	uint64_t last_tick;
	struct list_head alloc_list;
	struct nat_4tuplehash nat_tuplehash[2];
}__attribute__((__packed__));

#ifdef	__SYNC_FLOW_TABLE__
enum{
	FLOW_NAT_SYNC_MSG_DEL=0,
	FLOW_NAT_SYNC_MSG_ADD
};

struct flow_nat_msg {
	struct list_head list;

	uint8_t snat;
	uint8_t is_add_flow;
	uint16_t vip_idx;
	uint32_t first_ack_seq_no;
	struct nat_4tuplehash nat_tuplehash[2];
}__attribute__((__packed__));
#endif

struct srcip_nat{
	struct list_head alloc_list;
	struct list_head tbl_list;
	uint32_t self;
	uint32_t dstip;
	uint32_t dstip_idx;
}__attribute__((__packed__));

struct snat_ip{
	struct list_head alloc_list;
	struct list_head tbl_list;
	uint32_t dstip;
	uint32_t deadtime;
	uint32_t sip_sum;
	uint32_t snat_ip[NAT_MAX_SIPNUM];
}__attribute__((__packed__));

struct toa_vip{
	struct list_head alloc_list;
	struct list_head tbl_list;
	uint32_t vip;
}__attribute__((__packed__));

struct dnat_config{
	struct list_head alloc_list;
	struct list_head tbl_list;
	struct dnat_rule rule;
	uint32_t dstip;
	uint16_t index_dstip;
	uint16_t index_rule;
	uint8_t forward_level;
	uint8_t fwd_realip_mode;
}__attribute__((__packed__));

#define PKT_INFO_SZ	(2048)
#define PKT_INFO_NUM_PERCORE	(16*1024)
#define ETH_HLEN	14

struct ipv4_port{
	uint16_t	source;
	uint16_t	dest;
};

struct ipv4_info{
	struct ethhdr l2;
	struct iphdr ip;
	union{
		struct ipv4_port port;
		struct tcphdr tcp;
		struct udphdr udp;
		struct icmphdr icmp;
		struct igmphdr igmp;
	}proto;
};

struct srcsum_block_msg{
	//block
	uint32_t tcp_concurrent_new_connections;
	uint32_t udp_connections;
	uint32_t pps;
	uint32_t tcp_and_udp_connections;
	uint32_t tcp_concurrent_half;
	uint32_t udp_concurrent_new_connections;
	uint32_t tcp_connections;
	uint32_t bps;
	uint32_t icmp;
	uint32_t tcp_and_udp_concurrent_new_connections;
}__attribute__((__packed__));

struct dst_ip_limit_msg{
	uint32_t tcp_bps;	// mb
	}__attribute__((__packed__));

struct dst_pl_s{
	uint32_t dstip;
#ifdef 	BOND_2DIR
	uint16_t fwd_level;
	uint16_t toa_flag;
#else
	uint32_t toa_flag;
#endif

	//limit
	struct dst_ip_limit_msg ip;
	//block
	struct srcsum_block_msg src_bl;
}__attribute__((__packed__));

struct sum_msg {
	struct list_head list;
	uint32_t msg;
	uint32_t flag;
	uint32_t ip;
	uint32_t ip2;
} __attribute__((__packed__));

struct src_sum_tmp{
	uint32_t update;
	uint32_t halfreq_flow;
	uint32_t new_build_tcp_flow;
	uint32_t finish_tcp_flow;
	uint32_t new_build_udp_flow;
	uint32_t finish_udp_flow;
};

struct src_sum{
	struct list_head list;
	struct list_head pending_list;
	uint32_t src_addr;
	uint32_t dst_addr;
//	uint16_t flag;
	uint32_t halfreq_flow;
//	int sub_halfreq_flow;
	uint32_t new_build_tcp_flow;
	uint32_t finish_tcp_flow;
	uint32_t new_build_udp_flow;
	uint32_t finish_udp_flow;
}__attribute__((__packed__));

#ifdef __SRC_SUM__
enum {
	SRC_SUM_NOR = 0,
	SRC_SUM_ATTACK
};
struct src_sum_pack{
	struct list_head alloc_list;
	struct list_head tbl_list;
	uint32_t src_addr;
	uint32_t dst_addr;
	uint32_t flag;

	uint64_t last_tick;

	struct srcsum_block_msg src_stat;
}__attribute__((__packed__));

struct srcsum_dst_policy{
	struct list_head alloc_list;
	struct list_head tbl_list;
	uint32_t dst_addr;

	uint32_t mode;

	//block
	struct srcsum_block_msg src_block;
}__attribute__((__packed__));

struct io_src_policy{
	struct list_head list;
	struct list_head tbl_list;
	void *dstip_ptr;
	uint32_t srcip;
	uint32_t dstip;
	uint32_t flag;
	uint32_t timer_index;
	uint32_t bl_freeze_time_s;
	uint32_t wl_freeze_time_s;
}__attribute__((__packed__));
#endif

enum{
	WD_PPS_DST=0,
	WD_PPS_SRC,
	WD_BPS_DST,
	WD_BPS_SRC,
	WD_TCP_PPS_DST,
	WD_TCP_BPS_DST,
	WD_TCP_SYN_PPS_DST,
	WD_TCP_SYN_BPS_DST,
	WD_TCP_SYNACK_PPS_DST,
	WD_TCP_SYNACK_BPS_DST,
	WD_TCP_ACK_PPS_DST,
	WD_TCP_ACK_BPS_DST,
	WD_TCP_FIN_PPS_DST,
	WD_TCP_FIN_BPS_DST,
	WD_TCP_RST_PPS_DST,
	WD_TCP_RST_BPS_DST,
	WD_UDP_PPS_DST,
	WD_UDP_BPS_DST,
	WD_ICMP_PPS_DST,
	WD_ICMP_BPS_DST,
	WD_IGMP_PPS_DST,
	WD_IGMP_BPS_DST,
	WD_MAX
};

enum{
	WDL4_ALL_DST=0,
	WDL4_ALL_SRC,
	WDL4_TCP_DST,
	WDL4_TCP_SRC,
	WDL4_UDP_DST,
	WDL4_UDP_SRC,
	WDL4_MAX
};

enum{
	WDDN1_NAME_SRC=0,
	WDDN1_MAX
};

enum{
	WDDN1_NAME_SRC_IP=0,
	WDDN1_MAX_IP
};

struct mon_cell_arr{
	uint32_t *arr;
	int max;
	int curr;
};

struct wd_info{
	uint64_t key[2];
};

struct topK{
	int curr;
	void *arr[MAX_TOPN_PER];
};
/*
struct pcap_ship {
	struct list_head list;
	uint32_t len;
//	uint32_t ip;
	char buf[2048];
} __attribute__((__packed__));
*/
struct local_timeval
{
	uint32_t tv_sec;
	uint32_t tv_usec;
};

struct local_pcap_pkthdr
{
	struct local_timeval ts;
	uint32_t caplen;
	uint32_t len;
};

struct wd_pack{
	struct topK top[2];//0:local 1:remote
	struct wd_ops *ops;
};


struct wd_ops{
	int type;
	int (*mincmp)(void *,void *);
	void (*minheap_creat)(int,struct wd_pack *,int);
	void (*minheap_mod)(int,int,struct wd_pack *,int);
	void (*process)(void *,struct wd_pack *,int);
	void (*soft)(struct wd_pack *,int);
	void (*dump)(struct wd_pack *,int);
};

struct pp_info{
	uint32_t srcip;
	uint32_t dstip;
	uint16_t sport;
	uint16_t dport;
	uint32_t packet_info;
}__attribute__((__packed__));

struct pkt_info{
	struct list_head list;
	struct rte_mempool *mp;
	uint64_t time_stamp;
	uint32_t rss;
	uint32_t pad;

	struct ipv4_info ipv4;

}__attribute__((__packed__));

#define IN_TIMER_RES	10000 //10ms us
#define	IN_TIMER_1S		1000000 //1s us
#define IN_TIMER_MAX	1000000 //1s us
#define IN_TIMER_1ROUND	(IN_TIMER_MAX/IN_TIMER_1S)
#define IN_TIMER_ROUND_SZ	((IN_TIMER_MAX)/(IN_TIMER_RES))

#define TIMEOUT_FLOWTAG		(8/IN_TIMER_1ROUND)	//5s
#define TIMEOUT_FLOW		(60/IN_TIMER_1ROUND)		//1min
#define TIMEOUT_FLOWNAT	(600/IN_TIMER_1ROUND)		//10min
struct out_burst_cell{
	struct list_head alloc_list;
	void *burst_buf[1];//[BURST_SZ];
//	int burst_cnt;
}__attribute__((__packed__));

struct port_push{
	struct hash_array submit_list[MAX_CPU];
	struct hash_array back_list[MAX_CPU];
//	struct hash_array pending_list[MAX_CPU];
//	struct out_burst_cell *used[MAX_CPU];
	int port_id;
	int count;
};

struct port_pop{
	struct hash_array *remote_submit_list[MAX_CPU];
	struct hash_array *remote_back_list[MAX_CPU];
	struct hash_array tmp_send_list[MAX_CPU];
	struct hash_array tmp_back_list[MAX_CPU];
	int port_id;
	int port_queue_arr[MAX_TX_QUEUE];
	int count;
	int port_queue_arr_sz;
};

#define KNI_RING_SZ	(256*1024)
struct priv_kni{
	int queue_id[MAX_DEV];
	struct rte_kni *kni_array[MAX_DEV];
	struct rte_ring *ring_input[MAX_DEV];
};

struct priv_io_in{
	struct hash_array ip_pool;
#ifdef	__SYNC_FLOW_TABLE__
	struct hash_array flow_nat_sync_pool;
#endif
	struct hash_array srcsum_pool;
	struct hash_array netport_pool;
	struct hash_array dn1_pool;
	struct hash_array flow_pool;
	struct hash_array flowtag_pool;
	struct hash_array flownat_pool;
	struct hash_array srcipnat_pool;
	struct hash_array dnatconfig_pool;
    struct hash_array viptoa_pool;
	struct hash_array out_pool;
	struct hash_array *io_in_hash;
	struct hash_array *io_flow_hash;
	struct hash_array *io_flownat_hash;
	struct hash_array *io_srcip_hash;
	struct hash_array *dnat_config_hash;
    struct hash_array *io_viptoa_hash;
	struct hash_array *io_dn1_hash;
#ifdef __SRC_SUM__
	struct hash_array *sumsrc_srcip_hash;
	struct hash_array *srcip_policy_hash;
	struct hash_array srcip_policy_pool;
#endif
	struct hash_array ip_io2sum_pending[MAX_CPU];
	struct hash_array ip_io2sum_burst[MAX_CPU];
	struct hash_array ip_sum2io_burst[MAX_CPU];

	//io2sumsrc
	struct hash_array ip_io2sumsrc_burst[MAX_CPU];
	struct hash_array ip_sumsrc2io_burst[MAX_CPU];

	//msg src2io
	struct hash_array *msg_sumsrc2io_send[MAX_CPU];
	struct hash_array *msg_sumsrc2io_back[MAX_CPU];

#ifdef	__SYNC_FLOW_TABLE__
	struct hash_array flow_nat_sync_snd[MAX_CPU];
	struct hash_array flow_nat_sync_snd_back[MAX_CPU];


	struct hash_array *flow_nat_sync_rcv[MAX_CPU];
	struct hash_array *flow_nat_sync_rcv_back[MAX_CPU];
#endif

//	struct hash_array pcap_pool;
//	struct hash_array io2pcap_burst[MAX_CPU];
//	struct hash_array pcap2io_burst[MAX_CPU];
	struct hash_array netport_sum2io_burst[MAX_CPU];
	struct hash_array dn1_sum2io_burst[MAX_CPU];
	struct port_info_sum port_sub[MAX_DEV*2];
	struct port_push port_do_push[MAX_DEV];
	struct nat_map_tuple tuplepair[MAX_TUPLEPAIR*2];
	struct nat_map_tuple freshtuplepair[MAX_TUPLEPAIR*2];
	struct sum_map_tuple totaltuplepair[TOTAL_MAX_TUPLEPAIR];
	struct sum_map_tuple totalfreshtuple[TOTAL_MAX_TUPLEPAIR];
	struct rte_ring *ring_input[MAX_DEV];
	int port_sum_sig;
	int port_sum_curr;

	//int nat_flowlist_sig;
	//int nat_flowlist_curr;
	//int nat_srclist_sig;
	//int nat_srclist_curr;
	int nat_deadtime;
	int nat_tuplepair_sig;
	int nat_tuplepair_curr;
	int fresh_tuplepair_sig;
	int fresh_tuplepair_curr;
	int sum_tuplepair_sig;
	int sum_freshtuple_sig;

	struct hash_array *flowtimer;
	//in out in 1
	struct rte_ring *out_ring[MAX_DEV];
	int out_ring_dev_cnt;
//	int out_ring_sz;
	int out_queue[MAX_DEV][MAX_TX_QUEUE];
	int out_queue_sz[MAX_DEV];

#ifdef VLAN_ON
	char l2_data[6+6+4];
#else
	char l2_data[6+6+2];
#endif
	char l2_data_in[6+6+2];
#ifdef BOND_2DIR
	char l2_data_out[6+6+2];
#endif
	int l2_sig;
	int l2_sig_out;

//	uint64_t quick_all_bps;
//	uint64_t quick_all_pps;

#if 1//debug
	uint32_t miss_alloced;
	uint32_t miss_alloced_netport;
	uint32_t miss_alloced_dn1;
	uint32_t miss_alloced_flow;
	uint32_t miss_alloced_flowtag;
	uint32_t miss_alloced_out;
	uint32_t miss_alloced_flownat;
#endif
//	uint64_t io2sum_map;
//	int io2sum_cnt;
};

struct priv_io_out{
	struct port_pop port_do_pop[MAX_DEV];
};

struct dn1_pending{
	struct hash_array pending[DN1_HASH_ARRAY_SZ];
	uint32_t hash_idx[DN1_HASH_ARRAY_SZ];
	uint32_t pending_cnt;
};

struct priv_sumsrc{
	struct hash_array ip_sum_src_pool;
	struct hash_array *ip_sum_src_hash;
	struct hash_array *ltimer;
	struct hash_array dstip_policy_pool;
	struct hash_array *dstip_policy_hash;

	// io2sumsrc
	struct hash_array *sum_src_io2s_burst[MAX_CPU];
	struct hash_array *sum_src_s2io_burst[MAX_CPU];

	// sumsrc2io
	struct hash_array msg_io_pool;
	struct hash_array msg_sumsrc2io_send[MAX_CPU];
	struct hash_array msg_sumsrc2io_back[MAX_CPU];

};

#define time_after(a,b)		((int64_t)((b) - (a)) < 0)

struct priv_sum{
	struct hash_array ip_sum_pool;
	struct hash_array netport_sum_pool;
	struct hash_array dn1_sum_pool;
	struct hash_array flow_sum_pool;
//	struct rte_ring *ringfromio;//[MAX_CPU];
	struct hash_array *sum_hash;

	struct dn1_pending *sum_dn1_hash[2];
	struct dn1_pending *sum_dn1_hash_http[2];
	struct hash_array sum_sum2io_pending[MAX_CPU];
	struct hash_array *sum_ip_io2sum_burst[MAX_CPU];
	struct hash_array *sum_ip_sum2io_burst[MAX_CPU];
	struct hash_array sum_netport_sum2io_pending[MAX_CPU];
	struct hash_array *sum_netport_sum2io_burst[MAX_CPU];

	struct hash_array sum_dn1_sum2io_pending[MAX_CPU];
	struct hash_array *sum_dn1_sum2io_burst[MAX_CPU];

//	uint64_t sum2io_map;
//	int sum2io_cnt;
	struct wd_pack wd[WD_MAX];
	int wd_valid_cnt;
	int wd_switch;

//	uint32_t l4_tlb_idx;

	struct l4_port_g_b *netport_tbl[2];
//	struct wd_pack netport_port_top[WDL4_MAX];

	struct ip_sum_b **mon_ip_burst;
	int mon_ip_burst_cnt;
	struct mon_cell_arr mon_ip_core[2];
	int mon_ip_idx;
	int mon_ip_switch;

#if 1//debug
	uint32_t miss_alloced;
	uint32_t miss_alloced_netport;
	uint32_t miss_alloced_dn1;
#endif
};

struct priv_timer{
	uint32_t *timer_triger[MAX_CPU];
	uint32_t *timer_idle[MAX_CPU];
	uint32_t *timer_l4_idx[MAX_CPU];
	uint64_t timer_map;
	int timer_cnt;
	struct wd_pack wd[WD_MAX];
	int wd_valid_cnt;
	struct l4_port_g_b *netport_tbl;
	struct dn1_pending *dn1_hash;
	struct dn1_pending *dn1_hash_http;
	struct hash_array dn1_timer_pool;

	struct wd_pack wdl4_g[WDL4_MAX];
	int wdl4_g_valid_cnt;

	struct wd_pack wddn1_g[WDDN1_MAX];
	int wddn1_g_valid_cnt;

	struct wd_pack wddn1_g_http[WDDN1_MAX];
	int wddn1_g_valid_cnt_http;

#if 1//debug
	uint32_t miss_alloced_dn1;
#endif
};

struct core_timer{
	struct hash_array *event;
	struct hash_array *natlist;
	void (*handler)(void *,void *);
	uint32_t queue_sz;
	uint32_t pointer;
};

//struct priv_pcap{
//	struct hash_array *pcap_io2pcap_burst[MAX_CPU];
//	struct hash_array *pcap_io2pcap_back[MAX_CPU];

//	int pcap_io2pcap_cnt;
//};

//struct msg_io2dis_rsp_flow{
//	struct list_head list;
//	struct ipv4_4tuple reply_tuple;
//	uint32_t vip;
//};

struct priv_dist{
		//kni
#ifdef __MAIN_LOOP_KNI__
	struct rte_ring *kni_ring[MAX_DEV];
#else
	struct rte_mempool *io_buf;
#endif
//	struct hash_array *msg_io2dis_rvc[MAX_CPU];
//	struct hash_array *msg_dis2io_snd[MAX_CPU];
//	struct hash_array flow_pool;
	struct hash_array srcipnat_pool;
//	struct hash_array *flow_hash;
	struct hash_array *io_srcip_hash;
};

struct lcore_info_s{
	struct list_head list;
	uint8_t port_id[MAX_DEV];
	uint8_t txport_id[MAX_DEV];
	uint8_t port_cnt;
	uint8_t socket_id;
	uint8_t core_id;
	uint16_t queue_id[MAX_DEV];
//	struct port_sum_s *port_stat_arr;
	int type;
//	struct nat_map_tuple nat_tuple[BURST_SZ*2];
	uint32_t timer_flag;
	uint32_t timer_idle;
	uint64_t state;
	int (*run)(void);
	struct core_timer localtimer;
	union{
		struct priv_io_in io_in;
#ifdef __MAIN_LOOP_KNI__
		struct priv_kni kni;
#endif
		struct priv_sum sum;
		struct priv_timer timer;
		struct priv_io_out io_out;
		struct priv_sumsrc sumsrc;
		struct priv_dist distribute;
//		struct priv_pcap pcap;
	};
};

struct out_queue_s{
	void *buf[BURST_SZ];
	int buf_pos;
};

struct out_buf_s{
	struct out_queue_s queue_buf[MAX_CPU];
};

/*
struct ship_slist_p{
	struct slist_header *remote_ch;
	int *remote_cnt;
};

struct ship_slist_c{
	struct slist_header local_ch;
	int local_cnt;
};
*/


/*
static inline void switch_aa(uint64_t *x, uint64_t *y)
{
     *x=*x^*y;
     *y=*x^*y;
     *x=*x^*y;
}
*/

extern int init_step;

extern struct wd_ops ip_pps_dst_ops;
extern struct wd_ops ip_bps_dst_ops;
extern struct wd_ops ip_pps_src_ops;

extern struct wd_ops l4_all_dst_ops;
extern struct wd_ops l4_all_src_ops;
extern struct wd_ops l4_tcp_dst_ops;
extern struct wd_ops l4_tcp_src_ops;
extern struct wd_ops l4_udp_dst_ops;
extern struct wd_ops l4_udp_src_ops;
extern struct wd_ops l4_all_dst_ops2;
extern struct wd_ops l4_all_src_ops2;
extern struct wd_ops l4_tcp_dst_ops2;
extern struct wd_ops l4_tcp_src_ops2;
extern struct wd_ops l4_udp_dst_ops2;
extern struct wd_ops l4_udp_src_ops2;
extern struct wd_ops name_1_src_ops;
extern struct wd_ops name_1_srcip_ops;

extern uint64_t timer_perform_aver[MAX_CPU];
extern uint64_t timer_perform_min[MAX_CPU];
extern uint64_t timer_perform_max[MAX_CPU];

extern uint64_t attack_event_id;

extern char *ip2str(char str[], uint32_t ip);
extern int main_loop_kni(void);
extern int main_loop_sum(void);
extern int main_loop_sum_ip(void);
extern int main_loop_sum_src(void);
extern int main_loop_timer(void);
extern int main_loop_io_sj(void);
extern int main_loop_flow(void);
extern void in_timer_handler(void *t,void *c);
extern int main_loop_s0(void);
extern int main_loop_out(void);
extern int main_loop_gather(void);
extern int main_loop_natlistsum(void);
extern int main_loop_natlistsum2(void);
extern int main_loop_natlistfresh(void);
extern int main_loop_distribute(void);
extern int main_loop_nat(void);
//extern int main_loop_pcap(void);
//extern int wd_process_pps_dst(void *in,struct wd_pack *wd,int s);
//extern int wd_process_bps_dst(void *in,struct wd_pack *wd,int s);


#endif

