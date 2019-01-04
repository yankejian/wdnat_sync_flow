#ifndef __BASE_H
#define __BASE_H

#define CONSTRUCTOR __attribute__((constructor))
#define DESTRUCTOR	__attribute__((destructor))

#define MAX_ARGV		32

#define WATERMARK_FLOW_DIV	2
#define WATERMARK_FLOWPTS_DIV	2
#define WATERMARK_IPPOOL_DIV	2

#define FLAG_CONFIGED	0x1
#define FLAG_STOP		0x2
#define FLAG_RESTART	0x4
//#define FLAG_MODE_RTC	0x08

#define __MAIN_LOOP_KNI__
#define __SRCP_BIT_MAP__
#define __SRC_SUM__
#define __INTER_CONN_IP__
#define __SYNC_FLOW_TABLE__
#define __FIRTST_ACK_SEQ__


#define MAX_CPU	48
#define	MAX_DEV	4
#define MAX_SOCKET	2

#define min(x,y) ((x) < (y) ? x : y)

enum{
	FUN_NULL=0,
	FUN_KNI,
	FUN_IO_OUT,	//Ë½Íø²à
	FUN_IO_IN,	//¹«Íø²à
	FUN_SUM,
	FUN_CALC,
	FUN_TIMER,
	FUN_PCAP,
	FUN_SUM_SRC,
	//FUN_NAT_LISTSUM,
	//FUN_NAT_LISTSUM2,
	//FUN_NAT_LISTFRESH,
	FUN_DISTRIBUTE,
	FUN_MAX,
};

struct mmb{
#ifdef DEBUG_MODULE
	char *name;
#endif
	struct list_head node;
	void *private;
	int (*preinit)(void *);
	int (*init)(void *);
	int (*deinit)(void *);
	int (*subdeinit)(void *);
};

typedef struct {
    int     signo;
    char   *signame;
    char   *name;
    void  (*handler)(int signo);
	struct sigaction oldact;
	int flag;
} m_signal_t;

struct mon_file{
	char *name;
	int  (*parser)(char *);
	time_t lasttime;
    int64_t ctime;
    int64_t mtime;
    int32_t version;
    int32_t dataLength;

};

struct dev_list{
	char *dev_id;
	char *kernel_driver;
	struct list_head list;
};

struct port_info_s{
	uint8_t flag;
	uint8_t socket;
	uint8_t rx_queue_cnt;
	uint8_t tx_queue_cnt;
};

struct io_switch_notify{
	uint64_t req;
	uint64_t ack;
	struct list_head pkt_list[2];
};

struct msg_pipe{
	struct list_head ch;
	struct list_head pending;
	uint64_t req;
};

struct ship_slist{
	struct slist_header ship_ch;
	int ship_cnt;
};

struct skip_slist_cp{
		struct ship_slist *pp;
		struct ship_slist cc;
};

struct hash_array{
	struct list_head header;
	uint32_t load;
};

struct timer_info{
	struct hash_array *ip_timer;
	struct hash_array *flow_timer;
	struct hash_array *flowpts_timer;
	uint32_t queue_sz;
	uint32_t pointer;
};

//typedef int (*topK_cmp_cb_fn)(int,int,void *,int);

//struct topK{
//	int cap;
//	int curr_idx;
//	void **arr;
//	topK_cmp_cb_fn cmp;
//};




extern struct machine me;
extern int term_pending;
//extern int term_delay;

#endif
