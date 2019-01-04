#ifndef __M_ZK_H
#define __M_ZK_H

#define ZK_ROOT		"/wy_fw"

#define ZK_RETRY		(-1U)	

#define ZK_INIT_TIMEOUT	5000
#define ZK_MON_TIMEOUT	2000

#define MON_LINK		0
#define MON_MON			1

#define FILE_BUF_SIZE	(64*1024*1024)

struct zk_s_list{
	char *ip;
	int port;
	struct list_head list;
};

extern struct list_head zk_server_list;
extern pthread_cond_t cond_step1;
extern pthread_mutex_t lock_step1;
extern pthread_cond_t cond_step2;
extern pthread_mutex_t lock_step2;
extern pthread_cond_t cond_mon;
extern pthread_mutex_t lock_mon;
extern pthread_t zk_thread_id;

#define version_after(a,b)	((int)((unsigned int)(b) - (unsigned int)(a)) < 0)

int zk_init(void);
int zk_deinit(void);


#endif
