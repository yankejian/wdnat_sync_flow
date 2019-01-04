#ifndef __M_KAFKA_H
#define __M_KAFKA_H

#include "rdkafka.h"  /* for Kafka driver */

enum{
	TOPIC_MACHINE_STAT=0,
	TOPIC_DSTIP_STAT,
	TOPIC_ATTACK_EVENT,
	TOPIC_SRC_STATION_EVENT,
	TOPIC_MAX
};

struct topic_info{
	rd_kafka_topic_t *rkt;
	rd_kafka_topic_conf_t *topic_conf;
	char *topic_name;
};

struct kafka_info{
	int inited;
	char *brokers_list;
	rd_kafka_conf_t *conf;
	rd_kafka_t *handle;
	struct topic_info channel_kafka[TOPIC_MAX];
};

extern struct mmb mm_kafka;
extern pthread_cond_t kafka_cond;
extern pthread_mutex_t kafka_mutex;

extern int m_kafka_preinit(void *m);
extern int m_kafka_deinit(void *m);
//extern 	int kafka_init();

#endif
