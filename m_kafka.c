#include "all.h"

//#define LOG_EMERG   0
//#define LOG_ALERT   1
//#define LOG_CRIT    2
//#define LOG_ERR     3
//#define LOG_WARNING 4
//#define LOG_NOTICE  5
//#define LOG_INFO    6
//#define LOG_DEBUG   7


pthread_t kafka_thread_id=(pthread_t)0;
pthread_cond_t kafka_cond;
pthread_mutex_t kafka_mutex;



/**
 * Message delivery report callback.
 * Called once for each message.
 * See rdkafka.h for more information.
 */
static void msg_delivered (rd_kafka_t *rk,
			   void *payload, size_t len,
			   int error_code,
			   void *opaque, void *msg_opaque) {

	if (error_code)
		RUNNING_LOG_INFO("%% Message delivery failed: %s\n",
			rd_kafka_err2str(error_code));
}

void *ch_kafka_thread(void *args)
{
	
	while(!term_pending)
		{
        pthread_mutex_lock(&kafka_mutex);
        pthread_cond_wait(&kafka_cond, &kafka_mutex);
		pthread_mutex_unlock(&kafka_mutex);

		}

	
	RUNNING_LOG_INFO("%s : kafka thread exit now\n",__FUNCTION__);
}

#if 0
static rd_kafka_t *rk;

void *kafka_thread(void *args)
{
	rd_kafka_topic_t *rkt;
	char *brokers = "localhost:9092";
	char *topic = "mytest";
	int partition = RD_KAFKA_PARTITION_UA;
	int opt;
	rd_kafka_conf_t *conf;
	rd_kafka_topic_conf_t *topic_conf;
	char errstr[512];
	char tmp[16];
	char buf[2048];
	int len;
	int i=1;
	
	/* Kafka configuration */
	conf = rd_kafka_conf_new();

        /* Set logger */
//        rd_kafka_conf_set_log_cb(conf, logger);

	/* Quick termination */
	snprintf(tmp, sizeof(tmp), "%i", SIGIO);
	rd_kafka_conf_set(conf, "internal.termination.signal", tmp, NULL, 0);

	/* Topic configuration */
	topic_conf = rd_kafka_topic_conf_new();

	rd_kafka_conf_set_dr_cb(conf, msg_delivered);
	
	/* Create Kafka handle */
	if (!(rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf,
				errstr, sizeof(errstr)))) {
		fprintf(stderr,
			"%% Failed to create new producer: %s\n",
			errstr);
		return;
	}
	
	rd_kafka_set_log_level(rk, 7/*LOG_DEBUG*/);
	
	/* Add brokers */
	if (rd_kafka_brokers_add(rk, brokers) == 0) {
		fprintf(stderr, "%% No valid brokers specified\n");
		return;
	}
	
	/* Create topic */
	rkt = rd_kafka_topic_new(rk, topic, topic_conf);
			topic_conf = NULL; /* Now owned by topic */

	
	while(!term_pending)
	{
		
		sprintf(buf,"abc_%d\n",i++);
		len=strlen(buf);
		if (rd_kafka_produce(rkt, partition,
					 RD_KAFKA_MSG_F_COPY,
					 /* Payload and length */
					 buf, len,
					 /* Optional key and its length */
					 NULL, 0,
					 /* Message opaque, provided in
					  * delivery report callback as
					  * msg_opaque. */
					 NULL) == -1) {
			fprintf(stderr,
				"%% Failed to produce to topic %s "
				"partition %i: %s\n",
				rd_kafka_topic_name(rkt), partition,
				rd_kafka_err2str(rd_kafka_last_error()));
			/* Poll to handle delivery reports */
		}
		else
			{
			fprintf(stderr, "%% Sent %zd bytes to topic "
				"%s partition %i\n",
			len, rd_kafka_topic_name(rkt), partition);

			}
		
		rd_kafka_poll(rk, 0);


		sleep(1);	
	}

	/* Wait for messages to be delivered */
	while (rd_kafka_outq_len(rk) > 0)
		rd_kafka_poll(rk, 100);
	
	/* Destroy topic */
	rd_kafka_topic_destroy(rkt);
	
	/* Destroy the handle */
	rd_kafka_destroy(rk);

	RUNNING_LOG_INFO("%s : conf thread exit now\n",__FUNCTION__);

}


int kafka_init()
{
	int rc;

	EARLY_LOG_DEBUG("%s\n",__FUNCTION__);


	pthread_cond_init(&kafka_cond, NULL);
	pthread_mutex_init(&kafka_mutex, NULL);

	rc = pthread_create(&kafka_thread_id, NULL,  &kafka_thread, NULL);
	if (rc != 0) {
		RUNNING_LOG_ERROR("Failed to create kafka thread, err=%s\n", strerror(errno));
		return MM_FAIL;
	}	

	return MM_SUCCESS;

}
#endif

struct mmb mm_kafka={
	.name="m_kafka",
	.preinit=m_kafka_preinit,
	.deinit=m_kafka_deinit,
};

int m_kafka_preinit(__attribute__((unused)) void *m)
{
	char tmp[16];
	char errstr[512];
	int i,rc;

	RUNNING_LOG_DEBUG("%s\n",__FUNCTION__);

	me.ch_kafka.inited=0;

	/* Kafka configuration */
	me.ch_kafka.conf = rd_kafka_conf_new();

        /* Set logger */
//        rd_kafka_conf_set_log_cb(conf, logger);

	/* Quick termination */
	snprintf(tmp, sizeof(tmp), "%i", SIGIO);
	rd_kafka_conf_set(me.ch_kafka.conf, "internal.termination.signal", tmp, NULL, 0);

	rd_kafka_conf_set_dr_cb(me.ch_kafka.conf, msg_delivered);
	
	/* Create Kafka handle */
	if (!(me.ch_kafka.handle = rd_kafka_new(RD_KAFKA_PRODUCER, me.ch_kafka.conf,
				errstr, sizeof(errstr)))) {
		RUNNING_LOG_ERROR("%% Failed to create new producer: %s\n",errstr);
		exit(1);
	}
	
	rd_kafka_set_log_level(me.ch_kafka.handle, 6/*LOG_INFO*/);
	
	/* Add brokers */
	if (rd_kafka_brokers_add(me.ch_kafka.handle, me.ch_kafka.brokers_list) == 0) {
		RUNNING_LOG_ERROR("%% No valid brokers specified\n");
		exit(1);
	}

	for(i=0;i<TOPIC_MAX;i++)
		{
		if(me.ch_kafka.channel_kafka[i].topic_name)
			{
			/* Topic configuration */
			me.ch_kafka.channel_kafka[i].topic_conf = rd_kafka_topic_conf_new();
			/* Create topic */
			me.ch_kafka.channel_kafka[i].rkt = rd_kafka_topic_new(me.ch_kafka.handle, 
				me.ch_kafka.channel_kafka[i].topic_name, me.ch_kafka.channel_kafka[i].topic_conf);
			
			me.ch_kafka.channel_kafka[i].topic_conf = NULL; /* Now owned by topic */	
			}
		}
	
	me.ch_kafka.inited=1;

	pthread_cond_init(&kafka_cond, NULL);
	pthread_mutex_init(&kafka_mutex, NULL);

	rc = pthread_create(&kafka_thread_id, NULL,  &ch_kafka_thread, NULL);
	if (rc != 0) {
		RUNNING_LOG_ERROR("Failed to create kafka thread, err=%s\n", strerror(errno));
		exit(1);
	}	

	RUNNING_LOG_DEBUG("%s finished\n",__FUNCTION__);

	return MM_SUCCESS;
}

int m_kafka_deinit(__attribute__((unused)) void *m)
{
	int i;
	int run = 5;

	RUNNING_LOG_INFO("%s\n",__FUNCTION__);

	if(me.ch_kafka.inited)
		{
		/* Poll to handle delivery reports */
		rd_kafka_poll(me.ch_kafka.handle, 0);

		/* Wait for messages to be delivered */
		while (run && rd_kafka_outq_len(me.ch_kafka.handle) > 0)
			rd_kafka_poll(me.ch_kafka.handle, 100);

		/* Destroy topic */
		for(i=0;i<TOPIC_MAX;i++)
			{
			if(me.ch_kafka.channel_kafka[i].topic_name)
				rd_kafka_topic_destroy(me.ch_kafka.channel_kafka[i].rkt);
			}		

		/* Destroy the handle */
		rd_kafka_destroy(me.ch_kafka.handle);

		/* Let background threads clean up and terminate cleanly. */
		run = 5;
		while (run-- > 0 && rd_kafka_wait_destroyed(1000) == -1)
			RUNNING_LOG_ERROR("Waiting for librdkafka to decommission\n");
		
		if (run <= 0)
			rd_kafka_dump(running_log_fp, me.ch_kafka.handle);		

		for(i=0;i<TOPIC_MAX;i++)
			{
			if(me.ch_kafka.channel_kafka[i].topic_name)
				free(me.ch_kafka.channel_kafka[i].topic_name);
			}

		free(me.ch_kafka.brokers_list);
		}

	RUNNING_LOG_INFO("%s finished\n",__FUNCTION__);

	return MM_SUCCESS;	
}


