#include "all.h"

//#define ZK_TEST

struct list_head zk_server_list;
pthread_cond_t cond_step1;
pthread_mutex_t lock_step1;
pthread_cond_t cond_step2;
pthread_mutex_t lock_step2;
pthread_cond_t cond_mon;
pthread_mutex_t lock_mon;
pthread_t zk_thread_id=(pthread_t)0;
zhandle_t *zh;
char file_buf[FILE_BUF_SIZE];
int zk_state=0;
//uint32_t retry;

static void dumpStat(const struct Stat *stat) {
    char tctimes[40];
    char tmtimes[40];
    time_t tctime;
    time_t tmtime;

    if (!stat) {
        fprintf(stderr,"null\n");
        return;
    }
    tctime = stat->ctime/1000;
    tmtime = stat->mtime/1000;
       
    ctime_r(&tmtime, tmtimes);
    ctime_r(&tctime, tctimes);
       
    EARLY_LOG_DEBUG("\tctime = %s\tczxid=%llx\n"
    "\tmtime=%s\tmzxid=%llx\n"
    "\tversion=%x\taversion=%x\n"
    "\tephemeralOwner = %llx\n"
    "\tdatalan = %d\n",
     tctimes, stat->czxid, tmtimes,
    stat->mzxid,
    (unsigned int)stat->version, (unsigned int)stat->aversion,
    stat->ephemeralOwner,stat->dataLength);
}


static const char* state2String(int state){
  if (state == 0)
    return "CLOSED_STATE";
  if (state == ZOO_CONNECTING_STATE)
    return "CONNECTING_STATE";
  if (state == ZOO_ASSOCIATING_STATE)
    return "ASSOCIATING_STATE";
  if (state == ZOO_CONNECTED_STATE)
    return "CONNECTED_STATE";
  if (state == ZOO_EXPIRED_SESSION_STATE)
    return "EXPIRED_SESSION_STATE";
  if (state == ZOO_AUTH_FAILED_STATE)
    return "AUTH_FAILED_STATE";

  return "INVALID_STATE";
}

static const char* type2String(int state){
  if (state == ZOO_CREATED_EVENT)
    return "CREATED_EVENT";
  if (state == ZOO_DELETED_EVENT)
    return "DELETED_EVENT";
  if (state == ZOO_CHANGED_EVENT)
    return "CHANGED_EVENT";
  if (state == ZOO_CHILD_EVENT)
    return "CHILD_EVENT";
  if (state == ZOO_SESSION_EVENT)
    return "SESSION_EVENT";
  if (state == ZOO_NOTWATCHING_EVENT)
    return "NOTWATCHING_EVENT";

  return "UNKNOWN_EVENT_TYPE";
}

void watcher(zhandle_t *zzh, int type, int state, const char *path,
             void* context)
{
    EARLY_LOG_DEBUG("%s: %s state = %s\n", __FUNCTION__,type2String(type), state2String(state));

    if(type == ZOO_SESSION_EVENT)
		{
        if(state == ZOO_CONNECTED_STATE)
			{
            pthread_mutex_lock(&lock_step1);
            pthread_cond_broadcast(&cond_step1);
            pthread_mutex_unlock(&lock_step1);
       		}
    	}

}

int upload_file(struct mon_file *f,char *zk_path)
{
	int r,len;
	struct stat buf;
	struct Stat zk_stat;
    FILE *fp;
	
	r=stat(f->name, &buf);
	if((r)||!(buf.st_mode & S_IFREG))
		{
		EARLY_LOG_ERROR("%s , MISSING %s file\n",__FUNCTION__,f->name);
		return MM_FAIL;
		}

    if((fp = fopen(f->name, "r")) == NULL) 
		{
		EARLY_LOG_ERROR("%s , Fail open %s file\n",__FUNCTION__,f->name);
		return MM_FAIL;
		}

	if((len = fread(file_buf, 1, buf.st_size, fp)) != buf.st_size) 
		{
		EARLY_LOG_ERROR("%s , Fail read %s file\n",__FUNCTION__,f->name);
		fclose(fp);
		return MM_FAIL;
		}

	fclose(fp);

	r=zoo_create(zh, zk_path, NULL, 0, &ZOO_OPEN_ACL_UNSAFE, 0, NULL,0);
	if(r!=ZOK)
		{
		EARLY_LOG_ERROR("%s , sync create %s -> %s fail\n",__FUNCTION__,f->name,zk_path);
		return MM_FAIL;
		}

	r=zoo_set2(zh,zk_path,file_buf,buf.st_size,-1,&zk_stat);
	if(r!=ZOK)
		{
		EARLY_LOG_ERROR("%s , sync set %s -> %s fail\n",__FUNCTION__,f->name,zk_path);
		return MM_FAIL;
		}	

	EARLY_LOG_INFO("upload %s ctime=%llu<-%llu mtime=%llu<-%llu v=%d<-%d len=%d<-%d\n",
		f->name,
		zk_stat.ctime,f->ctime,
		zk_stat.mtime,f->mtime,
		zk_stat.version,f->version,
		zk_stat.dataLength,f->dataLength);

	f->ctime=zk_stat.ctime;
	f->mtime=zk_stat.mtime;
	f->version=zk_stat.version;
	f->dataLength=zk_stat.dataLength;
			
	return MM_SUCCESS;
}


int download_file(struct mon_file *f,char *zk_path)
{
	FILE *fp;
	struct Stat zk_stat;
	int len=FILE_BUF_SIZE;

	if(zoo_get(zh, zk_path, 0, file_buf, &len, &zk_stat)!=ZOK)
		{
		EARLY_LOG_ERROR("%s ,zk get %s fail\n",__FUNCTION__,zk_path);
		return MM_FAIL;
		}

	if((fp=fopen(f->name,"w+"))==NULL)
		return MM_FAIL;

	if(fwrite(file_buf,len,1,fp)!=1)
		return MM_FAIL;

	fclose(fp);

	EARLY_LOG_INFO("download %s ctime=%llu<-%llu mtime=%llu<-%llu v=%d<-%d len=%d<-%d %d\n",
		f->name,
		zk_stat.ctime,f->ctime,
		zk_stat.mtime,f->mtime,
		zk_stat.version,f->version,
		zk_stat.dataLength,f->dataLength,len);

	f->ctime=zk_stat.ctime;
	f->mtime=zk_stat.mtime;
	f->version=zk_stat.version;
	f->dataLength=zk_stat.dataLength;	

	return MM_SUCCESS;
}

void *zk_thread(void *args)
{
	int r=0,i,rv;
	struct list_head tmp_list;
	struct zk_s_list *dd, *temp;
	char tbuf[1024];
	struct timeval now;
	struct timespec outtime;
	struct mon_file *pp;


	INIT_LIST_HEAD(&tmp_list);
    pthread_cond_init(&cond_mon,0);
    pthread_mutex_init(&lock_mon,0);

#if 1
	while(!term_pending)
		{
		if(zk_state==1)
			{
			if(zoo_state(zh)!=ZOO_CONNECTED_STATE)
				{
				EARLY_LOG_INFO("%s : link become %s\n",__FUNCTION__,state2String(zoo_state(zh)));
				zookeeper_close(zh);
				zk_state=0;
				continue;
				}
			
			if(term_pending)
				break;
			
			for(i=0,pp=&file_mon[0];i<sizeof(file_mon)/sizeof(file_mon[0]);i++,pp++) 
				{
					int rc;
					struct Stat stat;
		
					memset(&stat,0,sizeof(struct Stat));
		
					sprintf(tbuf,"%s/%s/%s",ZK_ROOT,me.id,basename(pp->name));
					rc = zoo_exists(zh, tbuf, 0, &stat);
		//			dumpStat(&stat);
					if(rc)
						{				
						EARLY_LOG_INFO("%s(%d) :file %s not exist,upload it\n",__FUNCTION__,__LINE__,pp->name);
						upload_file(pp,tbuf);
						}
					else//exist
						{
						if((stat.ctime!=pp->ctime)||
							(stat.mtime!=pp->mtime)||
							(stat.version!=pp->version)||
							(stat.dataLength!=pp->dataLength))//update
							{
							char tmp[256];
							
							sprintf(tmp,"mv -f %s %s.bak}",pp->name,pp->name);
							system(tmp);
							if(download_file(pp,tbuf)==MM_FAIL)
								{
								EARLY_LOG_INFO("%s(%d) : sync %s fail,recover to old version\n",__FUNCTION__,__LINE__,pp->name);
								sprintf(tmp,"mv -f %s.bak %s}",pp->name,pp->name);
								system(tmp);
								}
							else
								{
								EARLY_LOG_INFO("update %s ctime=%llu<-%llu mtime=%llu<-%llu v=%d<-%d len=%d<-%d\n",
									pp->name,
									stat.ctime,pp->ctime,
									stat.mtime,pp->mtime,
									stat.version,pp->version,
									stat.dataLength,pp->dataLength);
								
								pp->ctime=stat.ctime;
								pp->mtime=stat.mtime;
								pp->version=stat.version;
								pp->dataLength=stat.dataLength;
								sprintf(tmp,"rm -f %s.bak}",pp->name);
								system(tmp);
								}
							}
						}
					}

				gettimeofday(&now, NULL);
				outtime.tv_sec = now.tv_sec + ZK_MON_TIMEOUT/1000;
				outtime.tv_nsec = now.tv_usec * 1000;
				
				pthread_mutex_lock(&lock_mon);
				rv=pthread_cond_timedwait(&cond_mon,&lock_mon,&outtime);
				pthread_mutex_unlock(&lock_mon);
			}
		else//default link state
			{
				list_for_each_entry_safe(dd,temp,&zk_server_list,list){
					zh=NULL;
					if(term_pending)
						break;
					
					r=0;
					list_del_init(&dd->list);
					list_add_tail(&dd->list,&tmp_list);
					sprintf(tbuf,"%s:%u",dd->ip,dd->port);
					EARLY_LOG_INFO("%s , try host = %s\n",__FUNCTION__,tbuf);
					
					zh = zookeeper_init(tbuf, watcher, ZK_INIT_TIMEOUT, 0, 0, 0);
					if (zh)
						{
						gettimeofday(&now, NULL);
						outtime.tv_sec = now.tv_sec + ZK_INIT_TIMEOUT/1000;
						outtime.tv_nsec = now.tv_usec * 1000;
						
						pthread_mutex_lock(&lock_step1);
						rv=pthread_cond_timedwait(&cond_step1,&lock_step1,&outtime);
						pthread_mutex_unlock(&lock_step1);
						
						if(zoo_state(zh)==ZOO_CONNECTED_STATE)
							{
							EARLY_LOG_INFO("%s : host %s connnect OK %p\n",__FUNCTION__,tbuf,zh);
							r=1;
							break;
							}
						else
							{
							EARLY_LOG_INFO("%s : host %s connnect fail\n",__FUNCTION__,state2String(zoo_state(zh)));
							zookeeper_close(zh);
							}
						}
				}	

				list_splice_tail_init(&tmp_list,&zk_server_list);

				if(term_pending)
					{
					EARLY_LOG_DEBUG("%s : caught term_pending at %d\n",__FUNCTION__,__LINE__);
					if(r)
						zookeeper_close(zh);

					continue;
					}

				if(!r)//link zk cliustor fail, fall back to local config
					{
					pthread_mutex_lock(&lock_step2);
		            pthread_cond_broadcast(&cond_step2);
		            pthread_mutex_unlock(&lock_step2);
					EARLY_LOG_INFO("%s : let main thread go\n",__FUNCTION__);
					sleep(ZK_INIT_TIMEOUT/1000);
					continue;
					}		

				//link ok,check id 
				sprintf(tbuf,"%s/%s",ZK_ROOT,me.id);
				r=zoo_create(zh, tbuf, me.id, strlen(me.id), &ZOO_OPEN_ACL_UNSAFE, 0, NULL,0);
				/*
				* ZOK operation completed successfully
				* ZNONODE the parent node does not exist.
				* ZNODEEXISTS the node already exists
				* ZNOAUTH the client does not have permission.
				* ZNOCHILDRENFOREPHEMERALS cannot create children of ephemeral nodes.
				* \param data The data that will be passed to the completion routine when the 
				* function completes.
				* \return ZOK on success or one of the following errcodes on failure:
				* ZBADARGUMENTS - invalid input parameters
				* ZINVALIDSTATE - zhandle state is either ZOO_SESSION_EXPIRED_STATE or ZOO_AUTH_FAILED_STATE
				* ZMARSHALLINGERROR - failed to marshall a request; possibly, out of memory
				*/
				if(r==ZOK)//upload all mon files,go to mom loop
					{
					EARLY_LOG_INFO("%s(%d) : met OK\n",__FUNCTION__,__LINE__);	
					zk_state=1;
					}
				else if(r==ZNODEEXISTS)//id exist ,go to mom loop
					{
					EARLY_LOG_INFO("%s(%d) : met EXIST\n",__FUNCTION__,__LINE__);
					zk_state=1;
					}
				else
					{
					EARLY_LOG_INFO("%s(%d) : met error %s\n",__FUNCTION__,__LINE__,zerror(r));				
					zookeeper_close(zh);
					sleep(ZK_INIT_TIMEOUT/1000);
					continue;					
					}
				
				pthread_mutex_lock(&lock_step2);
				pthread_cond_broadcast(&cond_step2);
				pthread_mutex_unlock(&lock_step2);
			}
		}

#else
	while(!term_pending)
		{
//retry_link:
		list_for_each_entry_safe(dd,temp,&zk_server_list,list){
			zh=NULL;
			if(term_pending)
				break;
			
			r=0;
			list_del_init(&dd->list);
			list_add_tail(&dd->list,&tmp_list);
			sprintf(tbuf,"%s:%u",dd->ip,dd->port);
			EARLY_LOG_INFO("%s , try host = %s\n",__FUNCTION__,tbuf);
			
			zh = zookeeper_init(tbuf, watcher, ZK_INIT_TIMEOUT, 0, 0, 0);
			if (zh)
				{
				gettimeofday(&now, NULL);
				outtime.tv_sec = now.tv_sec + ZK_INIT_TIMEOUT/1000;
				outtime.tv_nsec = now.tv_usec * 1000;
				
				pthread_mutex_lock(&lock_step1);
				rv=pthread_cond_timedwait(&cond_step1,&lock_step1,&outtime);
				pthread_mutex_unlock(&lock_step1);
				
				if(zoo_state(zh)==ZOO_CONNECTED_STATE)
					{
					EARLY_LOG_INFO("%s : host %s connnect OK %p\n",__FUNCTION__,tbuf,zh);
					r=1;
					break;
					}
				else
					{
					EARLY_LOG_INFO("%s : host %s connnect fail\n",__FUNCTION__,state2String(zoo_state(zh)));
					zookeeper_close(zh);
					}
				}
		}

		list_splice_tail_init(&tmp_list,&zk_server_list);
		if(term_pending)
			{
			EARLY_LOG_DEBUG("%s : caught term_pending at %d\n",__FUNCTION__,__LINE__);
			if(r)
				zookeeper_close(zh);

			continue;
			}

		if(!r)//link zk cliustor fail, fall back to local config
			{
//fall_back:
			pthread_mutex_lock(&lock_step2);
            pthread_cond_broadcast(&cond_step2);
            pthread_mutex_unlock(&lock_step2);
			EARLY_LOG_INFO("%s : let main thread go\n",__FUNCTION__);
			sleep(ZK_INIT_TIMEOUT/1000);
			//goto retry_link;
			continue;
			}

		//link ok,check id 
		sprintf(tbuf,"%s/%s",ZK_ROOT,me.id);
		r=zoo_create(zh, tbuf, me.id, strlen(me.id), &ZOO_OPEN_ACL_UNSAFE, 0, NULL,0);
		/*
		* ZOK operation completed successfully
		* ZNONODE the parent node does not exist.
		* ZNODEEXISTS the node already exists
		* ZNOAUTH the client does not have permission.
		* ZNOCHILDRENFOREPHEMERALS cannot create children of ephemeral nodes.
		* \param data The data that will be passed to the completion routine when the 
		* function completes.
		* \return ZOK on success or one of the following errcodes on failure:
		* ZBADARGUMENTS - invalid input parameters
		* ZINVALIDSTATE - zhandle state is either ZOO_SESSION_EXPIRED_STATE or ZOO_AUTH_FAILED_STATE
		* ZMARSHALLINGERROR - failed to marshall a request; possibly, out of memory
		*/
		switch(r)
			{
			case ZOK://upload all mon files,go to mom loop
				EARLY_LOG_INFO("%s(%d) : met OK\n",__FUNCTION__,__LINE__);	
				break;
			case ZNODEEXISTS://id exist ,go to mom loop
				EARLY_LOG_INFO("%s(%d) : met EXIST\n",__FUNCTION__,__LINE__);	
				break;
			default:
				EARLY_LOG_INFO("%s(%d) : met error %s\n",__FUNCTION__,__LINE__,zerror(r));				
				zookeeper_close(zh);
				sleep(ZK_INIT_TIMEOUT/1000);
				//goto retry_link;
				continue;
			}	

		pthread_mutex_lock(&lock_step2);
		pthread_cond_broadcast(&cond_step2);
		pthread_mutex_unlock(&lock_step2);


mon_loop:
		if(zoo_state(zh)!=ZOO_CONNECTED_STATE)
			{
			EARLY_LOG_INFO("%s : link become %s\n",__FUNCTION__,state2String(zoo_state(zh)));
			zookeeper_close(zh);
			//goto retry_link;
			continue;
			}

		if(term_pending)
			break;
	
		for(i=0,pp=&file_mon[0];i<sizeof(file_mon)/sizeof(file_mon[0]);i++,pp++)
			{
			int rc;
			struct Stat stat;

			memset(&stat,0,sizeof(struct Stat));

			sprintf(tbuf,"%s/%s/%s",ZK_ROOT,me.id,basename(pp->name));
			rc = zoo_exists(zh, tbuf, 0, &stat);
//			dumpStat(&stat);
			if(rc)
				{				
				EARLY_LOG_INFO("%s(%d) :file %s not exist,upload it\n",__FUNCTION__,__LINE__,pp->name);
				upload_file(pp,tbuf);
				}
			else//exist
				{
				if((stat.ctime!=pp->ctime)||
					(stat.mtime!=pp->mtime)||
					(stat.version!=pp->version)||
					(stat.dataLength!=pp->dataLength))//update
					{
					char tmp[256];
					
					sprintf(tmp,"mv -f %s %s.bak}",pp->name,pp->name);
					system(tmp);
					if(download_file(pp,tbuf)==MM_FAIL)
						{
						EARLY_LOG_INFO("%s(%d) : sync %s fail,recover to old version\n",__FUNCTION__,__LINE__,pp->name);
						sprintf(tmp,"mv -f %s.bak %s}",pp->name,pp->name);
						system(tmp);
						}
					else
						{
						EARLY_LOG_INFO("update %s ctime=%llu<-%llu mtime=%llu<-%llu v=%d<-%d len=%d<-%d\n",
							pp->name,
							stat.ctime,pp->ctime,
							stat.mtime,pp->mtime,
							stat.version,pp->version,
							stat.dataLength,pp->dataLength);
						
						pp->ctime=stat.ctime;
						pp->mtime=stat.mtime;
						pp->version=stat.version;
						pp->dataLength=stat.dataLength;
						sprintf(tmp,"rm -f %s.bak}",pp->name);
						system(tmp);
						}
					}
				}
			}

		gettimeofday(&now, NULL);
		outtime.tv_sec = now.tv_sec + ZK_MON_TIMEOUT/1000;
		outtime.tv_nsec = now.tv_usec * 1000;
		
		pthread_mutex_lock(&lock_mon);
		rv=pthread_cond_timedwait(&cond_mon,&lock_mon,&outtime);
		pthread_mutex_unlock(&lock_mon);
		if(rv==EINTR)
			{
			EARLY_LOG_INFO("%s : get interrupt for cond_mon\n",__FUNCTION__);
			continue;
			}

		goto mon_loop;
		}
#endif

	if(!list_empty(&zk_server_list))
		list_for_each_entry_safe(dd,temp,&zk_server_list,list){
			list_del_init(&dd->list);
			EARLY_LOG_INFO("cleanup zk = %s %d\n",dd->ip,dd->port);
			free(dd->ip);
			free(dd);
		}

	if(!list_empty(&tmp_list))
		list_for_each_entry_safe(dd,temp,&tmp_list,list){
			list_del_init(&dd->list);
			EARLY_LOG_INFO("cleanup tmp list = %s %d\n",dd->ip,dd->port);
			free(dd->ip);
			free(dd);
		}	

	EARLY_LOG_INFO("%s(%d) : zk thread exit now\n",__FUNCTION__,__LINE__);
}

#ifdef ZK_TEST

void *zk_test_thread(void *args)
{
	zhandle_t *zhxx;
	int rc;
	int id;
	char data[100];
	int data_len;
	struct Stat stat,laststat;
	int test_len;
	char test_data[100];


	sleep(5);
	id=*(int *)args;

	data_len=sizeof(data);


    zoo_set_debug_level(/*ZOO_LOG_LEVEL_DEBUG*/ZOO_LOG_LEVEL_ERROR);
    zoo_deterministic_conn_order(1); // enable deterministic order

	zhxx = zookeeper_init("192.168.30.11:2181", NULL, ZK_INIT_TIMEOUT, 0, 0, 0);
	if(zhxx==NULL)
		{
		EARLY_LOG_INFO("%s(%d) : thread tid=%d id=%d zk init fail\n",__FUNCTION__,__LINE__,pthread_self(),id);
		return NULL;
		}

	sprintf(test_data,"%d",pthread_self());
	test_len=strlen(test_data);
//	test_len+=id;
//	snprintf(test_data,test_len,"%s","1234567890abcdef");
	EARLY_LOG_INFO("%s(%d) : thread tid=%d id=%d %d %s\n",__FUNCTION__,__LINE__,pthread_self(),id,test_len,test_data);

	while(1)
		{
//		EARLY_LOG_INFO("%s(%d) kkkkkkkkk : thread tid=%d id=%d\n",__FUNCTION__,__LINE__,pthread_self(),id);
			rc = zoo_exists(zhxx, "/abc/dd", 0, &stat);
			if(rc==ZOK)
				{
				int x=0;
				/*
				EARLY_LOG_INFO("thread (%d) : ctime=%llu mtime=%llu v=%d len=%d\n",
					pthread_self(),stat.ctime,stat.mtime,stat.version,stat.dataLength);		*/

				if(stat.ctime !=laststat.ctime)
					{
					EARLY_LOG_INFO("thread (%d) : ctime mismatch %llu %llu\n",
						pthread_self(),stat.ctime,laststat.ctime);	
					x|=1;
					}
				
				if(stat.mtime !=laststat.mtime)
					{
					EARLY_LOG_INFO("thread (%d) : mtime mismatch %llu %llu\n",
						pthread_self(),stat.mtime,laststat.mtime);					
					x|=2;
					}

				if(stat.version !=laststat.version)
					{
					EARLY_LOG_INFO("thread (%d) : version mismatch %d %d\n",
						pthread_self(),stat.version,laststat.version);	
					x|=4;
					}	

				if(stat.dataLength !=laststat.dataLength)
					{
					EARLY_LOG_INFO("thread (%d) : dataLength mismatch %d %d\n",
						pthread_self(),stat.dataLength,laststat.dataLength);	
					x|=8;
					}	

				if(x)
					{
					data_len=100;
					rc=zoo_get(zhxx,"/abc/dd",0,data,&data_len,&laststat);
					if(rc==ZOK)
						{
						EARLY_LOG_INFO("thread (%d) : update ctime=%llu->%llu mtime=%llu->%llu v=%d->%d len=%d->%d data=%s datalen=%d\n",
							pthread_self(),
							stat.ctime,laststat.ctime,
							stat.mtime,laststat.mtime,
							stat.version,laststat.version,
							stat.dataLength,laststat.dataLength,
							data,data_len);			

						memcpy(&laststat,&stat,sizeof(stat));
						}
					}

				}
			else
				{
				EARLY_LOG_INFO("thread (%d) : zk exist fail\n",
					pthread_self());	

				}

			sleep(5);

			rc=zoo_set2(zhxx,"/abc/dd",test_data,test_len,-1,&stat);
			if(rc==ZOK)
				{
					EARLY_LOG_INFO("thread (%d) : write ctime=%llu mtime=%llu v=%d len=%d data=%s datalen=%d\n",
						pthread_self(),
						stat.ctime,stat.mtime,stat.version,
						stat.dataLength,
						data,data_len);					
				}


			//write
		}
}
#endif

#ifdef ZK_TEST
pthread_t zk_test_thread_id[3];
int xx_id[3];
#endif


int zk_init(void)
{
	int rc;

//	retry=ZK_RETRY;
/*
	file_buf=(char *)malloc(FILE_BUF_SIZE);
	if(file_buf==NULL)
		{
		EARLY_LOG_ERROR("file buffer malloc fail\n");
		exit(1);
		}

	memset(file_buf,'a',FILE_BUF_SIZE);
	if(sync_mon_file("./abcd",file_buf,FILE_BUF_SIZE)!=MM_SUCCESS)
		{
		EARLY_LOG_ERROR("kkkkkkkkkkkkkkkkkkkkkkkkkk\n");
		exit(1);		
		}
*/
    zoo_set_debug_level(/*ZOO_LOG_LEVEL_DEBUG*/ZOO_LOG_LEVEL_ERROR);
    zoo_deterministic_conn_order(1); // enable deterministic order

    pthread_cond_init(&cond_step1,0);
    pthread_mutex_init(&lock_step1,0);
    pthread_cond_init(&cond_step2,0);
    pthread_mutex_init(&lock_step2,0);
    pthread_cond_init(&cond_mon,0);
    pthread_mutex_init(&lock_mon,0);

	zk_state=0;//link

#ifdef ZK_TEST
{
	int i;

	for(i=0;i<3;i++)
		{
		xx_id[i]=i+1;
		rc = pthread_create(&zk_test_thread_id[i], NULL,  &zk_test_thread, &xx_id[i]);
		if (rc != 0) {
			EARLY_LOG_ERROR("thread %d fail\n", i);
			}	

		}
}
#else

	rc = pthread_create(&zk_thread_id, NULL,  &zk_thread, NULL);
	if (rc != 0) {
		EARLY_LOG_ERROR("Failed to create zk thread, err=%s\n", strerror(errno));
		//return MM_FAIL;
		exit(1);
	}	

    pthread_mutex_lock(&lock_step2);
    pthread_cond_wait(&cond_step2,&lock_step2);
    pthread_mutex_unlock(&lock_step2);    	
	if(term_pending)
		{
		EARLY_LOG_DEBUG("%s : met term_pending\n", __FUNCTION__);
		return MM_FAIL;
		}

	EARLY_LOG_DEBUG("%s : zk go continue\n", __FUNCTION__);
	
#endif
	return MM_SUCCESS;

}

/*
int zk_deinit(void)
{
    pthread_cond_destroy(&cond_step1);
	EARLY_LOG_DEBUG("%s : 111111111111111111111\n", __FUNCTION__);
    pthread_mutex_destroy(&lock_step1);
	
	EARLY_LOG_DEBUG("%s : 222222222222222222222222\n", __FUNCTION__);
    pthread_cond_destroy(&cond_step2);
	
	EARLY_LOG_DEBUG("%s : 333333333333333333333333333\n", __FUNCTION__);
    pthread_mutex_destroy(&lock_step2);
	
	EARLY_LOG_DEBUG("%s : 44444444444444444444444444\n", __FUNCTION__);
    pthread_cond_destroy(&cond_mon);
	
	EARLY_LOG_DEBUG("%s : 55555555555555555555555555555555\n", __FUNCTION__);
    pthread_mutex_destroy(&lock_mon);
	
	EARLY_LOG_DEBUG("%s : 666666666666666666666666666666\n", __FUNCTION__);

//	if(file_buf)
//		free(file_buf);

}
*/
