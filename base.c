#include "all.h"

struct machine me;
struct list_head base_module;
int term_pending;
//int term_delay;
int fd_lock=-1;

int attach_module(struct mmb *m,struct list_head *head)
{
	INIT_LIST_HEAD(&m->node);
	list_add(&m->node,head);
	if(m->preinit)
		return m->preinit(m->private);
	else
		return MM_SUCCESS;	
}

int detach_module(struct mmb *m)
{	
	list_del_init(&m->node);
	if(m->deinit)
		return m->deinit(m->private);
	else
		return MM_SUCCESS;
}

int lock_app()
{
	struct flock lock;	
	char buf[32];  
	  
	fd_lock = open(DEFAULT_PID_FILE, O_WRONLY | O_CREAT, 0666);	
	if (fd_lock < 0) 
		{  
		perror("Open lock file "DEFAULT_PID_FILE"\n");  
		return MM_FAIL;
		}  
	  
	bzero(&lock, sizeof(lock));  
	  
	if (fcntl(fd_lock, F_GETLK, &lock) < 0)
		{  
		perror("Fail to get lock\n");  
		return MM_FAIL;
		}  
	  
	lock.l_type = F_WRLCK;	
	lock.l_whence = SEEK_SET;  
	  
	if (fcntl(fd_lock, F_SETLK, &lock) < 0) 
		{  
		perror("Fail to set lock\n");  
		return MM_FAIL;
		}  
	  
	pid_t pid = getpid();  
	int len = snprintf(buf, 32, "%d\n", (int)pid);	
	  
	write(fd_lock, buf, len);	  

	return MM_SUCCESS;
}

void unlock_app()
{
	struct flock lock;	

	lock.l_type = F_UNLCK;	
	lock.l_whence = SEEK_SET;  
	  
	if (fcntl(fd_lock, F_SETLK, &lock) < 0) 
		perror("Fail to set lock in unlock");  
	
	close(fd_lock);	
	
	system("rm -f "DEFAULT_PID_FILE);
}

void CONSTRUCTOR base_init()
{	
	if(lock_app()==MM_FAIL)
		{
		perror("lock app error !\n");
		fd_lock=-1;
		exit(1);
		}

	if(early_get_root()!=MM_SUCCESS)
		{
		perror("base_init error !\n");
		exit(1);
		}
	
	term_pending=0;
	INIT_LIST_HEAD(&base_module);

	attach_module(&mm_signal,&base_module);
	attach_module(&mm_conf,&base_module);
	attach_module(&mm_log,&base_module);
	attach_module(&mm_kafka,&base_module);
	attach_module(&mm_plat,&base_module);

}

void DESTRUCTOR base_deinit()
{
	struct mmb *m, *temp;
	int i;

	term_pending=1;

	if(fd_lock==-1)
		return;

	if(!list_empty(&base_module))
		list_for_each_entry_safe(m, temp, &base_module, node) {
			detach_module(m);
		}

	if(me.id)
		{
		free(me.id);
		me.id=NULL;
		}

	if(me.root_dir)
		{
		free(me.root_dir);
		me.root_dir=NULL;
		}

	if(me.config_file)
		{
		free(me.config_file);
		me.config_file=NULL;
		}

	//some bug
//	if(me.param.argc)
//		{		
//		for(i=0;i<me.param.argc;i++)
//			{
//			if(me.param.argv[i])
//				{
//				free(me.param.argv[i]);
//				me.param.argv[i]=NULL;
//				}
//			}
//		}

	if(me.runnning_log_file)
		{
		free(me.runnning_log_file);
		me.runnning_log_file=NULL;
		}

	if(me.hw_log_file)
		{
		free(me.hw_log_file);
		me.hw_log_file=NULL;
		}

	if(me.flow_log_file)
		{
		free(me.flow_log_file);
		me.flow_log_file=NULL;
		}

	if(me.alert_log_file)
		{
		free(me.alert_log_file); 
		me.alert_log_file=NULL;
		}

	EARLY_LOG_INFO("fw exit now !\n");

	freopen("/dev/tty","w",stderr);

	if(running_log_fp)
		{
		fclose(running_log_fp);
		running_log_fp=NULL;
		}

	if(flow_log_fp)
		{
		fclose(flow_log_fp);
		flow_log_fp=NULL;
		}

	if(hw_log_fp)
		{
		fclose(hw_log_fp);
		hw_log_fp=NULL;
		}

	if(alert_log_fp)
		{
		fclose(alert_log_fp);
		alert_log_fp=NULL;
		}

	unlock_app();
}

int init(void)
{
	struct mmb *m, *temp;
	int r;

	list_for_each_entry_safe(m, temp, &base_module, node) {
		if(m->init)
			{
			r=m->init(m->private);
			if(r!=MM_SUCCESS)
				{
				ALERT_LOG("%s : module %s init error\n",__FUNCTION__,m->name);
				exit(1);
				}
			}
	}
}
