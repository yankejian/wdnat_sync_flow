#include "all.h"

/*
SIGHUP	1	Term	终端的挂断或进程死亡
SIGINT	2	Term	来自键盘的中断信号
SIGQUIT	3	Core	来自键盘的离开信号
SIGILL	4	Core	非法指令
SIGABRT	6	Core	来自abort的异常信号
SIGFPE	8	Core	浮点例外
SIGKILL	9	Term	杀死
SIGSEGV	11	Core	段非法错误(内存引用无效)
SIGPIPE	13	Term	管道损坏：向一个没有读进程的管道写数据
SIGALRM	14	Term	来自alarm的计时器到时信号
SIGTERM	15	Term	终止
SIGUSR1	30,10,16	Term	用户自定义信号1
SIGUSR2	31,12,17	Term	用户自定义信号2
SIGCHLD	20,17,18	Ign	子进程停止或终止
SIGCONT	19,18,25	Cont	如果停止，继续执行
SIGSTOP	17,19,23	Stop	非来自终端的停止信号
SIGTSTP	18,20,24	Stop	来自终端的停止信号
SIGTTIN	21,21,26	Stop	后台进程读终端
SIGTTOU	22,22,27	Stop	后台进程写终端
*/


m_signal_t sig[]={
    { SIGINT,
      "SIGINT",
      "SIGINT",
      m_signal_handler },
	{ SIGQUIT,
	  "SIGQUIT",
	  "SIGQUIT",
	  m_signal_handler },
	/*{ SIGSEGV,
	  "SIGSEGV",
	  "SIGSEGV",
	  m_signal_handler },*/
	{ SIGTERM,
	  "SIGTERM",
	  "SIGTERM",
	  m_signal_handler },
	{ 0, NULL, "", NULL }
};


struct mmb mm_signal={
	.name="m_signal",
	.preinit=m_signal_preinit,
	.deinit=m_signal_deinit,
};


void m_signal_handler(int signo)
{
    m_signal_t    *s;

	EARLY_LOG_DEBUG("recieve signo =%2d\n",signo);

    for (s = sig; s->signo != 0; s++) {
        if (s->signo == signo) {
            break;
        }
    }

	term_pending=1;
//	if(term_delay)
//		return;

	pthread_mutex_lock(&conf_mutex);
	pthread_cond_broadcast(&conf_cond);
	pthread_mutex_unlock(&conf_mutex);

	pthread_mutex_lock(&kafka_mutex);
	pthread_cond_broadcast(&kafka_cond);
	pthread_mutex_unlock(&kafka_mutex);

	pthread_mutex_lock(&lock_step1);
	pthread_cond_broadcast(&cond_step1);
	pthread_mutex_unlock(&lock_step1);

	pthread_mutex_lock(&lock_mon);
	pthread_cond_broadcast(&cond_mon);
	pthread_mutex_unlock(&lock_mon);

	pthread_mutex_lock(&lock_step2);
	pthread_cond_broadcast(&cond_step2);
	pthread_mutex_unlock(&lock_step2);

	EARLY_LOG_DEBUG("recieve signo =%2d exit\n",signo);

	exit(1);
/*
	switch(signo){
		case SIGINT:
//			break;
		case SIGQUIT:
//			break;
		case SIGKILL:
//			break;
		case SIGSEGV:
//			break;
		case SIGTERM:
//			break;
		default:
			printf("%s : caught signal %d\n",__FUNCTION__,s->signo);
			break;
	}
*/
}


int m_signal_preinit(__attribute__((unused)) void *m)
{
    m_signal_t      *s;
    struct sigaction   sa;
	EARLY_LOG_ERROR("\n");
	EARLY_LOG_ERROR("\n");
	EARLY_LOG_ERROR("\n");
	EARLY_LOG_ERROR("======================================\n");
	EARLY_LOG_ERROR("version:%s %s %s:\n",VERSION_NUM,__DATE__,__TIME__);
	EARLY_LOG_ERROR("%s\n",VERSION_INFO);
	EARLY_LOG_ERROR("======================================\n");
	printf("======================================\n");
	printf("version:%s %s %s:\n",VERSION_NUM,__DATE__,__TIME__);
	printf("%s\n",VERSION_INFO);
	printf("======================================\n");

	EARLY_LOG_DEBUG("%s\n",__FUNCTION__);

    for (s = sig; s->signo != 0; s++) {
		memset(&sa,0,sizeof(struct sigaction));
        sa.sa_handler = s->handler;
        sigemptyset(&sa.sa_mask);
        if (sigaction(s->signo, &sa, &s->oldact) == -1) {
			EARLY_LOG_ERROR("%s : sigaction fail signal %d\n",__FUNCTION__,s->signo);
            //return MM_FAIL;
            exit(1);
        }
		s->flag=1;
    }


	return MM_SUCCESS;
}

int m_signal_deinit(__attribute__((unused)) void *m)
{
	m_signal_t      *s;
    struct sigaction   sa;
	int i;

	EARLY_LOG_DEBUG("%s...\n",__FUNCTION__);

    for (s = sig; s->signo != 0; s++) {
		if(s->flag)	{
	        if (sigaction(s->signo, &s->oldact, NULL) == -1){
				EARLY_LOG_ERROR("%s : sigaction fail recover signal %d\n",__FUNCTION__,s->signo);
//	            return MM_FAIL;
	        }
		}
    }

//	EARLY_LOG_DEBUG("%s : waiting threads exit\n",__FUNCTION__);

	if(conf_thread_id)
		pthread_join(conf_thread_id,NULL);
	if(zk_thread_id)
		pthread_join(zk_thread_id,NULL);

	EARLY_LOG_DEBUG("%s: finished waiting threads exit\n",__FUNCTION__);
/*
    pthread_cond_destroy(&conf_cond);

	EARLY_LOG_DEBUG("%s : finished waiting threads exit 3333333333333333333\n",__FUNCTION__);
    pthread_mutex_destroy(&conf_mutex);


	EARLY_LOG_DEBUG("%s : finished waiting threads exit 22222222222222222222222\n",__FUNCTION__);
//	zk_deinit();

	EARLY_LOG_DEBUG("%s : finished waiting threads exit 111111111111111111111\n",__FUNCTION__);
*/
	return MM_SUCCESS;
}
