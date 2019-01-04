#include "all.h"

/*
SIGHUP	1	Term	�ն˵ĹҶϻ��������
SIGINT	2	Term	���Լ��̵��ж��ź�
SIGQUIT	3	Core	���Լ��̵��뿪�ź�
SIGILL	4	Core	�Ƿ�ָ��
SIGABRT	6	Core	����abort���쳣�ź�
SIGFPE	8	Core	��������
SIGKILL	9	Term	ɱ��
SIGSEGV	11	Core	�ηǷ�����(�ڴ�������Ч)
SIGPIPE	13	Term	�ܵ��𻵣���һ��û�ж����̵Ĺܵ�д����
SIGALRM	14	Term	����alarm�ļ�ʱ����ʱ�ź�
SIGTERM	15	Term	��ֹ
SIGUSR1	30,10,16	Term	�û��Զ����ź�1
SIGUSR2	31,12,17	Term	�û��Զ����ź�2
SIGCHLD	20,17,18	Ign	�ӽ���ֹͣ����ֹ
SIGCONT	19,18,25	Cont	���ֹͣ������ִ��
SIGSTOP	17,19,23	Stop	�������ն˵�ֹͣ�ź�
SIGTSTP	18,20,24	Stop	�����ն˵�ֹͣ�ź�
SIGTTIN	21,21,26	Stop	��̨���̶��ն�
SIGTTOU	22,22,27	Stop	��̨����д�ն�
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
