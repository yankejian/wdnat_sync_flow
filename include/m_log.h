#ifndef __M_LOG_H
#define __M_LOG_H

#define RTE_LOGTYPE_FW	RTE_LOGTYPE_USER1

extern struct mmb mm_log;

typedef enum {LOG_LEVEL_ERROR=1,LOG_LEVEL_WARN=2,LOG_LEVEL_INFO=3,LOG_LEVEL_DEBUG=4}LogLevel;

extern LogLevel early_log_level;
extern LogLevel running_log_level;
extern FILE *running_log_fp;
extern FILE *flow_log_fp;
extern FILE *hw_log_fp;
extern FILE *alert_log_fp;
extern FILE *mon_log_fp;

void do_log(FILE *fp,const char* format,...);
void do_log_notime(FILE *fp,const char* format,...);

#define EARLY_LOG_ERROR(x, ...) do{if(early_log_level>=LOG_LEVEL_ERROR){do_log(stderr,x,##__VA_ARGS__);}}while(0)
#define EARLY_LOG_WARN(x, ...) do{if(early_log_level>=LOG_LEVEL_WARN){do_log(stderr,x,##__VA_ARGS__);}}while(0)
#define EARLY_LOG_INFO(x, ...) do{if(early_log_level>=LOG_LEVEL_INFO){do_log(stderr,x,##__VA_ARGS__);}}while(0)
#define EARLY_LOG_DEBUG(x, ...) do{if(early_log_level>=LOG_LEVEL_DEBUG){do_log(stderr,x,##__VA_ARGS__);}}while(0)

#define RUNNING_LOG_ERROR(x, ...) do{if(running_log_level>=LOG_LEVEL_ERROR){do_log(running_log_fp,x,##__VA_ARGS__);}}while(0)
#define RUNNING_LOG_WARN(x, ...) do{if(running_log_level>=LOG_LEVEL_WARN){do_log(running_log_fp,x,##__VA_ARGS__);}}while(0)
#define RUNNING_LOG_INFO(x, ...) do{if(running_log_level>=LOG_LEVEL_INFO){do_log(running_log_fp,x,##__VA_ARGS__);}}while(0)
#define RUNNING_LOG_DEBUG(x, ...) do{if(running_log_level>=LOG_LEVEL_DEBUG){do_log(running_log_fp,x,##__VA_ARGS__);}}while(0)

#define FLOW_LOG(x, ...) do{do_log(flow_log_fp,x,##__VA_ARGS__);}while(0)
#define ALERT_LOG(x, ...) do{do_log(alert_log_fp,x,##__VA_ARGS__);}while(0)
#define MON_LOG(x, ...) do{do_log(mon_log_fp,x,##__VA_ARGS__);}while(0)

#define HW_LOG(x, ...) do{do_log_notime(hw_log_fp,x,##__VA_ARGS__);}while(0)
#define HW_LOG_TIME(x, ...) do{do_log(hw_log_fp,x,##__VA_ARGS__);}while(0)


int early_get_root();
int m_log_preinit(void *m);
int m_log_deinit( void *m);

#endif
