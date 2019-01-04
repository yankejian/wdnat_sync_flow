#include "all.h"

struct mmb mm_log={
	.name="m_rtelog",
	.preinit=m_log_preinit,
	.deinit=m_log_deinit,
};

LogLevel early_log_level=LOG_LEVEL_DEBUG;
LogLevel running_log_level=LOG_LEVEL_DEBUG;
FILE *running_log_fp;
FILE *flow_log_fp;
FILE *hw_log_fp;
FILE *alert_log_fp;
FILE *mon_log_fp;
FILE *output_log_fp;

int early_get_root()
{
	int r;
	struct stat buf;
    FILE *fp;
	char cbuf[PATH_MAX];
	char root_dir[PATH_MAX];
	char runlog[PATH_MAX];
	int flag=0;
	
	r=stat(DEFAULT_CONFIG_FILE, &buf);
	if((r)||!(buf.st_mode & S_IFREG))
		{
		perror("MISSING ./config file\n");
		return MM_FAIL;
		}

    if((fp = fopen(DEFAULT_CONFIG_FILE, "r")) == NULL) 
		{
       	perror("FAIL OPEN ./config file\n");
		return MM_FAIL;
		}
   
	cbuf[0]=0;
	while (!feof(fp))
	   {
		   fgets(cbuf, sizeof(cbuf), fp);
		   if(strstr(cbuf, "running_log")!=NULL)
				{
					char *p, *p0=cbuf,*p1;
					int len;

					flag|=2;

//					printf("found running_log str %s\n",cbuf);

					p = strchr(p0, ':');

					p0=strchr(p,'"');
					p1=strchr(p0+1,'"');
					*p1=0;

					strcpy(runlog,p0+1);
//					printf("running_log =%s %s\n",p0+1,runlog);

					if(flag==3)
						break;
				}
		   else if(strstr(cbuf, "root")!=NULL)
				{
					char *p, *p0=cbuf,*p1;
					int len;

					flag|=1;

//					printf("found root str %s\n",cbuf);

					p = strchr(p0, ':');

					p0=strchr(p,'"');
					p1=strchr(p0+1,'"');
					*p1=0;

					strcpy(root_dir,p0+1);
//					printf("rootdir =%s\n",p0+1,runlog);
					
					if(flag==3)
						break;
				}
	   }

	sprintf(cbuf,"%s/%s",root_dir,runlog);

	freopen(cbuf,"a+",stderr);

    fclose(fp);	
}

void do_log(FILE *fp,const char* format,...)
{
    va_list va;
	static char buf[4096];

    
    va_start(va,format);
    vsnprintf(buf, 4095,format,va);
    va_end(va); 

    struct timeval tv;
    struct tm lt;
    time_t now = 0;
    
    gettimeofday(&tv,0);

    now = tv.tv_sec;
    localtime_r(&now, &lt);


    fprintf(fp, "%d-%02d-%02d %02d:%02d:%02d:%d @ %s", 
		(1900+lt.tm_year),(1+lt.tm_mon),lt.tm_mday,lt.tm_hour,
		lt.tm_min,lt.tm_sec,(int)(tv.tv_usec),buf);

    fflush(fp);
}

void do_log_notime(FILE *fp,const char* format,...)
{
    va_list va;
	static char buf[4096];

    
    va_start(va,format);
    vsnprintf(buf, 4095,format,va);
    va_end(va); 

    fprintf(fp, "%s",buf);

    fflush(fp);
}



int m_log_preinit(__attribute__((unused)) void *m)
{
	char cbuf[PATH_MAX];

	sprintf(cbuf,"%s/%s",me.root_dir,me.runnning_log_file);
    if((running_log_fp = fopen(cbuf, "a+")) == NULL) 
		{
       	EARLY_LOG_ERROR("running log access fail !\n");
		exit(1);
		}

	sprintf(cbuf,"%s/%s",me.root_dir,me.flow_log_file);
    if((flow_log_fp = fopen(cbuf, "a+")) == NULL) 
		{
       	EARLY_LOG_ERROR("flow log access fail !\n");
		exit(1);
		}	

	sprintf(cbuf,"%s/%s",me.root_dir,me.hw_log_file);
    if((hw_log_fp = fopen(cbuf, "a+")) == NULL) 
		{
       	EARLY_LOG_ERROR("hw log access fail !\n");
		exit(1);
		}

	sprintf(cbuf,"%s/%s",me.root_dir,me.alert_log_file);
    if((alert_log_fp = fopen(cbuf, "a+")) == NULL) 
		{
       	EARLY_LOG_ERROR("alert log access fail !\n");
		exit(1);
		}


	return MM_SUCCESS;	
}

int m_log_deinit(__attribute__((unused)) void *m)
{

	return MM_SUCCESS;	
}
