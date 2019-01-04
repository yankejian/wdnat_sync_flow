#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
//#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
//#include <event.h>
#include <limits.h>

#include <netinet/in.h>
#include <linux/if.h>
//#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <libgen.h>


typedef struct cell{
	int a;
	int b;
	int c;
}CELL_S;


typedef struct bulk{
	int cnt;
//	int cell_sz;
	void *free;
}BULK_S;

BULK_S a;

void *get_cell(void *head)
{
	CELL_S *p=(CELL_S *)a.free;

	if(*((int *)p)==0)
		a.free+=sizeof(CELL_S);
	else
		a.free=*((int *)p);

	a.cnt--;
	
	printf("get cell %p,free be %p\n",p,a.free);

	return p;
}

void *free(void *f)
{
	*((int *)f)=a.free;
	a.free=f;
	a.cnt++;
}

void walk(void *head)
{
}

void main()
{
	void *t;
	
	a.free=malloc(sizeof(CELL_S)*10);
	a.cell_sz=sizeof(CELL_S);
	a.cnt=10;

	memset(a.free,0,sizeof(CELL_S)*10);

	t=malloc(sizeof(CELL_S)*1);

	(int *)(a.free+9*sizeof(CELL_S))=&t;
	a.cnt+=1;

	
	
	

}

