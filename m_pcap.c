#include "all.h"

static FILE *pcap_fp;

static unsigned char pacp_file_header[24] = {
	0xd4,0xc3,0xb2,0xa1,0x02,0x00,0x04,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0xff,0xff,0x00,0x00,0x01,0x00,0x00,0x00
};
/*
struct local_timeval
{
	uint32_t tv_sec;
	uint32_t tv_usec;
};


struct local_pcap_pkthdr
{
	struct local_timeval ts;
	int32_t caplen;
	int32_t len;
};
*/

static int init_pcap_file()
{
	int fileflag = 0;
	struct tm *p;
	time_t now;
	char timebuf[100] = {0};
	char filepath[100] = {0};
	char hostIP[32];
	char pcap_save_file[64];

	time(&now);
	p = localtime(&now);
	sprintf(timebuf,"%d%02d%02d-%02d%02d%02d",(1900+p->tm_year),(1+p->tm_mon),p->tm_mday,p->tm_hour,p->tm_min,p->tm_sec);
	sprintf(pcap_save_file,"cap.pcap", timebuf);
	sprintf(filepath,"./%s", pcap_save_file);


	if(!access(filepath, F_OK))
		fileflag = 1;

	if ((pcap_fp = fopen(filepath, "a+")) != NULL) {
		if(!fileflag) {
			if(fwrite(pacp_file_header,1,sizeof(pacp_file_header),pcap_fp) != sizeof(pacp_file_header)){
				RUNNING_LOG_INFO("Failed to write pcap file header %s \n", filepath);
				return -1;

			}else{
				RUNNING_LOG_INFO("Success to write pcap file header %s \n", filepath);
				return 0;
			}
		}
	}else{
		RUNNING_LOG_INFO("init_pcap_file failed ! \n");
	}

}

void save_pcap_file(struct rte_mbuf *mbuf)
{
	unsigned char *p;
	struct local_pcap_pkthdr hdr;
	int    usec, flen;
    struct timeval tv;

	if(pcap_fp == NULL)
	{
		init_pcap_file();
	}

    gettimeofday(&tv,0);

	p = rte_pktmbuf_mtod(mbuf, unsigned char *);

	hdr.ts.tv_sec = tv.tv_sec;
	hdr.ts.tv_usec = tv.tv_usec;
	hdr.caplen = mbuf->data_len;
	hdr.len = mbuf->data_len;

	if(pcap_fp != NULL){
		/* write header */
		if(fwrite(&hdr, 1, sizeof(struct local_pcap_pkthdr), pcap_fp) != sizeof(struct local_pcap_pkthdr)) {
			RUNNING_LOG_INFO("%s:Failed to write pcap head info \n", __FUNCTION__);
			return;
		}

		/* write data */
		if(fwrite((char *)p, 1, hdr.len, pcap_fp) != (unsigned int)hdr.len)
			RUNNING_LOG_INFO("%s:Failed to write pcap data info \n", __FUNCTION__);

		fflush(pcap_fp);
	}

//	if(pcap_fp != NULL)
//		fclose(pcap_fp);
}

int cap_pcap_file(struct rte_mbuf *mbuf,char *filename)
{
	char filepath[256];
	FILE *fd;
	int flag=0;
	unsigned char *p;
	struct local_pcap_pkthdr hdr;
    struct timeval tv;

	sprintf(filepath,"./%s", filename);

	if(!access(filepath, F_OK))
		flag=1;

	if ((fd = fopen(filepath, "a+")) == NULL)
		return MM_FAIL;

	if(!flag)
		{
			if(fwrite(pacp_file_header,1,sizeof(pacp_file_header),fd) != sizeof(pacp_file_header)){
				RUNNING_LOG_INFO("Failed to write pcap file header %s \n", filepath);
				return MM_FAIL;
			}
		}

    gettimeofday(&tv,0);

	p = rte_pktmbuf_mtod(mbuf, unsigned char *);

	hdr.ts.tv_sec = tv.tv_sec;
	hdr.ts.tv_usec = tv.tv_usec;
	hdr.caplen = mbuf->data_len;
	hdr.len = mbuf->data_len;

	if(fwrite(&hdr, 1, sizeof(struct local_pcap_pkthdr), fd) != sizeof(struct local_pcap_pkthdr)) {
		RUNNING_LOG_INFO("%s:Failed to write pcap head info %s\n", __FUNCTION__,filename);
		fclose(fd);
		return MM_FAIL;
	}

	/* write data */
	if(fwrite((char *)p, 1, hdr.len, fd) != (unsigned int)hdr.len)
		RUNNING_LOG_INFO("%s:Failed to write pcap data info %s\n", __FUNCTION__,filename);

	fclose(fd);

	return MM_SUCCESS;
}

