#ifndef __M_PCAP_H
#define __M_PCAP_H

extern void save_pcap_file(struct rte_mbuf *mbuf);
extern int cap_pcap_file(struct rte_mbuf *mbuf,char *filename);


#endif
