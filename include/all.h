#ifndef __ALL_H
#define __ALL_H

#define DEBUG_MODULE

//#define USE_PKT_INFO

#define DUP_MBUF

#define RTC_MODE

#define NO_FLOWPTS

//#define THREE_HASH


//#define MBUF_POOL_PERPORT


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

//#include <event.h>
//#include <linux/rtnetlink.h>
//#include <linux/netlink.h>
#include <linux/if_arp.h>
#include <linux/neighbour.h>
#include <sys/sysinfo.h>
//#include <libnetlink.h>
//#include <linux/jhash.h>
//#include <net/checksum.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

//#include <syslog.h>

#define __USE_GNU
#include<sched.h>
#include<ctype.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_kni.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_timer.h>
#include <rte_errno.h>
#include <rte_arp.h>

#define MM_SUCCESS	0
#define MM_FAIL		-1

#ifndef FALSE
#define FALSE	0
#endif
#ifndef TRUE
#define TRUE	1
#endif

#include "zookeeper_log.h"
#include "zookeeper.h"

//#include "md5.h"
#include "curl/curl.h"

#include "list.h"
#include "queue.h"
#include "base.h"
#include "m_signal.h"
#include "m_conf.h"
#include "m_zk.h"
#include "m_log.h"
#include "m_kafka.h"
#include "m_core.h"
#include "m_kni.h"
#include "m_plat.h"
#include "m_nl.h"
#include "m_pcap.h"
#include "bitmap.h"

#endif
