#ifndef __M_NL_H
#define __M_NL_H

#define _PF(f) case f: str = #f ; break;


#define MSG_FAMILY_RTM  		1
#define MSG_FAMILY_ADM  		2
#define MSG_FAMILY_DSTM 		3
#define MSG_FAMILY_RTM_MULTICAST 	4
#define MSG_FAMILY_NAT 			5
#define MSG_FAMILY_IFACE        6
#define MSG_FAMILY_ADDR         7
#define MSG_FAMILY_NEIGH        8
#define MSG_FAMILY_SNOOPING     9
#define MSG_FAMILY_VNB		10
#define MSG_FAMILY_XFRM		11

//struct nlsock
//{
//    struct rtnl_handle  rtnl;
//    char               *name;
//    struct event        ev;
//    rtnl_filter_t   recv;
//};

extern int ping_thread_stop;
extern int ping_thread_start;

extern int init_nl(void);
extern int init_ping(void);


#endif
