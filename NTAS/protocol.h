//protocol.h

#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/ipc.h>
#include <semaphore.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <limits.h>
#include <syslog.h>
#include <pcap.h>
typedef struct _pcap_header{
	u_int flag;
	u_char info[20];
}pcap_header;
//start of data structure define
//the define of ETHER_hear structure
#define ETHER_LEN 14
#define ETHER_ADDR_LEN 6
#define ETHER_TYPE_LEN 2

/* type of MAC_protocol */
#define ETHER_TYPE_IP 0x0800 //ip
#define ETHER_TYPE_ARP 0x0806 //arp

//other protocol (use less)
#define ETHER_TYPE_MIN 0x0600
#define ETHER_TYPE_8021Q 0x8100
#define ETHER_TYPE_BRCM 0x886c
#define ETHER_TYPE_802_1X 0x888e
#define ETHER_TYPE_802_1X_PREAUTH 0x88c7

/* type of ETHER struct define */
typedef struct _ether_header{
u_char host_dest[ETHER_ADDR_LEN];
u_char host_src[ETHER_ADDR_LEN];
u_short type;
}ether_header;


//the define of  ip_header structure
#define IP_LEN_MIN 20

/*type of IP protocol*/
#define IP_ICMP 1
#define IP_IGMP 2
#define IP_TCP 6
#define IP_UDP 17
#define IP_IGRP 88
#define IP_OSPF 89
typedef struct _ip_header{
	u_char ver_ihl; //version(4bits)+header length(4 bits)
	u_char tos; //type of service
	u_short  tlen; //total length
	u_short ident; //identification
	u_short flags_fo; //flags(3 bits)+fragment offset(13 bits)
	u_char ttl; //time to live
	u_char proto; //protocol
	u_short crc; //header checksum
	u_int saddr; //source address
	u_int daddr; //destination address
}ip_header;

//tcp_header structure define
#define TCP_LEN_MIN 20
/*tcp six control bits */
#define TH_FIN 0x01 //terminal
#define TH_SYN 0x02 //syn
#define TH_RST 0x04 //reset
#define TH_PSH 0x08 //push
#define TH_ACK 0x10 //ack
#define TH_URG 0x20 //urg
typedef struct _tcp_header{
	u_short th_sport; //source port
	u_short th_dport; //destination port
	u_int th_seq; //sequence number field
	u_int th_ack; //acknowledgement number field
	u_char th_len:4; //header length
	u_char th_x2:4; //unused
	u_char th_flags; //control bits
 	u_short th_win; //window
 	u_short th_sum; //checksum
 	u_short th_urp; //urgent pointer
}tcp_header;

//udp_header structure define
#define UDP_LEN 8
typedef struct _udp_header{
	u_short uh_sport; //source port
	u_short uh_dport; //destination port
	u_short uh_len; //datagram length
	u_short uh_sum; //checksum
}udp_header;

#endif  /*_PROTOCOL_H */
