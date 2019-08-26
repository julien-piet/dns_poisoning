#ifndef DNS_POIS_H_
#define DNS_POIS_H_

#define BUF_SIZE 65536

#include "header.h"
#include "dns.h"

#define LINKTYPE_NULL 0 
#define LINKTYPE_ETH 1
#define LINKTYPE_WIFI 127

struct sending_args{
    
    struct sockaddr_in sockinfo;
    char* source_ip;
    u_int16_t source_port;
    uint8_t* buf; //contains the DNS request
    
};

typedef struct sending_args sending_args;

void sendDNS(void * args);
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

#endif /* DNS_pois.h */
