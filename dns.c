/*
 * dns.c
 *
 * get_domain_name Adapted from jiaziyi's work
 */

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<stdbool.h>
#include<time.h>
#include<errno.h>
#include "dns.h"


void build_dns_header(dns_header *dns, int id, int query, int qd_count,
        int an_count, int ns_count, int ar_count)
{

    dns->id = htons(id);
    dns->qr = (uint8_t) query;
    dns->qd_count = htons(qd_count);
    dns->an_count = htons(an_count);
    dns->ns_count = htons(ns_count);
    dns->ar_count = htons(ar_count);
    dns->rd = 1;
    dns->tc = 0;
    dns->aa = 0;
    dns->opcode = 0;
    dns->rcode = 0;
    dns->cd = 0;
    dns->ad = 0;
    dns->z = 0;
    dns->ra = 0;

}

void build_name_section(uint8_t *qname, char *host_name, int *position)
{

    char host_cp[HOST_NAME_SIZE];
    strncpy(host_cp, (char*)host_name, HOST_NAME_SIZE);

    //printf("host name: %s\n", host_cp);

    char *tk;
    tk = strtok(host_cp, ".");
    int i = 0;
    while(tk!=NULL)
    {
        *(qname+i) = (uint8_t)(strlen(tk)); //set the number of chars in the label

        i++;
        strncpy((char*)(qname+i), tk, strlen(tk)); //the label

        i+= strlen(tk);
        tk = strtok(NULL,".");
    }
    *(qname+i) = '\0';

    *position = i+1;

}



void send_dns_query(int sockfd, char *dns_server, char *host_name)
{
    struct sockaddr server;
    struct sockaddr_in *server_v4 = (struct sockaddr_in *)(&server);
    server_v4->sin_family = AF_INET;
    server_v4->sin_port = htons(53);
    server_v4->sin_addr.s_addr = inet_addr(dns_server);

    uint8_t buf[BUF_SIZE];
    dns_header *dns = (dns_header *)&buf;
    build_dns_header(dns,rand() % 65535, 0, 1, 0, 0, 0);

    uint8_t *qname = (uint8_t *)dns;
    qname += sizeof(dns_header);
    int offset;
    build_name_section(qname,host_name,&offset);

    qname += offset;

    question *queryInfo = (question *)qname;
    queryInfo->qtype = htons(TYPE_A);
    queryInfo->qclass = htons(CLASS_IN);

    if( sendto(sockfd, buf, offset+sizeof(dns_header)+sizeof(question), 0, &server, sizeof(struct sockaddr_in)) < 0)
    {
        printf("Resolve failed\n");
        printf("Error : %s\n",strerror(errno));
    }

}

int parse_dns_query(uint8_t *buf, query *queries,
        res_record *answers, res_record *auth, res_record *addit)
{

    uint16_t *id = (uint16_t *)buf;
    int intid = ntohs((int) *id);

    uint8_t *start = buf;

    //retrieving query section

    buf += 4;
    int qd_count = ntohs(((uint16_t *) buf)[0]);
    buf += 2;
    int an_count = ntohs(((uint16_t *) buf)[0]);
    buf += 2;
    int ns_count = ntohs(((uint16_t *) buf)[0]);
    buf += 2;
    int ar_count = ntohs(((uint16_t *) buf)[0]);
    buf += 2;

    queries = (query *) buf;

    for(int i = 0; i < qd_count; i++){
        while(((char *)buf)[0] != '\0'){
            buf++;
        }
        buf++;
        buf += 4;
    }

    printf("\nLocal answers : \n");

    for(int i = 0; i < an_count; i++){

        if(i < 10){
            int position;
            answers[i].name = malloc(sizeof(char) * HOST_NAME_SIZE);
            get_domain_name(buf,start,answers[i].name,&position);
            buf += position;

            answers[i].element = malloc(sizeof(r_element));

            answers[i].element->type = ntohs(*(uint16_t *)buf);
            buf += 2;
            answers[i].element->_class = ntohs(*(uint16_t *)buf);
            buf += 2;
            answers[i].element->ttl = ntohl(*(uint32_t *)buf);
            buf += 4;
            answers[i].element->rdlength = ntohs(*(uint16_t *)buf);
            buf += 2;

            answers[i].rdata = malloc(ntohs(answers[i].element->rdlength));
            memcpy(answers[i].rdata,buf,ntohs(answers[i].element->rdlength));
            buf += answers[i].element->rdlength;

            printf("Address n° %d : %s\n", i+1, (char *)answers[i].name);
            char legibleIP[50];
            if(answers[i].element->type == 1){
                inet_ntop(AF_INET, answers[i].rdata, legibleIP, 50);
                printf("Addr : %s\n",legibleIP);
            }
        }
        else{
            res_record temp;

            int position;
            temp.name = malloc(sizeof(char) * HOST_NAME_SIZE);
            get_domain_name(buf,start,temp.name,&position);
            buf += position;

            temp.element = malloc(sizeof(r_element));

            temp.element->type = ntohs(*(uint16_t *)buf);
            buf += 2;
            temp.element->_class = ntohs(*(uint16_t *)buf);
            buf += 2;
            temp.element->ttl = ntohl(*(uint32_t *)buf);
            buf += 4;
            temp.element->rdlength = ntohs(*(uint16_t *)buf);
            buf += 2;

            temp.rdata = malloc(ntohs(temp.element->rdlength));
            memcpy(temp.rdata,buf,ntohs(temp.element->rdlength));
            buf += temp.element->rdlength;

            free(temp.name);
            free(temp.element);
            free(temp.rdata);
        }

    }

    printf("\nAuthoritarive nameservers : \n");

    for(int i = 0; i < ns_count; i++){

        if(i < 10){
            int position;
            auth[i].name = malloc(sizeof(char) * HOST_NAME_SIZE);
            get_domain_name(buf,start,auth[i].name,&position);
            buf += position;

            auth[i].element = malloc(sizeof(r_element));

            auth[i].element->type = ntohs(*(uint16_t *)buf);
            buf += 2;
            auth[i].element->_class = ntohs(*(uint16_t *)buf);
            buf += 2;
            auth[i].element->ttl = ntohl(*(uint32_t *)buf);
            buf += 4;
            auth[i].element->rdlength = ntohs(*(uint16_t *)buf);
            buf += 2;

            auth[i].rdata = malloc(ntohs(auth[i].element->rdlength));
            memcpy(auth[i].rdata,buf,ntohs(auth[i].element->rdlength));
            buf += auth[i].element->rdlength;

            printf("Address n° %d : %s\n", i+1, (char *)auth[i].name);
            char *legibleIP = malloc(50);
            if(auth[i].element->type == 1){
                inet_ntop(AF_INET, auth[i].rdata, legibleIP, 50);
                printf("Addr : %s\n",legibleIP);
            }
        }
        else{
            res_record temp;

            int position;
            temp.name = malloc(sizeof(char) * HOST_NAME_SIZE);
            get_domain_name(buf,start,temp.name,&position);
            buf += position;

            temp.element = malloc(sizeof(r_element));

            temp.element->type = ntohs(*(uint16_t *)buf);
            buf += 2;
            temp.element->_class = ntohs(*(uint16_t *)buf);
            buf += 2;
            temp.element->ttl = ntohl(*(uint32_t *)buf);
            buf += 4;
            temp.element->rdlength = ntohs(*(uint16_t *)buf);
            buf += 2;

            temp.rdata = malloc(ntohs(temp.element->rdlength));
            memcpy(temp.rdata,buf,ntohs(temp.element->rdlength));
            buf += temp.element->rdlength;

            free(temp.name);
            free(temp.element);
            free(temp.rdata);
        }

    }

    printf("\nAdditional Records : \n");

    for(int i = 0; i < ar_count; i++){


        if(i < 10){
            int position;
            addit[i].name = malloc(sizeof(char) * HOST_NAME_SIZE);
            get_domain_name(buf,start,addit[i].name,&position);
            buf += position;

            addit[i].element = malloc(sizeof(r_element));

            addit[i].element->type = ntohs(*(uint16_t *)buf);
            buf += 2;
            addit[i].element->_class = ntohs(*(uint16_t *)buf);
            buf += 2;
            addit[i].element->ttl = ntohl(*(uint32_t *)buf);
            buf += 4;
            addit[i].element->rdlength = ntohs(*(uint16_t *)buf);
            buf += 2;

            addit[i].rdata = malloc(ntohs(addit[i].element->rdlength));
            memcpy(addit[i].rdata,buf,ntohs(addit[i].element->rdlength));
            buf += addit[i].element->rdlength;

            printf("Address n° %d : %s\n", i+1, (char *)addit[i].name);
            char *legibleIP = malloc(50);
            if(addit[i].element->type == 1){
                inet_ntop(AF_INET, addit[i].rdata, legibleIP, 50);
                printf("Addr : %s\n",legibleIP);
            }
        }
        else{
            res_record temp;

            int position;
            temp.name = malloc(sizeof(char) * HOST_NAME_SIZE);
            get_domain_name(buf,start,temp.name,&position);
            buf += position;

            temp.element = malloc(sizeof(r_element));

            temp.element->type = ntohs(*(uint16_t *)buf);
            buf += 2;
            temp.element->_class = ntohs(*(uint16_t *)buf);
            buf += 2;
            temp.element->ttl = ntohl(*(uint32_t *)buf);
            buf += 4;
            temp.element->rdlength = ntohs(*(uint16_t *)buf);
            buf += 2;

            temp.rdata = malloc(ntohs(temp.element->rdlength));
            memcpy(temp.rdata,buf,ntohs(temp.element->rdlength));
            buf += temp.element->rdlength;

            free(temp.name);
            free(temp.element);
            free(temp.rdata);
        }

    }

    return intid;

}


void get_domain_name(uint8_t *p, uint8_t *buff, uint8_t *name, int *position)
{
    // true iif the buffer uses compression (see below)
    bool compressed = false;

    int i = 0;

    // real length of the buffer, that is if we use compression,
    // the length will be smaller
    //     eg. 01 62 c0 5f will have buffer_len 4
    //         but the actual host_name is longer, because
    //         we use compression and concatenate what is
    //         at position 5f immediatly after 01 62
    int buffer_len = -1;

    while(*p!=0)
    {
        // the rest of the chain points to somewhere else
        if ((*p & 0xc0) == 0xc0) {
            //	The pointer takes the form of a two octet sequence:
            //
            //	    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            //	    | 1  1|                OFFSET                   |
            //	    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            //
            //	The first two bits are ones. The OFFSET field specifies an offset from
            //	the start of the message (i.e., the first octet of the ID field in the
            //	domain header).

            uint16_t offset = ntohs(*((uint16_t*)p)) & 0x3fff;
            p = buff+offset;

            // +2 comes from c0 xx, where xx is the address
            // the pointer points to
            if (!compressed){
                buffer_len = i+2;
                compressed = true;
            }

        }
        uint8_t num = *((uint8_t*)p);
        strncpy((char*)(name+i), (char*)(p+1), num);
        p+= (num+1);
        i+= num;
        strncpy((char*)(name+i), ".", 1);
        i++;
    }
    *(name+i)='\0';

    // +1 because we take into account the nul length end character,
    // which is not present when using a pointer (ie. when we use
    // compression). Indeed, the pointer points to a chain already
    // ending by the \0 char
    if (compressed == false) buffer_len = i+1;

    // position can change both when there is compression
    // and when there is not. Thus, use not_compressed_len to see
    // if we moved forward in the chain
    if(buffer_len > 0) *position = buffer_len;
}


void get_dns_name(uint8_t *dns, uint8_t *host)
{
    char host_cp[HOST_NAME_SIZE];
    strncpy(host_cp, (char*)host, HOST_NAME_SIZE);

    //	printf("host name: %s\n", host_cp);

    char *tk;
    tk = strtok(host_cp, ".");
    int i = 0;
    while(tk!=NULL)
    {
        //		sprintf(length, "%lu", strlen(tk));
        *(dns+i) = (uint8_t)(strlen(tk)); //set the number of chars in the label

        i++;
        strncpy((char*)(dns+i), tk, strlen(tk)); //the label

        i+= strlen(tk);
        tk = strtok(NULL,".");
    }
    *(dns+i) = '\0';
}

void get_dns_record(char* host, uint8_t *answer, char* file, int* num, int* offset, int type, int class){

    FILE *fp = fopen(file,"r");
    if(fp == 0 || fp == NULL){
        printf("Error in file opening. \n");
        return;
    }

    *num = 0;
    *offset = 0;

    char *line = malloc(sizeof(char) * HOST_NAME_SIZE);
    while(fgets(line, BUF_SIZE, fp) != NULL){

        int defaultResponse = 0;

        if(line[0] == '*') defaultResponse = 1;

        if(strstr(line, host) != NULL && defaultResponse == 0){
            uint8_t *startOfAnswer = answer; //in case invalid line

            char* linecopy = malloc(sizeof(char) * HOST_NAME_SIZE);
            strcpy(linecopy,line);
            char *tk = strtok(line,"\t"); //select NAME entry

            int position;

            build_name_section(answer,tk,&position);
            answer += position;
            *offset += position;

            strcpy(line,linecopy);

            tk = strtok(line,"\t"); //select TYPE entry
            tk = strtok(NULL,"\t");

            if(atoi(tk) != type){
                answer = startOfAnswer;
                continue;
            }

            *((uint16_t *)answer) = htons(atoi(tk));
            answer += 2;

            tk = strtok(NULL,"\t"); //select CLASS entry

            if(atoi(tk) != class){
                answer = startOfAnswer;
                continue;
            }

            *((uint16_t *)answer) = htons(atoi(tk));
            answer += 2;

            tk = strtok(NULL,"\t"); //select TTL entry

            *((uint32_t *)answer) = htonl(atoi(tk));
            answer += 4;

            tk = strtok(NULL,"\t"); //select RDLENGTH entry

            *((uint16_t *)answer) = htons(atoi(tk));
            answer += 2;

            *offset += 10;

            tk = strtok(NULL,"\t"); //select RDATA entry

            int j = 0;
            while(1){

                if(tk[j] == '\n'){
                    tk[j] = '\0';
                    break;
                }
                j++;

            }
            int addr_class = AF_INET;
            if(type == 1){
                addr_class = AF_INET;
            }
            else if(type == 28){
                addr_class = AF_INET6;
            }

            if(inet_pton(addr_class, tk, answer) < 0){
                printf("Error in IP conversion : %s\n",strerror(errno));
            }
            *offset += ntohs(*(uint16_t *)(answer-2));

            answer+=ntohs(*(uint16_t *)(answer-2));

            (*num)++;

            free(linecopy);

        }

        if(defaultResponse){

            int position;
            build_name_section(answer,host,&position);
            answer += position;
            *offset += position;

            char *tk = strtok(line,"\t"); 
            tk = strtok(NULL,"\t"); //select TYPE entry

            *((uint16_t *)answer) = htons(atoi(tk));
            answer += 2;

            tk = strtok(NULL,"\t"); //select CLASS entry

            *((uint16_t *)answer) = htons(atoi(tk));
            answer += 2;

            tk = strtok(NULL,"\t"); //select TTL entry

            *((uint32_t *)answer) = htonl(atoi(tk));
            answer += 4;

            tk = strtok(NULL,"\t"); //select RDLENGTH entry

            *((uint16_t *)answer) = htons(atoi(tk));
            answer += 2;

            *offset += 10;

            tk = strtok(NULL,"\t"); //select RDATA entry

            int j = 0;
            while(1){

                if(tk[j] == '\n'){
                    tk[j] = '\0';
                    break;
                }
                j++;

            }
            int addr_class = AF_INET;
            if(type == 1){
                addr_class = AF_INET;
            }
            else if(type == 28){
                addr_class = AF_INET6;
            }

            if(inet_pton(addr_class, tk, answer) < 0){
                printf("Error in IP conversion : %s\n",strerror(errno));
            }
            *offset += ntohs(*(uint16_t *)(answer-2));

            (*num)++;
        }


    }

    free(line);

    fclose(fp);

}

int build_dns_answer(uint8_t *dns, uint8_t *buf){

    uint16_t *id = (uint16_t *)buf;
    int intid = ntohs((int) *id);

    uint8_t *start = dns;

    //retrieving header info

    build_dns_header((dns_header *)dns, intid, 1, 0, 0, 0, 0);

    buf += 2;
    uint8_t bitOps = *buf;
    bitOps = ntohs(bitOps);

    ((dns_header *)dns)->rd = bitOps & 1;
    ((dns_header *)dns)->tc = (bitOps & 2) >> 1;
    ((dns_header *)dns)->aa = (bitOps & 4) >> 2;
    ((dns_header *)dns)->opcode = (bitOps>>3) & 15;

    buf += 1;
    bitOps = ntohs(*buf);

    ((dns_header *)dns)->rcode = bitOps & 15;
    ((dns_header *)dns)->z = (bitOps>>4) & 7;
    ((dns_header *)dns)->ra = 0;

    buf += 1;
    int qd_count = ntohs(((uint16_t *) buf)[0]);
    ((dns_header *)dns)->qd_count = htons(qd_count);
    buf += 8;

    dns += sizeof(dns_header);
    int size = sizeof(dns_header);
    uint8_t *queries = buf;

    int distance = 0;
    for(int i = 0; i < qd_count; i++){
        while(((char *)buf)[0] != '\0'){
            buf++;
            distance++;
        }
        buf += 5;
        distance += 5;
    }

    size += distance;

    buf = queries;
    memcpy(dns,buf,distance);
    dns += distance;

    int an_count = 0;
    int num;
    int offset;
    int position;

    char file[] = "dns_records";

    for(int i = 0; i < qd_count; i++){

        position = 0;
        char* host = malloc(sizeof(char) * HOST_NAME_SIZE);
        get_domain_name(buf, NULL, (uint8_t *)host, &position);
        buf += position + 1;
        question *queryInfo = (question *)buf;
        int type = ntohs(queryInfo->qtype);
        int class = ntohs(queryInfo->qclass);
        buf += 4;

        get_dns_record(host, dns, file, &num, &offset, type, class);
        dns += offset;
        size += offset;
        an_count += num;

        free(host);
    }

    dns = start;
    ((dns_header *)dns)->an_count = htons(an_count);

    if(an_count == 0){
        //recursivity to be implemented
    }

    ((dns_header *)dns)->ns_count = htons(0);
    ((dns_header *)dns)->ar_count = htons(0);

    return size;

}
/**
 * exit with an error message
 */

void exit_with_error(char *message)
{
    fprintf(stderr, "%s\n", message);
    exit(EXIT_FAILURE);
}

