#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>


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
    char *target = "10.0.2.15";
    uint16_t src_port = 15511;
    uint16_t dst_port = 23;

    //Create RAW socket
    int sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    //Define a new packet based on common MTU
    char *packet = malloc(1500);
    char src_ip[32];
    strcpy(src_ip, "1.2.3.4");
    //Define headers
    struct iphdr *iph = (struct iphdr*) packet;
    struct tcphdr *tcph = (struct tcphdr*) (packet + sizeof(struct ip));
    struct sockaddr_in sin;
    struct pseudo_hdr psh;
    
    //Setting up socket
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dst_port);
    sin.sin_addr.s_addr = inet_addr(target);

    //clear the packet buffer
    memset(packet, 0, 1500);

    /* if something is set to 0, it is not necessary write them out. */
    //Fill IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->id = htons(1551);
    iph->ttl = 255; //Set to max because we can
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; /* when set to 0, the kernel will calculate for you */
    iph->saddr = inet_addr(src_ip);
    iph->daddr = sin.sin_addr.s_addr;
    //Calculate IP checksum
    //iph->check = chksum((uint16_t *) packet, iph->tot_len >> 1); 

    //Fill TCP header
    
    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = 1551;
    tcph->ack_seq = 0;
    tcph->doff = 5; /* No TCP options */
    //tcph->fin = 0;
    tcph->syn = 1; /* This is synchronization packet */
    //tcph->rst = 0;
    //tcph->psh = 0;
    //tcph->ack = 0;
    //tcph->urg = 0;
    tcph->window = htons(5000);
    tcph->check = 0; 
    tcph->urg_ptr = 0;

    //Fill TCP Pseudo header
    psh.src_ip = inet_addr(src_ip);
    psh.dst_ip = sin.sin_addr.s_addr;
    psh.reserved = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_len = htons(20);
    //Calculate the TCP checksum
    memcpy(&psh.tcph, tcph, sizeof(struct tcphdr));
    tcph->check = chksum((uint16_t *)&psh, sizeof(struct pseudo_hdr));

    //Tell kernel that we construct the header
    int _one = 1;
    const int *one = &_one;
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, one, sizeof(_one)) < 0){
        printf("Error setting socket");
        exit(0);
    }

    int once = 1;
    while(once){
        //Increase the source ip and port
        tcph->check = 0;
        iph->saddr = iph->saddr + 1;
        tcph->source = tcph->source + 1;
        psh.src_ip = iph->saddr;
        memcpy(&psh.tcph, tcph, sizeof(struct tcphdr));
        tcph->check = chksum((uint16_t *)&psh, sizeof(struct pseudo_hdr));

        for(int i=0; i<iph->tot_len; i++){
            printf("%08x \n", packet[i]);
        }
        printf("\n");

        //Send out the packet
        if(sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0){
            printf("Error sending packet\n");
        }
        else{
            printf("Packet Sent!\n");
        }
        once--;
        
    }
    return 0;

}