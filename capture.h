#ifndef CAPTURE_H
#define CAPTURE_H
#include "raw_types.h"
#include <pcap.h>
extern struct socket_pair *pair;

struct thread_resource
{
    const pcap_if_t *dev;
    const char *fitler;
    pthread_t tid;
    int *ports;   
    int sock;
};

struct pcap_ethernet
{
    char src[6];
    char dst[6];
    unsigned short proto;
};

void configure_remote_addr(const char *ip, struct sockaddr_in *dst_addr);
pcap_if_t *configure_local_addr(struct sockaddr_in *local_addr);
void *capture(void *arg);
void deal_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void cancel_capture(void *arg);
pcap_if_t *init_devs(const struct sockaddr_in *local_addr);
#endif // CAPTURE_H
