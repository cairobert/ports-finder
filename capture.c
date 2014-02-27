#include "bdnet.h"
#include "capture.h"
#include <pcap.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define PACKET_LEN 54
#define CAP_BUFSIZ 512

void configure_remote_addr(const char *ip, struct sockaddr_in *dst_addr)
{
    struct addrinfo hint, *dst;
    struct sockaddr_in *addr;
    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = IPPROTO_TCP;
    if (-1 == getaddrinfo(ip, NULL, &hint, &dst) )
    {
        fprintf(stderr, "Cannot resolve %s\n", ip);
        exit(1);
    }
    addr = (struct sockaddr_in *) dst->ai_addr;

    memcpy(dst_addr, addr, sizeof(*addr));
    freeaddrinfo(dst);
}

pcap_if_t *configure_local_addr(struct sockaddr_in *local_addr)
{
    int sock = 0;
    struct sockaddr_in dns;
    const char *google_dns_ip = "8.8.8.8";
    socklen_t len;
    int dns_port = 53;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == sock)
    {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        exit(2);
    }
    dns.sin_family = AF_INET;
    dns.sin_port = htons(dns_port);
    dns.sin_addr.s_addr = inet_addr(google_dns_ip);
    if (-1 == connect(sock, (struct sockaddr*)&dns, sizeof(dns)))
    {
        fprintf(stderr, "Cannot determine the local ip address: %s\n", strerror(errno));
        exit(3);
    }
    len = sizeof(*local_addr);
    memset(local_addr, 0 ,sizeof(*local_addr));
    if (-1 == getsockname(sock, (struct sockaddr*)local_addr, &len))
    {
        fprintf(stderr, "getsockname: %s\n", strerror(errno));
        exit(4);
    }
    close(sock);
    return init_devs(local_addr);
}

pcap_if_t *init_devs(const struct sockaddr_in *local_addr)
{
    pcap_if_t *devs, *d;
    struct pcap_addr *a = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    if (1 == pcap_findalldevs(&devs, errbuf))
    {
        fprintf(stderr, "findall_devs: %s\n", errbuf);
        exit(1);
    }
    for (d = devs; NULL != d; d = d->next)
    {
        if (NULL != d->addresses)
        {            
            a = d->addresses;
            for ( ; NULL != a; a = a->next)
            {
                if (AF_INET == a->addr->sa_family)
                {
                    struct sockaddr_in *addr = ((struct sockaddr_in *)a->addr);
                    if (addr->sin_addr.s_addr == local_addr->sin_addr.s_addr)
                    {
#ifndef NNDEBUG
                        printf("device ip addr = %s\n", inet_ntoa(addr->sin_addr));
#endif
                        break;
                    }
                }
            }
            if (NULL != a)
                break;
        }
    }
    if (NULL == d)
    {
        fprintf(stderr, "Cannot find effective network device.");
        exit(1);
    }
    return d;
}

void *capture(void *arg)
{
    struct thread_resource *thrd = (struct thread_resource *)arg;
    struct bpf_program bpf;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    bpf_u_int32 mask, net ;
    struct sockaddr_in addr;
#ifndef NNDEBUG
    printf("thread running...\n");
#endif
    if (NULL == thrd->dev->name)
    {
        fprintf(stderr, "capture: %s's name is NULL.\n", thrd->dev->name);
        exit(1);
    }
    if (-1 == pcap_lookupnet(thrd->dev->name, &net, &mask, errbuf))
    {
        fprintf(stderr, "cannot get local netmask.\n");
        exit(1);
    }

#ifndef NNDEBUG
    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = net;
    printf("net: %s ", inet_ntoa(addr.sin_addr));
    addr.sin_addr.s_addr = mask;
    printf("mask: %s\n", inet_ntoa(addr.sin_addr));
#endif
    if (NULL == (handle = pcap_open_live(thrd->dev->name, 100, 0, 1000, errbuf)))
    {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        pthread_exit((void*) 2);
    }
    if (NULL == thrd->fitler)
    {
        fprintf(stderr, "You must set the filter\n");
        pthread_exit((void*)3);
    }

    if (-1 == pcap_compile(handle, &bpf, thrd->fitler, 0, mask) )
    {        
        fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(handle));
        pthread_exit((void*) 4);
    }
    if( -1 == pcap_setfilter(handle, &bpf))
    {
        fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(handle));
        pthread_exit((void*) 5);
    }
#ifndef NNDEBUG
    printf("device name: %s, filter: %s\n", thrd->dev->name, thrd->fitler);
#endif

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    pcap_loop(handle, -1, deal_packet, (u_char*)arg);
    pthread_exit((void*)0);
}

void deal_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct thread_resource *adhandle = (struct thread_resource *)args;
    struct pcap_ethernet *ether = (struct pcap_ethernet *)packet;
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(*ether));
    struct tcphdr *tcp = (struct tcphdr *)((char*)ip + sizeof(struct iphdr));
    struct sockaddr_in addr;
    static int i = 0;
    int len = header->len;
    char *ptr = (char *)packet;
#ifndef NNDEBUG    
    adhandle->ports[12345] = 0;
    if (ip->protocol != IPPROTO_TCP)
        return;
    addr.sin_addr.s_addr = ip->saddr;
    printf("%d. %s got packet from %s:%d ",  ++i, ip->protocol == IPPROTO_TCP ? "tcp":"else",
           inet_ntoa(addr.sin_addr), ntohs(tcp->source));

    addr.sin_addr.s_addr = ip->daddr;
    printf("to %s:%d, length: %d, ", inet_ntoa(addr.sin_addr), ntohs(tcp->dest), header->len);
    printf("%s%s%s%s\n", tcp->syn?"SYN ":"", tcp->ack?"ACK ":"", tcp->rst?"RST ":"", tcp->fin?"FIN ":"");
#endif
    if (ntohs(ether->proto) != 0x0800)     //not IP datagram
        return;
    if (4 == ip->version && ip->daddr == pair->src->sin_addr.s_addr && ip->saddr == pair->dst->sin_addr.s_addr
            && ip->protocol == IPPROTO_TCP && tcp->dest == pair->src->sin_port && tcp->syn && tcp->ack)
    {
        adhandle->ports[ntohs(tcp->source)] = 1;
        send_reset_back(adhandle->sock, ip);
    }
}

void cancel_capture(void *arg)
{
    struct thread_resource *adhandle = (struct thread_resource *)arg;
    if (0 != adhandle->tid)
    {
        pthread_cancel(adhandle->tid);
        pthread_join(adhandle->tid, NULL);
    }
}
