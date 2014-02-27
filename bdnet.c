#include "bdnet.h"
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int write_tcp4(int sock, void *buf, int datalen, const struct socket_pair *p, const struct seqs *seq, int opt)
{
    struct sockaddr_in *src = p->src, *dst = p->dst;
    struct sockaddr_in addr;
    struct iphdr *ip;
    struct tcphdr *tcp;
    if (-1 != build_ip4(buf, sizeof(struct tcphdr) + datalen, p, IPPROTO_TCP))
        if (-1 != build_tcp4((char*)buf + sizeof(struct iphdr), (struct iphdr*)buf, datalen,
                             ntohs(src->sin_port), ntohs(dst->sin_port), seq, opt))
        {
            sendto(sock, buf, sizeof(struct iphdr) + sizeof(struct tcphdr) + datalen, 0, (struct sockaddr*)dst, sizeof(*dst));
/*
#ifndef NNDEBUG
            ip = (struct iphdr*)buf;
            tcp = (struct tcphdr *)((char*)buf + sizeof(*ip));
            addr.sin_addr.s_addr = ip->saddr;
            printf("send from %s:%d to ", inet_ntoa(addr.sin_addr), ntohs(tcp->source));
            addr.sin_addr.s_addr = ip->daddr;
            printf("%s:%d\n", inet_ntoa(addr.sin_addr), ntohs(tcp->dest));
#endif
*/
        }
}

int build_ip4(void *buf, int datalen, const struct socket_pair *p, int proto)
{
    struct sockaddr_in *src = p->src, *dst = p->dst;
    struct iphdr *ip = (struct iphdr *)buf;
    if (NULL == buf)
        return -1;
    memset(ip, 0, sizeof(*ip));

    ip->id = 0;
    ip->version = 4;
    ip->ihl = sizeof(*ip) >> 2;
    ip->tot_len = htonl(sizeof(*ip) + datalen);
#ifdef IP_DF
    ip->frag_off |= htons(IP_DF);
#else
    ip->frag_off |= htons(0x4000);
#endif
    ip->ttl = 255;
    ip->protocol = proto;
    ip->saddr = src->sin_addr.s_addr;
    ip->daddr = dst->sin_addr.s_addr;
    ip->check = 0;
    ip->check = checksum((u_int16_t *)ip, sizeof(*ip));
    return 0;
}

int build_tcp4(void *buf, const struct iphdr *ip, int datalen, int sport, int dport, const struct seqs *seq, int opt)
{
    struct tcphdr *tcp = (struct tcphdr *)buf;
    memset(tcp, 0, sizeof(*tcp));
    int mask = opt & TCP_UDP_MASK;
    if (mask & TCP_FIN)
        tcp->fin = 1;
    if (mask & TCP_SYN)
        tcp->syn = 1;
    if (mask & TCP_RST)
        tcp->rst = 1;
    if (mask & TCP_ACK)
        tcp->ack = 1;
    if (NULL != seq)
    {
        tcp->ack_seq = seq->tcp_ack_seq;
        tcp->seq = seq->tcp_seq;
    }
    else
    {
        tcp->ack_seq = 0;
        tcp->seq = 0;
    }
    tcp->source = htons(sport);
    tcp->dest = htons(dport);
    tcp->doff = sizeof(*tcp) >> 2;
    tcp->window = htons(TCP_WINDOW);
    tcp->check = tcp_checksum4(tcp, ip, datalen);
    return 0;
}

u_int16_t tcp_checksum4(const struct tcphdr *tcp, const struct iphdr *ip, int datalen)
{
    struct tcpiphdr4 hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(&hdr.tcp, tcp, sizeof(*tcp));
    hdr.dest.s_addr = ip->daddr;
    hdr.source.s_addr = ip->saddr;
    hdr.len = htons(sizeof(*tcp) + datalen);
    hdr.proto = IPPROTO_TCP;
    return checksum((u_int16_t *)&hdr, sizeof(hdr));
}

u_int16_t checksum(const u_int16_t *thdr, int len)
{
    int sum = 0;
    const u_int16_t *ptr = thdr;
    u_int16_t answer;

    while (len > 1)
    {
        sum += *ptr;
        len -= sizeof(*ptr);
        ptr++;
    }
    if (1 == len)
    {
        *(u_int8_t *)(&answer) = *(u_int8_t*)ptr;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return(answer);
}

void send_reset_back(int sock, struct iphdr *ip)
{
    char buf[BUFSIZ] = {0};
    struct iphdr *ip_send = ip;
    struct tcphdr *tcp_send = (struct tcphdr*)(ip + sizeof(*ip_send));
    struct sockaddr_in src, dst;
    struct socket_pair *p = (struct socket_pair *)malloc(sizeof(struct socket_pair));
    struct seqs seq;
    p->src = &src;
    p->dst = &dst;
    src.sin_addr.s_addr = ip->daddr;
    src.sin_port = tcp_send->dest;
    src.sin_family = AF_INET;
    dst.sin_addr.s_addr = ip->saddr;
    dst.sin_port = tcp_send->source;
    dst.sin_family = AF_INET;
    seq.tcp_ack_seq = tcp_send->seq + 1;
    seq.tcp_seq = tcp_send->ack_seq;
    write_tcp4(sock, buf, 0, p, &seq, TCP_SYN|TCP_ACK);
    free(p);
}

