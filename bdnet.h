#ifndef BDNET_H
#define BDNET_H

#include "raw_types.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <pcap.h>

#ifndef BUFSIZ
#define BUFSIZ 256
#endif

#define TCP_UDP_MASK 0x0fff
#define TCP_FIN 0x1
#define TCP_SYN 0x2
#define TCP_RST 0x4
#define TCP_ACK 0x8
#define TCP_WINDOW 4096

struct tcpiphdr4
{
    struct in_addr source;
    struct in_addr dest;
    u_int8_t zerors;
    u_int8_t proto;
    u_int16_t len;
    struct tcphdr tcp;
};

int write_tcp4(int sock, void *buf, int datalen, const struct socket_pair *p, const struct seqs *seq, int opt);
int build_tcp4(void *buf, const struct iphdr *ip, int datalen, int sport, int dport, const struct seqs *seq, int opt);
int build_ip4(void *buf, int datalen, const struct socket_pair *p, int proto);
void send_reset_back(int sock, struct iphdr *ip);
u_int16_t checksum(const u_int16_t *thdr, int len);
u_int16_t tcp_checksum4(const struct tcphdr *tcp, const struct iphdr *ip, int datalen);
#endif // NETBD_H
