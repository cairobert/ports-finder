#include "bdnet.h"
#include "capture.h"
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define THREAD_NUM 1
#define MAX_PORT_NUM 65535
#define LOCAL_PORT 12345

struct socket_pair *pair;
int dst_sock;

void errquit(const char *msg);
void init_resource(struct thread_resource *threads, const int num, int sock, const pcap_if_t *dev, const char *filter, int *ports);
void *detect(void *arg);

int main(int argc, char **argv)
{

    struct sockaddr_in src, dst;
    struct thread_resource threads[THREAD_NUM];
    pthread_t tid;
    int ports[MAX_PORT_NUM + 1] = {0};
    pcap_if_t *dev;
    char filter[256] = {0};
    int i;
    int len = sizeof(i);

    if (argc != 2)
    {
        fprintf(stderr, "Usage: sniff target_ip\n");
        exit(1);
    }    
    if (-1 == (dst_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)))
        errquit("socket");

    if (NULL == (pair = (struct socket_pair *) malloc(sizeof(struct socket_pair))))
        errquit("malloc");
    pair->src = &src;
    pair->dst = &dst;

    printf("running...\n");
    configure_remote_addr(argv[1], pair->dst);
    snprintf(filter, 256, "tcp port %d", LOCAL_PORT);   // host 115.155.60.3 and dst port %d", LOCAL_PORT);

    dev = configure_local_addr(pair->src);
    pair->src->sin_port = htons(LOCAL_PORT);

#ifndef NNDEBUG
    printf("remote addr: %s\n", inet_ntoa(pair->dst->sin_addr));
    printf("local addr: %s\n", inet_ntoa(pair->src->sin_addr));
#endif

    init_resource(threads, THREAD_NUM, dst_sock, dev, filter, ports);
    for (i = 0; i < THREAD_NUM; ++i)
    {
        if (-1 == pthread_create(&threads[i].tid, NULL, capture, (void*)&threads[i]))
            errquit("pthread_create");
        pthread_detach(threads[i].tid);
    }
    sleep(1);
    if (-1 == pthread_create(&tid, NULL, detect, (void*)pair) )
        errquit("pthread_create");
    pthread_detach(tid);

    sleep(8);
    for (i = 0; i < THREAD_NUM; ++i)
        cancel_capture(&threads[i]);        
    printf("The following ports send SYN and ACK back:\n");
    for (i = 1; i < MAX_PORT_NUM + 1; ++i)
        if (0 != ports[i])
            printf("%d ", i);
    printf("\nDone!\n");
    free(pair);
    return(0);
}

void init_resource(struct thread_resource *threads, const int num, int sock, const pcap_if_t *dev, const char *filter, int *ports)
{
    int i;
    memset(threads, 0, sizeof(*threads) * num);

    for (i = 0; i < num; ++i)
    {
        threads[i].dev = dev;
        threads[i].fitler = filter;
        threads[i].ports = ports;
        threads[i].tid = 0;
        threads[i].sock = sock;
    }
}

void errquit(const char *msg)
{
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

void *detect(void *arg)
{
    struct socket_pair *p = (struct socket_pair *)arg;
    int i;

    for (i = 1; i <= MAX_PORT_NUM; ++i)
    {
        char buf[256] = {0};
        p->dst->sin_port = htons(i);
        write_tcp4(dst_sock, buf, 0, p, NULL, TCP_SYN);
    }

    pthread_exit((void*)0);
}
