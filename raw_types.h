#ifndef RAW_TYPES_H
#define RAW_TYPES_H
#include <sys/types.h>

struct socket_pair
{
    struct sockaddr_in *src;
    struct sockaddr_in *dst;
};

struct seqs
{
    u_int32_t tcp_seq;
    u_int32_t tcp_ack_seq;
};

#endif // TYPES_H
