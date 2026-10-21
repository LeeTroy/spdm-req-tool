/* AF_MCTP (Linux kernel MCTP stack) socket transport. */
#ifndef MCTP_IO_H
#define MCTP_IO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    int fd;
    uint8_t eid;
    uint32_t net;
    int ifindex;       /* >0: extended addressing directly on this interface */
    uint8_t haddr[8];  /* physical address for extended addressing */
    uint8_t halen;
} mctp_conn_t;

/* Opens an AF_MCTP datagram socket to the remote endpoint.
 * ifname may be NULL to rely on the kernel routing table. */
int mctp_open(mctp_conn_t *c, uint8_t eid, uint32_t net, const char *ifname,
              const char *lladdr);
void mctp_close(mctp_conn_t *c);

/* Sends one MCTP message of the given type (payload excludes the type byte). */
int mctp_send(mctp_conn_t *c, uint8_t type, const void *buf, size_t len);

/* Receives one message from the remote EID. Returns 0, -ETIMEDOUT or -errno. */
int mctp_recv(mctp_conn_t *c, uint8_t *type, void *buf, size_t max, size_t *len,
              int timeout_ms);

#endif
