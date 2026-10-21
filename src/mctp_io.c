#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <linux/mctp.h>

#include "mctp_io.h"

#ifndef AF_MCTP
#define AF_MCTP 45
#endif
#ifndef SOL_MCTP
#define SOL_MCTP 285
#endif

static int parse_lladdr(const char *s, uint8_t *out, uint8_t *len)
{
    unsigned v;
    int n = 0;

    while (s && *s) {
        if (n >= 8 || sscanf(s, "%2x", &v) != 1)
            return -EINVAL;
        out[n++] = (uint8_t)v;
        s += 2;
        if (*s == ':')
            s++;
        else if (*s)
            return -EINVAL;
    }
    *len = (uint8_t)n;
    return 0;
}

int mctp_open(mctp_conn_t *c, uint8_t eid, uint32_t net, const char *ifname,
              const char *lladdr)
{
    memset(c, 0, sizeof(*c));
    c->eid = eid;
    c->net = net;
    c->fd = socket(AF_MCTP, SOCK_DGRAM, 0);
    if (c->fd < 0)
        return -errno;

    if (ifname) {
        int one = 1;

        c->ifindex = (int)if_nametoindex(ifname);
        if (!c->ifindex) {
            int err = -errno;

            close(c->fd);
            return err ? err : -ENODEV;
        }
        if (lladdr && parse_lladdr(lladdr, c->haddr, &c->halen)) {
            close(c->fd);
            return -EINVAL;
        }
        if (setsockopt(c->fd, SOL_MCTP, MCTP_OPT_ADDR_EXT, &one, sizeof(one))) {
            int err = -errno;

            close(c->fd);
            return err;
        }
    }
    return 0;
}

void mctp_close(mctp_conn_t *c)
{
    if (c->fd >= 0)
        close(c->fd);
    c->fd = -1;
}

int mctp_send(mctp_conn_t *c, uint8_t type, const void *buf, size_t len)
{
    ssize_t rc;

    if (c->ifindex) {
        struct sockaddr_mctp_ext addr;

        memset(&addr, 0, sizeof(addr));
        addr.smctp_base.smctp_family = AF_MCTP;
        addr.smctp_base.smctp_network = c->net;
        addr.smctp_base.smctp_addr.s_addr = c->eid;
        addr.smctp_base.smctp_type = type;
        addr.smctp_base.smctp_tag = MCTP_TAG_OWNER;
        addr.smctp_ifindex = c->ifindex;
        addr.smctp_halen = c->halen;
        memcpy(addr.smctp_haddr, c->haddr, c->halen);
        rc = sendto(c->fd, buf, len, 0, (struct sockaddr *)&addr, sizeof(addr));
    } else {
        struct sockaddr_mctp addr;

        memset(&addr, 0, sizeof(addr));
        addr.smctp_family = AF_MCTP;
        addr.smctp_network = c->net;
        addr.smctp_addr.s_addr = c->eid;
        addr.smctp_type = type;
        addr.smctp_tag = MCTP_TAG_OWNER;
        rc = sendto(c->fd, buf, len, 0, (struct sockaddr *)&addr, sizeof(addr));
    }
    if (rc < 0)
        return -errno;
    return rc == (ssize_t)len ? 0 : -EIO;
}

static long elapsed_ms(const struct timespec *t0)
{
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC, &t);
    return (t.tv_sec - t0->tv_sec) * 1000 + (t.tv_nsec - t0->tv_nsec) / 1000000;
}

int mctp_recv(mctp_conn_t *c, uint8_t *type, void *buf, size_t max, size_t *len,
              int timeout_ms)
{
    struct timespec t0;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        struct sockaddr_mctp_ext addr;
        socklen_t alen = sizeof(addr);
        struct pollfd pfd = { .fd = c->fd, .events = POLLIN };
        int wait = timeout_ms < 0 ? -1 : timeout_ms - (int)elapsed_ms(&t0);
        ssize_t rc;

        if (timeout_ms >= 0 && wait <= 0)
            return -ETIMEDOUT;
        rc = poll(&pfd, 1, wait);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (rc == 0)
            return -ETIMEDOUT;

        rc = recvfrom(c->fd, buf, max, MSG_TRUNC, (struct sockaddr *)&addr, &alen);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if ((size_t)rc > max)
            return -EMSGSIZE;
        /* Only accept responses (tag owner clear) from our peer. */
        if (addr.smctp_base.smctp_addr.s_addr != c->eid ||
            (addr.smctp_base.smctp_tag & MCTP_TAG_OWNER))
            continue;
        *type = addr.smctp_base.smctp_type;
        *len = (size_t)rc;
        return 0;
    }
}
