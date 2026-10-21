/* libspdm requester context setup on top of the AF_MCTP transport. */
#ifndef SPDM_GLUE_H
#define SPDM_GLUE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mctp_io.h"

#define APP_DATA_TRANSFER_SIZE 0x1200
#define APP_MAX_SPDM_MSG_SIZE  0x10000

struct spdm_opts {
    uint8_t eid;
    uint32_t net;
    const char *ifname;
    const char *lladdr;
    int timeout_ms;          /* minimum response timeout */
    uint8_t version;         /* 0: any, else 0x10..0x14 (max/only version) */
    uint32_t base_asym;
    uint32_t base_hash;
    uint16_t dhe;
    uint16_t aead;
    uint32_t meas_hash;
    bool no_session_caps;    /* do not advertise KEY_EX/ENCRYPT/MAC */
};

typedef struct {
    struct spdm_opts opts;
    mctp_conn_t mctp;
    void *ctx;
    void *scratch;
    size_t scratch_size;
    uint8_t *sender_buf;
    uint8_t *receiver_buf;
    size_t buf_size;
    bool sender_busy;
    bool receiver_busy;
    /* trust anchors kept alive for libspdm (it stores pointers) */
    uint8_t *root_ca[10];
    size_t root_ca_len[10];
    int root_ca_count;
} spdm_app_t;

/* Defaults for algorithm masks (everything libspdm+mbedTLS supports). */
void spdm_opts_defaults(struct spdm_opts *o);

int spdm_app_init(spdm_app_t *app, const struct spdm_opts *o);
void spdm_app_deinit(spdm_app_t *app);

/* Provision a peer root certificate (DER). The buffer is owned by app afterwards. */
int spdm_app_add_root_ca(spdm_app_t *app, uint8_t *der, size_t len);

/* Helpers to read negotiated connection parameters. */
uint32_t spdm_conn_u32(void *ctx, int data_type);
uint8_t spdm_conn_version(void *ctx);
const char *spdm_status_str(uint32_t status);

#endif
