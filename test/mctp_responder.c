/*
 * spdm-test-responder: minimal libspdm responder over AF_MCTP, for testing
 * spdm-req-tool code paths the real device does not support (secure
 * sessions). Uses libspdm's sample keys, so it must never be deployed as a
 * real device.
 *
 *   spdm-test-responder [-k KEYDIR]    (KEYDIR contains ecp384/...)
 *
 * The requester then talks to a local EID of this host, e.g.
 *   spdm-req-tool -e <local-eid> -r KEYDIR/ecp384/ca.cert.der all
 */
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/mctp.h>

#include "library/spdm_responder_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "internal/libspdm_device_secret_lib.h"

#ifndef AF_MCTP
#define AF_MCTP 45
#endif

#define DATA_TRANSFER_SIZE 0x1200
#define MAX_SPDM_MSG_SIZE  0x10000

static int g_fd[2] = { -1, -1 }; /* type 5 (SPDM) and 6 (secured SPDM) */
static struct sockaddr_mctp g_peer;
static uint8_t *g_send_buf, *g_recv_buf;
static size_t g_buf_size;
static const char *g_key_dir = ".";

bool libspdm_read_input_file(const char *file_name, void **file_data, size_t *file_size)
{
    char path[512];
    FILE *f;
    long n;

    snprintf(path, sizeof(path), "%s/%s", g_key_dir, file_name);
    f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "responder: cannot open %s\n", path);
        return false;
    }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    *file_data = malloc(n);
    if (!*file_data || fread(*file_data, 1, n, f) != (size_t)n) {
        fclose(f);
        free(*file_data);
        return false;
    }
    fclose(f);
    *file_size = n;
    return true;
}

void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size)
{
}

bool libspdm_write_output_file(const char *file_name, const void *file_data, size_t file_size)
{
    return false; /* SET_CERTIFICATE / CSR persistence is not supported */
}

static int open_bound(uint8_t type)
{
    struct sockaddr_mctp addr;
    int fd = socket(AF_MCTP, SOCK_DGRAM, 0);

    if (fd < 0)
        return -1;
    memset(&addr, 0, sizeof(addr));
    addr.smctp_family = AF_MCTP;
    addr.smctp_network = MCTP_NET_ANY;
    addr.smctp_addr.s_addr = MCTP_ADDR_ANY;
    addr.smctp_type = type;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
        fprintf(stderr, "responder: bind type %u: %s\n", type, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static libspdm_return_t dev_send(void *ctx, size_t size, const void *msg, uint64_t timeout)
{
    const uint8_t *p = msg;
    struct sockaddr_mctp addr = g_peer;

    addr.smctp_type = p[0];
    addr.smctp_tag &= ~MCTP_TAG_OWNER;
    if (sendto(g_fd[0], p + 1, size - 1, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "responder: send: %s\n", strerror(errno));
        return LIBSPDM_STATUS_SEND_FAIL;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t dev_recv(void *ctx, size_t *size, void **msg, uint64_t timeout)
{
    struct pollfd pfd[2] = { { .fd = g_fd[0], .events = POLLIN },
                             { .fd = g_fd[1], .events = POLLIN } };
    uint8_t *buf = *msg;
    socklen_t alen = sizeof(g_peer);
    ssize_t n;
    int i;

    if (poll(pfd, 2, -1) <= 0)
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    i = (pfd[0].revents & POLLIN) ? 0 : 1;
    n = recvfrom(g_fd[i], buf + 1, *size - 1, 0, (struct sockaddr *)&g_peer, &alen);
    if (n < 0)
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    buf[0] = g_peer.smctp_type;
    *size = n + 1;
    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t acquire_send(void *ctx, void **b) { *b = g_send_buf; return 0; }
static void release_send(void *ctx, const void *b) { }
static libspdm_return_t acquire_recv(void *ctx, void **b) { *b = g_recv_buf; return 0; }
static void release_recv(void *ctx, const void *b) { }

#define SET(type, val)                                                         \
    do {                                                                       \
        __typeof__(val) v_ = (val);                                            \
        if (LIBSPDM_STATUS_IS_ERROR(libspdm_set_data(ctx, type, &param, &v_, sizeof(v_)))) { \
            fprintf(stderr, "responder: set_data(" #type ") failed\n");       \
            return 1;                                                          \
        }                                                                      \
    } while (0)

int main(int argc, char **argv)
{
    libspdm_data_parameter_t param;
    void *ctx, *scratch, *chain;
    size_t scratch_size, chain_size;
    uint32_t hash = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384;
    uint32_t asym = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
    int opt;

    while ((opt = getopt(argc, argv, "k:")) != -1) {
        if (opt == 'k')
            g_key_dir = optarg;
        else {
            fprintf(stderr, "usage: %s [-k keydir]\n", argv[0]);
            return 2;
        }
    }

    g_fd[0] = open_bound(MCTP_MESSAGE_TYPE_SPDM);
    g_fd[1] = open_bound(MCTP_MESSAGE_TYPE_SECURED_MCTP);
    if (g_fd[0] < 0 || g_fd[1] < 0)
        return 1;

    g_buf_size = LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE + DATA_TRANSFER_SIZE +
                 LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE;
    g_send_buf = malloc(g_buf_size);
    g_recv_buf = malloc(g_buf_size);
    ctx = calloc(1, libspdm_get_context_size());
    libspdm_init_context(ctx);
    libspdm_register_device_io_func(ctx, dev_send, dev_recv);
    libspdm_register_transport_layer_func(ctx, MAX_SPDM_MSG_SIZE,
                                          LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE,
                                          LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE,
                                          libspdm_transport_mctp_encode_message,
                                          libspdm_transport_mctp_decode_message);
    libspdm_register_device_buffer_func(ctx, (uint32_t)g_buf_size, (uint32_t)g_buf_size,
                                        acquire_send, release_send, acquire_recv,
                                        release_recv);
    scratch_size = libspdm_get_sizeof_required_scratch_buffer(ctx);
    scratch = malloc(scratch_size);
    libspdm_set_scratch_buffer(ctx, scratch, scratch_size);

    memset(&param, 0, sizeof(param));
    param.location = LIBSPDM_DATA_LOCATION_LOCAL;
    SET(LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, (uint8_t)14);
    SET(LIBSPDM_DATA_CAPABILITY_FLAGS,
        (uint32_t)(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
                   SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
                   SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
                   SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP |
                   SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
                   SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
                   SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
                   SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP |
                   SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP |
                   SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP));
    SET(LIBSPDM_DATA_MEASUREMENT_SPEC, (uint8_t)SPDM_MEASUREMENT_SPECIFICATION_DMTF);
    SET(LIBSPDM_DATA_MEASUREMENT_HASH_ALGO,
        (uint32_t)SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384);
    SET(LIBSPDM_DATA_BASE_ASYM_ALGO, asym);
    SET(LIBSPDM_DATA_BASE_HASH_ALGO, hash);
    SET(LIBSPDM_DATA_DHE_NAME_GROUP, (uint16_t)SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1);
    SET(LIBSPDM_DATA_AEAD_CIPHER_SUITE,
        (uint16_t)SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM);
    SET(LIBSPDM_DATA_REQ_BASE_ASYM_ALG,
        (uint16_t)SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384);
    SET(LIBSPDM_DATA_KEY_SCHEDULE, (uint16_t)SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM);
    SET(LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, (uint8_t)SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1);
    SET(LIBSPDM_DATA_HEARTBEAT_PERIOD, (uint8_t)30);
    SET(LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK, (uint8_t)0x01);

    if (!libspdm_read_responder_public_certificate_chain(hash, asym, &chain, &chain_size,
                                                         NULL, NULL)) {
        fprintf(stderr, "responder: cannot load sample certificate chain from %s\n", g_key_dir);
        return 1;
    }
    param.additional_data[0] = 0; /* slot */
    if (LIBSPDM_STATUS_IS_ERROR(libspdm_set_data(ctx, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                                                 &param, chain, chain_size))) {
        fprintf(stderr, "responder: cannot set certificate chain\n");
        return 1;
    }

    fprintf(stderr, "spdm-test-responder: listening for MCTP type 5/6 (sample keys from %s)\n",
            g_key_dir);
    for (;;) {
        libspdm_return_t st = libspdm_responder_dispatch_message(ctx);

        if (LIBSPDM_STATUS_IS_ERROR(st) && st != LIBSPDM_STATUS_UNSUPPORTED_CAP)
            fprintf(stderr, "responder: dispatch status 0x%08x\n", st);
    }
    return 0;
}
