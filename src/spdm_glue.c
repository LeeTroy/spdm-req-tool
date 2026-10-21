#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_mctp_lib.h"

#include "decode.h"
#include "output.h"
#include "spdm_glue.h"

/* libspdm callbacks only carry the SPDM context, so keep the (single) app here. */
static spdm_app_t *g_app;

void spdm_opts_defaults(struct spdm_opts *o)
{
    memset(o, 0, sizeof(*o));
    o->timeout_ms = 3000;
    o->base_asym = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
                   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
                   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521 |
                   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
                   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
                   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
                   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
                   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
                   SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096;
    o->base_hash = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
                   SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
                   SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512;
    o->dhe = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
             SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
             SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1 |
             SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048 |
             SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072 |
             SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096;
    o->aead = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM |
              SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
              SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305;
    o->meas_hash = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256 |
                   SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384 |
                   SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512 |
                   SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY;
}

/* ------------------------------------------------------------ device I/O */

static libspdm_return_t dev_send(void *ctx, size_t size, const void *msg, uint64_t timeout)
{
    const uint8_t *p = msg;
    int rc;

    if (size < 1)
        return LIBSPDM_STATUS_SEND_FAIL;
    /* libspdm's MCTP transport prepends the MCTP message type byte; the
     * kernel wants it in the socket address instead. */
    rc = mctp_send(&g_app->mctp, p[0], p + 1, size - 1);
    out_transport(true, p[0], g_app->mctp.eid, size - 1);
    if (rc) {
        out_log(ST_FAIL, "MCTP send to EID %u failed: %s", g_app->mctp.eid, strerror(-rc));
        return LIBSPDM_STATUS_SEND_FAIL;
    }
    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t dev_recv(void *ctx, size_t *size, void **msg, uint64_t timeout)
{
    uint8_t *buf = *msg;
    uint8_t type;
    size_t len;
    int tmo = (int)(timeout / 1000);
    int rc;

    if (tmo < g_app->opts.timeout_ms)
        tmo = g_app->opts.timeout_ms;
    if (*size < 2)
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    rc = mctp_recv(&g_app->mctp, &type, buf + 1, *size - 1, &len, tmo);
    if (rc) {
        out_log(ST_FAIL, "MCTP receive from EID %u failed: %s", g_app->mctp.eid,
                rc == -ETIMEDOUT ? "timeout" : strerror(-rc));
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
    out_transport(false, type, g_app->mctp.eid, len);
    buf[0] = type;
    *size = len + 1;
    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t acquire_sender(void *ctx, void **buf)
{
    if (g_app->sender_busy)
        return LIBSPDM_STATUS_ACQUIRE_FAIL;
    g_app->sender_busy = true;
    *buf = g_app->sender_buf;
    return LIBSPDM_STATUS_SUCCESS;
}

static void release_sender(void *ctx, const void *buf)
{
    g_app->sender_busy = false;
}

static libspdm_return_t acquire_receiver(void *ctx, void **buf)
{
    if (g_app->receiver_busy)
        return LIBSPDM_STATUS_ACQUIRE_FAIL;
    g_app->receiver_busy = true;
    *buf = g_app->receiver_buf;
    return LIBSPDM_STATUS_SUCCESS;
}

static void release_receiver(void *ctx, const void *buf)
{
    g_app->receiver_busy = false;
}

/* ------------------------------------------------------------- transport */

/* Wrap the MCTP transport so every SPDM message is seen in plaintext, i.e.
 * before encryption on the way out and after decryption on the way in. */
static libspdm_return_t tap_encode(void *ctx, const uint32_t *session_id, bool is_app_message,
                                   bool is_request_message, size_t message_size, void *message,
                                   size_t *transport_message_size, void **transport_message)
{
    if (!is_app_message)
        decode_and_report(ctx, true, session_id, message, message_size);
    return libspdm_transport_mctp_encode_message(ctx, session_id, is_app_message,
                                                 is_request_message, message_size, message,
                                                 transport_message_size, transport_message);
}

static libspdm_return_t tap_decode(void *ctx, uint32_t **session_id, bool *is_app_message,
                                   bool is_request_message, size_t transport_message_size,
                                   void *transport_message, size_t *message_size, void **message)
{
    libspdm_return_t st;

    st = libspdm_transport_mctp_decode_message(ctx, session_id, is_app_message,
                                               is_request_message, transport_message_size,
                                               transport_message, message_size, message);
    if (LIBSPDM_STATUS_IS_ERROR(st))
        out_log(ST_FAIL, "MCTP transport decode failed: %s", spdm_status_str(st));
    else if (!*is_app_message)
        decode_and_report(ctx, false, *session_id, *message, *message_size);
    return st;
}

/* ----------------------------------------------------------------- setup */

#define SET_LOCAL(type, val)                                                     \
    do {                                                                         \
        __typeof__(val) v_ = (val);                                              \
        st = libspdm_set_data(app->ctx, type, &param, &v_, sizeof(v_));          \
        if (LIBSPDM_STATUS_IS_ERROR(st)) {                                       \
            out_log(ST_FAIL, "libspdm_set_data(" #type ") failed: %s",           \
                    spdm_status_str(st));                                        \
            return -EINVAL;                                                      \
        }                                                                        \
    } while (0)

int spdm_app_init(spdm_app_t *app, const struct spdm_opts *o)
{
    libspdm_data_parameter_t param;
    libspdm_return_t st;
    uint32_t caps;
    int rc;

    memset(app, 0, sizeof(*app));
    app->opts = *o;
    g_app = app;

    rc = mctp_open(&app->mctp, o->eid, o->net, o->ifname, o->lladdr);
    if (rc) {
        out_log(ST_FAIL, "cannot open AF_MCTP socket%s%s: %s", o->ifname ? " on " : "",
                o->ifname ? o->ifname : "", strerror(-rc));
        return rc;
    }

    app->buf_size = LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE + APP_DATA_TRANSFER_SIZE +
                    LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE;
    app->sender_buf = calloc(1, app->buf_size);
    app->receiver_buf = calloc(1, app->buf_size);
    app->ctx = calloc(1, libspdm_get_context_size());
    if (!app->sender_buf || !app->receiver_buf || !app->ctx)
        return -ENOMEM;

    st = libspdm_init_context(app->ctx);
    if (LIBSPDM_STATUS_IS_ERROR(st))
        return -EINVAL;

    libspdm_register_device_io_func(app->ctx, dev_send, dev_recv);
    libspdm_register_transport_layer_func(app->ctx, APP_MAX_SPDM_MSG_SIZE,
                                          LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE,
                                          LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE,
                                          tap_encode, tap_decode);
    libspdm_register_device_buffer_func(app->ctx, (uint32_t)app->buf_size,
                                        (uint32_t)app->buf_size, acquire_sender,
                                        release_sender, acquire_receiver, release_receiver);

    app->scratch_size = libspdm_get_sizeof_required_scratch_buffer(app->ctx);
    app->scratch = calloc(1, app->scratch_size);
    if (!app->scratch)
        return -ENOMEM;
    libspdm_set_scratch_buffer(app->ctx, app->scratch, app->scratch_size);

    memset(&param, 0, sizeof(param));
    param.location = LIBSPDM_DATA_LOCATION_LOCAL;

    if (o->version) {
        spdm_version_number_t ver = (spdm_version_number_t)o->version << SPDM_VERSION_NUMBER_SHIFT_BIT;

        st = libspdm_set_data(app->ctx, LIBSPDM_DATA_SPDM_VERSION, &param, &ver, sizeof(ver));
        if (LIBSPDM_STATUS_IS_ERROR(st)) {
            out_log(ST_FAIL, "unsupported SPDM version %u.%u", o->version >> 4, o->version & 0xf);
            return -EINVAL;
        }
    }

    caps = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP;
    if (!o->no_session_caps)
        caps |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
                SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP;

    SET_LOCAL(LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, (uint8_t)0);
    SET_LOCAL(LIBSPDM_DATA_CAPABILITY_FLAGS, caps);
    /* DataTransferSize comes from the registered buffer sizes and
     * MaxSPDMmsgSize from libspdm_register_transport_layer_func(). */
    SET_LOCAL(LIBSPDM_DATA_MEASUREMENT_SPEC, (uint8_t)SPDM_MEASUREMENT_SPECIFICATION_DMTF);
    SET_LOCAL(LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, o->meas_hash);
    SET_LOCAL(LIBSPDM_DATA_BASE_ASYM_ALGO, o->base_asym);
    SET_LOCAL(LIBSPDM_DATA_BASE_HASH_ALGO, o->base_hash);
    SET_LOCAL(LIBSPDM_DATA_DHE_NAME_GROUP, o->dhe);
    SET_LOCAL(LIBSPDM_DATA_AEAD_CIPHER_SUITE, o->aead);
    SET_LOCAL(LIBSPDM_DATA_REQ_BASE_ASYM_ALG, (uint16_t)o->base_asym);
    SET_LOCAL(LIBSPDM_DATA_KEY_SCHEDULE, (uint16_t)SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM);
    SET_LOCAL(LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, (uint8_t)SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1);
    SET_LOCAL(LIBSPDM_DATA_MEL_SPEC, (uint8_t)SPDM_MEL_SPECIFICATION_DMTF);

    if (!libspdm_check_context(app->ctx)) {
        out_log(ST_FAIL, "libspdm context check failed");
        return -EINVAL;
    }
    return 0;
}

int spdm_app_add_root_ca(spdm_app_t *app, uint8_t *der, size_t len)
{
    libspdm_data_parameter_t param;
    libspdm_return_t st;

    if (app->root_ca_count >= (int)(sizeof(app->root_ca) / sizeof(app->root_ca[0])))
        return -ENOSPC;
    memset(&param, 0, sizeof(param));
    param.location = LIBSPDM_DATA_LOCATION_LOCAL;
    /* libspdm keeps the pointer; each call appends another trust anchor. */
    st = libspdm_set_data(app->ctx, LIBSPDM_DATA_PEER_PUBLIC_ROOT_CERT, &param, der, len);
    if (LIBSPDM_STATUS_IS_ERROR(st))
        return -EINVAL;
    app->root_ca[app->root_ca_count] = der;
    app->root_ca_len[app->root_ca_count] = len;
    app->root_ca_count++;
    return 0;
}

void spdm_app_deinit(spdm_app_t *app)
{
    int i;

    if (app->ctx) {
        libspdm_deinit_context(app->ctx);
        free(app->ctx);
    }
    free(app->scratch);
    free(app->sender_buf);
    free(app->receiver_buf);
    for (i = 0; i < app->root_ca_count; i++)
        free(app->root_ca[i]);
    mctp_close(&app->mctp);
    memset(app, 0, sizeof(*app));
    g_app = NULL;
}

/* -------------------------------------------------------------- helpers */

uint32_t spdm_conn_u32(void *ctx, int data_type)
{
    libspdm_data_parameter_t param;
    uint32_t v = 0;
    size_t sz = sizeof(v);

    memset(&param, 0, sizeof(param));
    param.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    if (LIBSPDM_STATUS_IS_ERROR(libspdm_get_data(ctx, (libspdm_data_type_t)data_type, &param,
                                                 &v, &sz)))
        return 0;
    return v;
}

uint8_t spdm_conn_version(void *ctx)
{
    return (uint8_t)(spdm_conn_u32(ctx, LIBSPDM_DATA_SPDM_VERSION) >> SPDM_VERSION_NUMBER_SHIFT_BIT);
}

const char *spdm_status_str(uint32_t s)
{
    static char buf[32];

    switch (s) {
    case LIBSPDM_STATUS_SUCCESS: return "success";
    case LIBSPDM_STATUS_INVALID_PARAMETER: return "invalid parameter";
    case LIBSPDM_STATUS_UNSUPPORTED_CAP: return "unsupported capability";
    case LIBSPDM_STATUS_INVALID_STATE_LOCAL: return "invalid local state";
    case LIBSPDM_STATUS_INVALID_STATE_PEER: return "invalid peer state";
    case LIBSPDM_STATUS_INVALID_MSG_FIELD: return "invalid message field";
    case LIBSPDM_STATUS_INVALID_MSG_SIZE: return "invalid message size";
    case LIBSPDM_STATUS_NEGOTIATION_FAIL: return "negotiation failed";
    case LIBSPDM_STATUS_BUSY_PEER: return "peer busy";
    case LIBSPDM_STATUS_NOT_READY_PEER: return "peer not ready";
    case LIBSPDM_STATUS_ERROR_PEER: return "peer returned ERROR";
    case LIBSPDM_STATUS_RESYNCH_PEER: return "peer requested resynch";
    case LIBSPDM_STATUS_BUFFER_FULL: return "buffer full";
    case LIBSPDM_STATUS_BUFFER_TOO_SMALL: return "buffer too small";
    case LIBSPDM_STATUS_SESSION_NUMBER_EXCEED: return "session number exceeded";
    case LIBSPDM_STATUS_SESSION_MSG_ERROR: return "session message error";
    case LIBSPDM_STATUS_ACQUIRE_FAIL: return "buffer acquire failed";
    case LIBSPDM_STATUS_RESET_REQUIRED_PEER: return "peer requires reset";
    case LIBSPDM_STATUS_PEER_BUFFER_TOO_SMALL: return "peer buffer too small";
    case LIBSPDM_STATUS_CRYPTO_ERROR: return "crypto error";
    case LIBSPDM_STATUS_VERIF_FAIL: return "verification failed";
    case LIBSPDM_STATUS_SEQUENCE_NUMBER_OVERFLOW: return "sequence number overflow";
    case LIBSPDM_STATUS_VERIF_NO_AUTHORITY: return "no trusted authority (root CA mismatch)";
    case LIBSPDM_STATUS_FIPS_FAIL: return "FIPS failure";
    case LIBSPDM_STATUS_INVALID_CERT: return "invalid certificate";
    case LIBSPDM_STATUS_SEND_FAIL: return "transport send failed";
    case LIBSPDM_STATUS_RECEIVE_FAIL: return "transport receive failed";
    case LIBSPDM_STATUS_MEAS_INVALID_INDEX: return "invalid measurement index";
    case LIBSPDM_STATUS_MEAS_INTERNAL_ERROR: return "measurement internal error";
    case LIBSPDM_STATUS_LOW_ENTROPY: return "low entropy";
    }
    snprintf(buf, sizeof(buf), "status 0x%08x", s);
    return buf;
}
