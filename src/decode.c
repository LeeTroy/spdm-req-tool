#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "library/spdm_requester_lib.h"
#include "library/spdm_crypt_lib.h"

#include "cbor.h"
#include "decode.h"
#include "output.h"
#include "spdm_glue.h"
#include "util.h"

/* Request context needed to parse the matching response. */
static struct {
    uint8_t req_code;
    uint8_t meas_attr;      /* GET_MEASUREMENTS param1 */
    uint8_t meas_op;        /* GET_MEASUREMENTS param2 */
    uint8_t chal_hash_type; /* CHALLENGE param2 */
    uint8_t kex_hash_type;  /* KEY_EXCHANGE param1 */
    uint8_t finish_sig;     /* FINISH param1 */
} g_req;

/* ---------------------------------------------------------------- names */

struct code_name {
    uint8_t code;
    const char *name;
    const char *desc;
};

static const struct code_name codes[] = {
    { 0x01, "DIGESTS", "Certificate chain digests" },
    { 0x02, "CERTIFICATE", "Certificate chain portion" },
    { 0x03, "CHALLENGE_AUTH", "Signed challenge response" },
    { 0x04, "VERSION", "Supported SPDM versions" },
    { 0x05, "CHUNK_SEND_ACK", "Chunk send acknowledge" },
    { 0x06, "CHUNK_RESPONSE", "Chunk of a large response" },
    { 0x07, "ENDPOINT_INFO", "Endpoint information" },
    { 0x60, "MEASUREMENTS", "Measurement blocks" },
    { 0x61, "CAPABILITIES", "Responder capabilities" },
    { 0x62, "SUPPORTED_EVENT_TYPES", "Supported event types" },
    { 0x63, "ALGORITHMS", "Selected algorithms" },
    { 0x64, "KEY_EXCHANGE_RSP", "Key exchange response" },
    { 0x65, "FINISH_RSP", "Handshake finish response" },
    { 0x66, "PSK_EXCHANGE_RSP", "PSK exchange response" },
    { 0x67, "PSK_FINISH_RSP", "PSK finish response" },
    { 0x68, "HEARTBEAT_ACK", "Heartbeat acknowledge" },
    { 0x69, "KEY_UPDATE_ACK", "Key update acknowledge" },
    { 0x6A, "ENCAPSULATED_REQUEST", "Encapsulated request" },
    { 0x6B, "ENCAPSULATED_RESPONSE_ACK", "Encapsulated response acknowledge" },
    { 0x6C, "END_SESSION_ACK", "End session acknowledge" },
    { 0x6D, "CSR", "Certificate signing request" },
    { 0x6E, "SET_CERTIFICATE_RSP", "Set certificate response" },
    { 0x6F, "MEASUREMENT_EXTENSION_LOG", "Measurement extension log" },
    { 0x70, "SUBSCRIBE_EVENT_TYPES_ACK", "Subscribe event types acknowledge" },
    { 0x71, "EVENT_ACK", "Event acknowledge" },
    { 0x7C, "KEY_PAIR_INFO", "Key pair information" },
    { 0x7D, "SET_KEY_PAIR_INFO_ACK", "Set key pair info acknowledge" },
    { 0x7E, "VENDOR_DEFINED_RESPONSE", "Vendor defined response" },
    { 0x7F, "ERROR", "Error response" },
    { 0x81, "GET_DIGESTS", "Request certificate chain digests" },
    { 0x82, "GET_CERTIFICATE", "Request certificate chain portion" },
    { 0x83, "CHALLENGE", "Authenticate the responder" },
    { 0x84, "GET_VERSION", "Request supported SPDM versions" },
    { 0x85, "CHUNK_SEND", "Send chunk of a large request" },
    { 0x86, "CHUNK_GET", "Get chunk of a large response" },
    { 0x87, "GET_ENDPOINT_INFO", "Request endpoint information" },
    { 0xE0, "GET_MEASUREMENTS", "Request measurements" },
    { 0xE1, "GET_CAPABILITIES", "Exchange capabilities" },
    { 0xE2, "GET_SUPPORTED_EVENT_TYPES", "Request supported event types" },
    { 0xE3, "NEGOTIATE_ALGORITHMS", "Negotiate cryptographic algorithms" },
    { 0xE4, "KEY_EXCHANGE", "Start secure session (DHE)" },
    { 0xE5, "FINISH", "Complete session handshake" },
    { 0xE6, "PSK_EXCHANGE", "Start secure session (PSK)" },
    { 0xE7, "PSK_FINISH", "Complete PSK handshake" },
    { 0xE8, "HEARTBEAT", "Session keep-alive" },
    { 0xE9, "KEY_UPDATE", "Update session keys" },
    { 0xEA, "GET_ENCAPSULATED_REQUEST", "Get encapsulated request" },
    { 0xEB, "DELIVER_ENCAPSULATED_RESPONSE", "Deliver encapsulated response" },
    { 0xEC, "END_SESSION", "Terminate secure session" },
    { 0xED, "GET_CSR", "Request certificate signing request" },
    { 0xEE, "SET_CERTIFICATE", "Provision certificate chain" },
    { 0xEF, "GET_MEASUREMENT_EXTENSION_LOG", "Request measurement extension log" },
    { 0xF0, "SUBSCRIBE_EVENT_TYPES", "Subscribe event types" },
    { 0xF1, "SEND_EVENT", "Send event" },
    { 0xFC, "GET_KEY_PAIR_INFO", "Request key pair information" },
    { 0xFD, "SET_KEY_PAIR_INFO", "Set key pair information" },
    { 0xFE, "VENDOR_DEFINED_REQUEST", "Vendor defined request" },
    { 0xFF, "RESPOND_IF_READY", "Retrieve delayed response" },
};

static const struct code_name *find_code(uint8_t code)
{
    size_t i;

    for (i = 0; i < sizeof(codes) / sizeof(codes[0]); i++)
        if (codes[i].code == code)
            return &codes[i];
    return NULL;
}

const char *spdm_code_name(uint8_t code)
{
    const struct code_name *c = find_code(code);

    return c ? c->name : "UNKNOWN";
}

const char *spdm_error_name(uint8_t code)
{
    switch (code) {
    case 0x01: return "InvalidRequest";
    case 0x02: return "InvalidSession";
    case 0x03: return "Busy";
    case 0x04: return "UnexpectedRequest";
    case 0x05: return "Unspecified";
    case 0x06: return "DecryptError";
    case 0x07: return "UnsupportedRequest";
    case 0x08: return "RequestInFlight";
    case 0x09: return "InvalidResponseCode";
    case 0x0A: return "SessionLimitExceeded";
    case 0x0B: return "SessionRequired";
    case 0x0C: return "ResetRequired";
    case 0x0D: return "ResponseTooLarge";
    case 0x0E: return "RequestTooLarge";
    case 0x0F: return "LargeResponse";
    case 0x10: return "MessageLost";
    case 0x11: return "InvalidPolicy";
    case 0x41: return "VersionMismatch";
    case 0x42: return "ResponseNotReady";
    case 0x43: return "RequestResynch";
    case 0x44: return "OperationFailed";
    case 0x45: return "NoPendingRequests";
    case 0xFF: return "VendorDefined";
    }
    return "Reserved";
}

const char *asym_name(uint32_t bit)
{
    switch (bit) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048: return "RSASSA-2048";
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048: return "RSAPSS-2048";
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072: return "RSASSA-3072";
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072: return "RSAPSS-3072";
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256: return "ECDSA-P256";
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096: return "RSASSA-4096";
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096: return "RSAPSS-4096";
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384: return "ECDSA-P384";
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521: return "ECDSA-P521";
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256: return "SM2-P256";
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519: return "EdDSA-25519";
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448: return "EdDSA-448";
    }
    return NULL;
}

const char *hash_name(uint32_t bit)
{
    switch (bit) {
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256: return "SHA-256";
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384: return "SHA-384";
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512: return "SHA-512";
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256: return "SHA3-256";
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384: return "SHA3-384";
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512: return "SHA3-512";
    case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256: return "SM3-256";
    }
    return NULL;
}

const char *meas_hash_name(uint32_t bit)
{
    switch (bit) {
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY: return "RawBitStreamOnly";
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256: return "SHA-256";
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384: return "SHA-384";
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512: return "SHA-512";
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256: return "SHA3-256";
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384: return "SHA3-384";
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512: return "SHA3-512";
    case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256: return "SM3-256";
    }
    return NULL;
}

const char *dhe_name(uint32_t bit)
{
    switch (bit) {
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048: return "FFDHE-2048";
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072: return "FFDHE-3072";
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096: return "FFDHE-4096";
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1: return "secp256r1";
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1: return "secp384r1";
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1: return "secp521r1";
    case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256: return "SM2-P256";
    }
    return NULL;
}

const char *aead_name(uint32_t bit)
{
    switch (bit) {
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM: return "AES-128-GCM";
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM: return "AES-256-GCM";
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305: return "ChaCha20-Poly1305";
    case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM: return "SM4-GCM";
    }
    return NULL;
}

static const char *keysched_name(uint32_t bit)
{
    return bit == SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM ? "SPDM" : NULL;
}

const char *pqc_name(uint32_t bit)
{
    static const char *n[] = { "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s",
                               "SLH-DSA-SHAKE-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f",
                               "SLH-DSA-SHA2-192s", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHA2-192f",
                               "SLH-DSA-SHAKE-192f", "SLH-DSA-SHA2-256s", "SLH-DSA-SHAKE-256s",
                               "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-256f" };
    int i;

    for (i = 0; i < (int)(sizeof(n) / sizeof(n[0])); i++)
        if (bit == (1u << i))
            return n[i];
    return NULL;
}

static const char *kem_name(uint32_t bit)
{
    switch (bit) {
    case 1: return "ML-KEM-512";
    case 2: return "ML-KEM-768";
    case 4: return "ML-KEM-1024";
    }
    return NULL;
}

char *bits_to_names(uint32_t mask, const char *(*name)(uint32_t))
{
    char buf[512];
    size_t off = 0;
    int i;

    buf[0] = '\0';
    for (i = 0; i < 32; i++) {
        uint32_t bit = 1u << i;
        const char *n;

        if (!(mask & bit))
            continue;
        n = name(bit);
        if (n)
            off += snprintf(buf + off, sizeof(buf) - off, "%s%s", off ? ", " : "", n);
        else
            off += snprintf(buf + off, sizeof(buf) - off, "%sbit%d", off ? ", " : "", i);
        if (off >= sizeof(buf))
            break;
    }
    if (!mask)
        snprintf(buf, sizeof(buf), "(none)");
    return strdup(buf);
}

static void add_algo(node_t *parent, const char *key, uint32_t mask,
                     const char *(*name)(uint32_t))
{
    char *s = bits_to_names(mask, name);
    node_t *n = node_add(parent, key, "%s  [0x%x]", s, mask);

    if (mask)
        node_style(n, NS_HILITE);
    free(s);
}

/* -------------------------------------------------------- capabilities */

struct cap_bit {
    int bit;
    int width;
    const char *name;
    const char *desc[4];
};

static const struct cap_bit cap_bits[] = {
    { 0, 1, "CACHE_CAP", { NULL, "Can cache negotiated state across reset" } },
    { 1, 1, "CERT_CAP", { NULL, "Supports GET_DIGESTS and GET_CERTIFICATE" } },
    { 2, 1, "CHAL_CAP", { NULL, "Supports CHALLENGE authentication" } },
    { 3, 2, "MEAS_CAP", { NULL, "Measurements without signature", "Measurements with signature" } },
    { 5, 1, "MEAS_FRESH_CAP", { NULL, "Recomputes measurements on reset" } },
    { 6, 1, "ENCRYPT_CAP", { NULL, "Supports message encryption in sessions" } },
    { 7, 1, "MAC_CAP", { NULL, "Supports message authentication in sessions" } },
    { 8, 1, "MUT_AUTH_CAP", { NULL, "Supports mutual authentication" } },
    { 9, 1, "KEY_EX_CAP", { NULL, "Supports KEY_EXCHANGE" } },
    { 10, 2, "PSK_CAP", { NULL, "Pre-shared key (no context)", "Pre-shared key (with context)" } },
    { 12, 1, "ENCAP_CAP", { NULL, "Supports encapsulated requests" } },
    { 13, 1, "HBEAT_CAP", { NULL, "Supports HEARTBEAT" } },
    { 14, 1, "KEY_UPD_CAP", { NULL, "Supports KEY_UPDATE" } },
    { 15, 1, "HANDSHAKE_IN_THE_CLEAR_CAP", { NULL, "Handshake messages sent in the clear" } },
    { 16, 1, "PUB_KEY_ID_CAP", { NULL, "Public key provisioned out of band" } },
    { 17, 1, "CHUNK_CAP", { NULL, "Supports large message chunking" } },
    { 18, 1, "ALIAS_CERT_CAP", { NULL, "Uses the AliasCert model" } },
    { 19, 1, "SET_CERT_CAP", { NULL, "Supports SET_CERTIFICATE" } },
    { 20, 1, "CSR_CAP", { NULL, "Supports GET_CSR" } },
    { 21, 1, "CERT_INSTALL_RESET_CAP", { NULL, "Reset needed after certificate install" } },
    { 22, 2, "EP_INFO_CAP", { NULL, "Endpoint info without signature", "Endpoint info with signature" } },
    { 24, 1, "MEL_CAP", { NULL, "Supports measurement extension log" } },
    { 25, 1, "EVENT_CAP", { NULL, "Supports SPDM events" } },
    { 26, 2, "MULTI_KEY_CAP", { NULL, "Multiple keys only", "Multiple keys negotiated" } },
    { 28, 1, "GET_KEY_PAIR_INFO_CAP", { NULL, "Supports GET_KEY_PAIR_INFO" } },
    { 29, 1, "SET_KEY_PAIR_INFO_CAP", { NULL, "Supports SET_KEY_PAIR_INFO" } },
    { 30, 1, "SET_KEY_PAIR_RESET_CAP", { NULL, "Reset needed after SET_KEY_PAIR_INFO" } },
    { 31, 1, "LARGE_RESP_CAP", { NULL, "Supports large SPDM responses" } },
};

void decode_caps(node_t *parent, const char *key, uint32_t flags, bool is_request)
{
    node_t *n = node_add(parent, key, "0x%08x", flags);
    size_t i;

    for (i = 0; i < sizeof(cap_bits) / sizeof(cap_bits[0]); i++) {
        const struct cap_bit *b = &cap_bits[i];
        uint32_t v = (flags >> b->bit) & ((1u << b->width) - 1);

        if (!v)
            continue;
        if (v < 4 && b->desc[v])
            node_add(n, b->name, "%s", b->desc[v]);
        else
            node_add(n, b->name, "value %u (reserved)", v);
    }
}

void decode_versions(node_t *parent, const uint8_t *e, int count)
{
    int i;

    for (i = 0; i < count; i++) {
        uint16_t v = get_le16(e + i * 2);

        node_add(parent, "VersionNumberEntry", "%u.%u (update %u, alpha %u)  [0x%04x]",
                 v >> 12, (v >> 8) & 0xf, (v >> 4) & 0xf, v & 0xf, v);
    }
}

/* ------------------------------------------------------- reader helper */

typedef struct {
    const uint8_t *p;
    size_t len;
    size_t off;
    node_t *n;
    bool trunc;
} rd_t;

static const uint8_t *take(rd_t *r, size_t n)
{
    const uint8_t *p;

    if (r->trunc)
        return NULL;
    if (r->off + n > r->len) {
        node_style(node_add(r->n, "TRUNCATED", "needed %zu bytes at offset %zu, only %zu left",
                            n, r->off, r->len - r->off), NS_ERR);
        r->trunc = true;
        return NULL;
    }
    p = r->p + r->off;
    r->off += n;
    return p;
}

static bool take_hex(rd_t *r, const char *key, size_t n)
{
    const uint8_t *p;

    if (!n)
        return true;
    p = take(r, n);
    if (!p)
        return false;
    node_add_hex(r->n, key, p, n);
    return true;
}

static uint8_t take8(rd_t *r, bool *ok)
{
    const uint8_t *p = take(r, 1);

    if (!p) {
        *ok = false;
        return 0;
    }
    return p[0];
}

static uint16_t take16(rd_t *r, bool *ok)
{
    const uint8_t *p = take(r, 2);

    if (!p) {
        *ok = false;
        return 0;
    }
    return get_le16(p);
}

static uint32_t take32(rd_t *r, bool *ok)
{
    const uint8_t *p = take(r, 4);

    if (!p) {
        *ok = false;
        return 0;
    }
    return get_le32(p);
}

/* ------------------------------------------------- negotiated sizes */

static uint32_t neg_hash_size(void *ctx)
{
    return libspdm_get_hash_size(spdm_conn_u32(ctx, LIBSPDM_DATA_BASE_HASH_ALGO));
}

static uint32_t neg_sig_size(void *ctx)
{
    uint32_t pqc = spdm_conn_u32(ctx, LIBSPDM_DATA_PQC_ASYM_ALGO);

    if (pqc)
        return libspdm_get_pqc_asym_signature_size(pqc);
    return libspdm_get_asym_signature_size(spdm_conn_u32(ctx, LIBSPDM_DATA_BASE_ASYM_ALGO));
}

static uint32_t neg_dhe_size(void *ctx)
{
    return libspdm_get_dhe_pub_key_size((uint16_t)spdm_conn_u32(ctx, LIBSPDM_DATA_DHE_NAME_GROUP));
}

/* MeasurementSummaryHash is present only if requested and the responder has MEAS_CAP. */
static uint32_t meas_summary_size(void *ctx, uint8_t hash_type)
{
    if (!hash_type ||
        !(spdm_conn_u32(ctx, LIBSPDM_DATA_CAPABILITY_FLAGS) &
          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP))
        return 0;
    return neg_hash_size(ctx);
}

static bool handshake_in_clear(void *ctx)
{
    libspdm_data_parameter_t param;
    uint32_t local = 0, peer;
    size_t sz = sizeof(local);

    memset(&param, 0, sizeof(param));
    param.location = LIBSPDM_DATA_LOCATION_LOCAL;
    libspdm_get_data(ctx, LIBSPDM_DATA_CAPABILITY_FLAGS, &param, &local, &sz);
    peer = spdm_conn_u32(ctx, LIBSPDM_DATA_CAPABILITY_FLAGS);
    return (local & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) &&
           (peer & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP);
}

/* --------------------------------------------------------- opaque data */

static void decode_dmtf_sm(node_t *parent, const uint8_t *d, size_t len)
{
    if (len < 2) {
        node_add_hex(parent, "Data", d, len);
        return;
    }
    node_add(parent, "SMDataVersion", "%u", d[0]);
    if (d[1] == 0 && len >= 4) {
        uint16_t v = get_le16(d + 2);

        node_add(parent, "SMDataID", "0 (Secured Message Version Selection)");
        node_style(node_add(parent, "SelectedVersion", "%u.%u", v >> 12, (v >> 8) & 0xf),
                   NS_HILITE);
    } else if (d[1] == 1 && len >= 3) {
        unsigned i, cnt = d[2];

        node_add(parent, "SMDataID", "1 (Supported Secured Message Versions)");
        for (i = 0; i < cnt && 3 + i * 2 + 2 <= len; i++) {
            uint16_t v = get_le16(d + 3 + i * 2);

            node_add(parent, "Version", "%u.%u", v >> 12, (v >> 8) & 0xf);
        }
    } else {
        node_add(parent, "SMDataID", "%u", d[1]);
        node_add_hex(parent, "Data", d + 2, len - 2);
    }
}

void decode_opaque(node_t *parent, const uint8_t *data, size_t len, uint8_t version)
{
    node_t *n;
    size_t off;
    unsigned i, total;

    if (!len)
        return;
    n = node_add(parent, "OpaqueData", "%zu bytes", len);
    if (version >= 0x12 && len >= 4) {
        /* General opaque data format (DSP0274 table "OpaqueData") */
        total = data[0];
        node_add(n, "TotalElements", "%u", total);
        off = 4;
        for (i = 0; i < total && off + 2 <= len; i++) {
            uint8_t id = data[off], vlen = data[off + 1];
            uint16_t dlen;
            node_t *e;

            if (off + 2 + vlen + 2 > len)
                break;
            dlen = get_le16(data + off + 2 + vlen);
            e = node_add(n, "OpaqueElement", "ID %u (%s)", id,
                         id == 0 ? "DMTF" : id == 0xFF ? "Vendor" : "Registry");
            if (vlen)
                node_add_hex(e, "VendorID", data + off + 2, vlen);
            if (off + 4 + vlen + dlen > len)
                break;
            if (id == 0)
                decode_dmtf_sm(e, data + off + 4 + vlen, dlen);
            else
                node_add_hex(e, "Data", data + off + 4 + vlen, dlen);
            off += 4 + vlen + dlen;
            off = (off + 3) & ~(size_t)3;
        }
        return;
    }
    if (len >= 8 && get_le32(data) == 0x444D5446) {
        /* DSP0277 1.0 secured message opaque header ("DMTF" spec id) */
        total = data[5];
        node_add(n, "SpecID", "DMTF, opaque version %u", data[4]);
        off = 8;
        for (i = 0; i < total && off + 4 <= len; i++) {
            uint8_t id = data[off], vlen = data[off + 1];
            uint16_t dlen = get_le16(data + off + 2 + vlen);
            node_t *e = node_add(n, "OpaqueElement", "ID %u", id);

            if (off + 4 + vlen + dlen > len)
                break;
            decode_dmtf_sm(e, data + off + 4 + vlen, dlen);
            off += 4 + vlen + dlen;
            off = (off + 3) & ~(size_t)3;
        }
        return;
    }
    node_add_hex(n, "Raw", data, len);
}

/* --------------------------------------------------------- measurement */

static const char *meas_type_name(uint8_t t)
{
    switch (t & 0x7f) {
    case 0: return "Immutable ROM";
    case 1: return "Mutable firmware";
    case 2: return "Hardware configuration";
    case 3: return "Firmware configuration";
    case 4: return "Freeform measurement manifest";
    case 5: return "Structured device mode";
    case 6: return "Mutable firmware version number";
    case 7: return "Mutable firmware security version number";
    case 8: return "Hash-extended measurement";
    case 9: return "Informational";
    case 10: return "Structured measurement manifest";
    }
    return "Reserved";
}

static bool is_printable(const uint8_t *p, size_t n)
{
    size_t i;

    if (!n)
        return false;
    for (i = 0; i < n; i++)
        if (!isprint(p[i]) && !(i == n - 1 && p[i] == 0))
            return false;
    return true;
}

void decode_meas_record(node_t *parent, const uint8_t *rec, size_t len, unsigned nblocks)
{
    size_t off = 0;
    unsigned i;

    for (i = 0; i < nblocks && off + 4 <= len; i++) {
        uint8_t index = rec[off], spec = rec[off + 1];
        uint16_t size = get_le16(rec + off + 2);
        const uint8_t *m = rec + off + 4;
        node_t *b;

        if (off + 4 + size > len) {
            node_style(node_add(parent, "MeasurementBlock", "truncated"), NS_ERR);
            return;
        }
        b = node_add(parent, "MeasurementBlock",
                     "Index %u%s", index,
                     index == 0xFD ? " (measurement manifest)" :
                     index == 0xFE ? " (device mode)" : "");
        node_add(b, "MeasurementSpecification", "0x%02x%s", spec, spec & 1 ? " (DMTF)" : "");
        node_add(b, "MeasurementSize", "%u", size);
        if ((spec & 1) && size >= 3) {
            uint8_t vt = m[0];
            uint16_t vs = get_le16(m + 1);
            const uint8_t *v = m + 3;

            node_add(b, "ValueType", "0x%02x: %s, %s", vt, meas_type_name(vt),
                     vt & 0x80 ? "raw bit stream" : "digest");
            node_add(b, "ValueSize", "%u", vs);
            if (3u + vs > size) {
                node_style(node_add(b, "Value", "truncated"), NS_ERR);
            } else if ((vt & 0x7f) == 5 && vs >= 16) {
                node_t *dm = node_add(b, "DeviceMode", NULL);

                node_add(dm, "OperationalModeCapabilities", "0x%08x", get_le32(v));
                node_add(dm, "OperationalModeState", "0x%08x", get_le32(v + 4));
                node_add(dm, "DeviceModeCapabilities", "0x%08x", get_le32(v + 8));
                node_add(dm, "DeviceModeState", "0x%08x", get_le32(v + 12));
            } else if ((vt & 0x80) && vs >= 2 && (v[0] >> 5) >= 4 &&
                       cbor_describe(b, "Value", v, vs)) {
                /* CBOR manifest (e.g. signed EAT); keep the raw bytes as well */
                node_add_hex(b, "RawValue", v, vs);
            } else if ((vt & 0x80) && is_printable(v, vs)) {
                node_style(node_add(b, "Value", "\"%.*s\"", (int)vs, v), NS_HILITE);
            } else if ((vt & 0x7f) == 7 && (vt & 0x80) && vs <= 8) {
                uint64_t svn = 0;
                int k;

                for (k = vs - 1; k >= 0; k--)
                    svn = (svn << 8) | v[k];
                node_style(node_add(b, "Value", "SVN %llu", (unsigned long long)svn), NS_HILITE);
            } else {
                node_add_hex(b, "Value", v, vs);
            }
        } else {
            node_add_hex(b, "Measurement", m, size);
        }
        off += 4 + size;
    }
}

/* ------------------------------------------------------ per-message */

static void dec_capabilities(void *ctx, rd_t *r, uint8_t ver, bool req)
{
    bool ok = true;
    uint8_t ct;
    uint16_t ext;
    uint32_t flags;

    if (ver < 0x11 && req)
        return;
    take8(r, &ok);
    ct = take8(r, &ok);
    ext = take16(r, &ok);
    flags = take32(r, &ok);
    if (!ok)
        return;
    node_add(r->n, "CTExponent", "%u (crypto timeout %llu us)", ct, 1ULL << ct);
    if (ext)
        node_add(r->n, "ExtFlags", "0x%04x", ext);
    decode_caps(r->n, "Flags", flags, req);
    if (ver >= 0x12) {
        uint32_t dts = take32(r, &ok), mms = take32(r, &ok);

        if (!ok)
            return;
        node_add(r->n, "DataTransferSize", "%u", dts);
        node_add(r->n, "MaxSPDMmsgSize", "%u", mms);
    }
}

static void dec_alg_structs(rd_t *r, unsigned count, bool req)
{
    unsigned i;

    for (i = 0; i < count; i++) {
        bool ok = true;
        /* AlgCount: bits 7:4 = FixedAlgCount (bytes of AlgSupported, 2), 3:0 = ExtAlgCount */
        uint8_t type = take8(r, &ok), cnt = take8(r, &ok);
        unsigned fixed = cnt >> 4, ext = cnt & 0xf;
        const uint8_t *sp;
        uint32_t sup = 0;
        const char *(*fn)(uint32_t) = NULL;
        const char *key = "AlgStruct";
        unsigned k;

        if (!ok || fixed > 4 || !(sp = take(r, fixed)))
            return;
        for (k = 0; k < fixed; k++)
            sup |= (uint32_t)sp[k] << (8 * k);
        switch (type) {
        case 2: key = req ? "DHE (supported)" : "DHE (selected)"; fn = dhe_name; break;
        case 3: key = req ? "AEAD (supported)" : "AEAD (selected)"; fn = aead_name; break;
        case 4: key = req ? "ReqBaseAsymAlg (supported)" : "ReqBaseAsymAlg (selected)"; fn = asym_name; break;
        case 5: key = req ? "KeySchedule (supported)" : "KeySchedule (selected)"; fn = keysched_name; break;
        case 6: key = req ? "ReqPqcAsymAlg (supported)" : "ReqPqcAsymAlg (selected)"; fn = pqc_name; break;
        case 7: key = req ? "KEM (supported)" : "KEM (selected)"; fn = kem_name; break;
        }
        if (fn)
            add_algo(r->n, key, sup, fn);
        else
            node_add(r->n, key, "type %u, value 0x%04x", type, sup);
        if (ext)
            take_hex(r, "AlgExternal", 4u * ext);
    }
}

static void dec_negotiate_algorithms(rd_t *r, uint8_t ver, uint8_t p1)
{
    bool ok = true;
    uint16_t length = take16(r, &ok);
    uint8_t ms = take8(r, &ok), other = take8(r, &ok);
    uint32_t asym = take32(r, &ok), hash = take32(r, &ok), pqc = take32(r, &ok);
    uint8_t ext_asym, ext_hash, mel;

    take(r, 8);
    ext_asym = take8(r, &ok);
    ext_hash = take8(r, &ok);
    take8(r, &ok);
    mel = take8(r, &ok);
    if (!ok)
        return;
    node_add(r->n, "Length", "%u", length);
    node_add(r->n, "MeasurementSpecification", "0x%02x%s", ms, ms & 1 ? " (DMTF)" : "");
    if (ver >= 0x12)
        node_add(r->n, "OtherParamsSupport", "0x%02x (opaque format %s%s)", other,
                 other & 2 ? "1" : other & 1 ? "0" : "none", other & 0x10 ? ", multi-key" : "");
    add_algo(r->n, "BaseAsymAlgo (supported)", asym, asym_name);
    add_algo(r->n, "BaseHashAlgo (supported)", hash, hash_name);
    if (ver >= 0x14 && pqc)
        add_algo(r->n, "PqcAsymAlgo (supported)", pqc, pqc_name);
    if (ver >= 0x13)
        node_add(r->n, "MELSpecification", "0x%02x%s", mel, mel & 1 ? " (DMTF)" : "");
    take_hex(r, "ExtAsym", 4u * ext_asym);
    take_hex(r, "ExtHash", 4u * ext_hash);
    if (ver >= 0x11)
        dec_alg_structs(r, p1, true);
}

static void dec_algorithms(rd_t *r, uint8_t ver, uint8_t p1)
{
    bool ok = true;
    uint16_t length = take16(r, &ok);
    uint8_t ms = take8(r, &ok), other = take8(r, &ok);
    uint32_t mh = take32(r, &ok), asym = take32(r, &ok), hash = take32(r, &ok);
    uint32_t pqc = take32(r, &ok);
    uint8_t mel, ext_asym, ext_hash;

    take(r, 7);
    mel = take8(r, &ok);
    ext_asym = take8(r, &ok);
    ext_hash = take8(r, &ok);
    take16(r, &ok);
    if (!ok)
        return;
    node_add(r->n, "Length", "%u", length);
    node_add(r->n, "MeasurementSpecificationSel", "0x%02x%s", ms, ms & 1 ? " (DMTF)" : "");
    if (ver >= 0x12)
        node_add(r->n, "OtherParamsSelection", "0x%02x (opaque format %s%s)", other,
                 other & 2 ? "1" : other & 1 ? "0" : "none", other & 0x10 ? ", multi-key" : "");
    add_algo(r->n, "MeasurementHashAlgo", mh, meas_hash_name);
    add_algo(r->n, "BaseAsymSel", asym, asym_name);
    add_algo(r->n, "BaseHashSel", hash, hash_name);
    if (ver >= 0x14 && pqc)
        add_algo(r->n, "PqcAsymSel", pqc, pqc_name);
    if (ver >= 0x13)
        node_add(r->n, "MELSpecificationSel", "0x%02x%s", mel, mel & 1 ? " (DMTF)" : "");
    take_hex(r, "ExtAsymSel", 4u * ext_asym);
    take_hex(r, "ExtHashSel", 4u * ext_hash);
    if (ver >= 0x11)
        dec_alg_structs(r, p1, false);
}

static void dec_digests(void *ctx, rd_t *r, uint8_t ver, uint8_t p1, uint8_t p2)
{
    uint32_t hs = neg_hash_size(ctx);
    int slot;

    if (ver >= 0x13)
        node_add(r->n, "SupportedSlotMask", "0x%02x", p1);
    node_add(r->n, "ProvisionedSlotMask", "0x%02x", p2);
    if (!hs)
        return;
    for (slot = 0; slot < 8; slot++) {
        char key[32];

        if (!(p2 & (1 << slot)))
            continue;
        snprintf(key, sizeof(key), "Digest[slot %d]", slot);
        if (!take_hex(r, key, hs))
            return;
    }
    if (r->off < r->len)
        take_hex(r, "KeyPairID/CertInfo/KeyUsageMask", r->len - r->off);
}

static void dec_challenge_auth(void *ctx, rd_t *r, uint8_t ver, uint8_t p1, uint8_t p2)
{
    uint32_t hs = neg_hash_size(ctx);
    bool ok = true;
    uint16_t olen;
    const uint8_t *op;

    node_add(r->n, "SlotID", "%u", p1 & 0xf);
    if (ver < 0x12 && (p1 & 0x80))
        node_add(r->n, "BasicMutAuthReq", "set");
    node_add(r->n, "SlotMask", "0x%02x", p2);
    take_hex(r, "CertChainHash", hs);
    take_hex(r, "Nonce", 32);
    take_hex(r, "MeasurementSummaryHash", meas_summary_size(ctx, g_req.chal_hash_type));
    olen = take16(r, &ok);
    if (!ok)
        return;
    op = take(r, olen);
    if (op)
        decode_opaque(r->n, op, olen, ver);
    if (ver >= 0x13)
        take_hex(r, "RequesterContext", 8);
    take_hex(r, "Signature", neg_sig_size(ctx));
}

static void dec_get_measurements(rd_t *r, uint8_t ver, uint8_t p1, uint8_t p2)
{
    node_t *a = node_add(r->n, "Attributes", "0x%02x", p1);

    if (p1 & 1)
        node_add(a, "SignatureRequested", "yes");
    if (p1 & 2)
        node_add(a, "RawBitStreamRequested", "yes");
    if (p1 & 4)
        node_add(a, "NewMeasurementRequested", "yes");
    if (p2 == 0)
        node_add(r->n, "Operation", "0x00 (query total number of measurement indices)");
    else if (p2 == 0xff)
        node_add(r->n, "Operation", "0xFF (all measurement blocks)");
    else
        node_add(r->n, "Operation", "0x%02x (measurement index %u)", p2, p2);
    if (p1 & 1) {
        bool ok = true;

        take_hex(r, "Nonce", 32);
        if (ver >= 0x11) {
            uint8_t s = take8(r, &ok);

            if (ok)
                node_add(r->n, "SlotIDParam", "%u", s & 0xf);
        }
    }
    if (ver >= 0x13)
        take_hex(r, "RequesterContext", 8);
}

static void dec_measurements(void *ctx, rd_t *r, uint8_t ver, uint8_t p1, uint8_t p2)
{
    bool ok = true;
    uint8_t nblocks;
    const uint8_t *lenp, *rec;
    uint32_t rlen;
    uint16_t olen;
    const uint8_t *op;
    node_t *rn;

    if (g_req.meas_op == 0)
        node_style(node_add(r->n, "TotalMeasurementIndices", "%u", p1), NS_HILITE);
    node_add(r->n, "SlotID", "%u", p2 & 0xf);
    if (ver >= 0x12)
        node_add(r->n, "ContentChanged", "%s",
                 (p2 >> 4 & 3) == 0 ? "not supported" :
                 (p2 >> 4 & 3) == 1 ? "changed during transcript" : "no change");
    nblocks = take8(r, &ok);
    lenp = take(r, 3);
    if (!ok || !lenp)
        return;
    rlen = get_le24(lenp);
    node_add(r->n, "NumberOfBlocks", "%u", nblocks);
    node_add(r->n, "MeasurementRecordLength", "%u", rlen);
    rec = take(r, rlen);
    if (!rec)
        return;
    rn = node_add(r->n, "MeasurementRecord", NULL);
    decode_meas_record(rn, rec, rlen, nblocks);
    take_hex(r, "Nonce", 32);
    olen = take16(r, &ok);
    if (!ok)
        return;
    op = take(r, olen);
    if (op)
        decode_opaque(r->n, op, olen, ver);
    if (ver >= 0x13)
        take_hex(r, "RequesterContext", 8);
    if (g_req.meas_attr & 1)
        take_hex(r, "Signature", neg_sig_size(ctx));
}

static void dec_key_exchange(void *ctx, rd_t *r, uint8_t ver, uint8_t p1, uint8_t p2)
{
    bool ok = true;
    uint16_t sid, olen;
    uint8_t policy;
    const uint8_t *op;

    node_add(r->n, "MeasurementSummaryHashType", "%s",
             p1 == 0 ? "none" : p1 == 1 ? "TCB components" : p1 == 0xff ? "all measurements" : "?");
    node_add(r->n, "SlotID", "%u", p2);
    sid = take16(r, &ok);
    policy = take8(r, &ok);
    take8(r, &ok);
    if (!ok)
        return;
    node_add(r->n, "ReqSessionID", "0x%04x", sid);
    if (ver >= 0x12)
        node_add(r->n, "SessionPolicy", "0x%02x%s", policy,
                 policy & 1 ? " (TerminationPolicy: keep on runtime update)" : "");
    take_hex(r, "RandomData", 32);
    take_hex(r, "ExchangeData (DHE public key)", neg_dhe_size(ctx));
    olen = take16(r, &ok);
    if (!ok)
        return;
    op = take(r, olen);
    if (op)
        decode_opaque(r->n, op, olen, ver);
}

static void dec_key_exchange_rsp(void *ctx, rd_t *r, uint8_t ver, uint8_t p1)
{
    bool ok = true;
    uint32_t hs = neg_hash_size(ctx);
    uint16_t sid, olen;
    uint8_t mut, slot;
    const uint8_t *op;

    node_add(r->n, "HeartbeatPeriod", "%u s%s", p1, p1 ? "" : " (heartbeat disabled)");
    sid = take16(r, &ok);
    mut = take8(r, &ok);
    slot = take8(r, &ok);
    if (!ok)
        return;
    node_add(r->n, "RspSessionID", "0x%04x", sid);
    node_add(r->n, "MutAuthRequested", "0x%02x%s", mut,
             mut == 0 ? " (no mutual auth)" : mut & 2 ? " (with ENCAP_REQUEST)" :
             mut & 4 ? " (with GET_DIGESTS)" : " (mutual auth)");
    if (mut)
        node_add(r->n, "ReqSlotIDParam", "%u", slot & 0xf);
    take_hex(r, "RandomData", 32);
    take_hex(r, "ExchangeData (DHE public key)", neg_dhe_size(ctx));
    take_hex(r, "MeasurementSummaryHash", meas_summary_size(ctx, g_req.kex_hash_type));
    olen = take16(r, &ok);
    if (!ok)
        return;
    op = take(r, olen);
    if (op)
        decode_opaque(r->n, op, olen, ver);
    take_hex(r, "Signature", neg_sig_size(ctx));
    if (!handshake_in_clear(ctx))
        take_hex(r, "ResponderVerifyData (HMAC)", hs);
}

static void dec_error(rd_t *r, uint8_t p1, uint8_t p2)
{
    node_t *n = node_add(r->n, "ErrorCode", "0x%02x %s", p1, spdm_error_name(p1));

    node_style(n, NS_ERR);
    node_add(r->n, "ErrorData", "0x%02x", p2);
    if (p1 == 0x42 && r->len - r->off >= 4) {
        const uint8_t *e = take(r, 4);
        node_t *x = node_add(r->n, "ResponseNotReady", NULL);

        node_add(x, "RDTExponent", "%u (%llu us)", e[0], 1ULL << e[0]);
        node_add(x, "RequestCode", "0x%02x %s", e[1], spdm_code_name(e[1]));
        node_add(x, "Token", "0x%02x", e[2]);
        node_add(x, "RDTM", "%u", e[3]);
    } else if (p1 == 0x0F && r->len - r->off >= 1) {
        node_add(r->n, "LargeResponseHandle", "0x%02x", r->p[r->off]);
        r->off++;
    }
    if (r->off < r->len)
        take_hex(r, "ExtendedErrorData", r->len - r->off);
}

static void dec_vendor(rd_t *r)
{
    bool ok = true;
    uint16_t std = take16(r, &ok);
    uint8_t vlen = take8(r, &ok);
    uint16_t plen;

    if (!ok)
        return;
    node_add(r->n, "StandardID", "0x%04x", std);
    take_hex(r, "VendorID", vlen);
    plen = take16(r, &ok);
    if (!ok)
        return;
    node_add(r->n, "PayloadLength", "%u", plen);
    take_hex(r, "Payload", plen);
}

/* OpaqueDataLength (2) + OpaqueData */
static void dec_opaque_field(rd_t *r, uint8_t ver)
{
    bool ok = true;
    uint16_t olen = take16(r, &ok);
    const uint8_t *op;

    if (!ok)
        return;
    node_add(r->n, "OpaqueDataLength", "%u", olen);
    op = take(r, olen);
    if (op)
        decode_opaque(r->n, op, olen, ver);
}

node_t *spdm_decode(void *ctx, bool is_request, const uint8_t *msg, size_t len)
{
    node_t *root = node_new("SPDM", NULL);
    rd_t r = { .p = msg, .len = len, .off = 4, .n = root };
    const struct code_name *cn;
    uint8_t ver, code, p1, p2;

    if (len < 4) {
        node_style(node_add(root, "TRUNCATED", "message shorter than SPDM header"), NS_ERR);
        return root;
    }
    ver = msg[0];
    code = msg[1];
    p1 = msg[2];
    p2 = msg[3];
    cn = find_code(code);
    {
        node_t *h = node_add(root, "Header", "SPDMVersion %u.%u, %s (0x%02x), Param1 0x%02x, Param2 0x%02x",
                             ver >> 4, ver & 0xf, cn ? cn->name : "UNKNOWN", code, p1, p2);

        if (cn)
            node_add(h, "Description", "%s", cn->desc);
    }

    switch (code) {
    case SPDM_GET_VERSION:
        break;
    case SPDM_VERSION: {
        bool ok = true;
        uint8_t cnt;

        take8(&r, &ok);
        cnt = take8(&r, &ok);
        if (!ok)
            break;
        node_add(root, "VersionNumberEntryCount", "%u", cnt);
        if (take(&r, cnt * 2u))
            decode_versions(root, msg + 6, cnt);
        break;
    }
    case SPDM_GET_CAPABILITIES:
        dec_capabilities(ctx, &r, ver, true);
        break;
    case SPDM_CAPABILITIES:
        dec_capabilities(ctx, &r, ver, false);
        break;
    case SPDM_NEGOTIATE_ALGORITHMS:
        dec_negotiate_algorithms(&r, ver, p1);
        break;
    case SPDM_ALGORITHMS:
        dec_algorithms(&r, ver, p1);
        break;
    case SPDM_GET_DIGESTS:
        break;
    case SPDM_DIGESTS:
        dec_digests(ctx, &r, ver, p1, p2);
        break;
    case SPDM_GET_CERTIFICATE: {
        bool ok = true;
        uint16_t off = take16(&r, &ok), l = take16(&r, &ok);

        node_add(root, "SlotID", "%u", p1 & 0xf);
        if (ver >= 0x13 && (p2 & 1))
            node_add(root, "SlotSizeRequested", "yes");
        if (ok) {
            node_add(root, "Offset", "%u", off);
            node_add(root, "Length", "%u", l);
        }
        break;
    }
    case SPDM_CERTIFICATE: {
        bool ok = true;
        uint16_t portion = take16(&r, &ok), rem = take16(&r, &ok);

        node_add(root, "SlotID", "%u", p1 & 0xf);
        if (ver >= 0x13)
            node_add(root, "CertModel", "%u (%s)", p2 & 7,
                     (p2 & 7) == 1 ? "DeviceCert" : (p2 & 7) == 2 ? "AliasCert" :
                     (p2 & 7) == 3 ? "GenericCert" : "none");
        if (!ok)
            break;
        node_add(root, "PortionLength", "%u", portion);
        node_add(root, "RemainderLength", "%u", rem);
        take_hex(&r, "CertChainPortion", portion);
        break;
    }
    case SPDM_CHALLENGE:
        node_add(root, "SlotID", "%u%s", p1, p1 == 0xff ? " (public key provisioned)" : "");
        node_add(root, "MeasurementSummaryHashType", "%s",
                 p2 == 0 ? "none" : p2 == 1 ? "TCB components" : p2 == 0xff ? "all measurements" : "?");
        take_hex(&r, "Nonce", 32);
        if (ver >= 0x13)
            take_hex(&r, "RequesterContext", 8);
        break;
    case SPDM_CHALLENGE_AUTH:
        dec_challenge_auth(ctx, &r, ver, p1, p2);
        break;
    case SPDM_GET_MEASUREMENTS:
        dec_get_measurements(&r, ver, p1, p2);
        break;
    case SPDM_MEASUREMENTS:
        dec_measurements(ctx, &r, ver, p1, p2);
        break;
    case SPDM_KEY_EXCHANGE:
        dec_key_exchange(ctx, &r, ver, p1, p2);
        break;
    case SPDM_KEY_EXCHANGE_RSP:
        dec_key_exchange_rsp(ctx, &r, ver, p1);
        break;
    case SPDM_FINISH:
        node_add(root, "SignatureIncluded", "%s", p1 & 1 ? "yes (mutual auth)" : "no");
        if (ver >= 0x14)
            dec_opaque_field(&r, ver);
        if (p1 & 1)
            take_hex(&r, "Signature", neg_sig_size(ctx));
        take_hex(&r, "RequesterVerifyData (HMAC)", neg_hash_size(ctx));
        break;
    case SPDM_FINISH_RSP:
        if (ver >= 0x14)
            dec_opaque_field(&r, ver);
        if (r.off < r.len)
            take_hex(&r, "ResponderVerifyData (HMAC)", r.len - r.off);
        break;
    case SPDM_HEARTBEAT:
    case SPDM_HEARTBEAT_ACK:
        break;
    case SPDM_KEY_UPDATE:
    case SPDM_KEY_UPDATE_ACK:
        node_add(root, "KeyOperation", "%s",
                 p1 == 1 ? "UpdateKey" : p1 == 2 ? "UpdateAllKeys" : p1 == 3 ? "VerifyNewKey" : "?");
        node_add(root, "Tag", "0x%02x", p2);
        break;
    case SPDM_END_SESSION:
        node_add(root, "NegotiatedStateClearing", "%s",
                 p1 & 1 ? "preserve negotiated state" : "clear negotiated state");
        break;
    case SPDM_END_SESSION_ACK:
        break;
    case SPDM_ERROR:
        dec_error(&r, p1, p2);
        break;
    case SPDM_RESPOND_IF_READY:
        node_add(root, "RequestCode", "0x%02x %s", p1, spdm_code_name(p1));
        node_add(root, "Token", "0x%02x", p2);
        break;
    case SPDM_CHUNK_GET: {
        bool ok = true;
        uint32_t seq = ver >= 0x14 ? take32(&r, &ok) : take16(&r, &ok);

        node_add(root, "Handle", "0x%02x", p2);
        if (ok)
            node_add(root, "ChunkSeqNo", "%u", seq);
        break;
    }
    case SPDM_CHUNK_RESPONSE: {
        bool ok = true;
        uint32_t seq, csize;

        if (ver >= 0x14) {
            seq = take32(&r, &ok);
        } else {
            seq = take16(&r, &ok);
            take16(&r, &ok);
        }
        csize = take32(&r, &ok);
        node_add(root, "LastChunk", "%s", p1 & 1 ? "yes" : "no");
        node_add(root, "Handle", "0x%02x", p2);
        if (!ok)
            break;
        node_add(root, "ChunkSeqNo", "%u", seq);
        node_add(root, "ChunkSize", "%u", csize);
        if (seq == 0) {
            uint32_t total = take32(&r, &ok);

            if (ok)
                node_add(root, "LargeMessageSize", "%u", total);
        }
        take_hex(&r, "Chunk", csize);
        break;
    }
    case SPDM_VENDOR_DEFINED_REQUEST:
    case SPDM_VENDOR_DEFINED_RESPONSE:
        dec_vendor(&r);
        break;
    default:
        if (r.off < r.len)
            take_hex(&r, "Payload", r.len - r.off);
        break;
    }

    if (!r.trunc && r.off < r.len && code != SPDM_ERROR)
        node_style(node_add_hex(root, "TrailingBytes", msg + r.off, r.len - r.off), NS_WARN);

    if (is_request) {
        g_req.req_code = code;
        if (code == SPDM_GET_MEASUREMENTS) {
            g_req.meas_attr = p1;
            g_req.meas_op = p2;
        } else if (code == SPDM_CHALLENGE) {
            g_req.chal_hash_type = p2;
        } else if (code == SPDM_KEY_EXCHANGE) {
            g_req.kex_hash_type = p1;
        } else if (code == SPDM_FINISH) {
            g_req.finish_sig = p1;
        }
    }
    return root;
}

/* Last plaintext message seen per request/response code. */
static struct last_msg {
    uint8_t *data;
    size_t len;
} g_last[256], g_last_req[256];

const uint8_t *decode_last_response(uint8_t code, size_t *len)
{
    *len = g_last[code].len;
    return g_last[code].data;
}

const uint8_t *decode_last_request(uint8_t code, size_t *len)
{
    *len = g_last_req[code].len;
    return g_last_req[code].data;
}

void decode_and_report(void *ctx, bool tx, const uint32_t *session_id, const void *msg,
                       size_t len)
{
    const uint8_t *m = msg;
    node_t *tree;
    char name[64];

    if (len >= 2) {
        struct last_msg *slot = tx ? &g_last_req[m[1]] : &g_last[m[1]];
        uint8_t *copy = malloc(len);

        if (copy) {
            memcpy(copy, m, len);
            free(slot->data);
            slot->data = copy;
            slot->len = len;
        }
    }

    /* The request bookkeeping must happen even when nothing is printed. */
    tree = spdm_decode(ctx, tx, m, len);
    if (len >= 4 && m[1] == SPDM_ERROR)
        snprintf(name, sizeof(name), "ERROR(%s)", spdm_error_name(m[2]));
    else
        snprintf(name, sizeof(name), "%s", len >= 2 ? spdm_code_name(m[1]) : "?");
    /* Skip the root wrapper: report its children. */
    out_msg(tx, session_id, name, len ? m[0] : 0, msg, len, tree->child);
    node_free(tree);
}
