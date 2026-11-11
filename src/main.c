/*
 * spdm-req-tool: SPDM requester front-end for libspdm over Linux AF_MCTP.
 */
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "library/spdm_requester_lib.h"
#include "library/spdm_crypt_lib.h"

#include "cert.h"
#include "decode.h"
#include "eat.h"
#include "output.h"
#include "spdm_glue.h"
#include "util.h"

#define CERT_CHAIN_MAX 0x10000
#define MEAS_RECORD_MAX 0x10000

struct tool {
    spdm_app_t app;
    struct spdm_opts sopts;

    /* command options */
    uint8_t slot;
    int meas_index;             /* -1: all */
    bool meas_sig;
    uint8_t meas_summary;       /* for CHALLENGE / KEY_EXCHANGE */
    const char *root_ca_files[10];
    int root_ca_count;
    const char *save_root_ca;
    const char *save_chain;
    uint32_t csr_key_id;        /* caliptra-vdm EXPORT_ATTESTED_CSR */
    struct { uint8_t addr, len; } mbx_reads[16]; /* intel-mbx DATA_READs */
    int mbx_read_count;
    int mbx_write_addr;         /* intel-mbx DATA_WRITE address, -1: none */
    uint8_t mbx_write_data[48];
    uint8_t mbx_write_len;
    bool mbx_negative;
    uint32_t mbx_seq;
    const char *cert_chain_file; /* set-cert */
    uint8_t cert_model;         /* set-cert SetCertModel */
    int key_pair_id;            /* -1: set-cert 1, key-pair-info all */
    uint8_t session_slot;       /* slot authenticating the set-cert / erase-cert session */
    bool set_cert_no_session;
    int expect_error;           /* -1: none, else the SPDM ERROR code a refusable step expects */

    /* state */
    bool connected;
    bool have_cert;
    bool digests_done;
    uint8_t digest_mask;
    uint8_t digests[8][LIBSPDM_MAX_HASH_SIZE];
    uint8_t *chain;
    size_t chain_len;
    bool chain_trusted;
    int passed, warned, failed;

    /* loop mode */
    int loop_interval;          /* seconds, 0: run once */
    int loop_count;             /* 0: until interrupted */
    bool loop_full;             /* redo VCA + certificate every round */
    int round;
    struct nonce_track {
        bool have;
        int round;
        uint8_t req[32];
        uint8_t rsp[32];
    } chal_nonce, meas_nonce, kex_random;
};

static volatile sig_atomic_t g_stop;

static void tally(struct tool *t, enum out_status st)
{
    if (st == ST_OK)
        t->passed++;
    else if (st == ST_WARN)
        t->warned++;
    else if (st == ST_FAIL)
        t->failed++;
}

/* Fresh requester nonce for this round, from libspdm's RNG. */
static void new_nonce(uint8_t nonce[32])
{
    if (!libspdm_get_random_number(32, nonce))
        memset(nonce, 0, 32);
}

/* Reports nonce freshness against the previous round; a repeated nonce means
 * a broken RNG (requester) or a possible replay (responder). */
static enum out_status check_nonces(struct tool *t, node_t *res, struct nonce_track *nt,
                                    const char *what, const uint8_t *req_sent,
                                    const uint8_t *req, const uint8_t *rsp)
{
    static const uint8_t zero[32];
    enum out_status st = ST_OK;
    node_t *n = node_add(res, "NonceFreshness", NULL);

    if (req_sent && memcmp(req_sent, req, 32)) {
        node_style(node_add(n, "Requester", "%s sent differs from the generated one", what),
                   NS_ERR);
        st = ST_FAIL;
    }
    if (!memcmp(rsp, zero, 32)) {
        node_style(node_add(n, "Responder", "all-zero %s", what), NS_ERR);
        st = ST_FAIL;
    }
    if (!nt->have) {
        node_add(n, "Status", "first round (round %d): nothing to compare yet", t->round);
    } else {
        if (!memcmp(nt->req, req, 32)) {
            node_style(node_add(n, "Requester", "REPEATED %s from round %d", what, nt->round),
                       NS_ERR);
            st = ST_FAIL;
        } else {
            node_style(node_add(n, "Requester", "fresh (differs from round %d)", nt->round), NS_OK);
        }
        if (!memcmp(nt->rsp, rsp, 32)) {
            node_style(node_add(n, "Responder",
                                "REPEATED %s from round %d (possible replay)", what, nt->round),
                       NS_ERR);
            st = ST_FAIL;
        } else {
            node_style(node_add(n, "Responder", "fresh (differs from round %d)", nt->round), NS_OK);
        }
    }
    memcpy(nt->req, req, 32);
    memcpy(nt->rsp, rsp, 32);
    nt->have = true;
    nt->round = t->round;
    return st;
}

static enum out_status worst(enum out_status a, enum out_status b)
{
    static const int rank[] = { [ST_OK] = 1, [ST_WARN] = 2, [ST_FAIL] = 3, [ST_SKIP] = 0 };

    return rank[a] >= rank[b] ? a : b;
}

#define STEP_END(t, id, st, res, ...)                     \
    do {                                                  \
        enum out_status st_ = (st);                       \
        out_step_end(id, st_, (res)->child, __VA_ARGS__);          \
        node_free(res);                                   \
        tally(t, st_);                                    \
    } while (0)

static uint32_t peer_caps(struct tool *t)
{
    return spdm_conn_u32(t->app.ctx, LIBSPDM_DATA_CAPABILITY_FLAGS);
}

static uint32_t neg_hash(struct tool *t)
{
    return spdm_conn_u32(t->app.ctx, LIBSPDM_DATA_BASE_HASH_ALGO);
}

/* ------------------------------------------------------------- version */

static int step_version(struct tool *t)
{
    libspdm_return_t st;
    node_t *res = node_new("", NULL);
    const uint8_t *v;
    size_t vlen;
    uint8_t ver;

    out_step_begin("version", "GET_VERSION - discover supported SPDM versions");
    st = libspdm_init_connection(t->app.ctx, true);
    if (LIBSPDM_STATUS_IS_ERROR(st)) {
        STEP_END(t, "version", ST_FAIL, res, "GET_VERSION failed: %s", spdm_status_str(st));
        return -1;
    }
    v = decode_last_response(SPDM_VERSION, &vlen);
    if (v && vlen >= 6) {
        node_t *n = node_add(res, "ResponderVersions", "%u entries", v[5]);

        if (vlen >= 6u + v[5] * 2u)
            decode_versions(n, v + 6, v[5]);
    }
    ver = spdm_conn_version(t->app.ctx);
    node_style(node_add(res, "NegotiatedVersion", "%u.%u", ver >> 4, ver & 0xf), NS_HILITE);
    STEP_END(t, "version", ST_OK, res, "Responder speaks SPDM %u.%u",
             ver >> 4, ver & 0xf);
    return 0;
}

/* ------------------------------------------------------------- connect */

static void add_selected_algos(struct tool *t, node_t *res)
{
    void *ctx = t->app.ctx;
    node_t *a = node_add(res, "SelectedAlgorithms", NULL);
    char *s;

#define ALGO(key, type, fn)                                       \
    do {                                                          \
        uint32_t v_ = spdm_conn_u32(ctx, type);                   \
        s = bits_to_names(v_, fn);                                \
        node_style(node_add(a, key, "%s", s), v_ ? NS_HILITE : NS_NONE); \
        free(s);                                                  \
    } while (0)
    ALGO("BaseAsymAlgo", LIBSPDM_DATA_BASE_ASYM_ALGO, asym_name);
    if (spdm_conn_version(ctx) >= 0x14)
        ALGO("PqcAsymAlgo", LIBSPDM_DATA_PQC_ASYM_ALGO, pqc_name);
    ALGO("BaseHashAlgo", LIBSPDM_DATA_BASE_HASH_ALGO, hash_name);
    ALGO("MeasurementHashAlgo", LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, meas_hash_name);
    ALGO("DHE", LIBSPDM_DATA_DHE_NAME_GROUP, dhe_name);
    if (spdm_conn_version(ctx) >= 0x14)
        ALGO("KEM", LIBSPDM_DATA_KEM_ALG, kem_name);
    ALGO("AEAD", LIBSPDM_DATA_AEAD_CIPHER_SUITE, aead_name);
    ALGO("ReqBaseAsymAlg", LIBSPDM_DATA_REQ_BASE_ASYM_ALG, asym_name);
#undef ALGO
    node_add(a, "KeySchedule", "%s",
             spdm_conn_u32(ctx, LIBSPDM_DATA_KEY_SCHEDULE) ? "SPDM" : "(none)");
    node_add(a, "MeasurementSpec", "%s",
             spdm_conn_u32(ctx, LIBSPDM_DATA_MEASUREMENT_SPEC) ? "DMTF" : "(none)");
}

static int step_connect(struct tool *t)
{
    libspdm_return_t st;
    node_t *res = node_new("", NULL);
    uint8_t ver;

    out_step_begin("connect",
                   "VCA - GET_VERSION / GET_CAPABILITIES / NEGOTIATE_ALGORITHMS");
    st = libspdm_init_connection(t->app.ctx, false);
    if (LIBSPDM_STATUS_IS_ERROR(st)) {
        STEP_END(t, "connect", ST_FAIL, res, "connection setup failed: %s", spdm_status_str(st));
        return -1;
    }
    t->connected = true;
    ver = spdm_conn_version(t->app.ctx);
    node_style(node_add(res, "SPDMVersion", "%u.%u", ver >> 4, ver & 0xf), NS_HILITE);
    node_add(res, "ResponderCTExponent", "%u",
             spdm_conn_u32(t->app.ctx, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT));
    decode_caps(res, "ResponderCapabilities", peer_caps(t), false);
    if (ver >= 0x12) {
        node_add(res, "ResponderDataTransferSize", "%u",
                 spdm_conn_u32(t->app.ctx, LIBSPDM_DATA_CAPABILITY_DATA_TRANSFER_SIZE));
        node_add(res, "ResponderMaxSPDMmsgSize", "%u",
                 spdm_conn_u32(t->app.ctx, LIBSPDM_DATA_CAPABILITY_MAX_SPDM_MSG_SIZE));
    }
    add_selected_algos(t, res);
    if (ver >= 0x13)
        node_add(res, "MultiKeyConn", "%s",
                 spdm_conn_u32(t->app.ctx, LIBSPDM_DATA_MULTI_KEY_CONN_RSP) & 0xff ?
                 "yes (KeyPairID in use)" : "no");
    STEP_END(t, "connect", ST_OK, res, "Negotiated SPDM %u.%u", ver >> 4, ver & 0xf);
    return 0;
}

static int ensure_connected(struct tool *t)
{
    return t->connected ? 0 : step_connect(t);
}

/* ------------------------------------------------------------- digests */

static int step_digests(struct tool *t)
{
    uint8_t buf[LIBSPDM_MAX_HASH_SIZE * 8];
    libspdm_return_t st;
    node_t *res;
    uint32_t hs;
    int i, n = 0;

    if (ensure_connected(t))
        return -1;
    out_step_begin("digests", "GET_DIGESTS - certificate chain digests per slot");
    res = node_new("", NULL);
    if (!(peer_caps(t) & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP)) {
        STEP_END(t, "digests", ST_SKIP, res, "responder has no CERT_CAP");
        return 0;
    }
    st = libspdm_get_digest(t->app.ctx, NULL, &t->digest_mask, buf);
    if (LIBSPDM_STATUS_IS_ERROR(st)) {
        STEP_END(t, "digests", ST_FAIL, res, "GET_DIGESTS failed: %s", spdm_status_str(st));
        return -1;
    }
    hs = libspdm_get_hash_size(neg_hash(t));
    node_add(res, "ProvisionedSlotMask", "0x%02x", t->digest_mask);
    for (i = 0; i < 8; i++) {
        char key[24];

        if (!(t->digest_mask & (1 << i)))
            continue;
        memcpy(t->digests[i], buf + n * hs, hs);
        snprintf(key, sizeof(key), "Slot%d", i);
        node_add_hex(res, key, t->digests[i], hs);
        n++;
    }
    t->digests_done = true;
    STEP_END(t, "digests", ST_OK, res, "%d certificate slot(s) provisioned", n);
    return 0;
}

/* ---------------------------------------------------------------- cert */

static int save_chain(struct tool *t, node_t *res)
{
    struct cert_list l = { 0 };
    uint32_t hs = libspdm_get_hash_size(neg_hash(t));
    const uint8_t *der;
    size_t dlen;
    int rc, i;

    if (str_ends_with(t->save_chain, ".bin")) {
        rc = write_file(t->save_chain, t->chain, t->chain_len);
    } else {
        for (i = 0; i < CERT_LIST_MAX && cert_chain_get(t->chain, t->chain_len, hs, i, &der, &dlen); i++) {
            l.der[i] = (uint8_t *)der;
            l.len[i] = dlen;
            l.count++;
        }
        rc = cert_save_pem_bundle(t->save_chain, &l);
    }
    if (rc)
        node_style(node_add(res, "SavedChain", "%s: %s", t->save_chain, strerror(-rc)), NS_ERR);
    else
        node_style(node_add(res, "SavedChain", "%s", t->save_chain), NS_OK);
    return rc;
}

static int step_cert(struct tool *t)
{
    libspdm_return_t st;
    const void *ta = NULL;
    size_t ta_len = 0;
    enum out_status status = ST_OK;
    node_t *res, *v;
    uint32_t hash_algo;
    char title[80], subj[256];

    if (ensure_connected(t))
        return -1;
    snprintf(title, sizeof(title), "GET_CERTIFICATE - certificate chain of slot %u", t->slot);
    out_step_begin("cert", title);
    res = node_new("", NULL);
    if (!(peer_caps(t) & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP)) {
        STEP_END(t, "cert", ST_SKIP, res, "responder has no CERT_CAP");
        return -1;
    }
    free(t->chain);
    t->chain = malloc(CERT_CHAIN_MAX);
    t->chain_len = CERT_CHAIN_MAX;
    st = libspdm_get_certificate_ex(t->app.ctx, NULL, t->slot, 0, &t->chain_len, t->chain,
                                    &ta, &ta_len);
    if (LIBSPDM_STATUS_IS_ERROR(st) && st != LIBSPDM_STATUS_VERIF_NO_AUTHORITY) {
        if (st == LIBSPDM_STATUS_VERIF_FAIL && t->chain_len && t->chain_len < CERT_CHAIN_MAX)
            cert_chain_describe(res, t->chain, t->chain_len, neg_hash(t));
        STEP_END(t, "cert", ST_FAIL, res, "GET_CERTIFICATE failed: %s", spdm_status_str(st));
        return -1;
    }
    t->have_cert = true;
    hash_algo = neg_hash(t);

    v = node_add(res, "Verification", NULL);
    node_style(node_add(v, "ChainIntegrity",
                        "OK (signatures, leaf certificate attributes, algorithms)"), NS_OK);
    if (t->digests_done && (t->digest_mask & (1 << t->slot))) {
        uint8_t h[LIBSPDM_MAX_HASH_SIZE];
        uint32_t hs = libspdm_get_hash_size(hash_algo);

        if (libspdm_hash_all(hash_algo, t->chain, t->chain_len, h) &&
            !memcmp(h, t->digests[t->slot], hs)) {
            node_style(node_add(v, "DigestMatch", "chain hash matches DIGESTS slot %u", t->slot),
                       NS_OK);
        } else {
            node_style(node_add(v, "DigestMatch", "chain hash does NOT match DIGESTS"), NS_ERR);
            status = ST_FAIL;
        }
    }
    if (st == LIBSPDM_STATUS_VERIF_NO_AUTHORITY) {
        node_style(node_add(v, "TrustAnchor",
                            "FAILED: chain is not anchored in any --root-ca certificate"),
                   NS_ERR);
        status = ST_FAIL;
        t->chain_trusted = false;
    } else if (ta && ta_len) {
        cert_subject(ta, ta_len, subj, sizeof(subj));
        node_style(node_add(v, "TrustAnchor", "OK: verified against root CA \"%s\"", subj), NS_OK);
        t->chain_trusted = true;
    } else {
        node_style(node_add(v, "TrustAnchor",
                            "NOT VERIFIED: no --root-ca given (use get-root-ca to obtain one)"),
                   NS_WARN);
        if (status == ST_OK)
            status = ST_WARN;
    }
    cert_chain_describe(res, t->chain, t->chain_len, hash_algo);
    if (t->save_chain)
        save_chain(t, res);
    STEP_END(t, "cert", status, res, "Retrieved %zu-byte chain with %d certificate(s)%s",
             t->chain_len, cert_chain_count(t->chain, t->chain_len, libspdm_get_hash_size(hash_algo)),
             status == ST_OK ? ", trusted" : status == ST_WARN ? ", trust not established" : "");
    return status == ST_FAIL ? -1 : 0;
}

static int ensure_cert(struct tool *t)
{
    if (t->have_cert)
        return 0;
    if (!t->digests_done && step_digests(t))
        return -1;
    return step_cert(t);
}

/* --------------------------------------------------------- get-root-ca */

static int step_get_root_ca(struct tool *t)
{
    const uint8_t *der;
    size_t dlen;
    uint32_t hs;
    node_t *res;
    char path[128];
    const char *out;
    int rc;

    if (ensure_cert(t) && !t->have_cert)
        return -1;
    out_step_begin("get-root-ca", "Extract the responder's root CA from its certificate chain");
    res = node_new("", NULL);
    hs = libspdm_get_hash_size(neg_hash(t));
    if (!cert_chain_get(t->chain, t->chain_len, hs, 0, &der, &dlen)) {
        STEP_END(t, "get-root-ca", ST_FAIL, res, "cannot parse certificate chain");
        return -1;
    }
    if (!cert_is_self_signed(der, dlen)) {
        node_add_hex(res, "RootHash", t->chain + 4, hs);
        cert_describe(res, "FirstCertificate", der, dlen);
        STEP_END(t, "get-root-ca", ST_FAIL, res,
                 "chain does not contain its root CA (first certificate is not self-signed); "
                 "obtain the root CA out of band and match it against RootHash");
        return -1;
    }
    if (t->save_root_ca) {
        out = t->save_root_ca;
    } else {
        snprintf(path, sizeof(path), "rootca-eid%u-slot%u.pem", t->sopts.eid, t->slot);
        out = path;
    }
    cert_describe(res, "RootCA", der, dlen);
    node_add_hex(res, "RootHash(chain header)", t->chain + 4, hs);
    rc = cert_save_file(out, der, dlen);
    if (rc) {
        STEP_END(t, "get-root-ca", ST_FAIL, res, "cannot write %s: %s", out, strerror(-rc));
        return -1;
    }
    node_style(node_add(res, "SavedTo", "%s", out), NS_OK);
    node_add(res, "Hint", "verify future connections with: --root-ca %s", out);
    STEP_END(t, "get-root-ca", t->chain_trusted ? ST_OK : ST_WARN, res,
             "Root CA saved to %s%s", out,
             t->chain_trusted ? "" : " (trust-on-first-use: verify its fingerprint out of band)");
    return 0;
}

/* ----------------------------------------------------------- challenge */

static const char *summary_name(uint8_t v)
{
    return v == 0 ? "none" : v == 1 ? "TCB" : "all";
}

static int step_challenge(struct tool *t)
{
    uint8_t meas_hash[LIBSPDM_MAX_HASH_SIZE], nonce_in[32], req_nonce[32], rsp_nonce[32];
    uint8_t opaque[1024];
    size_t opaque_len = sizeof(opaque);
    uint8_t slot_mask = 0, summary;
    enum out_status status;
    libspdm_return_t st;
    node_t *res;
    char title[80];

    if (ensure_connected(t))
        return -1;
    if (!(peer_caps(t) & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)) {
        out_step_begin("challenge", "CHALLENGE - authenticate the responder");
        res = node_new("", NULL);
        STEP_END(t, "challenge", ST_SKIP, res, "responder has no CHAL_CAP");
        return 0;
    }
    if (ensure_cert(t) && !t->have_cert)
        return -1;
    summary = (peer_caps(t) & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) ? t->meas_summary : 0;
    snprintf(title, sizeof(title), "CHALLENGE - authenticate responder (slot %u)", t->slot);
    out_step_begin("challenge", title);
    res = node_new("", NULL);
    new_nonce(nonce_in);
    st = libspdm_challenge_ex(t->app.ctx, NULL, t->slot, summary, meas_hash, &slot_mask,
                              nonce_in, req_nonce, rsp_nonce, opaque, &opaque_len);
    if (LIBSPDM_STATUS_IS_ERROR(st)) {
        STEP_END(t, "challenge", ST_FAIL, res, "CHALLENGE failed: %s", spdm_status_str(st));
        return -1;
    }
    node_style(node_add(res, "Signature", "VERIFIED with leaf certificate public key"), NS_OK);
    node_add(res, "SlotMask", "0x%02x", slot_mask);
    node_add_hex(res, "RequesterNonce", req_nonce, 32);
    node_add_hex(res, "ResponderNonce", rsp_nonce, 32);
    if (summary)
        node_add_hex(res, "MeasurementSummaryHash", meas_hash,
                     libspdm_get_hash_size(neg_hash(t)));
    if (opaque_len)
        decode_opaque(res, opaque, opaque_len, spdm_conn_version(t->app.ctx));
    status = check_nonces(t, res, &t->chal_nonce, "nonce", nonce_in, req_nonce, rsp_nonce);
    if (status == ST_FAIL) {
        STEP_END(t, "challenge", ST_FAIL, res, "signature verified, but the nonces are not fresh");
        return -1;
    }
    STEP_END(t, "challenge", t->chain_trusted ? ST_OK : ST_WARN, res,
             "Responder proved possession of the slot %u private key%s (summary: %s)", t->slot,
             t->chain_trusted ? "" : ", but its certificate chain is not trusted",
             summary_name(summary));
    return 0;
}

/* -------------------------------------------------------- measurements */

static int do_measurements(struct tool *t, const uint32_t *sid, const char *id)
{
    uint8_t *rec = malloc(MEAS_RECORD_MAX);
    uint32_t rec_len = MEAS_RECORD_MAX;
    uint8_t opaque[1024];
    size_t opaque_len = sizeof(opaque);
    uint8_t nonce_in[32], req_nonce[32], rsp_nonce[32];
    uint8_t changed = 0, nblocks = 0, total = 0, attr = 0, op;
    enum out_status status = ST_OK;
    uint32_t caps = peer_caps(t);
    libspdm_return_t st;
    node_t *res, *rn;
    char title[96];
    bool sig;

    sig = t->meas_sig && (caps & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG);
    op = t->meas_index < 0 ? SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS
                           : (uint8_t)t->meas_index;
    snprintf(title, sizeof(title), "GET_MEASUREMENTS - %s%s%s",
             t->meas_index < 0 ? "all blocks" : "single block", sig ? ", signed" : ", unsigned",
             sid ? " (in secure session)" : "");
    out_step_begin(id, title);
    res = node_new("", NULL);
    if (!(caps & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
        STEP_END(t, id, ST_SKIP, res, "responder has no MEAS_CAP");
        free(rec);
        return 0;
    }

    if (sig)
        attr |= SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
    rec_len = MEAS_RECORD_MAX;
    new_nonce(nonce_in);
    st = libspdm_get_measurement_ex(t->app.ctx, sid, attr, op, t->slot, &changed, &nblocks,
                                    &rec_len, rec, sig ? nonce_in : NULL, req_nonce, rsp_nonce,
                                    opaque, &opaque_len);
    if (LIBSPDM_STATUS_IS_ERROR(st)) {
        STEP_END(t, id, ST_FAIL, res, "GET_MEASUREMENTS failed: %s", spdm_status_str(st));
        free(rec);
        return -1;
    }
    if (sig)
        node_style(node_add(res, "Signature", "VERIFIED over L1/L2 transcript"), NS_OK);
    else
        node_style(node_add(res, "Signature", "not requested"), NS_WARN);
    node_add(res, "NumberOfBlocks", "%u", nblocks);
    rn = node_add(res, "Measurements", "%u bytes", rec_len);
    decode_meas_record(rn, rec, rec_len, nblocks);

    /* The number of indices is only queried for unsigned measurements: an
     * unsigned GET_MEASUREMENTS belongs to the L1/L2 transcript of the next
     * signed one, and some responders leave it out of the data they sign. */
    if (!sig) {
        rec_len = MEAS_RECORD_MAX;
        st = libspdm_get_measurement_ex(t->app.ctx, sid, 0,
                                        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
                                        t->slot, &changed, &total, &rec_len, rec, NULL, NULL,
                                        NULL, NULL, NULL);
        if (LIBSPDM_STATUS_IS_ERROR(st))
            node_style(node_add(res, "TotalMeasurementIndices", "query failed: %s",
                                spdm_status_str(st)), NS_WARN);
        else
            node_add(res, "TotalMeasurementIndices", "%u", total);
    }
    if (sig) {
        node_add_hex(res, "RequesterNonce", req_nonce, 32);
        node_add_hex(res, "ResponderNonce", rsp_nonce, 32);
        status = check_nonces(t, res, &t->meas_nonce, "nonce", nonce_in, req_nonce, rsp_nonce);
    }
    if (opaque_len)
        decode_opaque(res, opaque, opaque_len, spdm_conn_version(t->app.ctx));
    if (status == ST_FAIL) {
        STEP_END(t, id, ST_FAIL, res, "signature verified, but the nonces are not fresh");
        free(rec);
        return -1;
    }
    STEP_END(t, id, sig && !t->chain_trusted && !sid ? ST_WARN : ST_OK, res,
             "%u measurement block(s)%s", nblocks,
             sig ? (t->chain_trusted ? ", signature verified" :
                                        ", signature verified (chain not trusted)")
                 : "");
    free(rec);
    return 0;
}

static int step_meas(struct tool *t)
{
    if (ensure_connected(t))
        return -1;
    if (t->meas_sig && (peer_caps(t) & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG) &&
        ensure_cert(t) && !t->have_cert)
        return -1;
    return do_measurements(t, NULL, "meas");
}

/* ------------------------------------------------------------- session */

static int step_session(struct tool *t)
{
    uint8_t meas_hash[LIBSPDM_MAX_HASH_SIZE];
    uint32_t sid = 0, caps;
    uint8_t hb = 0, summary;
    enum out_status status = ST_OK;
    libspdm_return_t st;
    node_t *res;
    bool saved_sig;

    if (ensure_connected(t))
        return -1;
    caps = peer_caps(t);
    if (!(caps & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) || t->sopts.no_session_caps) {
        out_step_begin("session", "KEY_EXCHANGE / FINISH - establish secure session");
        res = node_new("", NULL);
        STEP_END(t, "session", ST_SKIP, res, "responder has no KEY_EX_CAP");
        return 0;
    }
    if (ensure_cert(t) && !t->have_cert)
        return -1;

    out_step_begin("session", "KEY_EXCHANGE / FINISH - establish secure session");
    res = node_new("", NULL);
    summary = (caps & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) ? t->meas_summary : 0;
    st = libspdm_start_session(t->app.ctx, false, NULL, 0, summary, t->slot, 0, &sid, &hb,
                               meas_hash);
    if (LIBSPDM_STATUS_IS_ERROR(st)) {
        STEP_END(t, "session", ST_FAIL, res, "session establishment failed: %s",
                 spdm_status_str(st));
        return -1;
    }
    node_style(node_add(res, "SessionID", "0x%08x", sid), NS_HILITE);
    node_add(res, "HeartbeatPeriod", "%u s", hb);
    node_style(node_add(res, "KEY_EXCHANGE_RSP signature", "VERIFIED"), NS_OK);
    node_style(node_add(res, "ResponderVerifyData", "VERIFIED (HMAC over TH1)"), NS_OK);
    node_add(res, "SessionKeys", "derived (handshake + data secrets)");
    if (summary)
        node_add_hex(res, "MeasurementSummaryHash", meas_hash, libspdm_get_hash_size(neg_hash(t)));
    {
        /* RandomData of KEY_EXCHANGE / KEY_EXCHANGE_RSP (offset 8, 32 bytes) */
        const uint8_t *kreq, *krsp;
        size_t lreq, lrsp;

        kreq = decode_last_request(SPDM_KEY_EXCHANGE, &lreq);
        krsp = decode_last_response(SPDM_KEY_EXCHANGE_RSP, &lrsp);
        if (kreq && krsp && lreq >= 40 && lrsp >= 40)
            status = check_nonces(t, res, &t->kex_random, "random data", NULL, kreq + 8,
                                  krsp + 8);
    }
    status = worst(status, t->chain_trusted ? ST_OK : ST_WARN);
    STEP_END(t, "session", status, res,
             "Secure session 0x%08x established%s", sid,
             status == ST_FAIL ? ", but the key exchange random data is not fresh" :
             t->chain_trusted ? "" : " (responder identity not anchored in a trusted root)");

    if (caps & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP) {
        out_step_begin("heartbeat", "HEARTBEAT - in-session keep-alive");
        res = node_new("", NULL);
        st = libspdm_heartbeat(t->app.ctx, sid);
        STEP_END(t, "heartbeat", LIBSPDM_STATUS_IS_ERROR(st) ? ST_FAIL : ST_OK, res,
                 "%s", LIBSPDM_STATUS_IS_ERROR(st) ? spdm_status_str(st) : "HEARTBEAT_ACK received");
    }
    if (caps & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP) {
        out_step_begin("key-update", "KEY_UPDATE - rotate session keys");
        res = node_new("", NULL);
        st = libspdm_key_update(t->app.ctx, sid, false);
        STEP_END(t, "key-update", LIBSPDM_STATUS_IS_ERROR(st) ? ST_FAIL : ST_OK, res,
                 "%s", LIBSPDM_STATUS_IS_ERROR(st) ? spdm_status_str(st)
                                                   : "all session keys updated and verified");
    }
    /* Measurements are confidential inside the session; no signature needed. */
    saved_sig = t->meas_sig;
    t->meas_sig = false;
    do_measurements(t, &sid, "session-meas");
    t->meas_sig = saved_sig;

    out_step_begin("end-session", "END_SESSION - terminate secure session");
    res = node_new("", NULL);
    st = libspdm_stop_session(t->app.ctx, sid, 0);
    STEP_END(t, "end-session", LIBSPDM_STATUS_IS_ERROR(st) ? ST_FAIL : ST_OK, res, "%s",
             LIBSPDM_STATUS_IS_ERROR(st) ? spdm_status_str(st) : "session closed");
    return 0;
}

/* -------------------------------------------------------- caliptra-vdm */

/* Caliptra VDM (OCP command registry): SPDM VENDOR_DEFINED_REQUEST with
 * standard id IANA and vendor id 0xA67F; the payload is
 * command_version(1) | command_code | data, and the response payload is
 * command_version | command_code | completion_code | data. */
#define CALIPTRA_VDM_STANDARD_IANA 0x0004
#define CALIPTRA_VDM_VENDOR_ID 0xA67Fu
#define CALIPTRA_VDM_VERSION 0x01
#define CALIPTRA_VDM_GET_ATTESTATION 0x05
#define CALIPTRA_VDM_EXPORT_ATTESTED_CSR 0x08
#define CALIPTRA_VDM_RSP_MAX 0x4000

static const char *caliptra_cc_str(uint8_t cc)
{
    switch (cc) {
    case 0x00: return "Success";
    case 0x01: return "GeneralError";
    case 0x02: return "InvalidParameter";
    case 0x03: return "InvalidPayloadSize";
    case 0x04: return "InsufficientResources";
    case 0x05: return "UnsupportedOperation";
    default: return "error";
    }
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* Sends one Caliptra VDM command (in session sid, or in the clear when NULL).
 * Returns the response payload after the completion code in *data / *data_len,
 * or -1 with the reason added to res. */
static int caliptra_vdm(struct tool *t, const uint32_t *sid, node_t *res, uint8_t cmd,
                        const uint8_t *data, size_t data_len, uint8_t *rsp, const uint8_t **out,
                        size_t *out_len)
{
    uint8_t req[128];
    size_t n = 0, rsp_len = CALIPTRA_VDM_RSP_MAX, plen;
    const uint8_t *p;
    libspdm_return_t st;

    if (data_len > sizeof(req) - 16)
        return -1;
    req[n++] = spdm_conn_version(t->app.ctx);
    req[n++] = SPDM_VENDOR_DEFINED_REQUEST;
    req[n++] = 0;
    req[n++] = 0;
    req[n++] = CALIPTRA_VDM_STANDARD_IANA & 0xff;
    req[n++] = CALIPTRA_VDM_STANDARD_IANA >> 8;
    req[n++] = 4;
    put_le32(req + n, CALIPTRA_VDM_VENDOR_ID);
    n += 4;
    req[n++] = (uint8_t)(data_len + 2);
    req[n++] = (uint8_t)((data_len + 2) >> 8);
    req[n++] = CALIPTRA_VDM_VERSION;
    req[n++] = cmd;
    memcpy(req + n, data, data_len);
    n += data_len;

    st = libspdm_send_receive_spdm_data(t->app.ctx, sid, req, n, rsp, &rsp_len);
    if (LIBSPDM_STATUS_IS_ERROR(st)) {
        node_style(node_add(res, "Error", "%s", spdm_status_str(st)), NS_ERR);
        return -1;
    }
    if (rsp_len >= 4 && rsp[1] == SPDM_ERROR) {
        node_style(node_add(res, "Error", "SPDM ERROR 0x%02x (data 0x%02x)", rsp[2], rsp[3]),
                   NS_ERR);
        return -1;
    }
    /* header(4) | standard_id(2) | vendor_id_len | vendor_id | rsp_len(2) | payload */
    if (rsp_len < 7 || rsp[1] != SPDM_VENDOR_DEFINED_RESPONSE ||
        rsp_len < 7u + rsp[6] + 2) {
        node_style(node_add(res, "Error", "malformed VENDOR_DEFINED_RESPONSE (%zu bytes)",
                            rsp_len), NS_ERR);
        return -1;
    }
    p = rsp + 7 + rsp[6];
    plen = (size_t)p[0] | (size_t)p[1] << 8;
    p += 2;
    if (rsp[4] != (CALIPTRA_VDM_STANDARD_IANA & 0xff) || rsp[5] != 0 || rsp[6] != 4 ||
        get_le32(rsp + 7) != CALIPTRA_VDM_VENDOR_ID || (size_t)(p - rsp) + plen > rsp_len ||
        plen < 3 || p[0] != CALIPTRA_VDM_VERSION || p[1] != cmd) {
        node_style(node_add(res, "Error", "unexpected VDM response header"), NS_ERR);
        node_add_hex(res, "Response", rsp, rsp_len < 64 ? rsp_len : 64);
        return -1;
    }
    node_add(res, "VDM response", "%zu bytes (SPDM message %zu bytes)", plen, rsp_len);
    if (p[2] != 0) {
        node_style(node_add(res, "CompletionCode", "0x%02x %s", p[2], caliptra_cc_str(p[2])),
                   NS_ERR);
        return -1;
    }
    node_style(node_add(res, "CompletionCode", "0x00 Success"), NS_OK);
    *out = p + 3;
    *out_len = plen - 3;
    return 0;
}

static bool contains(const uint8_t *hay, size_t hlen, const uint8_t *needle, size_t nlen)
{
    size_t i;

    for (i = 0; i + nlen <= hlen; i++)
        if (!memcmp(hay + i, needle, nlen))
            return true;
    return false;
}

static void vdm_step(struct tool *t, const uint32_t *sid, const char *id, const char *title,
                     uint8_t cmd, const uint8_t *data, size_t data_len, const uint8_t *nonce,
                     uint8_t *rsp)
{
    const uint8_t *out;
    size_t out_len;
    node_t *res;
    char what[96];
    enum eat_nonce eat_match = EAT_NONCE_NONE;
    bool eat = false;

    out_step_begin(id, title);
    res = node_new("", NULL);
    if (caliptra_vdm(t, sid, res, cmd, data, data_len, rsp, &out, &out_len)) {
        STEP_END(t, id, ST_FAIL, res, "no Caliptra VDM answer");
        return;
    }
    /* query: evidence_format(0) | data_len(4) | format bitmap (bit n: format n) */
    if (cmd == CALIPTRA_VDM_GET_ATTESTATION && get_le32(data) == 0) {
        uint32_t bits;

        if (out_len < 12 || get_le32(out + 4) != 4) {
            STEP_END(t, id, ST_FAIL, res, "malformed format query response (%zu bytes)", out_len);
            return;
        }
        bits = get_le32(out + 8);
        node_add(res, "SupportedFormats", "0x%08x%s%s", bits, bits & 2 ? " OCP-EAT" : "",
                 bits & 4 ? " PCR-quote" : "");
        STEP_END(t, id, bits ? ST_OK : ST_WARN, res, "evidence formats 0x%08x", bits);
        return;
    }
    if (out_len < (cmd == CALIPTRA_VDM_GET_ATTESTATION ? 8u : 4u)) {
        STEP_END(t, id, ST_FAIL, res, "response too short (%zu bytes)", out_len);
        return;
    }
    if (cmd == CALIPTRA_VDM_GET_ATTESTATION) {
        node_add(res, "EvidenceFormat", "%u", get_le32(out));
        out += 4;
        out_len -= 4;
    }
    node_add(res, "DataLength", "%u", get_le32(out));
    if (get_le32(out) != out_len - 4) {
        STEP_END(t, id, ST_FAIL, res, "data length %u, but %zu bytes came", get_le32(out),
                 out_len - 4);
        return;
    }
    if (cmd == CALIPTRA_VDM_GET_ATTESTATION)
        eat = eat_describe(res, "Evidence", out + 4, out_len - 4, nonce, nonce ? 32 : 0,
                           &eat_match);
    if (!eat)
        node_add_hex(res, "Data (first 32 bytes)", out + 4, out_len - 4 < 32 ? out_len - 4 : 32);
    snprintf(what, sizeof(what), "%zu bytes%s", out_len - 4, eat ? " OCP EAT" : "");
    if (nonce && eat_match != EAT_NONCE_NONE) {
        bool has = eat_match == EAT_NONCE_MATCH;

        STEP_END(t, id, has ? ST_OK : ST_FAIL, res, "%s%s", what,
                 has ? ", eat_nonce matches the requester nonce" :
                       ", eat_nonce differs from the requester nonce");
        return;
    }
    if (nonce) {
        bool has = contains(out + 4, out_len - 4, nonce, 32);

        node_style(node_add(res, "Nonce", has ? "found in the signed data" : "NOT found"),
                   has ? NS_OK : NS_ERR);
        STEP_END(t, id, has ? ST_OK : ST_FAIL, res, "%s%s", what,
                 has ? ", bound to the requester nonce" : ", requester nonce missing");
        return;
    }
    STEP_END(t, id, ST_OK, res, "%s", what);
}

/* Caliptra VDM commands (the MCU mailbox command set over SPDM) inside a
 * secure session. */
static int step_caliptra_vdm(struct tool *t)
{
    uint8_t req[44], nonce[32], meas_hash[LIBSPDM_MAX_HASH_SIZE], hb = 0, *rsp;
    uint32_t sid = 0, caps;
    libspdm_return_t st;
    node_t *res;

    if (ensure_connected(t))
        return -1;
    caps = peer_caps(t);
    if (ensure_cert(t) && !t->have_cert)
        return -1;
    out_step_begin("vdm-session", "KEY_EXCHANGE / FINISH - secure session for Caliptra VDM");
    res = node_new("", NULL);
    if (!(caps & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) || t->sopts.no_session_caps) {
        STEP_END(t, "vdm-session", ST_FAIL, res, "responder has no KEY_EX_CAP");
        return -1;
    }
    st = libspdm_start_session(t->app.ctx, false, NULL, 0, 0, t->slot, 0, &sid, &hb, meas_hash);
    if (LIBSPDM_STATUS_IS_ERROR(st)) {
        STEP_END(t, "vdm-session", ST_FAIL, res, "session establishment failed: %s",
                 spdm_status_str(st));
        return -1;
    }
    node_style(node_add(res, "SessionID", "0x%08x", sid), NS_HILITE);
    STEP_END(t, "vdm-session", t->chain_trusted ? ST_OK : ST_WARN, res,
             "Secure session 0x%08x established%s", sid,
             t->chain_trusted ? "" : " (responder identity not anchored in a trusted root)");

    rsp = malloc(CALIPTRA_VDM_RSP_MAX);
    if (!rsp)
        return -1;

    /* GET_ATTESTATION query: evidence_format 0 returns the supported formats */
    memset(req, 0, sizeof(req));
    put_le32(req + 4, 1);
    vdm_step(t, &sid, "vdm-attest-query", "Caliptra VDM GET_ATTESTATION - supported formats (in secure session)",
             CALIPTRA_VDM_GET_ATTESTATION, req, 44, NULL, rsp);

    /* GET_ATTESTATION: OCP EAT, ECC P-384, vendor slot, fresh nonce */
    put_le32(req, 1);
    put_le32(req + 4, 1);
    put_le32(req + 8, 0);
    new_nonce(nonce);
    memcpy(req + 12, nonce, 32);
    vdm_step(t, &sid, "vdm-attest-eat",
             "Caliptra VDM GET_ATTESTATION - OCP EAT, ECC P-384 (in secure session)",
             CALIPTRA_VDM_GET_ATTESTATION, req, 44, nonce, rsp);

    /* EXPORT_ATTESTED_CSR: device_key_id | algorithm (1: ECC P-384) | nonce */
    put_le32(req, t->csr_key_id);
    put_le32(req + 4, 1);
    new_nonce(nonce);
    memcpy(req + 8, nonce, 32);
    vdm_step(t, &sid, "vdm-csr",
             "Caliptra VDM EXPORT_ATTESTED_CSR - ECC P-384 (in secure session)",
             CALIPTRA_VDM_EXPORT_ATTESTED_CSR, req, 40, nonce, rsp);
    free(rsp);

    out_step_begin("vdm-end-session", "END_SESSION - terminate secure session");
    res = node_new("", NULL);
    st = libspdm_stop_session(t->app.ctx, sid, 0);
    STEP_END(t, "vdm-end-session", LIBSPDM_STATUS_IS_ERROR(st) ? ST_FAIL : ST_OK, res, "%s",
             LIBSPDM_STATUS_IS_ERROR(st) ? spdm_status_str(st) : "session closed");
    return 0;
}

/* ----------------------------------------------------------- intel-mbx */

/* Intel PFR mailbox (DOE) messages: MCTP vendor-defined PCI (0x7E), PCI VID
 * 0x8086 (big-endian), Cerberus INTEL_MESSAGE (0x0a); the payload is
 * seq_num(4) | command | status | address | length | data, zero-padded to a
 * multiple of 8. In a secure session they travel as application data, which
 * libspdm's MCTP transport encrypts as is, so byte 0 is the MCTP type. */
#define MCTP_TYPE_VDM_PCI 0x7E
#define INTEL_PCI_VID 0x8086
#define INTEL_MESSAGE_OP_CODE 0x0a
#define INTEL_MBX_DATA_WRITE 1
#define INTEL_MBX_DATA_READ 2
#define INTEL_MBX_DISCOVERY 3
#define INTEL_MBX_HDR 13
#define INTEL_MBX_RSP_MAX 1024
#define INTEL_MBX_BMC_CHECKPOINT 0x60

enum mbx_result { MBX_OK, MBX_SPDM_ERROR, MBX_TIMEOUT, MBX_FAIL };

static size_t mbx_build(struct tool *t, uint8_t *req, uint16_t vid, uint8_t cmd, uint8_t addr,
                        uint8_t len, const uint8_t *data, size_t data_len)
{
    size_t n = 0;

    req[n++] = MCTP_TYPE_VDM_PCI;
    req[n++] = vid >> 8;
    req[n++] = vid & 0xff;
    req[n++] = 0;
    req[n++] = INTEL_MESSAGE_OP_CODE;
    put_le32(req + n, ++t->mbx_seq);
    n += 4;
    req[n++] = cmd;
    req[n++] = 0;
    req[n++] = addr;
    req[n++] = len;
    memcpy(req + n, data, data_len);
    n += data_len;
    while ((n - 5) % 8)
        req[n++] = 0;
    return n;
}

/* Sends one message in session sid, or as a plain MCTP message when sid is
 * NULL, and returns the reply in rsp / *rsp_len (an SPDM ERROR for
 * MBX_SPDM_ERROR). */
static enum mbx_result mbx_exchange(struct tool *t, const uint32_t *sid, node_t *res,
                                    const uint8_t *req, size_t n, uint8_t *rsp, size_t *rsp_len,
                                    bool expect_timeout)
{
    enum mbx_result r = MBX_OK;
    libspdm_return_t st;
    const uint8_t *err;
    size_t elen;
    uint8_t type;
    int rc;

    t->app.quiet_timeout = expect_timeout;
    t->app.rx_timeout = false;
    if (sid) {
        decode_forget_response(SPDM_ERROR);
        st = libspdm_send_receive_data(t->app.ctx, sid, true, req, n, rsp, rsp_len);
        if (!LIBSPDM_STATUS_IS_ERROR(st))
            goto out;
        /* libspdm drops an SPDM message that answers application data, but
         * the transport tap has seen it decrypted. */
        err = decode_last_response(SPDM_ERROR, &elen);
        if (err && elen >= 4) {
            node_add(res, "Response", "SPDM ERROR 0x%02x %s (data 0x%02x), encrypted", err[2],
                     spdm_error_name(err[2]), err[3]);
            memcpy(rsp, err, elen < *rsp_len ? elen : *rsp_len);
            *rsp_len = elen < *rsp_len ? elen : *rsp_len;
            r = MBX_SPDM_ERROR;
        } else if (t->app.rx_timeout) {
            node_add(res, "Response", "none (timeout)");
            r = MBX_TIMEOUT;
        } else {
            node_style(node_add(res, "Error", "%s", spdm_status_str(st)), NS_ERR);
            r = MBX_FAIL;
        }
        goto out;
    }
    decode_app_and_report(true, NULL, req, n);
    rc = mctp_send(&t->app.mctp, req[0], req + 1, n - 1);
    out_transport(true, req[0], t->app.mctp.eid, n - 1);
    if (rc) {
        node_style(node_add(res, "Error", "MCTP send failed: %s", strerror(-rc)), NS_ERR);
        r = MBX_FAIL;
        goto out;
    }
    rc = mctp_recv(&t->app.mctp, &type, rsp + 1, *rsp_len - 1, rsp_len, t->sopts.timeout_ms);
    if (rc == -ETIMEDOUT) {
        node_add(res, "Response", "none (timeout)");
        r = MBX_TIMEOUT;
        goto out;
    }
    if (rc) {
        node_style(node_add(res, "Error", "MCTP receive failed: %s", strerror(-rc)), NS_ERR);
        r = MBX_FAIL;
        goto out;
    }
    out_transport(false, type, t->app.mctp.eid, *rsp_len);
    rsp[0] = type;
    *rsp_len += 1;
    decode_app_and_report(false, NULL, rsp, *rsp_len);
out:
    t->app.quiet_timeout = false;
    return r;
}

/* Checks a mailbox reply against its request. Returns the payload status
 * (0: OK) with the data in *data / *dlen, or -1 for a malformed reply. */
static int mbx_parse(node_t *res, const uint8_t *req, const uint8_t *rsp, size_t len,
                     const uint8_t **data, size_t *dlen)
{
    if (len < INTEL_MBX_HDR || rsp[0] != MCTP_TYPE_VDM_PCI || rsp[1] != req[1] ||
        rsp[2] != req[2] || rsp[4] != INTEL_MESSAGE_OP_CODE || rsp[9] != req[9] ||
        rsp[12] > len - INTEL_MBX_HDR) {
        node_style(node_add(res, "Error", "malformed mailbox reply (%zu bytes)", len), NS_ERR);
        node_add_hex(res, "Reply", rsp, len < 64 ? len : 64);
        return -1;
    }
    if (get_le32(rsp + 5) != get_le32(req + 5)) {
        node_style(node_add(res, "SeqNum", "%u, request had %u", get_le32(rsp + 5),
                            get_le32(req + 5)), NS_ERR);
        return -1;
    }
    if (rsp[10]) {
        node_style(node_add(res, "Status", "0x%02x%s", rsp[10], rsp[10] == 0xff ? " (fail)" : ""),
                   NS_ERR);
        return rsp[10];
    }
    node_style(node_add(res, "Status", "0x00 OK"), NS_OK);
    *data = rsp + INTEL_MBX_HDR;
    *dlen = rsp[12];
    return 0;
}

static const char *mbx_where(const uint32_t *sid)
{
    return sid ? "in secure session" : "in the clear";
}

static void mbx_fail_summary(struct tool *t, const char *id, node_t *res, enum mbx_result r,
                             const uint8_t *rsp)
{
    if (r == MBX_SPDM_ERROR)
        STEP_END(t, id, ST_FAIL, res, "SPDM ERROR %s (0x%02x)", spdm_error_name(rsp[2]), rsp[2]);
    else if (r == MBX_TIMEOUT)
        STEP_END(t, id, ST_FAIL, res, "no reply (timeout)");
    else
        STEP_END(t, id, ST_FAIL, res, "no mailbox reply");
}

/* DATA_READ of len bytes at addr. The value goes to val / *vlen (up to 48
 * bytes); with cmp it is compared with that earlier value. Returns 0 when a
 * value was read. */
static int mbx_read_step(struct tool *t, const uint32_t *sid, const char *id, uint8_t addr,
                         uint8_t len, const uint8_t *cmp, size_t cmp_len, uint8_t *val,
                         size_t *vlen)
{
    uint8_t req[INTEL_MBX_HDR + 8], rsp[INTEL_MBX_RSP_MAX];
    size_t n, rsp_len = sizeof(rsp), dlen;
    const uint8_t *data;
    enum out_status status = ST_OK;
    enum mbx_result r;
    char title[96], *h;
    node_t *res;
    int s;

    snprintf(title, sizeof(title), "Intel PFR mailbox DATA_READ 0x%02x, %u byte%s (%s)", addr,
             len, len == 1 ? "" : "s", mbx_where(sid));
    out_step_begin(id, title);
    res = node_new("", NULL);
    n = mbx_build(t, req, INTEL_PCI_VID, INTEL_MBX_DATA_READ, addr, len, NULL, 0);
    r = mbx_exchange(t, sid, res, req, n, rsp, &rsp_len, false);
    if (r != MBX_OK) {
        mbx_fail_summary(t, id, res, r, rsp);
        return -1;
    }
    s = mbx_parse(res, req, rsp, rsp_len, &data, &dlen);
    if (s) {
        if (s < 0)
            STEP_END(t, id, ST_FAIL, res, "malformed mailbox reply");
        else
            STEP_END(t, id, ST_FAIL, res, "mailbox status 0x%02x", s);
        return -1;
    }
    node_style(node_add_hex(res, "Value", data, dlen), NS_HILITE);
    if (dlen != len) {
        node_style(node_add(res, "Length", "%zu bytes, %u requested", dlen, len), NS_WARN);
        status = ST_WARN;
    }
    if (cmp) {
        bool same = cmp_len == dlen && !memcmp(cmp, data, dlen);

        node_style(node_add(res, "InTheClear", same ? "same value" : "DIFFERENT value"),
                   same ? NS_OK : NS_WARN);
        if (!same) {
            node_add_hex(res, "ClearValue", cmp, cmp_len);
            status = ST_WARN;
        }
    }
    h = hex_string(data, dlen);
    STEP_END(t, id, status, res, "0x%02x = %s%s%s", addr, h ? h : "?",
             !cmp ? "" : status == ST_OK ? ", same as in the clear" : ", differs from the clear",
             dlen != len ? " (short)" : "");
    free(h);
    if (val) {
        memcpy(val, data, dlen);
        *vlen = dlen;
    }
    return 0;
}

static void mbx_write_step(struct tool *t, const uint32_t *sid)
{
    uint8_t req[INTEL_MBX_HDR + 64], rsp[INTEL_MBX_RSP_MAX], addr = t->mbx_write_addr;
    size_t n, rsp_len = sizeof(rsp), dlen;
    const uint8_t *data;
    enum mbx_result r;
    char id[32], title[96], *h;
    node_t *res;
    int s;

    snprintf(id, sizeof(id), "mbx-write-0x%02x", addr);
    snprintf(title, sizeof(title), "Intel PFR mailbox DATA_WRITE 0x%02x (%s)", addr,
             mbx_where(sid));
    out_step_begin(id, title);
    res = node_new("", NULL);
    node_add_hex(res, "Written", t->mbx_write_data, t->mbx_write_len);
    n = mbx_build(t, req, INTEL_PCI_VID, INTEL_MBX_DATA_WRITE, addr, t->mbx_write_len,
                  t->mbx_write_data, t->mbx_write_len);
    r = mbx_exchange(t, sid, res, req, n, rsp, &rsp_len, false);
    if (r != MBX_OK) {
        mbx_fail_summary(t, id, res, r, rsp);
        return;
    }
    s = mbx_parse(res, req, rsp, rsp_len, &data, &dlen);
    h = hex_string(t->mbx_write_data, t->mbx_write_len);
    if (s < 0)
        STEP_END(t, id, ST_FAIL, res, "malformed mailbox reply");
    else if (s)
        STEP_END(t, id, ST_FAIL, res, "mailbox status 0x%02x", s);
    else
        STEP_END(t, id, ST_OK, res, "wrote %s to 0x%02x", h ? h : "?", addr);
    free(h);
    if (s)
        return;
    snprintf(id, sizeof(id), "mbx-readback-0x%02x", addr);
    mbx_read_step(t, sid, id, addr, t->mbx_write_len, NULL, 0, NULL, NULL);
}

/* A message the responder must not hand to the mailbox. want_error: an
 * encrypted SPDM ERROR with that code is expected; 0: no reply at all. */
static void mbx_negative_step(struct tool *t, const uint32_t *sid, const char *id,
                              const char *title, const uint8_t *req, size_t n, uint8_t want_error)
{
    uint8_t rsp[INTEL_MBX_RSP_MAX];
    size_t rsp_len = sizeof(rsp);
    enum mbx_result r;
    node_t *res;

    out_step_begin(id, title);
    res = node_new("", NULL);
    r = mbx_exchange(t, sid, res, req, n, rsp, &rsp_len, !want_error);
    if (want_error && r == MBX_SPDM_ERROR && rsp[2] == want_error)
        STEP_END(t, id, ST_OK, res, "SPDM ERROR %s, as expected", spdm_error_name(rsp[2]));
    else if (want_error && r == MBX_SPDM_ERROR)
        STEP_END(t, id, ST_FAIL, res, "SPDM ERROR %s (0x%02x), expected %s",
                 spdm_error_name(rsp[2]), rsp[2], spdm_error_name(want_error));
    else if (!want_error && r == MBX_TIMEOUT)
        STEP_END(t, id, ST_OK, res, "no reply, as expected");
    else if (r == MBX_OK)
        STEP_END(t, id, ST_FAIL, res, "the responder answered (%zu bytes), expected %s",
                 rsp_len, want_error ? "an SPDM ERROR" : "no reply");
    else
        STEP_END(t, id, ST_FAIL, res, "%s, expected %s",
                 r == MBX_TIMEOUT ? "no reply" : r == MBX_SPDM_ERROR ? "SPDM ERROR" : "failure",
                 want_error ? spdm_error_name(want_error) : "no reply");
}

/* Intel PFR mailbox reads in the clear, then the same reads (plus an optional
 * write and negative cases) inside a secure session. */
static int step_intel_mbx(struct tool *t)
{
    static const uint8_t pldm_get_tid[] = { 0x01, 0x80, 0x00, 0x02 };
    uint8_t clear[16][48], hb = 0, meas_hash[LIBSPDM_MAX_HASH_SIZE], req[INTEL_MBX_HDR + 8];
    size_t clear_len[16];
    bool have_clear[16];
    uint32_t sid = 0, caps;
    libspdm_return_t st;
    node_t *res;
    char id[32];
    size_t n;
    int i;

    for (i = 0; i < t->mbx_read_count; i++) {
        snprintf(id, sizeof(id), "mbx-clear-0x%02x", t->mbx_reads[i].addr);
        have_clear[i] = !mbx_read_step(t, NULL, id, t->mbx_reads[i].addr, t->mbx_reads[i].len,
                                       NULL, 0, clear[i], &clear_len[i]);
    }

    if (ensure_connected(t))
        return -1;
    caps = peer_caps(t);
    if ((caps & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) && !t->sopts.no_session_caps &&
        ensure_cert(t) && !t->have_cert)
        return -1;
    out_step_begin("mbx-session", "KEY_EXCHANGE / FINISH - secure session for the PFR mailbox");
    res = node_new("", NULL);
    if (!(caps & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) || t->sopts.no_session_caps) {
        STEP_END(t, "mbx-session", ST_FAIL, res, "responder has no KEY_EX_CAP");
        return -1;
    }
    st = libspdm_start_session(t->app.ctx, false, NULL, 0, 0, t->slot, 0, &sid, &hb, meas_hash);
    if (LIBSPDM_STATUS_IS_ERROR(st)) {
        STEP_END(t, "mbx-session", ST_FAIL, res, "session establishment failed: %s",
                 spdm_status_str(st));
        return -1;
    }
    node_style(node_add(res, "SessionID", "0x%08x", sid), NS_HILITE);
    STEP_END(t, "mbx-session", t->chain_trusted ? ST_OK : ST_WARN, res,
             "Secure session 0x%08x established%s", sid,
             t->chain_trusted ? "" : " (responder identity not anchored in a trusted root)");

    for (i = 0; i < t->mbx_read_count; i++) {
        snprintf(id, sizeof(id), "mbx-read-0x%02x", t->mbx_reads[i].addr);
        mbx_read_step(t, &sid, id, t->mbx_reads[i].addr, t->mbx_reads[i].len,
                      have_clear[i] ? clear[i] : NULL, have_clear[i] ? clear_len[i] : 0, NULL,
                      NULL);
    }

    if (t->mbx_write_addr >= 0)
        mbx_write_step(t, &sid);

    if (t->mbx_negative) {
        uint8_t addr = t->mbx_reads[0].addr, len = t->mbx_reads[0].len;

        n = mbx_build(t, req, 0x1414, INTEL_MBX_DATA_READ, addr, len, NULL, 0);
        mbx_negative_step(t, &sid, "mbx-neg-vid",
                          "MCTP 0x7E with VID 0x1414 - not Intel (in secure session)", req, n,
                          SPDM_ERROR_CODE_INVALID_REQUEST);
        n = mbx_build(t, req, INTEL_PCI_VID, INTEL_MBX_DISCOVERY, 0, 0, NULL, 0);
        mbx_negative_step(t, &sid, "mbx-neg-discovery",
                          "Intel mailbox DISCOVERY - not served (in secure session)", req, n, 0);
        mbx_read_step(t, &sid, "mbx-neg-after", addr, len, have_clear[0] ? clear[0] : NULL,
                      have_clear[0] ? clear_len[0] : 0, NULL, NULL);
        mbx_negative_step(t, &sid, "mbx-neg-pldm",
                          "PLDM GetTID as application data (in secure session)", pldm_get_tid,
                          sizeof(pldm_get_tid), SPDM_ERROR_CODE_INVALID_REQUEST);
    }

    out_step_begin("mbx-end-session", "END_SESSION - terminate secure session");
    res = node_new("", NULL);
    st = libspdm_stop_session(t->app.ctx, sid, 0);
    STEP_END(t, "mbx-end-session", LIBSPDM_STATUS_IS_ERROR(st) ? ST_FAIL : ST_OK, res, "%s",
             LIBSPDM_STATUS_IS_ERROR(st) ? spdm_status_str(st) : "session closed");
    return 0;
}

/* ------------------------------------------------------------ set-cert */

/* The SPDM ERROR answering the last request: sent directly or, for a request
 * split with CHUNK_SEND, inside the last CHUNK_SEND_ACK. */
static bool last_error(struct tool *t, uint8_t *code, uint8_t *data)
{
    size_t hdr = spdm_conn_version(t->app.ctx) >= 0x14 ? 8 : 6, len;
    const uint8_t *m;

    m = decode_last_response(SPDM_CHUNK_SEND_ACK, &len);
    if (m && len >= hdr + 4 && m[hdr + 1] == SPDM_ERROR) {
        *code = m[hdr + 2];
        *data = m[hdr + 3];
        return true;
    }
    m = decode_last_response(SPDM_ERROR, &len);
    if (m && len >= 4) {
        *code = m[2];
        *data = m[3];
        return true;
    }
    return false;
}

static void forget_errors(void)
{
    decode_forget_response(SPDM_ERROR);
    decode_forget_response(SPDM_CHUNK_SEND_ACK);
}

/* Outcome of a request the responder may refuse. Without --expect-error it
 * passes when accepted; with it, only on that SPDM ERROR. For anything but a
 * plain success the summary is written to msg. */
static enum out_status refusable_status(struct tool *t, node_t *res, libspdm_return_t st,
                                        char *msg, size_t size)
{
    bool failed = LIBSPDM_STATUS_IS_ERROR(st);
    uint8_t code = 0, data = 0;
    bool err = failed && last_error(t, &code, &data);
    const char *want = t->expect_error >= 0 ? spdm_error_name((uint8_t)t->expect_error) : NULL;

    msg[0] = 0;
    if (err)
        node_style(node_add(res, "Error", "SPDM ERROR 0x%02x %s (data 0x%02x)", code,
                            spdm_error_name(code), data),
                   code == t->expect_error ? NS_OK : NS_ERR);
    if (!want) {
        if (!failed)
            return ST_OK;
        if (err)
            snprintf(msg, size, "refused: SPDM ERROR %s (0x%02x)", spdm_error_name(code), code);
        else
            snprintf(msg, size, "failed: %s", spdm_status_str(st));
        return ST_FAIL;
    }
    if (err && code == t->expect_error) {
        snprintf(msg, size, "refused with SPDM ERROR %s (0x%02x), as expected",
                 spdm_error_name(code), code);
        return ST_OK;
    }
    if (err)
        snprintf(msg, size, "refused with SPDM ERROR %s (0x%02x), expected %s",
                 spdm_error_name(code), code, want);
    else if (failed)
        snprintf(msg, size, "failed: %s, expected SPDM ERROR %s", spdm_status_str(st), want);
    else
        snprintf(msg, size, "accepted, expected SPDM ERROR %s", want);
    return ST_FAIL;
}

/* MULTI_KEY_CONN_RSP: the responder identifies its keys by KeyPairID. */
static bool multi_key_conn(struct tool *t)
{
    return spdm_conn_version(t->app.ctx) >= 0x13 &&
           (spdm_conn_u32(t->app.ctx, LIBSPDM_DATA_MULTI_KEY_CONN_RSP) & 0xff);
}

static const char *cert_model_name(uint8_t m)
{
    return m == 0 ? "none" : m == 1 ? "DeviceCert" : m == 2 ? "AliasCert" :
           m == 3 ? "GenericCert" : "?";
}

/* KEY_EXCHANGE / FINISH authenticated with --session-slot for set-cert and
 * erase-cert. */
static int setcert_session(struct tool *t, const char *id, uint32_t *sid)
{
    uint8_t slot = t->slot, hb = 0, meas_hash[LIBSPDM_MAX_HASH_SIZE];
    libspdm_return_t st;
    node_t *res;
    char title[96];

    if (!(peer_caps(t) & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) ||
        t->sopts.no_session_caps) {
        out_step_begin(id, "KEY_EXCHANGE / FINISH - secure session for SET_CERTIFICATE");
        res = node_new("", NULL);
        STEP_END(t, id, ST_FAIL, res, "responder has no KEY_EX_CAP (use --set-cert-no-session)");
        return -1;
    }
    /* The session is authenticated with the certificate in --session-slot,
     * which may differ from the slot being written. */
    if (t->have_cert && t->slot != t->session_slot)
        t->have_cert = false;
    t->slot = t->session_slot;
    if (ensure_cert(t) && !t->have_cert) {
        t->slot = slot;
        return -1;
    }
    snprintf(title, sizeof(title),
             "KEY_EXCHANGE / FINISH - secure session for SET_CERTIFICATE (slot %u key)",
             t->session_slot);
    out_step_begin(id, title);
    res = node_new("", NULL);
    st = libspdm_start_session(t->app.ctx, false, NULL, 0, 0, t->session_slot, 0, sid, &hb,
                               meas_hash);
    t->slot = slot;
    if (LIBSPDM_STATUS_IS_ERROR(st)) {
        STEP_END(t, id, ST_FAIL, res, "session establishment failed: %s", spdm_status_str(st));
        return -1;
    }
    node_style(node_add(res, "SessionID", "0x%08x", *sid), NS_HILITE);
    STEP_END(t, id, t->chain_trusted ? ST_OK : ST_WARN, res, "Secure session 0x%08x established%s",
             *sid, t->chain_trusted ? "" : " (responder identity not anchored in a trusted root)");
    return 0;
}

static void setcert_end_session(struct tool *t, const char *id, uint32_t sid)
{
    libspdm_return_t st;
    node_t *res;

    out_step_begin(id, "END_SESSION - terminate secure session");
    res = node_new("", NULL);
    st = libspdm_stop_session(t->app.ctx, sid, 0);
    STEP_END(t, id, LIBSPDM_STATUS_IS_ERROR(st) ? ST_FAIL : ST_OK, res, "%s",
             LIBSPDM_STATUS_IS_ERROR(st) ? spdm_status_str(st) : "session closed");
}

/* SET_CERTIFICATE: writes the --cert-chain certificates (root first) to
 * --slot, or erases the slot (SPDM 1.3), inside a secure session unless
 * --set-cert-no-session. */
static int step_set_cert(struct tool *t, bool erase)
{
    const char *id = erase ? "erase-cert" : "set-cert";
    struct cert_list l = { 0 };
    uint8_t *chain = NULL, attr = 0, kp, model;
    size_t chain_len = 0;
    uint32_t sid = 0, *psid = NULL;
    enum out_status status;
    libspdm_return_t st;
    char title[112], msg[160];
    bool multi_key;
    node_t *res;
    uint8_t ver;
    int rc, i;

    if (ensure_connected(t))
        return -1;
    ver = spdm_conn_version(t->app.ctx);
    multi_key = multi_key_conn(t);
    /* KeyPairID and SetCertModel exist from SPDM 1.3 and must be 0 unless the
     * connection is multi-key. */
    kp = multi_key ? (uint8_t)(t->key_pair_id < 0 ? 1 : t->key_pair_id) : 0;
    model = multi_key && !erase ? t->cert_model : 0;

    if (!erase) {
        if (!t->cert_chain_file) {
            out_step_begin(id, "SET_CERTIFICATE - provision a certificate chain");
            res = node_new("", NULL);
            STEP_END(t, id, ST_FAIL, res, "no --cert-chain given");
            return -1;
        }
        rc = cert_load_file(t->cert_chain_file, &l);
        if (!rc)
            rc = cert_chain_build(&l, neg_hash(t), &chain, &chain_len);
        if (rc) {
            out_step_begin(id, "SET_CERTIFICATE - provision a certificate chain");
            res = node_new("", NULL);
            STEP_END(t, id, ST_FAIL, res, "cannot use %s: %s", t->cert_chain_file,
                     rc == -EINVAL ? "no PEM/DER certificate" :
                     rc == -E2BIG ? "chain longer than 65535 bytes" : strerror(-rc));
            cert_list_free(&l);
            return -1;
        }
    } else if (ver < 0x13) {
        out_step_begin(id, "SET_CERTIFICATE (Erase) - erase a certificate slot");
        res = node_new("", NULL);
        STEP_END(t, id, ST_FAIL, res, "Erase needs SPDM 1.3 or later (negotiated %u.%u)",
                 ver >> 4, ver & 0xf);
        return -1;
    }

    if (!t->set_cert_no_session) {
        if (setcert_session(t, erase ? "erase-cert-session" : "set-cert-session", &sid)) {
            free(chain);
            cert_list_free(&l);
            return -1;
        }
        psid = &sid;
    }

    snprintf(title, sizeof(title), "SET_CERTIFICATE%s - %s slot %u (%s)",
             erase ? " (Erase)" : "", erase ? "erase" : "write", t->slot,
             psid ? "in secure session" : "in the clear");
    out_step_begin(id, title);
    res = node_new("", NULL);
    node_add(res, "SlotID", "%u", t->slot);
    if (ver >= 0x13) {
        node_add(res, "KeyPairID", "%u%s", kp, multi_key ? "" : " (not a multi-key connection)");
        if (!erase)
            node_add(res, "SetCertModel", "%u (%s)", model, cert_model_name(model));
    }
    if (!erase) {
        node_t *c = node_add(res, "CertChain", "%zu bytes, %d certificate(s) from %s", chain_len,
                             l.count, t->cert_chain_file);
        uint32_t limit = spdm_conn_u32(t->app.ctx, LIBSPDM_DATA_CAPABILITY_DATA_TRANSFER_SIZE);

        node_add_hex(c, "RootHash", chain + 4, libspdm_get_hash_size(neg_hash(t)));
        for (i = 0; i < l.count; i++) {
            char key[24], subj[256];

            snprintf(key, sizeof(key), "Cert%d", i);
            cert_subject(l.der[i], l.len[i], subj, sizeof(subj));
            node_add(c, key, "%s (%zu bytes)", subj, l.len[i]);
        }
        if (limit && 4 + chain_len > limit)
            node_add(res, "Transfer", "CHUNK_SEND (request %zu bytes > DataTransferSize %u)",
                     4 + chain_len, limit);
    }
    if (erase)
        attr = SPDM_SET_CERTIFICATE_REQUEST_ATTRIBUTES_ERASE;
    else
        attr = (uint8_t)(model << SPDM_SET_CERTIFICATE_REQUEST_ATTRIBUTES_CERT_MODEL_OFFSET);
    forget_errors();
    st = libspdm_set_certificate_ex(t->app.ctx, psid, t->slot, erase ? NULL : chain,
                                    erase ? 0 : chain_len, ver >= 0x13 ? attr : 0, kp);
    status = refusable_status(t, res, st, msg, sizeof(msg));
    if (msg[0])
        STEP_END(t, id, status, res, "%s", msg);
    else
        STEP_END(t, id, status, res, "slot %u %s", t->slot,
                 erase ? "erased" : "written (SET_CERTIFICATE_RSP)");
    if (!LIBSPDM_STATUS_IS_ERROR(st)) {
        /* the slot changed: later digests / cert / challenge refetch */
        t->digests_done = false;
        t->have_cert = false;
    }
    free(chain);
    cert_list_free(&l);
    if (psid)
        setcert_end_session(t, erase ? "erase-cert-end-session" : "set-cert-end-session", sid);
    return status == ST_FAIL ? -1 : 0;
}

/* ------------------------------------------------------- key-pair-info */

static const char *key_pair_cap_name(uint32_t bit)
{
    switch (bit) {
    case SPDM_KEY_PAIR_CAP_GEN_KEY_CAP: return "GenKeyCap";
    case SPDM_KEY_PAIR_CAP_ERASABLE_CAP: return "ErasableCap";
    case SPDM_KEY_PAIR_CAP_CERT_ASSOC_CAP: return "CertAssocCap";
    case SPDM_KEY_PAIR_CAP_KEY_USAGE_CAP: return "KeyUsageCap";
    case SPDM_KEY_PAIR_CAP_ASYM_ALGO_CAP: return "AsymAlgoCap";
    case SPDM_KEY_PAIR_CAP_SHAREABLE_CAP: return "ShareableCap";
    default: return NULL;
    }
}

static const char *key_usage_name(uint32_t bit)
{
    switch (bit) {
    case SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE: return "KeyExUse";
    case SPDM_KEY_USAGE_BIT_MASK_CHALLENGE_USE: return "ChallengeUse";
    case SPDM_KEY_USAGE_BIT_MASK_MEASUREMENT_USE: return "MeasurementUse";
    case SPDM_KEY_USAGE_BIT_MASK_ENDPOINT_INFO_USE: return "EndpointInfoUse";
    case SPDM_KEY_USAGE_BIT_MASK_STANDARDS_KEY_USE: return "StandardsKeyUse";
    case SPDM_KEY_USAGE_BIT_MASK_VENDOR_KEY_USE: return "VendorKeyUse";
    default: return NULL;
    }
}

/* KEY_PAIR_INFO uses its own asymmetric algorithm bits. */
static const char *key_pair_asym_name(uint32_t bit)
{
    switch (bit) {
    case SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA2048: return "RSA2048";
    case SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA3072: return "RSA3072";
    case SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA4096: return "RSA4096";
    case SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256: return "ECC256";
    case SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC384: return "ECC384";
    case SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC521: return "ECC521";
    case SPDM_KEY_PAIR_ASYM_ALGO_CAP_SM2: return "SM2";
    case SPDM_KEY_PAIR_ASYM_ALGO_CAP_ED25519: return "Ed25519";
    case SPDM_KEY_PAIR_ASYM_ALGO_CAP_ED448: return "Ed448";
    default: return NULL;
    }
}

static const char *key_pair_pqc_name(uint32_t bit)
{
    switch (bit) {
    case SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_44: return "ML-DSA-44";
    case SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_65: return "ML-DSA-65";
    case SPDM_KEY_PAIR_PQC_ASYM_ALGO_CAP_ML_DSA_87: return "ML-DSA-87";
    default: return NULL;
    }
}

static node_t *add_bits(node_t *res, const char *key, uint32_t v, int width,
                        const char *(*name)(uint32_t))
{
    char *s = bits_to_names(v, name);
    node_t *n = node_add(res, key, "0x%0*x %s", width, v, s);

    free(s);
    return n;
}

/* GET_KEY_PAIR_INFO for one key pair; *total gets TotalKeyPairs. */
static int key_pair_info_one(struct tool *t, uint8_t kp, uint8_t *total)
{
    uint16_t caps = 0, kuc = 0, cku = 0, pki_len = 1024;
    uint32_t aac = 0, caa = 0, pqc_cap = 0, cur_pqc = 0;
    uint8_t mask = 0, pki[1024];
    enum out_status status;
    libspdm_return_t st;
    char id[32], title[64], msg[160];
    node_t *res;

    snprintf(id, sizeof(id), "key-pair-info-%u", kp);
    snprintf(title, sizeof(title), "GET_KEY_PAIR_INFO - key pair %u", kp);
    out_step_begin(id, title);
    res = node_new("", NULL);
    forget_errors();
    st = libspdm_get_key_pair_info(t->app.ctx, NULL, kp, total, &caps, &kuc, &cku, &aac, &caa,
                                   &pqc_cap, &cur_pqc, &mask, &pki_len, pki);
    status = refusable_status(t, res, st, msg, sizeof(msg));
    if (msg[0]) {
        STEP_END(t, id, status, res, "%s", msg);
        return LIBSPDM_STATUS_IS_ERROR(st) ? -1 : 0;
    }
    node_add(res, "TotalKeyPairs", "%u", *total);
    add_bits(res, "Capabilities", caps, 4, key_pair_cap_name);
    add_bits(res, "KeyUsageCapabilities", kuc, 4, key_usage_name);
    node_style(add_bits(res, "CurrentKeyUsage", cku, 4, key_usage_name), NS_HILITE);
    add_bits(res, "AsymAlgoCapabilities", aac, 8, key_pair_asym_name);
    add_bits(res, "CurrentAsymAlgo", caa, 8, key_pair_asym_name);
    if (spdm_conn_version(t->app.ctx) >= 0x14) {
        add_bits(res, "PqcAsymAlgoCapabilities", pqc_cap, 8, key_pair_pqc_name);
        add_bits(res, "CurrentPqcAsymAlgo", cur_pqc, 8, key_pair_pqc_name);
    }
    node_style(node_add(res, "AssocCertSlotMask", "0x%02x", mask), NS_HILITE);
    node_add_hex(res, "PublicKeyInfo", pki, pki_len);
    STEP_END(t, id, status, res, "key pair %u of %u: usage 0x%04x, slots 0x%02x", kp, *total,
             cku, mask);
    return 0;
}

static int step_key_pair_info(struct tool *t)
{
    uint8_t total = 0, kp;

    if (ensure_connected(t))
        return -1;
    if (t->key_pair_id >= 0)
        return key_pair_info_one(t, (uint8_t)t->key_pair_id, &total);
    if (key_pair_info_one(t, 1, &total))
        return -1;
    for (kp = 2; kp <= total && kp != 0; kp++)
        key_pair_info_one(t, kp, &total);
    return 0;
}

/* ---------------------------------------------------------------- loop */

static void on_signal(int sig)
{
    g_stop = 1;
    signal(sig, SIG_DFL); /* a second Ctrl-C exits immediately */
}

static void sleep_interruptible(int seconds)
{
    struct timespec ts = { .tv_sec = seconds };

    while (!g_stop && nanosleep(&ts, &ts) && errno == EINTR)
        ;
}

/* ----------------------------------------------------------------- CLI */

static void usage(FILE *f)
{
    fprintf(f,
"Usage: spdm-req-tool -e EID [options] COMMAND [COMMAND...]\n"
"\n"
"SPDM requester front-end for libspdm over the Linux kernel MCTP stack (AF_MCTP).\n"
"\n"
"Commands (run in the given order; prerequisites are run automatically):\n"
"  version       GET_VERSION only\n"
"  connect       VCA: GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHMS\n"
"  digests       GET_DIGESTS\n"
"  cert          GET_CERTIFICATE for --slot and verify the chain\n"
"  get-root-ca   extract the responder's root CA from its chain and save it\n"
"  challenge     CHALLENGE / CHALLENGE_AUTH signature verification\n"
"  meas          GET_MEASUREMENTS (signed when supported)\n"
"  session       KEY_EXCHANGE+FINISH, HEARTBEAT, KEY_UPDATE, measurements, END_SESSION\n"
"  caliptra-vdm  Caliptra VDM GET_ATTESTATION and EXPORT_ATTESTED_CSR in a secure session\n"
"  intel-mbx     Intel PFR mailbox reads in the clear and in a secure session\n"
"  set-cert      SET_CERTIFICATE: write --cert-chain to --slot (in a secure session)\n"
"  erase-cert    SET_CERTIFICATE with Erase (SPDM 1.3): erase --slot (in a secure session)\n"
"  key-pair-info GET_KEY_PAIR_INFO for --key-pair-id, or every key pair\n"
"  all           connect digests cert challenge meas session\n"
"\n"
"Connection:\n"
"  -e, --eid EID            responder endpoint ID (required)\n"
"  -n, --net NET            MCTP network ID (default: any)\n"
"  -i, --interface IFNAME   bypass routing: send on IFNAME (MCTP extended addressing)\n"
"  -L, --lladdr HEX         physical address for --interface, e.g. 1d or aa:bb (default: none)\n"
"  -t, --timeout MS         minimum response timeout (default 3000)\n"
"\n"
"SPDM:\n"
"  -V, --spdm-version VER   only negotiate VER (1.0 .. 1.4)\n"
"      --asym LIST          base asym algorithms, e.g. ecdsa-p384,ecdsa-p256,rsapss-3072\n"
"      --pqc-asym LIST      SPDM 1.4 PQC asym algorithms, e.g. ml-dsa-87,ml-dsa-65, or none\n"
"                           (default ml-dsa-44,ml-dsa-65,ml-dsa-87)\n"
"      --hash LIST          base hash algorithms, e.g. sha-384,sha-256\n"
"      --dhe LIST           DHE groups, e.g. secp384r1,secp256r1, or none (KEM only)\n"
"      --kem LIST           SPDM 1.4 KEM algorithms, e.g. ml-kem-1024, or none\n"
"                           (default ml-kem-512,ml-kem-768,ml-kem-1024)\n"
"      --aead LIST          AEAD suites, e.g. aes-256-gcm,aes-128-gcm\n"
"  -s, --slot N             certificate slot (default 0)\n"
"  -m, --meas-index N|all   measurement index (default all)\n"
"      --no-meas-sig        request unsigned measurements\n"
"      --meas-summary T     measurement summary hash for CHALLENGE/KEY_EXCHANGE:\n"
"                           none, tcb, all (default all)\n"
"      --no-session         do not advertise session capabilities\n"
"      --csr-key-id N       device key id for caliptra-vdm EXPORT_ATTESTED_CSR (default 1)\n"
"      --mbx-read LIST      intel-mbx registers to read, ADDR[:LEN],... (default 0x60,0x00)\n"
"      --mbx-write A=HEX    intel-mbx: also write HEX bytes to register A in the session,\n"
"                           then read it back (0x09 and 0x80 to 0x60 are refused)\n"
"      --mbx-negative       intel-mbx: also send messages the responder must refuse\n"
"      --cert-chain FILE    set-cert: certificates to write, root first (PEM bundle or\n"
"                           concatenated DER); the SPDM chain header and root hash are\n"
"                           built with the negotiated hash\n"
"      --cert-model M       set-cert SetCertModel: none, device, alias, generic (default alias)\n"
"      --key-pair-id N      set-cert/erase-cert KeyPairID (default 1; 0 is sent when the\n"
"                           connection is not multi-key); key-pair-info: only key pair N\n"
"      --session-slot N     slot whose key authenticates the set-cert/erase-cert session\n"
"                           (default 0)\n"
"      --set-cert-no-session  send SET_CERTIFICATE in the clear (negative test)\n"
"      --expect-error CODE  set-cert, erase-cert, key-pair-info: pass only if the responder\n"
"                           answers with this SPDM ERROR (name such as SessionRequired, or\n"
"                           a number)\n"
"\n"
"Certificates:\n"
"  -r, --root-ca FILE       trusted root CA (PEM or DER), may be repeated; the chain\n"
"                           must be anchored in one of them\n"
"  -R, --save-root-ca FILE  where get-root-ca stores the root CA (.der for DER, else PEM)\n"
"  -C, --save-chain FILE    save the certificate chain (PEM bundle, or raw SPDM chain if .bin)\n"
"\n"
"Loop:\n"
"  -l, --loop SEC           repeat the commands every SEC seconds (Ctrl-C stops);\n"
"                           every round uses fresh nonces and checks that the\n"
"                           requester and responder nonces differ from the last round\n"
"  -c, --count N            stop after N rounds (default: until interrupted)\n"
"      --loop-full          redo VCA and GET_CERTIFICATE every round (default: reuse\n"
"                           them; 'all' then repeats challenge, meas and session)\n"
"\n"
"Output:\n"
"  -v, --verbose            decode every SPDM request/response (-vv: also MCTP frames)\n"
"  -x, --hex                hex dump every SPDM message\n"
"  -j, --json               emit JSON lines (used by spdm-demo)\n"
"      --color WHEN         auto, always, never\n"
"  -q, --quiet              one line per step (and per loop round), no details\n"
"  -h, --help               this help\n"
"      --version            print version\n"
"\n"
"Examples:\n"
"  spdm-req-tool -e 42 all\n"
"  spdm-req-tool -e 42 -v connect cert\n"
"  spdm-req-tool -e 42 get-root-ca -R ast1080-root.pem\n"
"  spdm-req-tool -e 42 -r ast1080-root.pem challenge meas\n"
"  spdm-req-tool -e 42 -r ast1080-root.pem --loop 5 challenge meas\n"
"  spdm-req-tool -e 42 -s 2 --cert-chain owner-ecc-chain.der set-cert digests cert\n");
}

static int parse_algo_list(const char *list, const char *(*name)(uint32_t), uint32_t *out)
{
    char *dup = strdup(list), *save = NULL, *tok;
    uint32_t mask = 0;

    for (tok = strtok_r(dup, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        int i;
        bool found = false;

        for (i = 0; i < 32 && !found; i++) {
            const char *n = name(1u << i);

            if (n && !strcasecmp(n, tok)) {
                mask |= 1u << i;
                found = true;
            }
        }
        if (!found) {
            fprintf(stderr, "unknown algorithm '%s'\n", tok);
            free(dup);
            return -1;
        }
    }
    free(dup);
    *out = mask;
    return mask ? 0 : -1;
}

/* --mbx-read ADDR[:LEN],... */
static int parse_mbx_reads(struct tool *t, const char *list)
{
    char *dup = strdup(list), *save = NULL, *tok;
    int rc = 0;

    t->mbx_read_count = 0;
    for (tok = strtok_r(dup, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        char *end;
        unsigned long a = strtoul(tok, &end, 0), l = 1;

        if (*end == ':')
            l = strtoul(end + 1, &end, 0);
        if (*end || a > 0xff || l < 1 || l > 48 || t->mbx_read_count >= 16) {
            fprintf(stderr, "invalid --mbx-read entry '%s' (ADDR[:LEN], LEN 1..48, at most 16)\n",
                    tok);
            rc = -1;
            break;
        }
        t->mbx_reads[t->mbx_read_count].addr = (uint8_t)a;
        t->mbx_reads[t->mbx_read_count++].len = (uint8_t)l;
    }
    free(dup);
    if (!rc && !t->mbx_read_count) {
        fprintf(stderr, "empty --mbx-read list\n");
        rc = -1;
    }
    return rc;
}

/* --mbx-write ADDR=HEX */
static int parse_mbx_write(struct tool *t, const char *arg)
{
    const char *h;
    char *end;
    unsigned long a = strtoul(arg, &end, 0);
    size_t n = 0;

    if (*end != '=' || a > 0xff)
        goto bad;
    for (h = end + 1; *h; h += 2) {
        unsigned v;

        if (n >= sizeof(t->mbx_write_data) || sscanf(h, "%2x", &v) != 1 || !h[1])
            goto bad;
        t->mbx_write_data[n++] = (uint8_t)v;
    }
    if (!n)
        goto bad;
    /* Writing boot-done to the BMC checkpoint re-runs the PFR boot-complete
     * path (and re-initializes I3C). */
    if (a <= INTEL_MBX_BMC_CHECKPOINT && a + n > INTEL_MBX_BMC_CHECKPOINT &&
        (t->mbx_write_data[INTEL_MBX_BMC_CHECKPOINT - a] == 0x09 ||
         t->mbx_write_data[INTEL_MBX_BMC_CHECKPOINT - a] == 0x80)) {
        fprintf(stderr, "--mbx-write: refusing to write 0x%02x to the BMC checkpoint 0x60\n",
                t->mbx_write_data[INTEL_MBX_BMC_CHECKPOINT - a]);
        return -1;
    }
    t->mbx_write_addr = (int)a;
    t->mbx_write_len = (uint8_t)n;
    return 0;
bad:
    fprintf(stderr, "invalid --mbx-write '%s' (ADDR=HEX, e.g. 0x60=01, 1..48 bytes)\n", arg);
    return -1;
}

static int parse_cert_model(struct tool *t, const char *arg)
{
    static const char *names[] = { "none", "device", "alias", "generic" };
    uint8_t i;

    for (i = 0; i < 4; i++)
        if (!strcasecmp(arg, names[i])) {
            t->cert_model = i;
            return 0;
        }
    fprintf(stderr, "invalid --cert-model '%s' (none, device, alias, generic)\n", arg);
    return -1;
}

/* --expect-error: an SPDM error code name (as printed) or number */
static int parse_error_code(struct tool *t, const char *arg)
{
    char *end;
    unsigned long v = strtoul(arg, &end, 0);
    int i;

    if (!*end && end != arg && v <= 0xff) {
        t->expect_error = (int)v;
        return 0;
    }
    for (i = 1; i <= 0xff; i++)
        if (strcmp(spdm_error_name((uint8_t)i), "Reserved") &&
            !strcasecmp(arg, spdm_error_name((uint8_t)i))) {
            t->expect_error = i;
            return 0;
        }
    fprintf(stderr, "unknown SPDM error code '%s' (e.g. SessionRequired, UnexpectedRequest, 0x0b)\n",
            arg);
    return -1;
}

enum {
    OPT_ASYM = 0x100, OPT_PQC_ASYM, OPT_HASH, OPT_DHE, OPT_KEM, OPT_AEAD, OPT_NO_MEAS_SIG, OPT_MEAS_SUMMARY,
    OPT_COLOR, OPT_VERSION, OPT_NO_SESSION, OPT_LOOP_FULL, OPT_CSR_KEY_ID, OPT_MBX_READ,
    OPT_MBX_WRITE, OPT_MBX_NEGATIVE, OPT_CERT_CHAIN, OPT_CERT_MODEL, OPT_KEY_PAIR_ID,
    OPT_SESSION_SLOT, OPT_SET_CERT_NO_SESSION, OPT_EXPECT_ERROR,
};

static const struct option long_opts[] = {
    { "eid", required_argument, NULL, 'e' },
    { "net", required_argument, NULL, 'n' },
    { "interface", required_argument, NULL, 'i' },
    { "lladdr", required_argument, NULL, 'L' },
    { "timeout", required_argument, NULL, 't' },
    { "spdm-version", required_argument, NULL, 'V' },
    { "asym", required_argument, NULL, OPT_ASYM },
    { "pqc-asym", required_argument, NULL, OPT_PQC_ASYM },
    { "hash", required_argument, NULL, OPT_HASH },
    { "dhe", required_argument, NULL, OPT_DHE },
    { "kem", required_argument, NULL, OPT_KEM },
    { "aead", required_argument, NULL, OPT_AEAD },
    { "slot", required_argument, NULL, 's' },
    { "meas-index", required_argument, NULL, 'm' },
    { "no-meas-sig", no_argument, NULL, OPT_NO_MEAS_SIG },
    { "meas-summary", required_argument, NULL, OPT_MEAS_SUMMARY },
    { "no-session", no_argument, NULL, OPT_NO_SESSION },
    { "root-ca", required_argument, NULL, 'r' },
    { "save-root-ca", required_argument, NULL, 'R' },
    { "save-chain", required_argument, NULL, 'C' },
    { "verbose", no_argument, NULL, 'v' },
    { "hex", no_argument, NULL, 'x' },
    { "json", no_argument, NULL, 'j' },
    { "color", required_argument, NULL, OPT_COLOR },
    { "quiet", no_argument, NULL, 'q' },
    { "help", no_argument, NULL, 'h' },
    { "version", no_argument, NULL, OPT_VERSION },
    { "loop", required_argument, NULL, 'l' },
    { "count", required_argument, NULL, 'c' },
    { "loop-full", no_argument, NULL, OPT_LOOP_FULL },
    { "csr-key-id", required_argument, NULL, OPT_CSR_KEY_ID },
    { "mbx-read", required_argument, NULL, OPT_MBX_READ },
    { "mbx-write", required_argument, NULL, OPT_MBX_WRITE },
    { "mbx-negative", no_argument, NULL, OPT_MBX_NEGATIVE },
    { "cert-chain", required_argument, NULL, OPT_CERT_CHAIN },
    { "cert-model", required_argument, NULL, OPT_CERT_MODEL },
    { "key-pair-id", required_argument, NULL, OPT_KEY_PAIR_ID },
    { "session-slot", required_argument, NULL, OPT_SESSION_SLOT },
    { "set-cert-no-session", no_argument, NULL, OPT_SET_CERT_NO_SESSION },
    { "expect-error", required_argument, NULL, OPT_EXPECT_ERROR },
    { 0 }
};

static int run_command(struct tool *t, const char *cmd)
{
    if (!strcmp(cmd, "version"))
        return step_version(t);
    if (!strcmp(cmd, "connect"))
        return step_connect(t);
    if (!strcmp(cmd, "digests"))
        return step_digests(t);
    if (!strcmp(cmd, "cert"))
        return step_cert(t);
    if (!strcmp(cmd, "get-root-ca"))
        return step_get_root_ca(t);
    if (!strcmp(cmd, "challenge"))
        return step_challenge(t);
    if (!strcmp(cmd, "meas"))
        return step_meas(t);
    if (!strcmp(cmd, "session"))
        return step_session(t);
    if (!strcmp(cmd, "caliptra-vdm"))
        return step_caliptra_vdm(t);
    if (!strcmp(cmd, "intel-mbx"))
        return step_intel_mbx(t);
    if (!strcmp(cmd, "set-cert"))
        return step_set_cert(t, false);
    if (!strcmp(cmd, "erase-cert"))
        return step_set_cert(t, true);
    if (!strcmp(cmd, "key-pair-info"))
        return step_key_pair_info(t);
    if (!strcmp(cmd, "all")) {
        /* Later loop rounds reuse the connection and certificate chain and
         * only repeat the nonce-based steps (unless --loop-full). */
        if (!t->connected || !t->have_cert) {
            if (step_connect(t))
                return -1;
            step_digests(t);
            step_cert(t);
        }
        step_challenge(t);
        step_meas(t);
        step_session(t);
        return 0;
    }
    fprintf(stderr, "unknown command '%s' (see --help)\n", cmd);
    return -2;
}

static bool valid_command(const char *c)
{
    static const char *cmds[] = { "version", "connect", "digests", "cert", "get-root-ca",
                                  "challenge", "meas", "session", "caliptra-vdm",
                                  "intel-mbx", "set-cert", "erase-cert", "key-pair-info",
                                  "all" };
    size_t i;

    for (i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        if (!strcmp(c, cmds[i]))
            return true;
    return false;
}

int main(int argc, char **argv)
{
    static struct tool t;
    enum out_mode mode = OUT_TEXT;
    int color = -1, verbose = 0, opt, i, rc = 0;
    bool hex = false, quiet = false, have_eid = false;
    uint32_t v32;

    spdm_opts_defaults(&t.sopts);
    t.meas_index = -1;
    t.meas_sig = true;
    t.meas_summary = SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH;
    t.csr_key_id = 1;
    t.mbx_write_addr = -1;
    t.cert_model = SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT;
    t.key_pair_id = -1;
    t.expect_error = -1;

    while ((opt = getopt_long(argc, argv, "e:n:i:L:t:V:s:m:r:R:C:l:c:vxjqh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'e': {
            char *end;
            unsigned long e = strtoul(optarg, &end, 0);

            if (*end || e > 255) {
                fprintf(stderr, "invalid EID '%s'\n", optarg);
                return 2;
            }
            t.sopts.eid = (uint8_t)e;
            have_eid = true;
            break;
        }
        case 'n': t.sopts.net = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'i': t.sopts.ifname = optarg; break;
        case 'L': t.sopts.lladdr = optarg; break;
        case 't': t.sopts.timeout_ms = atoi(optarg); break;
        case 'V': {
            unsigned maj, min;

            if (sscanf(optarg, "%u.%u", &maj, &min) != 2 || maj != 1 || min > 4) {
                fprintf(stderr, "invalid SPDM version '%s'\n", optarg);
                return 2;
            }
            t.sopts.version = (uint8_t)((maj << 4) | min);
            break;
        }
        case OPT_ASYM:
            if (parse_algo_list(optarg, asym_name, &t.sopts.base_asym))
                return 2;
            break;
        case OPT_PQC_ASYM:
            if (!strcasecmp(optarg, "none"))
                t.sopts.pqc_asym = 0;
            else if (parse_algo_list(optarg, pqc_name, &t.sopts.pqc_asym))
                return 2;
            break;
        case OPT_HASH:
            if (parse_algo_list(optarg, hash_name, &t.sopts.base_hash))
                return 2;
            break;
        case OPT_DHE:
            if (!strcasecmp(optarg, "none"))
                v32 = 0;
            else if (parse_algo_list(optarg, dhe_name, &v32))
                return 2;
            t.sopts.dhe = (uint16_t)v32;
            break;
        case OPT_KEM:
            if (!strcasecmp(optarg, "none"))
                t.sopts.kem = 0;
            else if (parse_algo_list(optarg, kem_name, &t.sopts.kem))
                return 2;
            break;
        case OPT_AEAD:
            if (parse_algo_list(optarg, aead_name, &v32))
                return 2;
            t.sopts.aead = (uint16_t)v32;
            break;
        case 's': t.slot = (uint8_t)atoi(optarg); break;
        case 'm':
            t.meas_index = !strcmp(optarg, "all") ? -1 : atoi(optarg);
            if (t.meas_index == 0 || t.meas_index > 0xFE) {
                fprintf(stderr, "invalid measurement index '%s' (1..254 or all)\n", optarg);
                return 2;
            }
            break;
        case OPT_NO_MEAS_SIG: t.meas_sig = false; break;
        case OPT_MEAS_SUMMARY:
            if (!strcmp(optarg, "none"))
                t.meas_summary = SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH;
            else if (!strcmp(optarg, "tcb"))
                t.meas_summary = SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH;
            else if (!strcmp(optarg, "all"))
                t.meas_summary = SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH;
            else {
                fprintf(stderr, "invalid --meas-summary '%s'\n", optarg);
                return 2;
            }
            break;
        case OPT_NO_SESSION: t.sopts.no_session_caps = true; break;
        case 'r':
            if (t.root_ca_count >= 10) {
                fprintf(stderr, "too many --root-ca\n");
                return 2;
            }
            t.root_ca_files[t.root_ca_count++] = optarg;
            break;
        case 'R': t.save_root_ca = optarg; break;
        case 'l':
            t.loop_interval = atoi(optarg);
            if (t.loop_interval < 1) {
                fprintf(stderr, "invalid --loop interval '%s' (seconds, >= 1)\n", optarg);
                return 2;
            }
            break;
        case 'c': t.loop_count = atoi(optarg); break;
        case OPT_LOOP_FULL: t.loop_full = true; break;
        case OPT_CSR_KEY_ID: t.csr_key_id = (uint32_t)strtoul(optarg, NULL, 0); break;
        case OPT_MBX_READ:
            if (parse_mbx_reads(&t, optarg))
                return 2;
            break;
        case OPT_MBX_WRITE:
            if (parse_mbx_write(&t, optarg))
                return 2;
            break;
        case OPT_MBX_NEGATIVE: t.mbx_negative = true; break;
        case OPT_CERT_CHAIN: t.cert_chain_file = optarg; break;
        case OPT_CERT_MODEL:
            if (parse_cert_model(&t, optarg))
                return 2;
            break;
        case OPT_KEY_PAIR_ID:
        case OPT_SESSION_SLOT: {
            char *end;
            unsigned long v = strtoul(optarg, &end, 0);

            if (*end || v > (opt == OPT_KEY_PAIR_ID ? 255u : 7u)) {
                fprintf(stderr, "invalid --%s '%s'\n",
                        opt == OPT_KEY_PAIR_ID ? "key-pair-id" : "session-slot", optarg);
                return 2;
            }
            if (opt == OPT_KEY_PAIR_ID)
                t.key_pair_id = (int)v;
            else
                t.session_slot = (uint8_t)v;
            break;
        }
        case OPT_SET_CERT_NO_SESSION: t.set_cert_no_session = true; break;
        case OPT_EXPECT_ERROR:
            if (parse_error_code(&t, optarg))
                return 2;
            break;
        case 'C': t.save_chain = optarg; break;
        case 'v': verbose++; break;
        case 'x': hex = true; break;
        case 'j': mode = OUT_JSON; break;
        case 'q': quiet = true; break;
        case OPT_COLOR:
            color = !strcmp(optarg, "always") ? 1 : !strcmp(optarg, "never") ? 0 : -1;
            break;
        case OPT_VERSION:
            printf("spdm-req-tool %s (libspdm %u.%u.%u)\n", SPDM_REQ_TOOL_VERSION,
                   libspdm_module_version() >> 24 & 0xff, libspdm_module_version() >> 16 & 0xff,
                   libspdm_module_version() >> 8 & 0xff);
            return 0;
        case 'h': usage(stdout); return 0;
        default: usage(stderr); return 2;
        }
    }
    if (!t.mbx_read_count)
        parse_mbx_reads(&t, "0x60,0x00");
    if (!have_eid || optind >= argc) {
        usage(stderr);
        return 2;
    }
    for (i = optind; i < argc; i++)
        if (!valid_command(argv[i])) {
            fprintf(stderr, "unknown command '%s' (see --help)\n", argv[i]);
            return 2;
        }

    out_init(mode, color, verbose, hex, quiet);
    out_banner("spdm-req-tool %s | libspdm | AF_MCTP EID %u net %s%s%s", SPDM_REQ_TOOL_VERSION,
               t.sopts.eid, t.sopts.net ? "set" : "any", t.sopts.ifname ? " via " : "",
               t.sopts.ifname ? t.sopts.ifname : "");

    if (spdm_app_init(&t.app, &t.sopts)) {
        out_done(ST_FAIL, 0, 0, 1);
        return 1;
    }
    for (i = 0; i < t.root_ca_count; i++) {
        struct cert_list l;
        int k, r = cert_load_file(t.root_ca_files[i], &l);

        if (r) {
            out_log(ST_FAIL, "cannot load root CA %s: %s", t.root_ca_files[i],
                    r == -EINVAL ? "not a PEM/DER certificate" : strerror(-r));
            spdm_app_deinit(&t.app);
            return 1;
        }
        for (k = 0; k < l.count; k++) {
            char subj[256];

            cert_subject(l.der[k], l.len[k], subj, sizeof(subj));
            if (spdm_app_add_root_ca(&t.app, l.der[k], l.len[k])) {
                out_log(ST_FAIL, "too many root CAs");
                free(l.der[k]);
            } else {
                out_log(ST_OK, "trust anchor: %s (%s)", subj, t.root_ca_files[i]);
            }
        }
    }

    if (t.loop_interval) {
        struct sigaction sa;

        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_signal; /* no SA_RESTART: interrupts the sleep */
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
    }
    for (t.round = 1;; t.round++) {
        int p0 = t.passed, w0 = t.warned, f0 = t.failed;

        if (t.loop_interval)
            out_round_begin(t.round, t.loop_count, t.loop_interval);
        for (i = optind; i < argc && !g_stop; i++) {
            rc = run_command(&t, argv[i]);
            if (rc && !t.connected)
                break; /* nothing else can work without a connection */
        }
        if (!t.loop_interval)
            break;
        out_round_end(t.round, t.failed > f0 ? ST_FAIL : t.warned > w0 ? ST_WARN : ST_OK,
                      t.passed - p0, t.warned - w0, t.failed - f0);
        if (g_stop || (t.loop_count && t.round >= t.loop_count))
            break;
        /* After a failure (e.g. the device re-enumerated) start over with a new
         * connection; with --loop-full always do. */
        if (t.loop_full || t.failed > f0) {
            t.connected = false;
            t.have_cert = false;
            t.digests_done = false;
        }
        sleep_interruptible(t.loop_interval);
        if (g_stop)
            break;
    }

    out_done(t.failed ? ST_FAIL : t.warned ? ST_WARN : ST_OK, t.passed, t.warned, t.failed);
    free(t.chain);
    spdm_app_deinit(&t.app);
    return t.failed ? 1 : 0;
}
