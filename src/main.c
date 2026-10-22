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
"      --dhe LIST           DHE groups, e.g. secp384r1,secp256r1\n"
"      --aead LIST          AEAD suites, e.g. aes-256-gcm,aes-128-gcm\n"
"  -s, --slot N             certificate slot (default 0)\n"
"  -m, --meas-index N|all   measurement index (default all)\n"
"      --no-meas-sig        request unsigned measurements\n"
"      --meas-summary T     measurement summary hash for CHALLENGE/KEY_EXCHANGE:\n"
"                           none, tcb, all (default all)\n"
"      --no-session         do not advertise session capabilities\n"
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
"  spdm-req-tool -e 42 -r ast1080-root.pem --loop 5 challenge meas\n");
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

enum {
    OPT_ASYM = 0x100, OPT_PQC_ASYM, OPT_HASH, OPT_DHE, OPT_AEAD, OPT_NO_MEAS_SIG, OPT_MEAS_SUMMARY,
    OPT_COLOR, OPT_VERSION, OPT_NO_SESSION, OPT_LOOP_FULL,
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
                                  "challenge", "meas", "session", "all" };
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
            if (parse_algo_list(optarg, dhe_name, &v32))
                return 2;
            t.sopts.dhe = (uint16_t)v32;
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
