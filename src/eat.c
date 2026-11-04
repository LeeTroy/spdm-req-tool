/* OCP EAT decoder: COSE_Sign1 envelope, EAT claims (RFC 9711) and the TCG
 * concise evidence (CoRIM measurement-map) inside the measurements claim.
 * Anything not recognized falls back to the generic CBOR rendering. */
#include <stdio.h>
#include <string.h>

#include "cbor.h"
#include "eat.h"

#define TAG_SELF_DESCRIBED 55799
#define TAG_CWT 61
#define TAG_COSE_SIGN1 18
#define TAG_OID 111
#define TAG_CONCISE_EVIDENCE 571
#define CT_CONCISE_EVIDENCE 10571 /* application/ce+cbor */
#define OCP_EAT_PROFILE_OID "1.3.6.1.4.1.42623.1.3"

/* Skips the self-described CBOR and CWT tags, then expects COSE_Sign1
 * (tagged or not). Leaves c after the array head. */
static bool enter_cose_sign1(cbor_t *c)
{
    uint64_t tag, n;
    cbor_t save;

    for (;;) {
        save = *c;
        if (!cbor_tag(c, &tag))
            break;
        if (tag == TAG_COSE_SIGN1)
            break;
        if (tag != TAG_SELF_DESCRIBED && tag != TAG_CWT) {
            *c = save;
            return false;
        }
    }
    return cbor_array(c, &n) && n == 4;
}

bool eat_is_cose_sign1(const uint8_t *p, size_t len)
{
    cbor_t c = { p, p + len };

    return enter_cose_sign1(&c);
}

static const char *cose_alg_name(int64_t a)
{
    switch (a) {
    case -7: return "ES256";
    case -35: return "ES384";
    case -36: return "ES512";
    case -37: return "PS256";
    case -38: return "PS384";
    case -39: return "PS512";
    case -8: return "EdDSA";
    case -48: return "ML-DSA-44";
    case -49: return "ML-DSA-65";
    case -50: return "ML-DSA-87";
    }
    return NULL;
}

/* IANA Named Information hash algorithm registry (CoRIM digests). */
static const char *hash_alg_name(int64_t a)
{
    switch (a) {
    case 1: return "SHA-256";
    case 2: return "SHA-256/128";
    case 3: return "SHA-256/120";
    case 4: return "SHA-256/96";
    case 5: return "SHA-256/64";
    case 6: return "SHA-256/32";
    case 7: return "SHA-384";
    case 8: return "SHA-512";
    case 9: return "SHA3-224";
    case 10: return "SHA3-256";
    case 11: return "SHA3-384";
    case 12: return "SHA3-512";
    }
    return NULL;
}

static const char *dbgstat_name(int64_t v)
{
    switch (v) {
    case 0: return "enabled";
    case 1: return "disabled";
    case 2: return "disabled-since-boot";
    case 3: return "disabled-permanently";
    case 4: return "disabled-fully-and-permanently";
    }
    return NULL;
}

/* CoRIM flags-map */
static const char *flag_name(int64_t k)
{
    static const char *names[] = {
        "is-configured", "is-secure", "is-recovery", "is-debug", "is-replay-protected",
        "is-integrity-protected", "is-runtime-meas", "is-immutable", "is-tcb",
        "is-confidentiality-protected",
    };

    return k >= 0 && k < (int64_t)(sizeof(names) / sizeof(names[0])) ? names[k] : NULL;
}

static void add_label(char *buf, size_t size, int64_t k, const char *name)
{
    if (name)
        snprintf(buf, size, "%s", name);
    else
        snprintf(buf, size, "%lld", (long long)k);
}

/* tstr as a string, anything else rendered generically */
static void text_or_generic(cbor_t *c, node_t *parent, const char *key, int style)
{
    const uint8_t *s;
    size_t n;

    if (cbor_str(c, CBOR_TSTR, &s, &n))
        node_style(node_add(parent, key, "\"%.*s\"", (int)n, s), style);
    else
        cbor_render(c, parent, key);
}

/* [ alg, value ] digests */
static void digests(cbor_t *c, node_t *parent, const char *key)
{
    uint64_t n, i, k;
    node_t *d;
    cbor_t save = *c;

    if (!cbor_array(c, &n)) {
        cbor_render(c, parent, key);
        return;
    }
    d = node_add(parent, key, "%llu digest%s", (unsigned long long)n, n == 1 ? "" : "s");
    for (i = 0; i < n; i++) {
        const uint8_t *alg_s, *v;
        size_t alg_len, vlen;
        int64_t alg;
        char name[32];

        save = *c;
        if (!cbor_array(c, &k) || k != 2)
            goto generic;
        if (cbor_int(c, &alg)) {
            add_label(name, sizeof(name), alg, hash_alg_name(alg));
        } else if (cbor_str(c, CBOR_TSTR, &alg_s, &alg_len)) {
            snprintf(name, sizeof(name), "%.*s", (int)alg_len, alg_s);
        } else {
            goto generic;
        }
        if (!cbor_str(c, CBOR_BSTR, &v, &vlen))
            goto generic;
        node_add_hex(d, name, v, vlen);
        continue;
generic:
        *c = save;
        cbor_render(c, d, "digest");
    }
}

static void svn(cbor_t *c, node_t *parent)
{
    uint64_t tag;
    int64_t v;
    cbor_t save = *c;
    const char *kind = "";

    if (cbor_tag(c, &tag)) {
        if (tag == 552)
            kind = "";
        else if (tag == 553)
            kind = "min ";
        else
            goto generic;
    }
    if (!cbor_int(c, &v))
        goto generic;
    node_style(node_add(parent, "SVN", "%s%lld", kind, (long long)v), NS_HILITE);
    return;
generic:
    *c = save;
    cbor_render(c, parent, "SVN");
}

static void flags(cbor_t *c, node_t *parent)
{
    uint64_t n, i;
    node_t *f;
    cbor_t save = *c;

    if (!cbor_map(c, &n)) {
        cbor_render(c, parent, "Flags");
        return;
    }
    f = node_add(parent, "Flags", NULL);
    for (i = 0; i < n; i++) {
        int64_t k;
        char name[32];

        save = *c;
        if (!cbor_int(c, &k)) {
            *c = save;
            cbor_render(c, f, "key");
            cbor_render(c, f, "value");
            continue;
        }
        add_label(name, sizeof(name), k, flag_name(k));
        if (cbor_peek(c) == CBOR_SIMPLE && (*c->p == 0xf4 || *c->p == 0xf5)) {
            node_style(node_add(f, name, *c->p == 0xf5 ? "true" : "false"),
                       (k == 3 && *c->p == 0xf5) ? NS_WARN : NS_NONE);
            c->p++;
        } else {
            cbor_render(c, f, name);
        }
    }
}

/* CoRIM measurement-values-map */
static void mval(cbor_t *c, node_t *parent)
{
    uint64_t n, i, vn, tag;
    node_t *v;

    if (!cbor_map(c, &n)) {
        cbor_render(c, parent, "Value");
        return;
    }
    v = parent;
    for (i = 0; i < n; i++) {
        int64_t k;

        if (!cbor_int(c, &k)) {
            cbor_render(c, v, "key");
            cbor_render(c, v, "value");
            continue;
        }
        switch (k) {
        case 0: { /* version-map: { 0: version, ? 1: version-scheme } */
            uint64_t j;

            if (!cbor_map(c, &vn)) {
                cbor_render(c, v, "Version");
                break;
            }
            for (j = 0; j < vn; j++) {
                int64_t vk;

                if (!cbor_int(c, &vk)) {
                    cbor_render(c, v, "key");
                    cbor_render(c, v, "value");
                } else if (vk == 0) {
                    text_or_generic(c, v, "Version", NS_HILITE);
                } else {
                    cbor_render(c, v, vk == 1 ? "VersionScheme" : "version entry");
                }
            }
            break;
        }
        case 1: svn(c, v); break;
        case 2: digests(c, v, "Digests"); break;
        case 3: flags(c, v); break;
        case 4: {
            const uint8_t *b;
            size_t bl;
            cbor_t save = *c;

            if (cbor_tag(c, &tag) && tag == 560 && cbor_str(c, CBOR_BSTR, &b, &bl)) {
                node_add_hex(v, "RawValue", b, bl);
            } else {
                *c = save;
                cbor_render(c, v, "RawValue");
            }
            break;
        }
        case 5: cbor_render(c, v, "RawValueMask"); break;
        case 6: cbor_render(c, v, "MacAddress"); break;
        case 7: cbor_render(c, v, "IpAddress"); break;
        case 8: text_or_generic(c, v, "SerialNumber", NS_NONE); break;
        case 9: cbor_render(c, v, "UEID"); break;
        case 10: cbor_render(c, v, "UUID"); break;
        case 11: text_or_generic(c, v, "Name", NS_HILITE); break;
        case 13: cbor_render(c, v, "CryptoKeys"); break;
        case 14: {
            uint64_t rn, j;
            cbor_t save = *c;

            if (!cbor_map(c, &rn)) {
                *c = save;
                cbor_render(c, v, "IntegrityRegisters");
                break;
            }
            {
                node_t *r = node_add(v, "IntegrityRegisters", "%llu register%s",
                                     (unsigned long long)rn, rn == 1 ? "" : "s");

                for (j = 0; j < rn; j++) {
                    int64_t rk;
                    const uint8_t *s;
                    size_t sl;
                    char name[48];

                    if (cbor_int(c, &rk))
                        snprintf(name, sizeof(name), "Register %lld", (long long)rk);
                    else if (cbor_str(c, CBOR_TSTR, &s, &sl))
                        snprintf(name, sizeof(name), "%.*s", (int)sl, s);
                    else {
                        cbor_render(c, r, "key");
                        cbor_render(c, r, "value");
                        continue;
                    }
                    digests(c, r, name);
                }
            }
            break;
        }
        default: {
            char name[24];

            snprintf(name, sizeof(name), "%lld", (long long)k);
            cbor_render(c, v, name);
        }
        }
    }
}

/* CoRIM measurement-map: { ? 0: mkey, 1: mval, ? 2: authorized-by } */
static void measurement(cbor_t *c, node_t *parent, const char *key)
{
    uint64_t n, i;
    node_t *m;

    if (!cbor_map(c, &n)) {
        cbor_render(c, parent, key);
        return;
    }
    m = node_add(parent, key, NULL);
    for (i = 0; i < n; i++) {
        int64_t k;

        if (!cbor_int(c, &k)) {
            cbor_render(c, m, "key");
            cbor_render(c, m, "value");
            continue;
        }
        if (k == 0)
            text_or_generic(c, m, "Key", NS_HILITE);
        else if (k == 1)
            mval(c, m);
        else if (k == 2)
            cbor_render(c, m, "AuthorizedBy");
        else
            cbor_render(c, m, "entry");
    }
}

/* class-id: tagged OID (111), UUID (37) or bytes (560) */
static void class_id(cbor_t *c, node_t *parent)
{
    cbor_t save = *c;
    uint64_t tag;
    const uint8_t *b;
    size_t bl, i;
    char oid[128];

    if (!cbor_tag(c, &tag) || !cbor_str(c, CBOR_BSTR, &b, &bl))
        goto generic;
    if (tag == TAG_OID) {
        cbor_oid_str(b, bl, oid, sizeof(oid));
        node_style(node_add(parent, "ClassID", "OID %s", oid), NS_HILITE);
        return;
    }
    if (tag == 560) {
        for (i = 0; i < bl && b[i] >= 0x20 && b[i] <= 0x7e; i++)
            ;
        if (bl && i == bl)
            node_style(node_add(parent, "ClassID", "\"%.*s\"", (int)bl, b), NS_HILITE);
        else
            node_add_hex(parent, "ClassID", b, bl);
        return;
    }
    if (tag == 37 && bl == 16) {
        node_add(parent, "ClassID", "UUID %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
                 "%02x%02x%02x%02x%02x%02x", b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                 b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
        return;
    }
generic:
    *c = save;
    cbor_render(c, parent, "ClassID");
}

/* CoMID environment-map: { ? 0: class-map, ? 1: instance, ? 2: group } */
static void environment(cbor_t *c, node_t *parent)
{
    static const char *class_keys[] = { "ClassID", "Vendor", "Model", "Layer", "Index" };
    uint64_t n, i, cn, j;
    node_t *e;

    if (!cbor_map(c, &n)) {
        cbor_render(c, parent, "Environment");
        return;
    }
    e = node_add(parent, "Environment", NULL);
    for (i = 0; i < n; i++) {
        int64_t k;

        if (!cbor_int(c, &k)) {
            cbor_render(c, e, "key");
            cbor_render(c, e, "value");
            continue;
        }
        if (k != 0) {
            cbor_render(c, e, k == 1 ? "Instance" : k == 2 ? "Group" : "entry");
            continue;
        }
        if (!cbor_map(c, &cn)) {
            cbor_render(c, e, "Class");
            continue;
        }
        for (j = 0; j < cn; j++) {
            int64_t ck;

            if (!cbor_int(c, &ck) || ck < 0 || ck > 4) {
                cbor_render(c, e, "class entry");
                continue;
            }
            if (ck == 0)
                class_id(c, e);
            else if (ck == 1 || ck == 2)
                text_or_generic(c, e, class_keys[ck], NS_HILITE);
            else
                cbor_render(c, e, class_keys[ck]);
        }
    }
}

/* TCG concise evidence: tag 571 { 0: ev-triples-map, ? 1: evidence-id, ? 2: profile } */
static void concise_evidence(const uint8_t *p, size_t len, node_t *parent)
{
    cbor_t c = { p, p + len };
    uint64_t tag, n, i, tn, j, rn, mn, k;
    node_t *ce, *tr;

    if (!cbor_is_wellformed(p, len)) {
        node_style(node_add(parent, "ConciseEvidence", "malformed CBOR"), NS_ERR);
        node_add_hex(parent, "Raw", p, len);
        return;
    }
    if (cbor_peek(&c) == CBOR_TAG)
        cbor_tag(&c, &tag);
    if (!cbor_map(&c, &n)) {
        cbor_describe(parent, "ConciseEvidence", p, len);
        return;
    }
    ce = node_add(parent, "ConciseEvidence", "%zu bytes", len);
    for (i = 0; i < n; i++) {
        int64_t key;

        if (!cbor_int(&c, &key)) {
            cbor_render(&c, ce, "key");
            cbor_render(&c, ce, "value");
            continue;
        }
        if (key != 0 || !cbor_map(&c, &tn)) {
            cbor_render(&c, ce, key == 0 ? "EvidenceTriples" : key == 1 ? "EvidenceID" :
                                key == 2 ? "Profile" : "entry");
            continue;
        }
        for (j = 0; j < tn; j++) {
            int64_t tk;

            if (!cbor_int(&c, &tk)) {
                cbor_render(&c, ce, "key");
                cbor_render(&c, ce, "value");
                continue;
            }
            if (tk != 0 || !cbor_array(&c, &rn)) {
                cbor_render(&c, ce, tk == 0 ? "EvidenceTriples" : tk == 1 ? "IdentityTriples" :
                                    tk == 2 ? "AttestKeyTriples" : "triples");
                continue;
            }
            tr = node_add(ce, "EvidenceTriples", "%llu%s", (unsigned long long)rn,
                          rn ? "" : " (no measurements reported)");
            for (k = 0; k < rn; k++) {
                node_t *rec;
                char name[24];
                uint64_t m;

                snprintf(name, sizeof(name), "[%llu]", (unsigned long long)k);
                if (!cbor_array(&c, &m) || m != 2) {
                    cbor_render(&c, tr, name);
                    continue;
                }
                rec = node_add(tr, name, NULL);
                environment(&c, rec);
                if (!cbor_array(&c, &mn)) {
                    cbor_render(&c, rec, "Measurements");
                    continue;
                }
                {
                    uint64_t q;
                    node_t *ms = node_add(rec, "Measurements", "%llu", (unsigned long long)mn);

                    for (q = 0; q < mn; q++) {
                        snprintf(name, sizeof(name), "[%llu]", (unsigned long long)q);
                        measurement(&c, ms, name);
                    }
                }
            }
        }
    }
}

/* measurements claim: [ + [ content-format, bstr ] ] */
static void measurements_claim(cbor_t *c, node_t *parent)
{
    uint64_t n, i, two;
    node_t *m;
    cbor_t save = *c;

    if (!cbor_array(c, &n)) {
        cbor_render(c, parent, "measurements");
        return;
    }
    m = node_add(parent, "measurements", "%llu", (unsigned long long)n);
    for (i = 0; i < n; i++) {
        int64_t ct;
        const uint8_t *b;
        size_t bl;
        node_t *e;
        char name[24];

        snprintf(name, sizeof(name), "[%llu]", (unsigned long long)i);
        save = *c;
        if (!cbor_array(c, &two) || two != 2 || !cbor_int(c, &ct) ||
            !cbor_str(c, CBOR_BSTR, &b, &bl)) {
            *c = save;
            cbor_render(c, m, name);
            continue;
        }
        e = node_add(m, name, NULL);
        node_add(e, "ContentFormat", "%lld%s", (long long)ct,
                 ct == CT_CONCISE_EVIDENCE ? " (application/ce+cbor, TCG concise evidence)" : "");
        if (ct == CT_CONCISE_EVIDENCE)
            concise_evidence(b, bl, e);
        else if (!cbor_describe(e, "Content", b, bl))
            node_add_hex(e, "Content", b, bl);
    }
}

static void profile_claim(cbor_t *c, node_t *parent)
{
    uint64_t tag;
    const uint8_t *s;
    size_t sl;
    char oid[128];
    cbor_t save = *c;
    bool ascii = false;

    if (cbor_str(c, CBOR_TSTR, &s, &sl)) {
        snprintf(oid, sizeof(oid), "%.*s", (int)sl, s);
    } else if (cbor_tag(c, &tag) && tag == TAG_OID && cbor_str(c, CBOR_BSTR, &s, &sl)) {
        /* Seen in the field: the dotted string instead of DER content bytes */
        ascii = sl && s[0] >= '0' && s[0] <= '2' && memchr(s, '.', sl);
        if (ascii)
            snprintf(oid, sizeof(oid), "%.*s", (int)sl, s);
        else
            cbor_oid_str(s, sl, oid, sizeof(oid));
    } else {
        *c = save;
        cbor_render(c, parent, "eat_profile");
        return;
    }
    node_style(node_add(parent, "eat_profile", "%s%s", oid,
                        !strcmp(oid, OCP_EAT_PROFILE_OID) ? " (OCP EAT profile)" : ""),
               NS_HILITE);
    if (ascii)
        node_style(node_add(parent, "eat_profile note",
                            "non-standard: OID tag holds ASCII text, not DER"), NS_WARN);
}

static void claims(const uint8_t *p, size_t len, node_t *parent, const uint8_t *nonce,
                   size_t nonce_len, enum eat_nonce *match)
{
    cbor_t c = { p, p + len };
    uint64_t n, i;
    node_t *cl;

    if (!cbor_is_wellformed(p, len) || !cbor_map(&c, &n)) {
        if (!cbor_describe(parent, "Claims", p, len))
            node_add_hex(parent, "Payload", p, len);
        return;
    }
    cl = node_add(parent, "Claims", "%llu", (unsigned long long)n);
    for (i = 0; i < n; i++) {
        int64_t k, v;
        const uint8_t *b;
        size_t bl;
        char name[24];

        if (!cbor_int(&c, &k)) {
            cbor_render(&c, cl, "key");
            cbor_render(&c, cl, "value");
            continue;
        }
        switch (k) {
        case 10: /* eat_nonce */
            if (cbor_str(&c, CBOR_BSTR, &b, &bl)) {
                node_t *nn = node_add_hex(cl, "eat_nonce", b, bl);

                if (nonce) {
                    bool same = bl == nonce_len && !memcmp(b, nonce, bl);

                    node_style(nn, same ? NS_OK : NS_ERR);
                    node_style(node_add(cl, "eat_nonce check", same ?
                                        "matches the requester nonce" :
                                        "DIFFERS from the requester nonce"),
                               same ? NS_OK : NS_ERR);
                    if (match)
                        *match = same ? EAT_NONCE_MATCH : EAT_NONCE_DIFFERENT;
                }
            } else {
                cbor_render(&c, cl, "eat_nonce");
            }
            break;
        case 256: cbor_render(&c, cl, "ueid"); break;
        case 258: cbor_render(&c, cl, "oemid"); break;
        case 259: cbor_render(&c, cl, "hwmodel"); break;
        case 260: cbor_render(&c, cl, "hwversion"); break;
        case 261:
            if (cbor_int(&c, &v))
                node_add(cl, "uptime", "%lld s", (long long)v);
            else
                cbor_render(&c, cl, "uptime");
            break;
        case 263:
            if (cbor_int(&c, &v))
                node_style(node_add(cl, "dbgstat", "%lld (%s)", (long long)v,
                                    dbgstat_name(v) ? dbgstat_name(v) : "?"),
                           v == 0 ? NS_WARN : NS_NONE);
            else
                cbor_render(&c, cl, "dbgstat");
            break;
        case 265: profile_claim(&c, cl); break;
        case 267: cbor_render(&c, cl, "bootcount"); break;
        case 268: cbor_render(&c, cl, "bootseed"); break;
        case 270: text_or_generic(&c, cl, "swname", NS_HILITE); break;
        case 271: cbor_render(&c, cl, "swversion"); break;
        case 273: measurements_claim(&c, cl); break;
        default:
            snprintf(name, sizeof(name), "%lld", (long long)k);
            cbor_render(&c, cl, name);
        }
    }
}

/* COSE header map (protected or unprotected) */
static void header(cbor_t *c, node_t *parent, const char *key)
{
    uint64_t n, i;
    node_t *h;

    if (!cbor_map(c, &n)) {
        cbor_render(c, parent, key);
        return;
    }
    h = node_add(parent, key, NULL);
    for (i = 0; i < n; i++) {
        int64_t k, v;
        const uint8_t *b;
        size_t bl;

        if (!cbor_int(c, &k)) {
            cbor_render(c, h, "key");
            cbor_render(c, h, "value");
            continue;
        }
        if (k == 1 && cbor_int(c, &v))
            node_style(node_add(h, "alg", "%lld (%s)", (long long)v,
                                cose_alg_name(v) ? cose_alg_name(v) : "?"), NS_HILITE);
        else if (k == 4 && cbor_str(c, CBOR_BSTR, &b, &bl))
            node_add_hex(h, "kid", b, bl);
        else if (k == 3)
            cbor_render(c, h, "content type");
        else if (k == 33)
            cbor_render(c, h, "x5chain");
        else {
            char name[24];

            snprintf(name, sizeof(name), "%lld", (long long)k);
            cbor_render(c, h, name);
        }
    }
}

bool eat_describe(node_t *parent, const char *key, const uint8_t *p, size_t len,
                  const uint8_t *nonce, size_t nonce_len, enum eat_nonce *match)
{
    cbor_t c = { p, p + len };
    const uint8_t *b;
    size_t bl;
    node_t *e;

    if (match)
        *match = EAT_NONCE_NONE;
    if (!cbor_is_wellformed(p, len) || !enter_cose_sign1(&c))
        return false;
    e = node_add(parent, key, "OCP EAT, COSE_Sign1, %zu bytes", len);
    if (cbor_str(&c, CBOR_BSTR, &b, &bl)) {
        cbor_t h = { b, b + bl };

        if (!bl)
            node_add(e, "Protected", "empty");
        else if (cbor_is_wellformed(b, bl))
            header(&h, e, "Protected");
        else
            node_add_hex(e, "Protected", b, bl);
    } else {
        cbor_render(&c, e, "Protected");
    }
    header(&c, e, "Unprotected");
    if (cbor_str(&c, CBOR_BSTR, &b, &bl))
        claims(b, bl, e, nonce, nonce_len, match);
    else
        cbor_render(&c, e, "Payload");
    if (cbor_str(&c, CBOR_BSTR, &b, &bl))
        node_add_hex(e, "Signature", b, bl);
    else
        cbor_render(&c, e, "Signature");
    return true;
}
