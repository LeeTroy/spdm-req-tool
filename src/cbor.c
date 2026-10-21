/* Minimal CBOR (RFC 8949) to node-tree decoder, used to show CBOR encoded
 * measurement blocks (e.g. signed EAT / COSE_Sign1 manifests) readably. */
#include <stdio.h>
#include <string.h>

#include "cbor.h"

#define CBOR_MAX_DEPTH 24

typedef struct {
    const uint8_t *p;
    const uint8_t *end;
} cb_t;

static bool head(cb_t *c, uint8_t *mt, uint8_t *ai, uint64_t *val)
{
    unsigned n, i;

    if (c->p >= c->end)
        return false;
    *mt = *c->p >> 5;
    *ai = *c->p & 0x1f;
    c->p++;
    if (*ai < 24) {
        *val = *ai;
        return true;
    }
    if (*ai == 31) { /* indefinite length / break */
        *val = 0;
        return *mt >= 2;
    }
    if (*ai > 27)
        return false;
    n = 1u << (*ai - 24);
    if ((size_t)(c->end - c->p) < n)
        return false;
    *val = 0;
    for (i = 0; i < n; i++)
        *val = (*val << 8) | *c->p++;
    return true;
}

/* Well-formedness check of one data item. */
static bool skip(cb_t *c, int depth)
{
    uint8_t mt, ai;
    uint64_t v, i;

    if (depth > CBOR_MAX_DEPTH || !head(c, &mt, &ai, &v))
        return false;
    if (ai == 31) {
        if (mt == 7)
            return false; /* stray break */
        for (;;) {
            if (c->p >= c->end)
                return false;
            if (*c->p == 0xff) {
                c->p++;
                return true;
            }
            if (!skip(c, depth + 1))
                return false;
            if (mt == 5 && !skip(c, depth + 1))
                return false;
        }
    }
    switch (mt) {
    case 0: case 1: case 7:
        return true;
    case 2: case 3:
        if ((uint64_t)(c->end - c->p) < v)
            return false;
        c->p += v;
        return true;
    case 4: case 5:
        for (i = 0; i < v * (mt == 5 ? 2 : 1); i++)
            if (!skip(c, depth + 1))
                return false;
        return true;
    case 6:
        return skip(c, depth + 1);
    }
    return false;
}

bool cbor_is_wellformed(const uint8_t *p, size_t len)
{
    cb_t c = { p, p + len };

    if (!len)
        return false;
    while (c.p < c.end)
        if (!skip(&c, 0))
            return false;
    return true;
}

static const char *tag_name(uint64_t t)
{
    switch (t) {
    case 0: return "date/time string";
    case 1: return "epoch time";
    case 16: return "COSE_Encrypt0";
    case 17: return "COSE_Mac0";
    case 18: return "COSE_Sign1";
    case 24: return "embedded CBOR";
    case 37: return "UUID";
    case 61: return "CWT";
    case 96: return "COSE_Encrypt";
    case 97: return "COSE_Mac";
    case 98: return "COSE_Sign";
    case 111: return "OID";
    case 500: return "CoRIM";
    case 501: return "unsigned CoRIM";
    case 502: return "signed CoRIM";
    case 506: return "CoMID";
    case 552: return "SVN";
    case 553: return "min-SVN";
    case 560: return "tagged-bytes";
    case 571: return "TCG concise evidence";
    case 55799: return "self-described CBOR";
    }
    return NULL;
}

/* EAT / CWT claim keys (RFC 8392, RFC 9711) and COSE header labels. */
static const char *label_name(int64_t k)
{
    switch (k) {
    case 256: return "ueid";
    case 257: return "sueids";
    case 258: return "oemid";
    case 259: return "hwmodel";
    case 260: return "hwversion";
    case 261: return "uptime";
    case 262: return "oemboot";
    case 263: return "dbgstat";
    case 264: return "location";
    case 265: return "eat_profile";
    case 266: return "submods";
    case 267: return "bootcount";
    case 268: return "bootseed";
    case 269: return "dloas";
    case 270: return "swname";
    case 271: return "swversion";
    case 272: return "manifests";
    case 273: return "measurements";
    case 274: return "measres";
    case 275: return "intuse";
    }
    return NULL;
}

static const char *cose_alg(int64_t a)
{
    switch (a) {
    case -7: return "ES256";
    case -35: return "ES384";
    case -36: return "ES512";
    case -37: return "PS256";
    case -38: return "PS384";
    case -39: return "PS512";
    case -8: return "EdDSA";
    }
    return NULL;
}

static void render(cb_t *c, node_t *parent, const char *key, int depth);

static bool is_text(const uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        if (p[i] < 0x20 || p[i] > 0x7e)
            return false;
    return true;
}

/* Renders a map key as a short label, or returns false for complex keys. */
static bool key_label(cb_t *c, char *buf, size_t size)
{
    cb_t save = *c;
    uint8_t mt, ai;
    uint64_t v;

    if (!head(c, &mt, &ai, &v) || ai == 31)
        goto complex;
    if (mt == 0 || mt == 1) {
        int64_t k = mt == 0 ? (int64_t)v : -1 - (int64_t)v;
        const char *n = label_name(k);

        if (n)
            snprintf(buf, size, "%lld (%s)", (long long)k, n);
        else
            snprintf(buf, size, "%lld", (long long)k);
        return true;
    }
    if (mt == 3 && v < size - 3 && is_text(c->p, v)) {
        snprintf(buf, size, "\"%.*s\"", (int)v, c->p);
        c->p += v;
        return true;
    }
complex:
    *c = save;
    return false;
}

static void render(cb_t *c, node_t *parent, const char *key, int depth)
{
    uint8_t mt, ai;
    uint64_t v, i;
    const uint8_t *start = c->p;
    node_t *n;
    char k[96];

    if (depth > CBOR_MAX_DEPTH || !head(c, &mt, &ai, &v)) {
        node_style(node_add(parent, key, "malformed CBOR"), NS_ERR);
        c->p = c->end;
        return;
    }
    switch (mt) {
    case 0:
        node_add(parent, key, "%llu", (unsigned long long)v);
        return;
    case 1: {
        int64_t x = -1 - (int64_t)v;
        const char *alg = cose_alg(x);

        if (alg)
            node_add(parent, key, "%lld (%s)", (long long)x, alg);
        else
            node_add(parent, key, "%lld", (long long)x);
        return;
    }
    case 2:
    case 3:
        if (ai == 31) {
            n = node_add(parent, key, "%s (indefinite)", mt == 2 ? "bstr" : "tstr");
            while (c->p < c->end && *c->p != 0xff)
                render(c, n, "chunk", depth + 1);
            c->p++;
            return;
        }
        if (mt == 3) {
            node_style(node_add(parent, key, "\"%.*s\"", (int)v, c->p), NS_HILITE);
        } else if (v >= 2 && cbor_is_wellformed(c->p, v) && (c->p[0] >> 5) >= 4) {
            /* bstr-wrapped CBOR (COSE protected header / payload) */
            cb_t inner = { c->p, c->p + v };

            n = node_add(parent, key, "bstr(%llu), embedded CBOR", (unsigned long long)v);
            while (inner.p < inner.end)
                render(&inner, n, "item", depth + 1);
        } else if (v && is_text(c->p, v) && v >= 4) {
            node_add(parent, key, "bstr(%llu) \"%.*s\"", (unsigned long long)v, (int)v, c->p);
        } else {
            node_add_hex(parent, key, c->p, v);
        }
        c->p += v;
        return;
    case 4:
        n = node_add(parent, key, ai == 31 ? "array(*)" : "array(%llu)", (unsigned long long)v);
        for (i = 0; ai == 31 ? (c->p < c->end && *c->p != 0xff) : i < v; i++) {
            snprintf(k, sizeof(k), "[%llu]", (unsigned long long)i);
            render(c, n, k, depth + 1);
        }
        if (ai == 31)
            c->p++;
        return;
    case 5:
        n = node_add(parent, key, ai == 31 ? "map(*)" : "map(%llu)", (unsigned long long)v);
        for (i = 0; ai == 31 ? (c->p < c->end && *c->p != 0xff) : i < v; i++) {
            if (key_label(c, k, sizeof(k))) {
                render(c, n, k, depth + 1);
            } else {
                node_t *e = node_add(n, "entry", NULL);

                render(c, e, "key", depth + 1);
                render(c, e, "value", depth + 1);
            }
        }
        if (ai == 31)
            c->p++;
        return;
    case 6: {
        const char *tn = tag_name(v);

        n = node_add(parent, key, "tag %llu%s%s%s", (unsigned long long)v, tn ? " (" : "",
                     tn ? tn : "", tn ? ")" : "");
        if (v == 111 && c->p < c->end && (*c->p >> 5) == 2) {
            /* OID: show dotted form */
            uint8_t m2, a2;
            uint64_t l2;
            char dotted[128];
            size_t off = 0, j;
            uint64_t acc = 0;
            bool first = true;

            head(c, &m2, &a2, &l2);
            if (l2 && l2 <= (uint64_t)(c->end - c->p) && is_text(c->p, l2) &&
                c->p[0] >= '0' && c->p[0] <= '2' && memchr(c->p, '.', l2)) {
                /* Seen in the field: the dotted string instead of DER content bytes */
                node_add(n, "oid", "%.*s", (int)l2, c->p);
                node_style(node_add(n, "note", "non-standard: OID tag holds ASCII text, not DER"),
                           NS_WARN);
                c->p += l2;
                return;
            }
            for (j = 0; j < l2 && off + 24 < sizeof(dotted); j++) {
                acc = (acc << 7) | (c->p[j] & 0x7f);
                if (c->p[j] & 0x80)
                    continue;
                if (first) {
                    uint64_t a = acc < 80 ? acc / 40 : 2;

                    off += snprintf(dotted + off, sizeof(dotted) - off, "%llu.%llu",
                                    (unsigned long long)a, (unsigned long long)(acc - a * 40));
                    first = false;
                } else {
                    off += snprintf(dotted + off, sizeof(dotted) - off, ".%llu",
                                    (unsigned long long)acc);
                }
                acc = 0;
            }
            c->p += l2;
            node_add(n, "oid", "%s", dotted);
            return;
        }
        render(c, n, "content", depth + 1);
        return;
    }
    case 7:
        switch (ai) {
        case 20: node_add(parent, key, "false"); return;
        case 21: node_add(parent, key, "true"); return;
        case 22: node_add(parent, key, "null"); return;
        case 23: node_add(parent, key, "undefined"); return;
        case 25: case 26: case 27:
            node_add_hex(parent, key, start + 1, c->p - start - 1);
            return;
        }
        node_add(parent, key, "simple(%llu)", (unsigned long long)v);
        return;
    }
}

bool cbor_describe(node_t *parent, const char *key, const uint8_t *p, size_t len)
{
    cb_t c = { p, p + len };
    node_t *n;

    if (!cbor_is_wellformed(p, len))
        return false;
    n = node_add(parent, key, "CBOR, %zu bytes", len);
    while (c.p < c.end)
        render(&c, n, "item", 0);
    return true;
}
