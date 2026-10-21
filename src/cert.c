#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "library/spdm_crypt_lib.h"
#include "hal/library/cryptlib.h"

#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/asn1.h"
#include "mbedtls/oid.h"

#include "cert.h"
#include "util.h"

#define PEM_BEGIN "-----BEGIN CERTIFICATE-----"
#define PEM_END   "-----END CERTIFICATE-----"

int cert_load_file(const char *path, struct cert_list *out)
{
    uint8_t *data;
    size_t len;
    const char *p;
    int rc;

    memset(out, 0, sizeof(*out));
    rc = read_file(path, &data, &len);
    if (rc)
        return rc;

    p = strstr((const char *)data, PEM_BEGIN);
    if (!p) {
        /* DER: a single certificate starting with a SEQUENCE tag */
        if (len < 4 || data[0] != 0x30) {
            free(data);
            return -EINVAL;
        }
        out->der[0] = data;
        out->len[0] = len;
        out->count = 1;
        return 0;
    }
    while (p && out->count < CERT_LIST_MAX) {
        const char *b = p + strlen(PEM_BEGIN);
        const char *e = strstr(b, PEM_END);
        uint8_t *der;
        long n;

        if (!e)
            break;
        der = malloc(e - b);
        if (!der)
            break;
        n = base64_decode(b, e - b, der, e - b);
        if (n <= 0) {
            free(der);
            break;
        }
        out->der[out->count] = der;
        out->len[out->count] = (size_t)n;
        out->count++;
        p = strstr(e, PEM_BEGIN);
    }
    free(data);
    return out->count ? 0 : -EINVAL;
}

void cert_list_free(struct cert_list *l)
{
    int i;

    for (i = 0; i < l->count; i++)
        free(l->der[i]);
    memset(l, 0, sizeof(*l));
}

static int append_pem(FILE *f, const uint8_t *der, size_t len)
{
    char *b64 = base64_encode(der, len);
    size_t i, n;

    if (!b64)
        return -ENOMEM;
    n = strlen(b64);
    fprintf(f, "%s\n", PEM_BEGIN);
    for (i = 0; i < n; i += 64)
        fprintf(f, "%.64s\n", b64 + i);
    fprintf(f, "%s\n", PEM_END);
    free(b64);
    return 0;
}

int cert_save_file(const char *path, const uint8_t *der, size_t len)
{
    FILE *f;
    int rc;

    if (str_ends_with(path, ".der"))
        return write_file(path, der, len);
    f = fopen(path, "w");
    if (!f)
        return -errno;
    rc = append_pem(f, der, len);
    if (fclose(f) && !rc)
        rc = -errno;
    return rc;
}

int cert_save_pem_bundle(const char *path, const struct cert_list *l)
{
    FILE *f = fopen(path, "w");
    int i, rc = 0;

    if (!f)
        return -errno;
    for (i = 0; i < l->count && !rc; i++)
        rc = append_pem(f, l->der[i], l->len[i]);
    if (fclose(f) && !rc)
        rc = -errno;
    return rc;
}

static bool chain_certs(const uint8_t *chain, size_t len, uint32_t hash_size,
                        const uint8_t **certs, size_t *certs_len)
{
    size_t hdr = 4 + hash_size;

    if (len <= hdr)
        return false;
    *certs = chain + hdr;
    *certs_len = len - hdr;
    return true;
}

bool cert_chain_get(const uint8_t *chain, size_t len, uint32_t hash_size, int index,
                    const uint8_t **der, size_t *der_len)
{
    const uint8_t *certs;
    size_t clen;

    if (!chain_certs(chain, len, hash_size, &certs, &clen))
        return false;
    return libspdm_x509_get_cert_from_cert_chain(certs, clen, index, der, der_len);
}

int cert_chain_count(const uint8_t *chain, size_t len, uint32_t hash_size)
{
    const uint8_t *der;
    size_t dlen;
    int n = 0;

    while (cert_chain_get(chain, len, hash_size, n, &der, &dlen))
        n++;
    return n;
}

/* libspdm's mbedTLS build stubs out snprintf (my_snprintf returns 0), so the
 * mbedTLS formatters (x509_dn_gets, crt_info, ...) produce empty strings.
 * Format the parsed fields here instead. */

struct oid_name {
    const char *der; /* OID content bytes */
    size_t len;
    const char *name;
};

#define OID(s, n) { s, sizeof(s) - 1, n }
static const struct oid_name oid_names[] = {
    OID("\x55\x04\x03", "CN"),
    OID("\x55\x04\x05", "serialNumber"),
    OID("\x55\x04\x06", "C"),
    OID("\x55\x04\x07", "L"),
    OID("\x55\x04\x08", "ST"),
    OID("\x55\x04\x0a", "O"),
    OID("\x55\x04\x0b", "OU"),
    OID("\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01", "emailAddress"),
    OID("\x55\x1d\x0e", "SubjectKeyIdentifier"),
    OID("\x55\x1d\x0f", "KeyUsage"),
    OID("\x55\x1d\x11", "SubjectAltName"),
    OID("\x55\x1d\x13", "BasicConstraints"),
    OID("\x55\x1d\x1f", "CRLDistributionPoints"),
    OID("\x55\x1d\x20", "CertificatePolicies"),
    OID("\x55\x1d\x23", "AuthorityKeyIdentifier"),
    OID("\x55\x1d\x25", "ExtendedKeyUsage"),
    OID("\x67\x81\x05\x05\x04\x01", "TCG DICE TcbInfo"),
    OID("\x67\x81\x05\x05\x04\x04", "TCG DICE UEID"),
    OID("\x67\x81\x05\x05\x04\x05", "TCG DICE MultiTcbInfo"),
    OID("\x67\x81\x05\x05\x04\x64\x06", "tcg-dice-kp-identityInit"),
    OID("\x67\x81\x05\x05\x04\x64\x07", "tcg-dice-kp-identityLoc"),
    OID("\x67\x81\x05\x05\x04\x64\x09", "tcg-dice-kp-attestInit"),
    OID("\x67\x81\x05\x05\x04\x64\x0c", "tcg-dice-kp-eca"),
    OID("\x2b\x06\x01\x04\x01\x83\x1c\x82\x12\x01", "DMTF SPDM hardware identity"),
    OID("\x2b\x06\x01\x04\x01\x83\x1c\x82\x12\x02", "DMTF SPDM device info"),
    OID("\x2b\x06\x01\x04\x01\x83\x1c\x82\x12\x03", "DMTF SPDM requester auth"),
    OID("\x2b\x06\x01\x04\x01\x83\x1c\x82\x12\x04", "DMTF SPDM responder auth"),
    OID("\x2b\x06\x01\x04\x01\x83\x1c\x82\x12\x06", "DMTF SPDM extension"),
    OID("\x2a\x86\x48\xce\x3d\x04\x03\x02", "ecdsa-with-SHA256"),
    OID("\x2a\x86\x48\xce\x3d\x04\x03\x03", "ecdsa-with-SHA384"),
    OID("\x2a\x86\x48\xce\x3d\x04\x03\x04", "ecdsa-with-SHA512"),
    OID("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b", "sha256WithRSAEncryption"),
    OID("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c", "sha384WithRSAEncryption"),
    OID("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d", "sha512WithRSAEncryption"),
    OID("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a", "RSASSA-PSS"),
    OID("\x2b\x65\x70", "Ed25519"),
    OID("\x2b\x65\x71", "Ed448"),
};
#undef OID

static void oid_to_dotted(const unsigned char *p, size_t len, char *buf, size_t size)
{
    size_t off = 0, i = 0;
    unsigned long v = 0;
    bool first = true;

    buf[0] = '\0';
    for (i = 0; i < len && off + 24 < size; i++) {
        v = (v << 7) | (p[i] & 0x7f);
        if (p[i] & 0x80)
            continue;
        if (first) {
            unsigned long a = v < 80 ? v / 40 : 2;

            off += sprintf(buf + off, "%lu.%lu", a, v - a * 40);
            first = false;
        } else {
            off += sprintf(buf + off, ".%lu", v);
        }
        v = 0;
    }
}

static const char *oid_name(const unsigned char *p, size_t len, char *tmp, size_t size)
{
    size_t i;

    for (i = 0; i < sizeof(oid_names) / sizeof(oid_names[0]); i++)
        if (oid_names[i].len == len && !memcmp(oid_names[i].der, p, len))
            return oid_names[i].name;
    oid_to_dotted(p, len, tmp, size);
    return tmp;
}

static void dn_string(const mbedtls_x509_name *n, char *buf, size_t size)
{
    size_t off = 0;

    buf[0] = '\0';
    for (; n && off < size; n = n->next) {
        char tmp[64];
        const char *k = oid_name(n->oid.p, n->oid.len, tmp, sizeof(tmp));
        size_t vl = n->val.len, j;

        if (!n->oid.p)
            continue;
        off += snprintf(buf + off, size - off, "%s%s=", off ? ", " : "", k);
        for (j = 0; j < vl && off + 1 < size; j++) {
            unsigned char ch = n->val.p[j];

            buf[off++] = (ch >= 0x20 && ch < 0x7f) ? (char)ch : '?';
        }
        if (off < size)
            buf[off] = '\0';
    }
    if (off >= size)
        buf[size - 1] = '\0';
}

void cert_subject(const uint8_t *der, size_t len, char *buf, size_t size)
{
    mbedtls_x509_crt crt;

    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse_der(&crt, der, len) == 0)
        dn_string(&crt.subject, buf, size);
    else
        snprintf(buf, size, "(unparsable certificate)");
    mbedtls_x509_crt_free(&crt);
}

bool cert_is_self_signed(const uint8_t *der, size_t len)
{
    return libspdm_is_root_certificate(der, len);
}

static void add_time(node_t *n, const char *key, const mbedtls_x509_time *t)
{
    node_add(n, key, "%04d-%02d-%02d %02d:%02d:%02d UTC", t->year, t->mon, t->day, t->hour,
             t->min, t->sec);
}

static void add_key_usage(node_t *n, unsigned int ku)
{
    static const struct { unsigned int bit; const char *name; } kus[] = {
        { MBEDTLS_X509_KU_DIGITAL_SIGNATURE, "digitalSignature" },
        { MBEDTLS_X509_KU_NON_REPUDIATION, "nonRepudiation" },
        { MBEDTLS_X509_KU_KEY_ENCIPHERMENT, "keyEncipherment" },
        { MBEDTLS_X509_KU_DATA_ENCIPHERMENT, "dataEncipherment" },
        { MBEDTLS_X509_KU_KEY_AGREEMENT, "keyAgreement" },
        { MBEDTLS_X509_KU_KEY_CERT_SIGN, "keyCertSign" },
        { MBEDTLS_X509_KU_CRL_SIGN, "cRLSign" },
    };
    char buf[160];
    size_t off = 0, i;

    buf[0] = '\0';
    for (i = 0; i < sizeof(kus) / sizeof(kus[0]); i++)
        if (ku & kus[i].bit)
            off += snprintf(buf + off, sizeof(buf) - off, "%s%s", off ? ", " : "", kus[i].name);
    node_add(n, "KeyUsage", "%s", off ? buf : "(none)");
}

/* Walks Extensions ::= SEQUENCE OF Extension { extnID, critical, extnValue } */
static void add_extensions(node_t *parent, const mbedtls_x509_buf *v3)
{
    unsigned char *p = v3->p, *end = v3->p + v3->len;
    size_t len;
    node_t *n;

    if (!v3->p || !v3->len)
        return;
    /* v3_ext covers the [3] EXPLICIT wrapper; step into it if present */
    if (*p == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 3) &&
        mbedtls_asn1_get_tag(&p, end, &len,
                             MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 3))
        return;
    if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
        return;
    end = p + len;
    n = node_add(parent, "Extensions", NULL);
    while (p < end) {
        unsigned char *ext_end, *oid;
        size_t oid_len;
        int critical = 0;
        char tmp[64];
        node_t *e;

        if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
            return;
        ext_end = p + len;
        if (mbedtls_asn1_get_tag(&p, ext_end, &oid_len, MBEDTLS_ASN1_OID))
            return;
        oid = p;
        p += oid_len;
        mbedtls_asn1_get_bool(&p, ext_end, &critical);
        if (mbedtls_asn1_get_tag(&p, ext_end, &len, MBEDTLS_ASN1_OCTET_STRING))
            return;
        e = node_add(n, oid_name(oid, oid_len, tmp, sizeof(tmp)), "%zu bytes%s", len,
                     critical ? ", critical" : "");
        node_add_hex(e, "Value", p, len);
        p = ext_end;
    }
}

node_t *cert_describe(node_t *parent, const char *key, const uint8_t *der, size_t len)
{
    mbedtls_x509_crt crt;
    char buf[1024], tmp[64];
    uint8_t fp[32];
    node_t *n;
    int rc;

    mbedtls_x509_crt_init(&crt);
    rc = mbedtls_x509_crt_parse_der(&crt, der, len);
    if (rc) {
        n = node_add(parent, key, "unparsable certificate (mbedtls -0x%04x), %zu bytes", -rc, len);
        node_style(n, NS_ERR);
        node_add_hex(n, "DER", der, len);
        mbedtls_x509_crt_free(&crt);
        return n;
    }

    dn_string(&crt.subject, buf, sizeof(buf));
    n = node_add(parent, key, "%s", buf);
    node_style(n, NS_HILITE);
    node_add(n, "Subject", "%s", buf);
    dn_string(&crt.issuer, buf, sizeof(buf));
    node_add(n, "Issuer", "%s", buf);
    node_add(n, "Version", "v%d", crt.version);
    node_add_hex(n, "SerialNumber", crt.serial.p, crt.serial.len);
    add_time(n, "NotBefore", &crt.valid_from);
    add_time(n, "NotAfter", &crt.valid_to);
    if (mbedtls_x509_time_is_past(&crt.valid_to))
        node_style(node_add(n, "Validity", "EXPIRED"), NS_ERR);
    else if (mbedtls_x509_time_is_future(&crt.valid_from))
        node_style(node_add(n, "Validity", "NOT YET VALID"), NS_WARN);
    node_add(n, "PublicKey", "%s %zu bits", mbedtls_pk_get_name(&crt.pk),
             mbedtls_pk_get_bitlen(&crt.pk));
    node_add(n, "SignatureAlgorithm", "%s", oid_name(crt.sig_oid.p, crt.sig_oid.len, tmp, sizeof(tmp)));
    if (crt.MBEDTLS_PRIVATE(ext_types) & MBEDTLS_X509_EXT_BASIC_CONSTRAINTS) {
        if (crt.MBEDTLS_PRIVATE(ca_istrue) && crt.MBEDTLS_PRIVATE(max_pathlen) > 0)
            node_add(n, "BasicConstraints", "CA=true, pathlen=%d", crt.MBEDTLS_PRIVATE(max_pathlen) - 1);
        else
            node_add(n, "BasicConstraints", "CA=%s", crt.MBEDTLS_PRIVATE(ca_istrue) ? "true" : "false");
    }
    if (crt.MBEDTLS_PRIVATE(ext_types) & MBEDTLS_X509_EXT_KEY_USAGE)
        add_key_usage(n, crt.MBEDTLS_PRIVATE(key_usage));
    node_add(n, "SelfSigned", "%s", libspdm_is_root_certificate(der, len) ? "yes (root CA)" : "no");
    node_add(n, "Size", "%zu bytes", len);
    if (libspdm_hash_all(SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, der, len, fp))
        node_add_hex(n, "SHA256Fingerprint", fp, sizeof(fp));
    add_extensions(n, &crt.v3_ext);
    mbedtls_x509_crt_free(&crt);
    return n;
}

void cert_chain_describe(node_t *parent, const uint8_t *chain, size_t len, uint32_t hash_algo)
{
    uint32_t hs = libspdm_get_hash_size(hash_algo);
    const uint8_t *der;
    size_t dlen;
    uint8_t h[64];
    int i, count;
    node_t *n;

    if (len < 4 + hs) {
        node_style(node_add(parent, "CertChain", "too short (%zu bytes)", len), NS_ERR);
        return;
    }
    n = node_add(parent, "CertChain", "%zu bytes", len);
    node_add(n, "Length", "%u", get_le32(chain));
    node_add_hex(n, "RootHash", chain + 4, hs);
    if (cert_chain_get(chain, len, hs, 0, &der, &dlen) && libspdm_hash_all(hash_algo, der, dlen, h)) {
        if (memcmp(h, chain + 4, hs) == 0)
            node_style(node_add(n, "RootHashCheck", "matches hash of certificate[0]"), NS_OK);
        else
            node_style(node_add(n, "RootHashCheck",
                                "differs from certificate[0] (root CA not included in chain)"),
                       NS_WARN);
    }
    count = cert_chain_count(chain, len, hs);
    node_add(n, "Certificates", "%d", count);
    for (i = 0; i < count; i++) {
        char key[48];

        if (!cert_chain_get(chain, len, hs, i, &der, &dlen))
            break;
        snprintf(key, sizeof(key), "Certificate[%d]%s", i,
                 i == count - 1 ? " (leaf)" :
                 i == 0 && libspdm_is_root_certificate(der, dlen) ? " (root CA)" :
                 " (intermediate)");
        cert_describe(n, key, der, dlen);
    }
}
