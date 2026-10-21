/* X.509 / SPDM certificate chain helpers. */
#ifndef CERT_H
#define CERT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "node.h"

#define CERT_LIST_MAX 10

struct cert_list {
    int count;
    uint8_t *der[CERT_LIST_MAX];
    size_t len[CERT_LIST_MAX];
};

/* Loads one or more certificates from a PEM (possibly multi-cert) or DER file. */
int cert_load_file(const char *path, struct cert_list *out);
void cert_list_free(struct cert_list *l);

/* Writes a DER certificate; PEM unless the path ends in ".der". */
int cert_save_file(const char *path, const uint8_t *der, size_t len);
/* Writes several DER certificates as one PEM bundle. */
int cert_save_pem_bundle(const char *path, const struct cert_list *l);

/* Extracts certificate #index (0 = root, -1 = leaf) from an SPDM cert chain
 * (Length/Reserved/RootHash header followed by DER certificates). */
bool cert_chain_get(const uint8_t *chain, size_t len, uint32_t hash_size, int index,
                    const uint8_t **der, size_t *der_len);
int cert_chain_count(const uint8_t *chain, size_t len, uint32_t hash_size);

/* Adds a human-readable description of a DER certificate. */
node_t *cert_describe(node_t *parent, const char *key, const uint8_t *der, size_t len);
/* Adds a description of a whole SPDM certificate chain. */
void cert_chain_describe(node_t *parent, const uint8_t *chain, size_t len, uint32_t hash_algo);

/* Short subject string ("CN=..., O=...") for a DER certificate. */
void cert_subject(const uint8_t *der, size_t len, char *buf, size_t size);
bool cert_is_self_signed(const uint8_t *der, size_t len);

#endif
