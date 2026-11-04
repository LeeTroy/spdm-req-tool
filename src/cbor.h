/* Minimal CBOR (RFC 8949) decoder rendering into a node tree. */
#ifndef CBOR_H
#define CBOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "node.h"

bool cbor_is_wellformed(const uint8_t *p, size_t len);
/* Adds a decoded view of p under parent; returns false if p is not CBOR. */
bool cbor_describe(node_t *parent, const char *key, const uint8_t *p, size_t len);

/* Cursor over well-formed CBOR for structure-aware decoders. The getters
 * consume one item and return false (consuming nothing) on a type mismatch;
 * containers must have definite lengths. */
typedef struct {
    const uint8_t *p;
    const uint8_t *end;
} cbor_t;

enum { CBOR_UINT, CBOR_NINT, CBOR_BSTR, CBOR_TSTR, CBOR_ARRAY, CBOR_MAP, CBOR_TAG, CBOR_SIMPLE };

/* Major type of the next item, or -1 at the end. */
int cbor_peek(const cbor_t *c);
bool cbor_skip(cbor_t *c);
bool cbor_int(cbor_t *c, int64_t *v);
/* bstr or tstr, according to mt */
bool cbor_str(cbor_t *c, int mt, const uint8_t **p, size_t *len);
bool cbor_array(cbor_t *c, uint64_t *count);
bool cbor_map(cbor_t *c, uint64_t *count);
bool cbor_tag(cbor_t *c, uint64_t *tag);
/* Generic rendering of the next item (as cbor_describe does). */
void cbor_render(cbor_t *c, node_t *parent, const char *key);
/* Dotted form of DER OID content bytes. */
void cbor_oid_str(const uint8_t *p, size_t len, char *buf, size_t size);

#endif
