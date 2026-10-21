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

#endif
