/* OCP EAT decoder: an RFC 9711 EAT in a COSE_Sign1 CWT with TCG concise
 * evidence measurements (OCP Attestation profile, as returned by Caliptra
 * GET_ATTESTATION or carried in an SPDM measurement block). */
#ifndef EAT_H
#define EAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "node.h"

enum eat_nonce { EAT_NONCE_NONE = -1, EAT_NONCE_DIFFERENT = 0, EAT_NONCE_MATCH = 1 };

/* Quick check: p starts a COSE_Sign1 (optionally behind tags 55799 / 61). */
bool eat_is_cose_sign1(const uint8_t *p, size_t len);

/* Adds a named-field view of the EAT under parent as key. When nonce is
 * given, the eat_nonce claim is compared with it and *match is set.
 * Returns false (adding nothing) if p is not a COSE_Sign1 EAT. */
bool eat_describe(node_t *parent, const char *key, const uint8_t *p, size_t len,
                  const uint8_t *nonce, size_t nonce_len, enum eat_nonce *match);

#endif
