/* Human-readable decoding of SPDM messages (DSP0274 1.0 - 1.4). */
#ifndef DECODE_H
#define DECODE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "node.h"

/* Called by the transport tap for every plaintext SPDM message. */
void decode_and_report(void *ctx, bool tx, const uint32_t *session_id, const void *msg,
                       size_t len);

/* Last plaintext response received with the given response code (or NULL). */
const uint8_t *decode_last_response(uint8_t code, size_t *len);

/* Decodes one SPDM message into a tree. */
node_t *spdm_decode(void *ctx, bool is_request, const uint8_t *msg, size_t len);

const char *spdm_code_name(uint8_t code);
const char *spdm_error_name(uint8_t code);

/* Shared helpers used by the command result summaries. */
void decode_caps(node_t *parent, const char *key, uint32_t flags, bool is_request);
void decode_versions(node_t *parent, const uint8_t *entries, int count);
const char *asym_name(uint32_t bit);
const char *hash_name(uint32_t bit);
const char *meas_hash_name(uint32_t bit);
const char *dhe_name(uint32_t bit);
const char *aead_name(uint32_t bit);
char *bits_to_names(uint32_t mask, const char *(*name)(uint32_t));
void decode_meas_record(node_t *parent, const uint8_t *rec, size_t len, unsigned nblocks);
void decode_opaque(node_t *parent, const uint8_t *data, size_t len, uint8_t version);

#endif
