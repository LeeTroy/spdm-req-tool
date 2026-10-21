#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Lowercase hex string, caller frees. */
char *hex_string(const void *data, size_t len);
/* Classic 16-bytes-per-line hex dump, caller frees. */
char *hex_dump(const void *data, size_t len, const char *indent);

char *base64_encode(const uint8_t *data, size_t len);
/* Decodes base64, ignoring whitespace. Returns decoded length or -1. */
long base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_max);

int read_file(const char *path, uint8_t **data, size_t *len);
int write_file(const char *path, const void *data, size_t len);

static inline uint16_t get_le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t get_le24(const uint8_t *p) { return p[0] | (p[1] << 8) | ((uint32_t)p[2] << 16); }
static inline uint32_t get_le32(const uint8_t *p)
{
    return p[0] | (p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

bool str_ends_with(const char *s, const char *suffix);

#endif
