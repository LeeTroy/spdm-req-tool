#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

char *hex_string(const void *data, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    const uint8_t *p = data;
    char *s = malloc(len * 2 + 1);
    size_t i;

    if (!s)
        return NULL;
    for (i = 0; i < len; i++) {
        s[i * 2] = digits[p[i] >> 4];
        s[i * 2 + 1] = digits[p[i] & 0xf];
    }
    s[len * 2] = '\0';
    return s;
}

char *hex_dump(const void *data, size_t len, const char *indent)
{
    const uint8_t *p = data;
    size_t lines = (len + 15) / 16;
    size_t cap = lines * (strlen(indent) + 80) + 1;
    char *s = malloc(cap);
    size_t off = 0, i, j;

    if (!s)
        return NULL;
    s[0] = '\0';
    for (i = 0; i < len; i += 16) {
        off += snprintf(s + off, cap - off, "%s%04zx: ", indent, i);
        for (j = 0; j < 16; j++) {
            if (i + j < len)
                off += snprintf(s + off, cap - off, "%02x ", p[i + j]);
            else
                off += snprintf(s + off, cap - off, "   ");
        }
        off += snprintf(s + off, cap - off, " ");
        for (j = 0; j < 16 && i + j < len; j++)
            s[off++] = isprint(p[i + j]) ? (char)p[i + j] : '.';
        s[off++] = '\n';
        s[off] = '\0';
    }
    return s;
}

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(const uint8_t *data, size_t len)
{
    size_t out_len = ((len + 2) / 3) * 4;
    char *out = malloc(out_len + 1);
    size_t i, o = 0;

    if (!out)
        return NULL;
    for (i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)data[i] << 16;

        if (i + 1 < len)
            v |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len)
            v |= data[i + 2];
        out[o++] = b64[(v >> 18) & 0x3f];
        out[o++] = b64[(v >> 12) & 0x3f];
        out[o++] = i + 1 < len ? b64[(v >> 6) & 0x3f] : '=';
        out[o++] = i + 2 < len ? b64[v & 0x3f] : '=';
    }
    out[o] = '\0';
    return out;
}

long base64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_max)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0, i;

    for (i = 0; i < in_len; i++) {
        const char *pos;
        char c = in[i];

        if (c == '=')
            break;
        if (isspace((unsigned char)c))
            continue;
        pos = strchr(b64, c);
        if (!pos || !c)
            return -1;
        acc = (acc << 6) | (uint32_t)(pos - b64);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= out_max)
                return -1;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    return (long)o;
}

int read_file(const char *path, uint8_t **data, size_t *len)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    long size;

    if (!f)
        return -errno;
    if (fseek(f, 0, SEEK_END) || (size = ftell(f)) < 0 || fseek(f, 0, SEEK_SET)) {
        fclose(f);
        return -EIO;
    }
    buf = malloc(size + 1);
    if (!buf) {
        fclose(f);
        return -ENOMEM;
    }
    if (fread(buf, 1, size, f) != (size_t)size) {
        free(buf);
        fclose(f);
        return -EIO;
    }
    buf[size] = '\0';
    fclose(f);
    *data = buf;
    *len = size;
    return 0;
}

int write_file(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");

    if (!f)
        return -errno;
    if (fwrite(data, 1, len, f) != len) {
        fclose(f);
        return -EIO;
    }
    return fclose(f) ? -errno : 0;
}

bool str_ends_with(const char *s, const char *suffix)
{
    size_t ls = strlen(s), lx = strlen(suffix);

    return ls >= lx && strcasecmp(s + ls - lx, suffix) == 0;
}
