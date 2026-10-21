/* Output layer: renders tool events either as human-readable (optionally
 * colored) text or as JSON lines consumed by the spdm-demo TUI. */
#ifndef OUTPUT_H
#define OUTPUT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "node.h"

enum out_mode { OUT_TEXT, OUT_JSON };

enum out_status { ST_OK, ST_WARN, ST_FAIL, ST_SKIP };

struct out_cfg {
    enum out_mode mode;
    bool color;
    int verbose;   /* 0: results only, 1: + decoded messages */
    bool hex;      /* raw hex dump of every message */
    bool quiet;
};

extern struct out_cfg g_out;

void out_init(enum out_mode mode, int color /* -1 auto */, int verbose, bool hex, bool quiet);

void out_banner(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void out_step_begin(const char *id, const char *title);
void out_step_end(const char *id, enum out_status st, node_t *result, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
void out_msg(bool tx, const uint32_t *session_id, const char *name, uint8_t version,
             const void *raw, size_t raw_len, const node_t *tree);
void out_transport(bool tx, uint8_t mctp_type, uint8_t eid, size_t len);
void out_log(enum out_status lvl, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void out_done(enum out_status st, int passed, int warned, int failed);

const char *status_name(enum out_status st);

#endif
