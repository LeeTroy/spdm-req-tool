#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "output.h"
#include "util.h"

struct out_cfg g_out;

#define C_RESET  "\033[0m"
#define C_BOLD   "\033[1m"
#define C_DIM    "\033[2m"
#define C_RED    "\033[31m"
#define C_GREEN  "\033[32m"
#define C_YELLOW "\033[33m"
#define C_BLUE   "\033[34m"
#define C_MAGENTA "\033[35m"
#define C_CYAN   "\033[36m"

static const char *c(const char *code)
{
    return g_out.color ? code : "";
}

static double now_s(void)
{
    static struct timeval t0;
    struct timeval t;

    gettimeofday(&t, NULL);
    if (!t0.tv_sec)
        t0 = t;
    return (t.tv_sec - t0.tv_sec) + (t.tv_usec - t0.tv_usec) / 1e6;
}

void out_init(enum out_mode mode, int color, int verbose, bool hex, bool quiet)
{
    g_out.mode = mode;
    g_out.verbose = verbose;
    g_out.hex = hex;
    g_out.quiet = quiet;
    if (color < 0)
        g_out.color = isatty(STDOUT_FILENO) && !getenv("NO_COLOR");
    else
        g_out.color = color;
    if (mode == OUT_JSON)
        g_out.color = false;
    now_s();
}

const char *status_name(enum out_status st)
{
    switch (st) {
    case ST_OK:   return "ok";
    case ST_WARN: return "warn";
    case ST_FAIL: return "fail";
    case ST_SKIP: return "skip";
    }
    return "?";
}

/* ------------------------------------------------------------------ JSON */

static void json_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (; s && *s; s++) {
        unsigned char ch = (unsigned char)*s;

        switch (ch) {
        case '"':  fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n", f); break;
        case '\r': fputs("\\r", f); break;
        case '\t': fputs("\\t", f); break;
        default:
            if (ch < 0x20)
                fprintf(f, "\\u%04x", ch);
            else
                fputc(ch, f);
        }
    }
    fputc('"', f);
}

static const char *style_name(int s)
{
    switch (s) {
    case NS_OK:     return "ok";
    case NS_WARN:   return "warn";
    case NS_ERR:    return "err";
    case NS_HEX:    return "hex";
    case NS_HILITE: return "hi";
    }
    return NULL;
}

static void json_tree(FILE *f, const node_t *n)
{
    fputc('[', f);
    for (; n; n = n->next) {
        fputs("{\"k\":", f);
        json_str(f, n->key);
        if (n->val) {
            fputs(",\"v\":", f);
            json_str(f, n->val);
        }
        if (style_name(n->style)) {
            fputs(",\"s\":", f);
            json_str(f, style_name(n->style));
        }
        if (n->child) {
            fputs(",\"c\":", f);
            json_tree(f, n->child);
        }
        fputc('}', f);
        if (n->next)
            fputc(',', f);
    }
    fputc(']', f);
}

static void json_begin(const char *ev)
{
    printf("{\"ev\":\"%s\",\"t\":%.3f", ev, now_s());
}

static void json_end(void)
{
    fputs("}\n", stdout);
    fflush(stdout);
}

/* ------------------------------------------------------------------ text */

static const char *style_color(int s)
{
    switch (s) {
    case NS_OK:     return C_GREEN;
    case NS_WARN:   return C_YELLOW;
    case NS_ERR:    return C_RED;
    case NS_HEX:    return C_DIM;
    case NS_HILITE: return C_BOLD;
    }
    return "";
}

static void text_hex_value(const char *hex, int indent)
{
    size_t len = strlen(hex), i;
    const size_t per_line = 64; /* 32 bytes */

    if (len <= per_line) {
        printf("%s%s%s\n", c(C_DIM), hex, c(C_RESET));
        return;
    }
    putchar('\n');
    for (i = 0; i < len; i += per_line)
        printf("%*s%s%.*s%s\n", indent + 2, "", c(C_DIM), (int)per_line, hex + i, c(C_RESET));
}

static void text_tree(const node_t *n, int indent)
{
    for (; n; n = n->next) {
        printf("%*s", indent, "");
        if (n->val) {
            printf("%s%s:%s ", c(C_CYAN), n->key, c(C_RESET));
            if (n->style == NS_HEX)
                text_hex_value(n->val, indent);
            else
                printf("%s%s%s\n", c(style_color(n->style)), n->val, c(C_RESET));
        } else {
            printf("%s%s%s%s\n", c(C_BOLD), c(style_color(n->style)), n->key, c(C_RESET));
        }
        if (n->child)
            text_tree(n->child, indent + 2);
    }
}

static void text_status(enum out_status st)
{
    switch (st) {
    case ST_OK:   printf("%s[  OK  ]%s", c(C_GREEN C_BOLD), c(C_RESET)); break;
    case ST_WARN: printf("%s[ WARN ]%s", c(C_YELLOW C_BOLD), c(C_RESET)); break;
    case ST_FAIL: printf("%s[ FAIL ]%s", c(C_RED C_BOLD), c(C_RESET)); break;
    case ST_SKIP: printf("%s[ SKIP ]%s", c(C_DIM), c(C_RESET)); break;
    }
}

/* ---------------------------------------------------------------- events */

void out_banner(const char *fmt, ...)
{
    char *s = NULL;
    va_list ap;

    va_start(ap, fmt);
    if (vasprintf(&s, fmt, ap) < 0)
        s = NULL;
    va_end(ap);
    if (g_out.mode == OUT_JSON) {
        json_begin("banner");
        fputs(",\"msg\":", stdout);
        json_str(stdout, s);
        json_end();
    } else if (!g_out.quiet) {
        printf("%s%s%s\n", c(C_BOLD C_MAGENTA), s, c(C_RESET));
    }
    free(s);
}

void out_step_begin(const char *id, const char *title)
{
    if (g_out.mode == OUT_JSON) {
        json_begin("step_begin");
        fputs(",\"id\":", stdout);
        json_str(stdout, id);
        fputs(",\"title\":", stdout);
        json_str(stdout, title);
        json_end();
        return;
    }
    if (g_out.quiet)
        return;
    printf("\n%s==> %s%s\n", c(C_BOLD C_BLUE), title, c(C_RESET));
    fflush(stdout);
}

void out_step_end(const char *id, enum out_status st, node_t *result, const char *fmt, ...)
{
    char *s = NULL;
    va_list ap;

    va_start(ap, fmt);
    if (vasprintf(&s, fmt, ap) < 0)
        s = NULL;
    va_end(ap);

    if (g_out.mode == OUT_JSON) {
        json_begin("step_end");
        fputs(",\"id\":", stdout);
        json_str(stdout, id);
        printf(",\"status\":\"%s\",\"summary\":", status_name(st));
        json_str(stdout, s);
        fputs(",\"result\":", stdout);
        json_tree(stdout, result);
        json_end();
    } else if (g_out.quiet) {
        /* one line per step: status, step name, summary */
        text_status(st);
        printf(" %s%-12s%s %s\n", c(C_BOLD), id, c(C_RESET), s ? s : "");
        fflush(stdout);
    } else {
        printf("    ");
        text_status(st);
        printf(" %s\n", s ? s : "");
        if (result)
            text_tree(result, 6);
        fflush(stdout);
    }
    free(s);
}

void out_msg(bool tx, const uint32_t *session_id, const char *name, uint8_t version,
             const void *raw, size_t raw_len, const node_t *tree)
{
    if (g_out.mode == OUT_JSON) {
        char *hex = hex_string(raw, raw_len);

        json_begin("msg");
        printf(",\"dir\":\"%s\",\"name\":", tx ? "req" : "rsp");
        json_str(stdout, name);
        printf(",\"ver\":\"%u.%u\",\"len\":%zu", version >> 4, version & 0xf, raw_len);
        if (session_id)
            printf(",\"session\":\"0x%08x\"", *session_id);
        fputs(",\"hex\":", stdout);
        json_str(stdout, hex);
        fputs(",\"tree\":", stdout);
        json_tree(stdout, tree);
        json_end();
        free(hex);
        return;
    }
    if (!g_out.verbose && !g_out.hex)
        return;

    printf("    %s%s%s %s%-28s%s %sv%u.%u %4zu bytes%s",
           c(tx ? C_YELLOW C_BOLD : C_GREEN C_BOLD), tx ? "-->" : "<--", c(C_RESET),
           c(C_BOLD), name, c(C_RESET), c(C_DIM), version >> 4, version & 0xf, raw_len,
           c(C_RESET));
    if (session_id)
        printf("  %s[secured session 0x%08x]%s", c(C_MAGENTA), *session_id, c(C_RESET));
    putchar('\n');
    if (g_out.verbose && tree)
        text_tree(tree, 10);
    if (g_out.hex) {
        char *d = hex_dump(raw, raw_len, "          ");

        printf("%s%s%s", c(C_DIM), d ? d : "", c(C_RESET));
        free(d);
    }
    fflush(stdout);
}

void out_transport(bool tx, uint8_t mctp_type, uint8_t eid, size_t len)
{
    if (g_out.mode == OUT_JSON) {
        json_begin("mctp");
        printf(",\"dir\":\"%s\",\"type\":%u,\"eid\":%u,\"len\":%zu", tx ? "tx" : "rx",
               mctp_type, eid, len);
        json_end();
        return;
    }
    if (g_out.verbose < 2)
        return;
    printf("    %s   mctp %s eid %u type 0x%02x (%s) %zu bytes%s\n", c(C_DIM),
           tx ? "tx ->" : "rx <-", eid, mctp_type,
           mctp_type == 5 ? "SPDM" : mctp_type == 6 ? "Secured SPDM" : "?", len, c(C_RESET));
}

void out_log(enum out_status lvl, const char *fmt, ...)
{
    char *s = NULL;
    va_list ap;

    va_start(ap, fmt);
    if (vasprintf(&s, fmt, ap) < 0)
        s = NULL;
    va_end(ap);
    if (g_out.mode == OUT_JSON) {
        json_begin("log");
        printf(",\"level\":\"%s\",\"msg\":", status_name(lvl));
        json_str(stdout, s);
        json_end();
    } else if (lvl == ST_FAIL || lvl == ST_WARN) {
        fprintf(stderr, "%s%s: %s%s\n", c(lvl == ST_FAIL ? C_RED C_BOLD : C_YELLOW),
                lvl == ST_FAIL ? "error" : "warning", s, c(C_RESET));
    } else if (!g_out.quiet) {
        printf("    %s%s%s\n", c(C_DIM), s, c(C_RESET));
    }
    free(s);
}

void out_done(enum out_status st, int passed, int warned, int failed)
{
    if (g_out.mode == OUT_JSON) {
        json_begin("done");
        printf(",\"status\":\"%s\",\"passed\":%d,\"warned\":%d,\"failed\":%d",
               status_name(st), passed, warned, failed);
        json_end();
        return;
    }
    printf("\n%sSummary:%s %s%d passed%s, %s%d warning%s, %s%d failed%s\n", c(C_BOLD), c(C_RESET),
           c(C_GREEN), passed, c(C_RESET), c(C_YELLOW), warned, c(C_RESET),
           c(failed ? C_RED : ""), failed, c(C_RESET));
}

void out_round_begin(int round, int count, int interval)
{
    char ts[32];
    time_t now = time(NULL);

    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    if (g_out.mode == OUT_JSON) {
        json_begin("round_begin");
        printf(",\"round\":%d,\"count\":%d,\"interval\":%d,\"time\":", round, count, interval);
        json_str(stdout, ts);
        json_end();
        return;
    }
    if (g_out.quiet)
        return;
    if (count)
        printf("\n%s---------------- Round %d/%d  %s ----------------%s\n", c(C_BOLD C_MAGENTA),
               round, count, ts, c(C_RESET));
    else
        printf("\n%s---------------- Round %d  %s ----------------%s\n", c(C_BOLD C_MAGENTA),
               round, ts, c(C_RESET));
    fflush(stdout);
}

void out_round_end(int round, enum out_status st, int passed, int warned, int failed)
{
    if (g_out.mode == OUT_JSON) {
        json_begin("round_end");
        printf(",\"round\":%d,\"status\":\"%s\",\"passed\":%d,\"warned\":%d,\"failed\":%d",
               round, status_name(st), passed, warned, failed);
        json_end();
        return;
    }
    if (g_out.quiet) {
        char ts[32];
        time_t now = time(NULL);

        strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&now));
        text_status(st);
        printf(" %sround %-6d%s %s  %d passed, %d warning(s), %d failed\n", c(C_BOLD), round,
               c(C_RESET), ts, passed, warned, failed);
    } else {
        printf("    ");
        text_status(st);
        printf(" round %d: %d passed, %d warning(s), %d failed\n", round, passed, warned, failed);
    }
    fflush(stdout);
}
