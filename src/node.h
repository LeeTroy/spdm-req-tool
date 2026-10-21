/* Simple tree of key/value nodes used to describe decoded SPDM data.
 * The same tree is rendered as indented text or as JSON (for the demo TUI). */
#ifndef NODE_H
#define NODE_H

#include <stddef.h>
#include <stdint.h>

enum node_style {
    NS_NONE = 0,
    NS_OK,      /* positive result, rendered green  */
    NS_WARN,    /* warning, rendered yellow         */
    NS_ERR,     /* error, rendered red              */
    NS_HEX,     /* raw bytes, rendered dim          */
    NS_HILITE,  /* key information, rendered bold   */
};

typedef struct node {
    char *key;
    char *val;
    int style;
    struct node *child;
    struct node *last;
    struct node *next;
} node_t;

node_t *node_new(const char *key, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
node_t *node_add(node_t *parent, const char *key, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
node_t *node_add_hex(node_t *parent, const char *key, const void *data, size_t len);
void node_append(node_t *parent, node_t *child);
node_t *node_style(node_t *n, int style);
void node_free(node_t *n);

#endif
