#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "node.h"
#include "util.h"

static node_t *node_vnew(const char *key, const char *fmt, va_list ap)
{
    node_t *n = calloc(1, sizeof(*n));

    if (!n)
        return NULL;
    n->key = strdup(key ? key : "");
    if (fmt && vasprintf(&n->val, fmt, ap) < 0)
        n->val = NULL;
    return n;
}

node_t *node_new(const char *key, const char *fmt, ...)
{
    va_list ap;
    node_t *n;

    va_start(ap, fmt);
    n = node_vnew(key, fmt, ap);
    va_end(ap);
    return n;
}

void node_append(node_t *parent, node_t *child)
{
    if (!parent || !child)
        return;
    if (parent->last)
        parent->last->next = child;
    else
        parent->child = child;
    parent->last = child;
}

node_t *node_add(node_t *parent, const char *key, const char *fmt, ...)
{
    va_list ap;
    node_t *n;

    va_start(ap, fmt);
    n = node_vnew(key, fmt, ap);
    va_end(ap);
    node_append(parent, n);
    return n;
}

node_t *node_add_hex(node_t *parent, const char *key, const void *data, size_t len)
{
    node_t *n = node_add(parent, key, NULL);

    if (!n)
        return NULL;
    n->val = hex_string(data, len);
    n->style = NS_HEX;
    return n;
}

node_t *node_style(node_t *n, int style)
{
    if (n)
        n->style = style;
    return n;
}

void node_free(node_t *n)
{
    while (n) {
        node_t *next = n->next;

        node_free(n->child);
        free(n->key);
        free(n->val);
        free(n);
        n = next;
    }
}
