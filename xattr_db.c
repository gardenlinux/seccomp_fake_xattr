#define _GNU_SOURCE
#include <errno.h>
#include <search.h>
#include <string.h>

#include "debug.h"
#include "xattr_db.h"
#include "zalloc.h"

struct xattr_db_attr_list {
	struct xattr_db_attr_list *next;
	xattr_db_attr_name name;
	struct {
		size_t len;
		char * buf;
	} data;
};

static void xattr_db_attr_list_free(struct xattr_db_attr_list *head)
{
	while (head)
	{
		struct xattr_db_attr_list *next = head->next;
		if (head->data.buf) free(head->data.buf);
		free(head);
		head = next;
	}
}

static struct xattr_db_attr_list * xattr_db_attr_list_entry(struct xattr_db_attr_list **head, xattr_db_attr_name name, int create, int replace)
{
	struct xattr_db_attr_list *entry;

	while (*head)
	{
		int cmp = strncmp(name, (*head)->name, sizeof(xattr_db_attr_name));
		if (cmp == 0)
		{
			if (!create) return *head;
			else
			{
				errno = EEXIST;
				return NULL;
			}
		}
		else if (cmp < 0) break;
		else head = &(*head)->next;
	}

	if (replace)
	{
		errno = ENODATA;
		return NULL;
	}

	entry = zalloc(sizeof(struct xattr_db_attr_list));
	entry->next = *head;
	memcpy(entry->name, name, sizeof(xattr_db_attr_name));
	*head = entry;

	debug_printf("new xattr key \"%s\" added", name);

	return entry;
}

int xattr_db_attr_list_remove(struct xattr_db_attr_list **head, xattr_db_attr_name name)
{
	struct xattr_db_attr_list *entry;

	while (*head)
	{
		if (strncmp(name, (*head)->name, sizeof(xattr_db_attr_name)) == 0) break;
		else head = &(*head)->next;
	}

	entry = *head;
	if (!entry)
	{
		errno = ENODATA;
		return -1;
	}

	*head = entry->next;
	if (entry->data.buf) free(entry->data.buf);
	free(entry);

	return 0;
}

struct xattr_db_tree_node {
	xattr_db_file_id file_id;
	struct xattr_db_attr_list *head;
};

static void xattr_db_tree_node_free(struct xattr_db_tree_node *node)
{
	if (node->head) xattr_db_attr_list_free(node->head);
	free(node);
}

struct xattr_db_ctx {
	void *tree;
	struct xattr_db_tree_node *scratch;
};

static int xattr_db_file_id_compare(const struct xattr_db_tree_node *a, const struct xattr_db_tree_node *b)
{
	return memcmp(&a->file_id, &b->file_id, sizeof(xattr_db_file_id));
}

xattr_db_ctx * xattr_db_init()
{
	return zalloc(sizeof(struct xattr_db_ctx));
}

void xattr_db_free(xattr_db_ctx *ctx)
{
	tdestroy(ctx->tree, (void (*)(void *)) xattr_db_tree_node_free);
	if (ctx->scratch) xattr_db_tree_node_free(ctx->scratch);
	free(ctx);
}

static struct xattr_db_tree_node * xattr_db_tree_get(xattr_db_ctx *ctx, xattr_db_file_id file_id)
{
	struct xattr_db_tree_node *node;

	if (!ctx->scratch) ctx->scratch = zalloc(sizeof (struct xattr_db_tree_node));

	ctx->scratch->file_id = file_id;
	node = *((struct xattr_db_tree_node **) tsearch(ctx->scratch, &ctx->tree, (int (*)(const void *, const void *)) xattr_db_file_id_compare));

	if (node == ctx->scratch)
	{
		debug_printf("new database entry created for inode %lu on dev %u:%u", node->file_id.ino, node->file_id.dev.major, node->file_id.dev.minor);
		ctx->scratch = NULL;
	}
	else debug_printf("found database entry for inode %lu on dev %u:%u", node->file_id.ino, node->file_id.dev.major, node->file_id.dev.minor);

	return node;
}

int xattr_db_set(xattr_db_ctx *ctx, xattr_db_file_id file_id, xattr_db_attr_name name, const char *data, size_t len, int create, int replace)
{
	struct xattr_db_tree_node *node;
	struct xattr_db_attr_list *entry;

	node = xattr_db_tree_get(ctx, file_id);
	entry = xattr_db_attr_list_entry(&node->head, name, create, replace);

	if (!entry) return -1;

	if(entry->data.buf) free(entry->data.buf);

	entry->data.len = len;
	entry->data.buf = zalloc(len);
	memcpy(entry->data.buf, data, len);

	return 0;
}

ssize_t xattr_db_get(xattr_db_ctx *ctx, xattr_db_file_id file_id, xattr_db_attr_name name, char *data, size_t size)
{
	size_t len;
	struct xattr_db_tree_node *node;
	struct xattr_db_attr_list *entry;

	node = xattr_db_tree_get(ctx, file_id);
	entry = xattr_db_attr_list_entry(&node->head, name, 0, 1);

	if (!entry) return -1;

	len = entry->data.len;
	if (len > size)
	{
		errno = ERANGE;
		return len;
	}

	memcpy(data, entry->data.buf, len);
	return len;
}

ssize_t xattr_db_list(xattr_db_ctx *ctx, xattr_db_file_id file_id, char *buf, size_t size)
{
	struct xattr_db_tree_node *node;
	struct xattr_db_attr_list *head;
	size_t total_len = 0;
	int _errno;

	_errno = 0;

	node = xattr_db_tree_get(ctx, file_id);
	head = node->head;
	
	while (head)
	{
		size_t len = strnlen(head->name, sizeof(xattr_db_attr_name) - 1) + 1;
		if (len <= size)
		{
			memcpy(buf, head->name, len);
			buf += len;
			size -= len;
		}
		else
		{
			_errno = ERANGE;
			size = 0;
		}

		total_len += len;
		head = head->next;
	}

	if (_errno) errno = _errno;
	return total_len;
}

int xattr_db_remove(xattr_db_ctx *ctx, xattr_db_file_id file_id, xattr_db_attr_name name)
{
	struct xattr_db_tree_node *node;

	node = xattr_db_tree_get(ctx, file_id);
	return xattr_db_attr_list_remove(&node->head, name);
}
