#include <stdlib.h>
#include <stdint.h>
#include <linux/limits.h>
#include <sys/types.h>

typedef struct {
	struct {
		uint32_t major;
		uint32_t minor;
	} __attribute__((aligned(4),packed)) dev;
	uint64_t ino;
	struct {
		uint64_t sec;
		uint32_t nsec;
	} __attribute__((aligned(4),packed)) btime;
} __attribute__((aligned(4),packed)) xattr_db_file_id;

typedef char xattr_db_attr_name[XATTR_NAME_MAX + 1];
typedef struct xattr_db_ctx xattr_db_ctx;

xattr_db_ctx * xattr_db_init();
void xattr_db_free(xattr_db_ctx *ctx);

int xattr_db_set(xattr_db_ctx *ctx, xattr_db_file_id file_id, xattr_db_attr_name name, const char *data, size_t len, int create, int replace);
ssize_t xattr_db_get(xattr_db_ctx *ctx, xattr_db_file_id file_id, xattr_db_attr_name name, char *data, size_t size);
ssize_t xattr_db_list(xattr_db_ctx *ctx, xattr_db_file_id file_id, char *buf, size_t size);
int xattr_db_remove(xattr_db_ctx *ctx, xattr_db_file_id file_id, xattr_db_attr_name name);
