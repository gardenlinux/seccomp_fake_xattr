#include <errno.h>
#include <string.h>

#include "test.h"
#include "xattr_db.h"

void test_struct_size()
{
	static_assert(sizeof(xattr_db_file_id) == 28);
	static_assert(sizeof(xattr_db_attr_name) == 256);
}

void test_alloc_free()
{
	xattr_db_ctx *xattr_db = xattr_db_init();
	xattr_db_free(xattr_db);
}

void test_set_get()
{
	char get_data[TEST_BUF_SIZE];
	char set_data[] = { 'h', 'e', 'l', 'l', 'o' };
	size_t len;

	xattr_db_ctx *xattr_db = xattr_db_init();
	xattr_db_file_id file_id = { .dev = { .major = 0, .minor = 0 }, .ino = 1 };

	xattr_db_attr_name attr_name = "test";
	xattr_db_set(xattr_db, file_id, attr_name, set_data, sizeof(set_data), 0, 0);
	len = xattr_db_get(xattr_db, file_id, attr_name, get_data, sizeof(get_data));

	assert(len == sizeof(set_data));
	assert(memcmp(set_data, get_data, len) == 0);

	xattr_db_free(xattr_db);
}

void test_overwrite()
{
	char set_data_a[] = { 'h', 'e', 'l', 'l', 'o' };
	char set_data_b[] = { 'r', 'e', 'p', 'l', 'a', 'c', 'e', 'd' };
	char get_data[TEST_BUF_SIZE];
	ssize_t len;

	xattr_db_ctx *xattr_db = xattr_db_init();
	xattr_db_file_id file_id = { .dev = { .major = 0, .minor = 0 }, .ino = 1 };

	xattr_db_attr_name attr_name = "test";

	xattr_db_set(xattr_db, file_id, attr_name, set_data_a, sizeof(set_data_a), 0, 0);
	xattr_db_set(xattr_db, file_id, attr_name, set_data_b, sizeof(set_data_b), 0, 0);

	len = xattr_db_get(xattr_db, file_id, attr_name, get_data, sizeof(get_data));

	assert(len == sizeof(set_data_b));
	assert(memcmp(set_data_b, get_data, len) == 0);

	xattr_db_free(xattr_db);
}

void test_list()
{
	char set_data[] = { 'h', 'e', 'l', 'l', 'o' };
	char expected_list[] = "testA\0testB\0testC";
	char list[TEST_BUF_SIZE];
	ssize_t len;

	xattr_db_ctx *xattr_db = xattr_db_init();
	xattr_db_file_id file_id = { .dev = { .major = 0, .minor = 0 }, .ino = 1 };

	xattr_db_attr_name attr_name[] = { "testA", "testC", "testB", "testA" };
	for (size_t i = 0; i < array_size(attr_name); ++i)
	{
		xattr_db_set(xattr_db, file_id, attr_name[i], set_data, sizeof(set_data), 0, 0);
	}

	len = xattr_db_list(xattr_db, file_id, list, sizeof(list));
	assert(len == sizeof(expected_list));
	assert(memcmp(expected_list, list, len) == 0);

	len = xattr_db_list(xattr_db, file_id, NULL, 0);
	assert(len > 0);
	assert(errno == ERANGE);

	xattr_db_free(xattr_db);
}

void test_remove()
{
	char get_data[TEST_BUF_SIZE];
	char set_data[] = { 'h', 'e', 'l', 'l', 'o' };
	ssize_t len;

	xattr_db_ctx *xattr_db = xattr_db_init();
	xattr_db_file_id file_id = { .dev = { .major = 0, .minor = 0 }, .ino = 1 };

	xattr_db_attr_name attr_name = "test";
	xattr_db_set(xattr_db, file_id, attr_name, set_data, sizeof(set_data), 0, 0);
	len = xattr_db_get(xattr_db, file_id, attr_name, get_data, sizeof(get_data));

	assert(len == sizeof(set_data));
	assert(memcmp(set_data, get_data, len) == 0);

	assert(xattr_db_remove(xattr_db, file_id, attr_name) == 0);

	len = xattr_db_get(xattr_db, file_id, attr_name, get_data, sizeof(get_data));
	assert(len == -1);
	assert(errno == ENODATA);

	len = xattr_db_list(xattr_db, file_id, NULL, 0);
	assert(len == 0);

	xattr_db_free(xattr_db);
}

void test_get_errors()
{
	xattr_db_ctx *xattr_db = xattr_db_init();
	xattr_db_file_id file_id = { .dev = { .major = 0, .minor = 0 }, .ino = 1 };
	xattr_db_attr_name attr_name = "test";
	char set_data[] = { 'h', 'e', 'l', 'l', 'o' };
	char get_data[64];
	ssize_t len;

	len = xattr_db_get(xattr_db, file_id, attr_name, get_data, sizeof(get_data));
	assert(len == -1);
	assert(errno == ENODATA);

	xattr_db_set(xattr_db, file_id, attr_name, set_data, sizeof(set_data), 0, 0);

	len = xattr_db_get(xattr_db, file_id, attr_name, NULL, 0);
	assert(len > 0);
	assert(errno == ERANGE);

	xattr_db_free(xattr_db);
}

void test_set_errors()
{
	xattr_db_ctx *xattr_db = xattr_db_init();
	xattr_db_file_id file_id = { .dev = { .major = 0, .minor = 0 }, .ino = 1 };
	xattr_db_attr_name attr_name = "test";
	char set_data[] = { 'h', 'e', 'l', 'l', 'o' };
	int err;

	err = xattr_db_set(xattr_db, file_id, attr_name, set_data, sizeof(set_data), 0, 1);
	assert(err == -1);
	assert(errno == ENODATA);

	err = xattr_db_set(xattr_db, file_id, attr_name, set_data, sizeof(set_data), 1, 0);
	assert(err == 0);

	err = xattr_db_set(xattr_db, file_id, attr_name, set_data, sizeof(set_data), 1, 0);
	assert(err == -1);
	assert(errno == EEXIST);

	xattr_db_free(xattr_db);
}

test_set tests = {
	TEST(struct_size),
	TEST(alloc_free),
	TEST(set_get),
	TEST(overwrite),
	TEST(list),
	TEST(remove),
	TEST(get_errors),
	TEST(set_errors)
};

RUN_TESTS(tests)
