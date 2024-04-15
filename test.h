#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "array_size.h"
#include "child_account.h"
#include "debug.h"
#include "fd_account.h"
#include "mem_account.h"

#ifndef TEST_DEBUG
#define TEST_DEBUG 0
#endif

#ifndef TEST_BUF_SIZE
#define TEST_LIST_SIZE 64
#define TEST_BUF_SIZE 64
#endif

int debug = TEST_DEBUG;

typedef struct test {
	char *name;
	void (* func)();
} test_set[];

#define TEST(X) ((struct test) { #X, test_ ## X })

static void fmt_int_list(char *buf, size_t size, const int *list, size_t list_len)
{
	char *ptr = buf;
	
	size_t len;

	len = snprintf(ptr, size, "[ ");
	size -= len;
	ptr += len;

	for (size_t i = 0; i < list_len; ++i)
	{
		len = snprintf(ptr, size - 5, "%d%s", list[i], (i != list_len - 1) ? ", " : "");
		if (len > size - 6)
		{
			len = snprintf(ptr, size, "...");
			i = list_len;
		}
		size -= len;
		ptr += len;
	}

	len = snprintf(ptr, size, " ]");
}

int run_test_set(test_set tests, size_t num_tests, char *file_name)
{
	size_t num_passed;
	pid_t test_pid;
	int original_fd_list[TEST_LIST_SIZE];
	int fd_list[TEST_LIST_SIZE];
	size_t fd_list_len;
	char fd_list_fmt_buf[TEST_BUF_SIZE];
	int child_list[TEST_LIST_SIZE];
	size_t child_list_len;
	char child_list_fmt_buf[TEST_BUF_SIZE];
	int status;
	int passed;

	printf("%s\n", file_name);

	num_passed = 0;
	for (size_t i = 0; i < num_tests; ++i)
	{
		fflush(stdout);
		fflush(stderr);

		assert((test_pid = fork()) != -1);
		
		if (test_pid == 0)
		{
			size_t original_fd_list_len = get_fd_list(original_fd_list, array_size(original_fd_list));

			size_t original_mem_account = mem_account;
			tests[i].func();
			if (mem_account != original_mem_account)
			{
				fprintf(stderr, "memory leak detected during test (%lu bytes)\n", mem_account - original_mem_account);
				exit(1);
			}

			fd_list_len = get_fd_list(fd_list, array_size(fd_list));

			if(compare_fd_list(original_fd_list, original_fd_list_len, fd_list, fd_list_len) != 0)
			{
				fprintf(stderr, "file descriptor leak detected during test\n");

				fmt_int_list(fd_list_fmt_buf, array_size(fd_list_fmt_buf), original_fd_list, original_fd_list_len);
				fprintf(stderr, "fd list before test = %s\n", fd_list_fmt_buf);

				fmt_int_list(fd_list_fmt_buf, array_size(fd_list_fmt_buf), fd_list, fd_list_len);
				fprintf(stderr, "fd list after test  = %s\n", fd_list_fmt_buf);

				exit(1);
			}

			child_list_len = get_children(child_list, array_size(child_list));

			if(child_list_len > 0)
			{
				fprintf(stderr, "child processes not terminated or reaped during test\n");

				fmt_int_list(child_list_fmt_buf, array_size(child_list_fmt_buf), child_list, child_list_len);
				fprintf(stderr, "child processes = %s\n", child_list_fmt_buf);

				exit(1);
			}

			exit(0);
		}

		assert(wait(&status) != -1);
		passed = WIFEXITED(status) && WEXITSTATUS(status) == 0;
		num_passed += passed;
		printf("[%lu/%lu] %s: %s\n", i+1, num_tests, tests[i].name, passed ? "\033[92mpassed\033[0m" : "\033[91mfailed\033[0m");
#ifdef TEST_FAIL_FAST
		if (status != 0) break;
#endif
	}
	printf("%s: %lu tests passed, %lu tests failed\n", file_name, num_passed, num_tests - num_passed);
	return num_passed != num_tests;
}

#define RUN_TESTS(X) int main() { return run_test_set(X, array_size(X), __FILE__); }

void test_always_pass() { }
void test_always_fail() { abort(); }
