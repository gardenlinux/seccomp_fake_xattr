#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <sys/stat.h>

#include "array_size.h"
#include "path.h"
#include "seccomp_unotify.h"
#include "test.h"

static int handle_getuid(void *, struct seccomp_data *data, int, int)
{
	assert(data->nr == SYS_getuid);
	return 42;
}

static int handle_fake_uid(void *ctx, struct seccomp_data *data, int, int)
{
	if (data->nr == SYS_getuid)
	{
		return *((int *) ctx);
	}

	if (data->nr == SYS_setuid)
	{
		*((int *) ctx) = (int) data->args[0];
		return 0;
	}

	errno = ENOSYS;
	return -1;
}

static int handle_uname(void *ctx, struct seccomp_data *data, int, int proc_mem_fd)
{
	struct utsname utsname;
	ssize_t len;

	assert(data->nr == SYS_uname);

	uname(&utsname);
	strncpy(utsname.version, ctx, sizeof(utsname.version) - 1);

	len = pwrite(proc_mem_fd, &utsname, sizeof(utsname), data->args[0]);
	if (len != sizeof(utsname))
	{
		if (len >= 0) errno = EFAULT;
		return -1;
	}

	return 0;
}

static int handle_getxattr(void *, struct seccomp_data *data, int, int proc_mem_fd)
{
	char name[XATTR_NAME_MAX + 1];
	path_t path;
	struct statx file_statx;
	char buf[TEST_BUF_SIZE];
	size_t len;
	ssize_t written_len;

	if (pread(proc_mem_fd, name, sizeof(name), data->args[1]) == -1) return -1;
	if (strnlen(name, sizeof(name)) >= sizeof(name))
	{
		errno = ERANGE;
		return -1;
	}

	debug_printf("name=%s", name);

	if (strcmp(name, "stat.ino") != 0)
	{
		errno = ENODATA;
		return -1;
	}

	if (pread(proc_mem_fd, path, sizeof(path), data->args[0]) == -1) return -1;
	if (strnlen(path, sizeof(path)) >= sizeof(path))
	{
		errno = ENAMETOOLONG;
		return -1;
	}

	debug_printf("path=%s", path);

	if (statx(AT_FDCWD, path, 0, STATX_INO, &file_statx) == -1) return -1;

	snprintf(buf, sizeof(buf), "%llu", file_statx.stx_ino);

	len = strlen(buf);
	if (data->args[3] == 0) return len;
	if (data->args[3] < len)
	{
		errno = ERANGE;
		return -1;
	}

	written_len = pwrite(proc_mem_fd, buf, len, data->args[2]);
	if ((size_t) written_len != len)
	{
		if (written_len >= 0) errno = EFAULT;
		return -1;
	}

	return len;
}

static seccomp_unotify_handler empty_syscall_handlers[] = { };

static seccomp_unotify_handler getuid_syscall_handlers[] = {
	[SYS_getuid] = handle_getuid
};

static seccomp_unotify_handler fakeuid_syscall_handlers[] = {
	[SYS_setuid] = handle_fake_uid,
	[SYS_getuid] = handle_fake_uid
};

static seccomp_unotify_handler uname_syscall_handlers[] = {
	[SYS_uname] = handle_uname
};

static seccomp_unotify_handler getxattr_syscall_handlers[] = {
	[SYS_getxattr] = handle_getxattr
};

static int seccomp_unotify_sh(char *cmd, void *ctx, seccomp_unotify_handler *syscall_handlers, size_t len_syscall_handlers)
{
	return seccomp_unotify_vfork_exec(ctx, syscall_handlers, len_syscall_handlers, "/bin/sh", (char * []) { "/bin/sh", "-c", cmd, NULL }, (char * []) { NULL });
}

static void test_no_opt()
{
	assert(seccomp_unotify_sh("true", NULL, empty_syscall_handlers, array_size(empty_syscall_handlers)) == 0);
}

static void test_exit_code()
{
	assert(seccomp_unotify_sh("exit 42", NULL, empty_syscall_handlers, array_size(empty_syscall_handlers)) == 42);
}

static void test_handler()
{
	assert(seccomp_unotify_sh("[ $(./do_syscall getuid) = 42 ]", NULL, getuid_syscall_handlers, array_size(getuid_syscall_handlers)) == 0);
}

static void test_ctx()
{
	int uid = 0;
	assert(seccomp_unotify_sh("[ $(./do_syscall getuid) = 0 ] && [ $(./do_syscall setuid int:42) = 0 ] && [ $(./do_syscall getuid) = 42 ]", &uid, fakeuid_syscall_handlers, array_size(fakeuid_syscall_handlers)) == 0);
}

static void test_write_mem()
{
	assert(seccomp_unotify_sh("[ $(uname -v) = " __FILE__ " ]", __FILE__, uname_syscall_handlers, array_size(uname_syscall_handlers)) == 0);
}

static void test_file_access()
{
	assert(seccomp_unotify_sh("touch .tmp/test_file && [ $(./do_syscall getxattr str:.tmp/test_file str:stat.ino buf:str:64 int:64 | head -n 1) = $(stat -c '\%i' .tmp/test_file) ]", NULL, getxattr_syscall_handlers, array_size(getxattr_syscall_handlers)) == 0);
}

static void test_cwd()
{
	assert(seccomp_unotify_sh("do_syscall_path=$(realpath do_syscall) && mkdir -p .tmp/test_dir && cd .tmp/test_dir && touch test_file && [ $($do_syscall_path getxattr str:test_file str:stat.ino buf:str:64 int:64 | head -n 1) = $(stat -c '\%i' test_file) ]", NULL, getxattr_syscall_handlers, array_size(getxattr_syscall_handlers)) == 0);
}

static void test_chroot()
{
	assert(seccomp_unotify_sh("touch .tmp/chroot/test_file && [ $(chroot .tmp/chroot /do_syscall getxattr str:/test_file str:stat.ino buf:str:64 int:64 | head -n 1) = $(stat -c '\%i' .tmp/chroot/test_file) ]", NULL, getxattr_syscall_handlers, array_size(getxattr_syscall_handlers)) == 0);
}

static void test_mntns()
{
	assert(seccomp_unotify_sh("touch .tmp/test_file .tmp/test_mnt && [ $(unshare --map-root-user --mount --propagation unchanged sh -c 'mount --bind .tmp/test_file .tmp/test_mnt && ./do_syscall getxattr str:.tmp/test_mnt str:stat.ino buf:str:64 int:64' | head -n 1) = $(stat -c '\%i' .tmp/test_file) ]", NULL, getxattr_syscall_handlers, array_size(getxattr_syscall_handlers)) == 0);
}

test_set tests = {
	TEST(no_opt),
	TEST(exit_code),
	TEST(handler),
	TEST(ctx),
	TEST(write_mem),
	TEST(file_access),
	TEST(cwd),
	TEST(chroot),
	TEST(mntns)
};

RUN_TESTS(tests)
