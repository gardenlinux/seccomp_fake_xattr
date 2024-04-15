#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "array_size.h"
#include "debug.h"
#include "mem_account.h"
#include "path.h"
#include "seccomp_unotify.h"
#include "xattr_db.h"
#include "zalloc.h"

static int get_file_id(xattr_db_file_id *file_id, struct seccomp_data *data, int proc_dir_fd, int proc_mem_fd)
{
	int dir_fd = AT_FDCWD;
	int statx_flags;
	path_t path;
	ssize_t path_len;
	path_t readlink_buf;
	struct statx file_statx;

	dir_fd = AT_FDCWD;
	statx_flags = 0;

	if (data->nr == SYS_fsetxattr || data->nr == SYS_fgetxattr || data->nr == SYS_flistxattr || data->nr == SYS_fremovexattr)
	{
		dir_fd = proc_dir_fd;
		path_len = snprintf(path, sizeof(path), "fd/%d", (int) data->args[0]);
		if (path_len < 0 || path_len >= (ssize_t) sizeof(path)) return -1;

		if (debug)
		{
			memset(readlink_buf, 0, sizeof(readlink_buf));
			readlinkat(dir_fd, path, readlink_buf, sizeof(readlink_buf) - 1);
			debug_printf("path=%s", readlink_buf);
		}
	}
	else
	{
		if (pread(proc_mem_fd, path, sizeof(path), data->args[0]) == -1) return -1;
		if (strnlen(path, sizeof(path)) >= sizeof(path))
		{
			errno = ENAMETOOLONG;
			return -1;
		}

		debug_printf("path=%s", path);
	}

	if (data->nr == SYS_lsetxattr || data->nr == SYS_lgetxattr || data->nr == SYS_llistxattr || data->nr == SYS_lremovexattr) statx_flags = AT_SYMLINK_NOFOLLOW;

	if(statx(dir_fd, path, statx_flags, STATX_BASIC_STATS | STATX_BTIME, &file_statx) == -1) return -1;

	file_id->ino = file_statx.stx_ino;
	file_id->dev.major = file_statx.stx_dev_major;
	file_id->dev.minor = file_statx.stx_dev_minor;
	file_id->btime.sec = file_statx.stx_btime.tv_sec;
	file_id->btime.nsec = file_statx.stx_btime.tv_nsec;

	return 0;
}

static int handle_setxattr(void *ctx, struct seccomp_data *data, int proc_dir_fd, int proc_mem_fd)
{
	xattr_db_file_id file_id;
	xattr_db_attr_name attr_name;
	char *data_buf;
	size_t data_len;
	ssize_t read_len;
	int xattr_flags;
	int ret;

	if (get_file_id(&file_id, data, proc_dir_fd, proc_mem_fd) == -1) return -1;

	if (pread(proc_mem_fd, attr_name, sizeof(attr_name), data->args[1]) == -1) return -1;
	if (strnlen(attr_name, sizeof(attr_name)) >= sizeof(attr_name))
	{
		errno = ERANGE;
		return -1;
	}

	debug_printf("name=%s", attr_name);

	data_len = data->args[3];
	if (data_len > XATTR_SIZE_MAX)
	{
		errno = ERANGE;
		return -1;
	}

	data_buf = zalloc(data_len);

	read_len = pread(proc_mem_fd, data_buf, data_len, data->args[2]);
	if ((size_t) read_len != data_len)
	{
		if (read_len >= 0) errno = EFAULT;
		free(data_buf);
		return -1;
	}

	xattr_flags = data->args[4];
	ret = xattr_db_set((xattr_db_ctx *) ctx, file_id, attr_name, data_buf, data_len, xattr_flags & XATTR_CREATE, xattr_flags & XATTR_REPLACE);

	free(data_buf);

	return ret;
}

static int handle_getxattr(void *ctx, struct seccomp_data *data, int proc_dir_fd, int proc_mem_fd)
{
	xattr_db_file_id file_id;
	xattr_db_attr_name attr_name;
	char *data_buf;
	size_t data_size;
	ssize_t len;
	ssize_t write_len;

	if (get_file_id(&file_id, data, proc_dir_fd, proc_mem_fd) == -1) return -1;

	if (pread(proc_mem_fd, attr_name, sizeof(attr_name), data->args[1]) == -1) return -1;
	if (strnlen(attr_name, sizeof(attr_name)) >= sizeof(attr_name))
	{
		errno = ERANGE;
		return -1;
	}

	debug_printf("name=%s", attr_name);

	data_size = data->args[3];
	if (data_size > XATTR_SIZE_MAX) data_size = XATTR_SIZE_MAX;

	data_buf = zalloc(data_size);

	len = xattr_db_get((xattr_db_ctx *) ctx, file_id, attr_name, data_buf, data_size);
	if (len == -1 || len > (ssize_t) data_size)
	{
		if (data_size != 0) len = -1;
		goto _return;
	}

	write_len = pwrite(proc_mem_fd, data_buf, len, data->args[2]);
	if (write_len != len)
	{
		if (len >= 0) errno = EFAULT;
		len = -1;
	}

	_return:
	free(data_buf);
	return len;
}

static int handle_listxattr(void *ctx, struct seccomp_data *data, int proc_dir_fd, int proc_mem_fd)
{
	xattr_db_file_id file_id;
	char *list_buf;
	size_t list_size;
	ssize_t len;
	ssize_t write_len;

	if (get_file_id(&file_id, data, proc_dir_fd, proc_mem_fd) == -1) return -1;

	list_size = data->args[2];
	if (list_size > XATTR_LIST_MAX) list_size = XATTR_LIST_MAX;

	list_buf = zalloc(list_size);

	len = xattr_db_list((xattr_db_ctx *) ctx, file_id, list_buf, list_size);
	if (len == -1 || len > (ssize_t) list_size)
	{
		if (list_size != 0) len = -1;
		goto _return;
	}

	write_len = pwrite(proc_mem_fd, list_buf, len, data->args[1]);
	if (write_len != len)
	{
		if (len >= 0) errno = EFAULT;
		len = -1;
	}

	_return:
	free(list_buf);
	return len;
}

static int handle_removexattr(void *ctx, struct seccomp_data *data, int proc_dir_fd, int proc_mem_fd)
{
	xattr_db_file_id file_id;
	xattr_db_attr_name attr_name;

	if (get_file_id(&file_id, data, proc_dir_fd, proc_mem_fd) == -1) return -1;

	if (pread(proc_mem_fd, attr_name, sizeof(attr_name), data->args[1]) == -1) return -1;
	if (strnlen(attr_name, sizeof(attr_name)) >= sizeof(attr_name))
	{
		errno = ERANGE;
		return -1;
	}

	debug_printf("name=%s", attr_name);

	return xattr_db_remove((xattr_db_ctx *) ctx, file_id, attr_name);
}

static seccomp_unotify_handler xattr_syscall_handlers[] = {
	[SYS_setxattr] = handle_setxattr,
	[SYS_lsetxattr] = handle_setxattr,
	[SYS_fsetxattr] = handle_setxattr,
	[SYS_getxattr] = handle_getxattr,
	[SYS_lgetxattr] = handle_getxattr,
	[SYS_fgetxattr] = handle_getxattr,
	[SYS_listxattr] = handle_listxattr,
	[SYS_llistxattr] = handle_listxattr,
	[SYS_flistxattr] = handle_listxattr,
	[SYS_removexattr] = handle_removexattr,
	[SYS_lremovexattr] = handle_removexattr,
	[SYS_fremovexattr] = handle_removexattr,
};

static void on_sigchld(int)
{
	pid_t pid;

	debug_printf("SIGCHLD recieved\n");

	while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)
	{
		debug_printf("reaped zombie process %d\n", pid);
	}
}

int debug = 0;

int main(int, char **argv)
{
	char *debug_env;
	char *check_mem_env;
	struct sigaction sa;
	struct clone_args clone_args;
	pid_t pid;
	xattr_db_ctx *db;
	int wstatus;
	int ret;

	debug_env = getenv("FAKE_XATTR_DEBUG");
	if (debug_env && *debug_env == '1') debug = 1;

	debug_printf("%s debug mode", argv[0]);

	sa = (struct sigaction) {
		.sa_handler = on_sigchld,
		.sa_flags = SA_NOCLDSTOP
	};

	sigaction(SIGCHLD, &sa, NULL);

	prctl(PR_SET_CHILD_SUBREAPER, 1);

	clone_args = (struct clone_args) {
		.flags = CLONE_CLEAR_SIGHAND
	};

	pid = syscall(SYS_clone3, &clone_args, sizeof(clone_args));
	if (pid == -1) err(1, "clone");

	if (pid == 0)
	{
		db = xattr_db_init();
		ret = seccomp_unotify_vfork_exec(db, xattr_syscall_handlers, array_size(xattr_syscall_handlers), argv[1], argv + 1, environ);
		xattr_db_free(db);

		debug_printf("max heap memory usage: %lu bytes", max_mem_account);
		if (mem_account)
		{
			debug_printf("memory leak detected (%lu bytes)", mem_account);
			check_mem_env = getenv("FAKE_XATTR_CHECK_MEM");
			if (check_mem_env && *check_mem_env == '1') raise(SIGSEGV);
		}

		return ret;
	}
	else
	{
		while (waitpid(pid, &wstatus, __WCLONE) == -1) if (errno != EINTR) err(1, "waitpid");
		return WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;
	}
}
