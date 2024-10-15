#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "clone_vfork.h"
#include "debug.h"
#include "path.h"
#include "seccomp_unotify.h"
#include "syscall_lookup.h"

#define _return(x) { _return_code = x; goto _on_return; }

int enter_proc_mntns(int target_proc_dir_fd, int self_proc_dir_fd)
{
	int _return_code;
	path_t readlink_buf;
	int self_proc_mntns_fd;
	int target_proc_mntns_fd;
	struct stat self_proc_mntns_stat;
	struct stat target_proc_mntns_stat;

	_return_code = 0;

	if (debug)
	{
		memset(readlink_buf, 0, sizeof(readlink_buf));
		readlinkat(self_proc_dir_fd, "ns/mnt", readlink_buf, sizeof(readlink_buf) - 1);
		debug_printf("self mount namespace: %s", readlink_buf);

		memset(readlink_buf, 0, sizeof(readlink_buf));
		readlinkat(target_proc_dir_fd, "ns/mnt", readlink_buf, sizeof(readlink_buf) - 1);
		debug_printf("target mount namespace: %s", readlink_buf);
	}

	self_proc_mntns_fd = -1;
	target_proc_mntns_fd = -1;

	self_proc_mntns_fd = openat(self_proc_dir_fd, "ns/mnt", O_RDONLY);
	if (self_proc_mntns_fd == -1) _return(-1);

	target_proc_mntns_fd = openat(target_proc_dir_fd, "ns/mnt", O_RDONLY);
	if (target_proc_mntns_fd == -1) _return(-1);

	if (fstat(self_proc_mntns_fd, &self_proc_mntns_stat) == -1) _return(-1);
	if (fstat(target_proc_mntns_fd, &target_proc_mntns_stat) == -1) _return(-1);

	if (target_proc_mntns_stat.st_dev != self_proc_mntns_stat.st_dev || target_proc_mntns_stat.st_ino != self_proc_mntns_stat.st_ino)
	{
		debug_printf("setns %s", readlink_buf);
		_return_code = setns(target_proc_mntns_fd, CLONE_NEWNS);
	}

	_on_return:
	if (self_proc_mntns_fd != -1) close(self_proc_mntns_fd);
	if (target_proc_mntns_fd != -1) close(target_proc_mntns_fd);
	return _return_code;
}

static int fchroot(int fd)
{
	if (fchdir(fd) == -1) return -1;
	return chroot(".");
}

static int enter_proc_root(int target_proc_dir_fd, int self_proc_dir_fd)
{
	int _return_code;
	path_t readlink_buf;
	int self_proc_root_fd;
	int target_proc_root_fd;
	struct stat self_proc_root_stat;
	struct stat target_proc_root_stat;

	_return_code = 0;

	if (debug)
	{
		memset(readlink_buf, 0, sizeof(readlink_buf));
		readlinkat(self_proc_dir_fd, "root", readlink_buf, sizeof(readlink_buf) - 1);
		debug_printf("self root directory: %s", readlink_buf);

		memset(readlink_buf, 0, sizeof(readlink_buf));
		readlinkat(target_proc_dir_fd, "root", readlink_buf, sizeof(readlink_buf) - 1);
		debug_printf("target root directory: %s", readlink_buf);
	}

	self_proc_root_fd = -1;
	target_proc_root_fd = -1;

	self_proc_root_fd = openat(self_proc_dir_fd, "root", O_RDONLY);
	if (self_proc_root_fd == -1) _return(-1);

	target_proc_root_fd = openat(target_proc_dir_fd, "root", O_RDONLY);
	if (target_proc_root_fd == -1) _return(-1);

	if (fstat(self_proc_root_fd, &self_proc_root_stat) == -1) _return(-1);
	if (fstat(target_proc_root_fd, &target_proc_root_stat) == -1) _return(-1);

	if (target_proc_root_stat.st_dev != self_proc_root_stat.st_dev || target_proc_root_stat.st_ino != self_proc_root_stat.st_ino)
	{
		debug_printf("chroot %s", readlink_buf);
		_return_code = fchroot(target_proc_root_fd);
	}

	_on_return:
	if (self_proc_root_fd != -1) close(self_proc_root_fd);
	if (target_proc_root_fd != -1) close(target_proc_root_fd);
	return _return_code;
}

static int enter_proc_cwd(int target_proc_dir_fd, int self_proc_dir_fd)
{
	int _return_code;
	path_t readlink_buf;
	int self_proc_cwd_fd;
	int target_proc_cwd_fd;
	struct stat self_proc_cwd_stat;
	struct stat target_proc_cwd_stat;

	_return_code = 0;

	if (debug)
	{
		memset(readlink_buf, 0, sizeof(readlink_buf));
		readlinkat(self_proc_dir_fd, "cwd", readlink_buf, sizeof(readlink_buf) - 1);
		debug_printf("self working directory: %s", readlink_buf);

		memset(readlink_buf, 0, sizeof(readlink_buf));
		readlinkat(target_proc_dir_fd, "cwd", readlink_buf, sizeof(readlink_buf) - 1);
		debug_printf("target working directory: %s", readlink_buf);
	}

	self_proc_cwd_fd = -1;
	target_proc_cwd_fd = -1;

	self_proc_cwd_fd = openat(self_proc_dir_fd, "cwd", O_RDONLY);
	if (self_proc_cwd_fd == -1) _return(-1);

	target_proc_cwd_fd = openat(target_proc_dir_fd, "cwd", O_RDONLY);
	if (target_proc_cwd_fd == -1) _return(-1);

	if (fstat(self_proc_cwd_fd, &self_proc_cwd_stat) == -1) _return(-1);
	if (fstat(target_proc_cwd_fd, &target_proc_cwd_stat) == -1) _return(-1);

	if (target_proc_cwd_stat.st_dev != self_proc_cwd_stat.st_dev || target_proc_cwd_stat.st_ino != self_proc_cwd_stat.st_ino)
	{
		debug_printf("chdir %s", readlink_buf);
		_return_code = fchdir(target_proc_cwd_fd);
	}

	_on_return:
	if (self_proc_cwd_fd != -1) close(self_proc_cwd_fd);
	if (target_proc_cwd_fd != -1) close(target_proc_cwd_fd);
	return _return_code;
}

struct handle_syscall_vfork_arg {
	volatile int *ret;
	void *ctx;
	seccomp_unotify_handler *syscall_handlers;
	int proc_dir_fd;
	struct seccomp_data *data;
};

static int handle_syscall_vfork(void *_arg)
{
	struct handle_syscall_vfork_arg *arg;

	volatile int *ret;
	void *ctx;
	seccomp_unotify_handler *syscall_handlers;
	int proc_dir_fd;
	struct seccomp_data *data;

	int _return_code;
	int proc_self_dir_fd;
	int proc_target_mem_fd;

	debug_printf("vforked");

	arg = _arg;
	ret = arg->ret;
	ctx = arg->ctx;
	syscall_handlers = arg->syscall_handlers;
	proc_dir_fd = arg->proc_dir_fd;
	data = arg->data;

	_return_code = 0;
	proc_self_dir_fd = -1;
	proc_target_mem_fd = -1;

	proc_self_dir_fd = open("/proc/self", O_PATH | O_DIRECTORY);
	if (proc_self_dir_fd == -1) _return(-1);

	if (
		enter_proc_mntns(proc_dir_fd, proc_self_dir_fd) == -1 ||
		enter_proc_root(proc_dir_fd, proc_self_dir_fd) == -1 ||
		enter_proc_cwd(proc_dir_fd, proc_self_dir_fd) == -1
	) _return(-1);

	proc_target_mem_fd = openat(proc_dir_fd, "mem", O_RDWR);
	if (proc_target_mem_fd == -1) _return(-1);

	if (syscall_handlers[data->nr])
	{
		_return_code = syscall_handlers[data->nr](ctx, data, proc_dir_fd, proc_target_mem_fd);
	} else
	{
		errno = ENOSYS;
		_return_code = -1;
	}

	_on_return:
	if (proc_self_dir_fd != -1) close(proc_self_dir_fd);
	if (proc_target_mem_fd != -1) close(proc_target_mem_fd);
	*ret = _return_code;
	return 0;
}

static int handle_syscall(void *ctx, seccomp_unotify_handler *syscall_handlers, int proc_dir_fd, struct seccomp_data *data)
{
	volatile int status;
	int wstatus;
	pid_t pid;

	status = 0;
	pid = clone_vfork(handle_syscall_vfork, & (struct handle_syscall_vfork_arg) { &status, ctx, syscall_handlers, proc_dir_fd, data }, 0);
	if (pid == -1)
	{
		warn("clone");
		return -1;
	}

	if (waitpid(pid, &wstatus, __WCLONE) == -1)
	{
		warn("waitpid");
		return -1;
	}
	if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) return -1;

	return status;
}

static int supervisor(pid_t target_pid, int seccomp_notify_fd, void *ctx, seccomp_unotify_handler *syscall_handlers)
{
	struct seccomp_notif_sizes sizes;
	struct seccomp_notif *req;
	struct seccomp_notif_resp *resp;
	siginfo_t siginfo;
	struct pollfd poll_seccomp_notify_fd;
	path_t proc_dir_path;
	ssize_t proc_dir_path_len;
	int proc_dir_fd;
	int status;
	int ret;

	ret = -1;

	if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == -1) err(1, "seccomp(SECCOMP_GET_NOTIF_SIZES)");
	if (sizes.seccomp_notif < sizeof(struct seccomp_notif)) sizes.seccomp_notif = sizeof(struct seccomp_notif);
	if (sizes.seccomp_notif_resp < sizeof(struct seccomp_notif_resp)) sizes.seccomp_notif_resp = sizeof(struct seccomp_notif_resp);

	req = alloca(sizes.seccomp_notif);
	resp = alloca(sizes.seccomp_notif_resp);

	debug_printf("listening for seccomp notify events");

	poll_seccomp_notify_fd = (struct pollfd) {
		.fd = seccomp_notify_fd,
		.events = POLLIN
	};

	while (1)
	{
		if (target_pid)
		{
			waitid(P_PID, target_pid, &siginfo, WEXITED | WNOHANG);
			if (siginfo.si_pid == target_pid)
			{
				debug_printf("target %d exited with status %d", siginfo.si_pid, siginfo.si_status);

				ret = siginfo.si_status;
				target_pid = 0;
			}
		}

		if (poll(&poll_seccomp_notify_fd, 1, -1) == -1)
		{
			if (errno == EINTR) continue;
			err(1, "poll");
		}

		debug_printf("seccomp_notify_fd polled (0x%04x)", poll_seccomp_notify_fd.revents);

		if (poll_seccomp_notify_fd.revents & POLLHUP)
		{
			debug_printf("seccomp_notify_fd POLLHUP event recieved");

			if (target_pid)
			{
				while (waitid(P_PID, target_pid, &siginfo, WEXITED) == -1)
				{
					if (errno != EINTR) err(1, "waitid");
				}

				debug_printf("target %d exited with status %d", siginfo.si_pid, siginfo.si_status);

				ret = siginfo.si_status;
				target_pid = 0;
			}

			break;
		}
		if (!(poll_seccomp_notify_fd.revents & POLLIN)) continue;

		memset(req, 0, sizes.seccomp_notif);
		if (ioctl(seccomp_notify_fd, SECCOMP_IOCTL_NOTIF_RECV, req) == -1)
		{
			if (errno == EINTR) continue;
			err(1, "ioctl(SECCOMP_IOCTL_NOTIF_RECV)");
		}

		debug_printf("event recieved (pid=%d, syscall=%s@%d, id=%llx, flags=%x)", req->pid, syscall_lookup[req->data.nr], req->data.nr, req->id, req->flags);

		proc_dir_path_len = snprintf(proc_dir_path, sizeof(proc_dir_path), "/proc/%u", req->pid);
		if (proc_dir_path_len < 0 || proc_dir_path_len >= (ssize_t) sizeof(proc_dir_path)) err(1, "snprintf");

		proc_dir_fd = open(proc_dir_path, O_PATH | O_DIRECTORY);
		if (proc_dir_fd == -1) continue;

		if (ioctl(seccomp_notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &req->id) == -1)
		{
			close(proc_dir_fd);
			continue;
		}

		status = handle_syscall(ctx, syscall_handlers, proc_dir_fd, &req->data);
		close(proc_dir_fd);

		memset(resp, 0, sizes.seccomp_notif_resp);
		resp->id = req->id;
		resp->val = status;
		resp->error = (status == -1) ? -errno : 0;
		if (ioctl(seccomp_notify_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) == -1)
		{
			if (errno == ENOENT) continue;
			err(1, "ioctl(SECCOMP_IOCTL_NOTIF_SEND)");
		}

		debug_printf("response send (id=%llx, value=%lld, error=%d)", resp->id, resp->val, resp->error);
	}

	return ret;
}

struct target_vfork_arg {
	volatile int *seccomp_notify_fd;
	seccomp_unotify_handler *syscall_handlers;
	size_t len_syscall_handlers;
	char *file;
	char **argv;
	char **envp;
};

static int target_vfork(void *_arg)
{
	struct target_vfork_arg *arg;

	volatile int *seccomp_notify_fd;
	seccomp_unotify_handler *syscall_handlers;
	size_t len_syscall_handlers;
	char *file;
	char **argv;
	char **envp;

	int len;
	int *filtered_syscalls;
	struct sock_filter *bpf_filter;
	struct sock_fprog bpf_prog;

	debug_printf("vforked");

	arg = _arg;
	seccomp_notify_fd = arg->seccomp_notify_fd;
	syscall_handlers = arg->syscall_handlers;
	len_syscall_handlers = arg->len_syscall_handlers;
	file = arg->file;
	argv = arg->argv;
	envp = arg->envp;

	len = 0;
	for (size_t i = 0; i < len_syscall_handlers; ++i) if (syscall_handlers[i]) ++len;

	filtered_syscalls = alloca(len * sizeof(int));

	for (size_t i = 0, j = 0; i < len_syscall_handlers; ++i)
	{
		if (syscall_handlers[i])
		{
			filtered_syscalls[j] = i;
			++j;
		}
	}

	bpf_filter = alloca(sizeof(struct sock_filter[len + 3]));

	bpf_filter[0] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr)));
	bpf_filter[len+1] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
	bpf_filter[len+2] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);

	for (int i = 0; i < len; ++i)
	{
		bpf_filter[i+1] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, filtered_syscalls[i], len-i, 0);
	}

	bpf_prog = (struct sock_fprog) {
		.len = len + 3,
		.filter = bpf_filter
	};

	*seccomp_notify_fd = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &bpf_prog);
	if (*seccomp_notify_fd == -1) err(1, "seccomp(SECCOMP_SET_MODE_FILTER)");

	if(unshare(CLONE_FILES) == -1) err(1, "unshare");
	close(*seccomp_notify_fd);

	if (execvpe(file, argv, envp) == -1) err(1, "execvp");

	return 0;
}

static void on_sigchld(int)
{
	debug_printf("SIGCHLD recieved\n");
}

int seccomp_unotify_vfork_exec(void *ctx, seccomp_unotify_handler *syscall_handlers, size_t len_syscall_handlers, char *file, char **argv, char **envp)
{
	struct sigaction sa;
	struct sigaction old_sa;
	volatile int seccomp_notify_fd;
	pid_t pid;
	int ret;

	sa = (struct sigaction) {
		.sa_handler = on_sigchld,
		.sa_flags = SA_NOCLDSTOP
	};

	sigaction(SIGCHLD, &sa, &old_sa);

	seccomp_notify_fd = -1;
	pid = clone_vfork(target_vfork, & (struct target_vfork_arg) { &seccomp_notify_fd, syscall_handlers, len_syscall_handlers, file, argv, envp }, CLONE_FILES | SIGCHLD);
	if (pid == -1) err(1, "clone");

	if (seccomp_notify_fd == -1) err(1, "target_vfork");
	ret = supervisor(pid, seccomp_notify_fd, ctx, syscall_handlers);
	close(seccomp_notify_fd);

	sigaction(SIGCHLD, &old_sa, NULL);

	return ret;
}
