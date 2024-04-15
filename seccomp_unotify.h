#include <linux/seccomp.h>
#include <sys/syscall.h>

typedef int (*seccomp_unotify_handler)(void *ctx, struct seccomp_data *data, int proc_dir_fd, int proc_mem_fd);

int seccomp_unotify_vfork_exec(void *ctx, seccomp_unotify_handler *syscall_handlers, size_t len_syscall_handlers, char *file, char **argv, char **envp);
