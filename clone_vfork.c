#define _GNU_SOURCE
#include <linux/sched.h>
#include <sched.h>
#include <sys/mman.h>

#include "clone_vfork.h"

#define CLONE_STACK_SIZE 0x100000

pid_t clone_vfork(int (*func)(void *), void *arg, int flags)
{
	void *clone_stack;
	pid_t pid;

	clone_stack = mmap(
		NULL,
		CLONE_STACK_SIZE,
		PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS,
		-1,
		0
	);

	if (!clone_stack) return -1;

	pid = clone(func, clone_stack + CLONE_STACK_SIZE, CLONE_VM | CLONE_VFORK | CLONE_CLEAR_SIGHAND | flags, arg);
	munmap(clone_stack, CLONE_STACK_SIZE);

	return pid;
}
