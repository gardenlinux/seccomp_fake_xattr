#include <sys/types.h>

pid_t clone_vfork(int (*func)(void *), void *arg, int flags);
