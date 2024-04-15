#include <stdio.h>
#include <unistd.h>

extern int debug;

#define __STR(x) #x
#define _STR(x) __STR(x)
#define debug_printf(fmt, ...) if (debug) fprintf(stderr, "\033[2mdebug: " __FILE__ ":" _STR(__LINE__) " (%s) [%d]: " fmt "\033[0m\n", __func__, getpid(), ##__VA_ARGS__)
