#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "zalloc.h"

void * zalloc(size_t size)
{
	void *ptr;

	debug_printf("allocating %lu bytes", size);

	ptr = malloc(size);
	if (!ptr)
	{
		perror("malloc");
		abort();
	}
	memset(ptr, 0, size);
	return ptr;
}
