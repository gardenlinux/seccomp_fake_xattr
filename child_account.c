#include <stdio.h>

#include "child_account.h"

size_t get_children(int *list, size_t size)
{
	FILE *file;
	size_t len;

	file = fopen("/proc/thread-self/children", "r");
	len = 0;
	for (int child; fscanf(file, "%d", &child) != EOF; ++len) if (len < size) list[len] = child;
	fclose(file);
	return len;
}
