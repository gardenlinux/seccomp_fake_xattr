#define _GNU_SOURCE
#include <dirent.h>
#include <stdlib.h>

#include "fd_account.h"

static int filter(const struct dirent *entry)
{
	return *entry->d_name != '.';
}

size_t get_fd_list(int *fd_list, size_t size)
{
	struct dirent **dirent_list;
	int n;

	n = scandir("/proc/self/fd", &dirent_list, filter, versionsort);
	if (n == -1) return -1;

	for (size_t i = 0; i < (size_t) n; ++i)
	{
		if (i < size) fd_list[i] = atoi(dirent_list[i]->d_name);
		free(dirent_list[i]);
	}
	free(dirent_list);

	return n;
}

int compare_fd_list(int *fd_list_a, size_t len_a, int *fd_list_b, size_t len_b)
{
	if (len_a != len_b) return 1;
	for (size_t i = 0; i < len_a; ++i) if(fd_list_a[i] != fd_list_b[i]) return 1;
	return 0;
}
