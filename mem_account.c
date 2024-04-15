#include <stddef.h>

extern void * __libc_malloc(size_t);
extern void * __libc_calloc(size_t, size_t);
extern void * __libc_realloc(void *, size_t);
extern void * __libc_reallocarray(void *, size_t, size_t);
extern void * __libc_memalign(size_t, size_t);
extern void * __libc_valloc(size_t);
extern void * __libc_pvalloc(size_t);
extern void * __libc_free(void *);
extern size_t malloc_usable_size (void *);

size_t mem_account = 0;
size_t max_mem_account = 0;

void * malloc(size_t size)
{
	void *ptr;
	size_t usable_size;
	
	ptr = __libc_malloc(size);
	usable_size = malloc_usable_size(ptr);
	mem_account += usable_size;
	if (mem_account > max_mem_account) max_mem_account = mem_account;
	return ptr;
}

void * calloc(size_t num, size_t size)
{
	void *ptr;
	size_t usable_size;

	ptr = __libc_calloc(num, size);
	usable_size = malloc_usable_size(ptr);
	mem_account += usable_size;
	if (mem_account > max_mem_account) max_mem_account = mem_account;
	return ptr;
}

void * realloc(void *old_ptr, size_t size)
{
	size_t old_usable_size;
	void *new_ptr;
	size_t new_usable_size;

	old_usable_size = malloc_usable_size(old_ptr);
	new_ptr = __libc_realloc(old_ptr, size);
	new_usable_size = malloc_usable_size(new_ptr);
	mem_account += new_usable_size - old_usable_size;
	if (mem_account > max_mem_account) max_mem_account = mem_account;
	return new_ptr;
}

void * reallocarray(void *old_ptr, size_t num, size_t size)
{
	size_t old_usable_size;
	void *new_ptr;
	size_t new_usable_size;

	old_usable_size = malloc_usable_size(old_ptr);
	new_ptr = __libc_reallocarray(old_ptr, num, size);
	new_usable_size = malloc_usable_size(new_ptr);
	mem_account += new_usable_size - old_usable_size;
	if (mem_account > max_mem_account) max_mem_account = mem_account;
	return new_ptr;
}

void * memalign(size_t alignment, size_t size)
{
	void *ptr;
	size_t usable_size;

	ptr = __libc_memalign(alignment, size);
	usable_size = malloc_usable_size(ptr);
	mem_account += usable_size;
	if (mem_account > max_mem_account) max_mem_account = mem_account;
	return ptr;
}

void * valloc(size_t size)
{
	void *ptr;
	size_t usable_size;

	ptr = __libc_valloc(size);
	usable_size = malloc_usable_size(ptr);
	mem_account += usable_size;
	if (mem_account > max_mem_account) max_mem_account = mem_account;
	return ptr;
}

void * pvalloc(size_t size)
{
	void *ptr;
	size_t usable_size;

	ptr = __libc_pvalloc(size);
	usable_size = malloc_usable_size(ptr);
	mem_account += usable_size;
	if (mem_account > max_mem_account) max_mem_account = mem_account;
	return ptr;
}

void free(void *ptr)
{
	size_t usable_size;
	
	usable_size = malloc_usable_size(ptr);
	__libc_free(ptr);
	mem_account -= usable_size;
}
