#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <err.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>

#include "syscall_lookup.h"
#include "zalloc.h"

int debug = 0;

static int resolve_syscall(const char *syscall_descrpitor)
{
	if (!syscall_descrpitor)
	{
		errno = EINVAL;
		return -1;
	}
	if (*syscall_descrpitor == '#') return atoi(syscall_descrpitor + 1);
	for (size_t i = 0; i < syscall_lookup_len; ++i)
	{
		if (strcmp(syscall_descrpitor, syscall_lookup[i]) == 0) return i;
	}

	errno = ENOSYS;
	return -1;
}

enum input_type { INPUT_TYPE_INT = ':tni', INPUT_TYPE_STR = ':rts', INPUT_TYPE_HEX = ':xeh', INPUT_TYPE_BUF = ':fub' };

static uint8_t from_hex_lookup[] = {
	['0'] = 0x00, ['1'] = 0x01, ['2'] = 0x02, ['3'] = 0x03, ['4'] = 0x04, ['5'] = 0x05, ['6'] = 0x06, ['7'] = 0x07, ['8'] = 0x08, ['9'] = 0x09,
	['A'] = 0x0a, ['B'] = 0x0b, ['C'] = 0x0c, ['D'] = 0x0d, ['E'] = 0x0e, ['F'] = 0x0f,
	['a'] = 0x0a, ['b'] = 0x0b, ['c'] = 0x0c, ['d'] = 0x0d, ['e'] = 0x0e, ['f'] = 0x0f
};

static char to_hex_lookup[] = {
	[0x00] = '0', [0x01] = '1', [0x02] = '2', [0x03] = '3', [0x04] = '4', [0x05] = '5', [0x06] = '6', [0x07] = '7',
	[0x08] = '8', [0x09] = '9', [0x0a] = 'a', [0x0b] = 'b', [0x0c] = 'c', [0x0d] = 'd', [0x0e] = 'e', [0x0f] = 'f'
};

static void print_hex(const char *buf, size_t len)
{
	// "00 00 00 00 00 00 00 00    ........"

	char line_buf[36];
	size_t num_lines;
	size_t line_len;

	num_lines = (len + 7) / 8;
	for (size_t line = 0; line < num_lines; ++line)
	{
		memset(line_buf, ' ', 35);
		line_buf[35] = '\0';
		line_len = (line == num_lines - 1) ? len % 8 : 8;
		for (size_t i = 0; i < line_len; ++i)
		{
			line_buf[i * 3] = to_hex_lookup[buf[i] >> 4 & 0x0f];
			line_buf[(i * 3) + 1] = to_hex_lookup[buf[i] & 0x0f];
			line_buf[i + 27] = (buf[i] >= 0x20 && buf[i] <= 0x7e) ? buf[i] : '.';
		}
		puts(line_buf);
		buf += 8;
	}
}

static int setup_input(const char *input_descriptor, size_t *input)
{
	enum input_type input_type = *((int *) input_descriptor);
	input_descriptor += sizeof(int);

	switch (input_type)
	{
		size_t len;
		char *buf;

		case INPUT_TYPE_INT:
			int value = atoi(input_descriptor);
			*input = (size_t) value;
			break;
		case INPUT_TYPE_STR:
			len = strlen(input_descriptor) + 1;
			buf = zalloc(len);
			memcpy(buf, input_descriptor, len);
			*input = (size_t) buf;
			break;
		case INPUT_TYPE_HEX:
			size_t hex_len = strlen(input_descriptor);
			if (hex_len % 2)
			{
				errno = EINVAL;
				return -1;
			}
			len = hex_len / 2;
			buf = zalloc(len);
			for (size_t i = 0; i < len; ++i)
			{
				buf[i] = (from_hex_lookup[(int) input_descriptor[i * 2]] << 4) | from_hex_lookup[(int) input_descriptor[(i * 2) + 1]];
			}
			*input = (size_t) buf;
			break;
		case INPUT_TYPE_BUF:
			len = (size_t) atoi(input_descriptor + sizeof(int));
			buf = zalloc(len);
			*input = (size_t) buf;
			break;
		default:
			errno = EINVAL;
			return -1;
	}

	return 0;
}

static void cleanup_input(const char *input_descriptor, size_t input)
{
	enum input_type input_type = *((int *) input_descriptor);
	input_descriptor += sizeof(int);

	switch (input_type)
	{
		case INPUT_TYPE_BUF:
			enum input_type output_type = *((int *) input_descriptor);
			if (output_type == INPUT_TYPE_STR) puts((char *) input);
			else if (output_type == INPUT_TYPE_HEX)
			{
				size_t len = (size_t) atoi(input_descriptor + sizeof(int));
				print_hex((char *) input, len);
			}
			__attribute__ ((fallthrough));
		case INPUT_TYPE_STR:
		case INPUT_TYPE_HEX:
			free((void *) input);
			break;
		default:
			break;
	}
}

int main(int argc, char **argv)
{
	size_t arg[8] = { 0 };
	int ret;

	int syscall_nr = resolve_syscall(argv[1]);
	if (syscall_nr == -1) err(1, "resolve_syscall");
	arg[0] = (size_t) syscall_nr;

	for (int i = 2; i < argc; ++i)
	{
		int status = setup_input(argv[i], &arg[i-1]);
		if (status == -1) err(1, "setup_input");
	}

	ret = syscall(arg[0], arg[1], arg[2], arg[3], arg[4], arg[5], arg[6], arg[7]);

	for (int i = 2; i < argc; ++i) cleanup_input(argv[i], arg[i-1]);

	printf("%d\n", ret);

	return 0;
}
