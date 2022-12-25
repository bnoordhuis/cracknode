// Copyright (c) 2022, Ben Noordhuis <info@bnoordhuis.nl>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define arraylen(a)	(sizeof(a) / sizeof(*a))

__asm__(".symver dlvsym,dlvsym@GLIBC_2.2.5");

int	(*nextfcntl64v228)(int fd, int cmd, ...);
int	(*nextfcntlv225)(int fd, int cmd, ...);

// call fcntl64() when available or fall back to plain fcntl()
// makes no functional difference on x86_64 but needs rethinking for i386
__asm__(
	".globl		fcntl64v228;			"
	".type		fcntl64v228,@function;		"
	".symver	fcntl64v228,fcntl64@@GLIBC_2.28;"
	"fcntl64v228:					"
	"endbr64;					"
	"push		%r15;				"
	"mov		nextfcntl64v228(%rip),%r15;	"
	"test		%r15,%r15;			"
	"cmovz		nextfcntlv225(%rip),%r15;	"
	"call		*%r15;				"
	"pop		%r15;				"
	"ret;						"
);

__attribute__((constructor, visibility("hidden")))
void
init(void)
{
	nextfcntl64v228	= dlvsym(RTLD_NEXT, "fcntl64", "GLIBC_2.28");
	nextfcntlv225	= dlvsym(RTLD_NEXT, "fcntl", "GLIBC_2.2.5");
}

// - don't use stdout/stderr, not initialized yet
//
// - argv and envp can be parsed from first argument but it's
//   super tedious so we just read it from /proc/self instead
void
go(long *arg)
{
	int	argc, envc, fd;
	long	n;
	char	*p;
	char	*argv[1<<14];
	char	*envp[1<<14];
	char	argsbuf[1<<18];
	char	envsbuf[1<<18];
	char	preload[1<<12];

	// arg[1] is the full path to ourselves
	snprintf(preload, sizeof(preload), "LD_PRELOAD=%s", (char*) arg[1]);

	fd = open("/proc/self/cmdline", O_RDONLY);
	if (fd < 0)
	{
		printf("open /proc/self/cmdline: %m\n");
		_exit(1);
	}
	n = read(fd, argsbuf, sizeof(argsbuf));
	if (n < 0)
	{
		printf("read /proc/self/cmdline: %m\n");
		_exit(1);
	}
	close(fd);

	argc = 0;
	for (p = argsbuf; p < argsbuf+n; p = 1 + strchr(p, 0))
		if (argc < (int) arraylen(argv)-1)
			argv[argc++] = p;
	argv[argc] = 0;

	if (argc < 2)
	{
		printf("usage: hacknode node [...args]\n");
		_exit(1);
	}

	fd = open("/proc/self/environ", O_RDONLY);
	if (fd < 0)
	{
		printf("open /proc/self/environ: %m\n");
		_exit(1);
	}
	n = read(fd, envsbuf, sizeof(envsbuf));
	if (n < 0)
	{
		printf("read /proc/self/environ: %m\n");
		_exit(1);
	}
	close(fd);

	envc = 0;
	for (p = envsbuf; p < envsbuf+n; p = 1+strchr(p, 0))
		if (envc < (int) arraylen(envp)-2) // space for LD_PRELOAD,LD_DEBUG
			envp[envc++] = p;
	envp[envc++]	= preload;
	//envp[envc++]	= "LD_DEBUG=all";
	envp[envc]	= 0;

	execvpe(argv[1], argv+1, envp);
	printf("execve %s: %m\n", argv[1]); // note: no stderr
	_exit(1);
}

__asm__(
	".globl		_start;				"
	"_start:					"
	"endbr64;					"
	"mov		%rsp,%rdi;			"
	"jmp		go;				"
);

__attribute__((section(".interp")))
const char interp[] = "/lib64/ld-linux-x86-64.so.2";
