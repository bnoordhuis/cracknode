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
#include <elf.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define arraylen(a)	(sizeof(a) / sizeof(*a))
#define die(...)	errx(1, __VA_ARGS__)

struct buf
{
	char	*p;
	size_t	n;
};

void
patch(char *filename);

int	(*nextfcntl64v228)(int fd, int cmd, ...);
int	(*nextfcntlv225)(int fd, int cmd, ...);

__attribute__((constructor, visibility("hidden")))
void
init(void)
{
	nextfcntl64v228	= dlvsym(RTLD_NEXT, "fcntl64", "GLIBC_2.28");
	nextfcntlv225	= dlvsym(RTLD_NEXT, "fcntl", "GLIBC_2.2.5");
}

// argv and envp can be parsed from first argument but it's
// super tedious so we just read it from /proc/self instead
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
	p = (char*) arg[1];
	if (sizeof("LD_PRELOAD=")+strlen(p) >= sizeof(preload))
		die("executable path too long");

	strcpy(preload, "LD_PRELOAD=");
	strcat(preload, p);

	fd = open("/proc/self/cmdline", O_RDONLY);
	if (fd < 0)
		die("open /proc/self/cmdline: %m");
	n = read(fd, argsbuf, sizeof(argsbuf));
	if (n < 0)
		die("read /proc/self/cmdline: %m");
	close(fd);

	argc = 0;
	for (p = argsbuf; p < argsbuf+n; p = 1 + strchr(p, 0))
		if (argc < (int) arraylen(argv)-1)
			argv[argc++] = p;
	argv[argc] = 0;

	if (argc < 2)
		die("usage: hacknode [-patch] node [...args]");

	if (!strcmp(argv[1], "-patch"))
	{
		if (argc != 3)
			die("usage: hacknode -patch <executable>");
		patch(argv[2]);
		_exit(0);
	}

	fd = open("/proc/self/environ", O_RDONLY);
	if (fd < 0)
		die("open /proc/self/environ: %m");
	n = read(fd, envsbuf, sizeof(envsbuf));
	if (n < 0)
		die("read /proc/self/environ: %m");
	close(fd);

	envc = 0;
	for (p = envsbuf; p < envsbuf+n; p = 1+strchr(p, 0))
		if (envc < (int) arraylen(envp)-2) // space for LD_PRELOAD,LD_DEBUG
			envp[envc++] = p;
	envp[envc++]	= preload;
	//envp[envc++]	= "LD_DEBUG=all";
	envp[envc]	= 0;

	execvpe(argv[1], argv+1, envp);
	die("execve %s: %m", argv[1]);
}

char *
search(struct buf haystack, char *needle)
{
	char	*p;

	if ((p = memmem(haystack.p, haystack.n, needle, 1+strlen(needle))))
		return p;

	return needle;
}

void
makeweak(struct buf strtab, struct buf symtab, char *name)
{
	name = search(strtab, name);

	Elf64_Sym *s = (void *) symtab.p;
	for (/* empty */; s < (Elf64_Sym *) (symtab.p + symtab.n); s++)
		if (name == strtab.p+s->st_name)
			goto found;
	return;

found:

	switch (s->st_info)
	{
		default:
			die("%s: bad symbol type %02x", name, s->st_info);
		case 0x12: // GLOBAL FUNC
		case 0x22: // WEAK FUNC (no change)
			s->st_info = 0x22;
	}
}

void
delsymver(struct buf dynstr, struct buf verneed, char *libname, char *symver)
{
	libname	= search(dynstr, libname);
	symver	= search(dynstr, symver);

	Elf64_Verneed *need = (void *) verneed.p;
	while (libname != dynstr.p+need->vn_file)
	{
		if (!need->vn_next)
			return;	// not found
		need = (void *) ((char *) need + need->vn_next);
	}

	Elf64_Vernaux *aux = (void *) ((char *) need + need->vn_aux);
	Elf64_Vernaux *found = 0;
	while (aux->vna_next)
	{
		if (symver == dynstr.p+aux->vna_name)
			found = aux;
		aux = (void *) ((char *) aux + aux->vna_next);
	}

	if (found)
	{
		Elf64_Vernaux *next = (void *) ((char *) found + found->vna_next);
		memmove(found, next, (char *) &aux[1] - (char *) next);
		need->vn_cnt--;
	}
}

void
patch(char *filename)
{
	struct stat	s;
	int		fd;
	ssize_t		n, r;
	char		*p;

	fd = open(filename, O_RDWR);
	if (fd < 0)
		die("open %s: %m", filename);

	if (fstat(fd, &s))
		die("fstat %s: %m", filename);

	n = s.st_size;
	p = mmap(0, n, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED)
		die("mmap %s: %m", filename);

	if (memcmp(p, "\177ELF", 4))
		die("bad ELF magic");

	Elf64_Ehdr *eh = (void *) p;

	if (eh->e_type != ET_EXEC)
		die("not an executable");


	if (eh->e_machine != EM_X86_64)
		die("not an x86_64 executable");

	Elf64_Shdr *sh = (void *) &p[eh->e_shoff];

	if (eh->e_shstrndx == 0)
		die("no section name table");

	if (eh->e_shstrndx == 0xFFFF)
		die("TODO handle big section name table");

	struct buf dynstr	= {0, 0};
	struct buf verneed	= {0, 0};
	struct buf symtab	= {0, 0};
	struct buf strtab	= {0, 0};

	for (unsigned i = 0; i < eh->e_shnum; i++)
	{
		struct buf sec =
		{
			.p = p + sh[i].sh_offset,
			.n = sh[i].sh_size,
		};

		struct buf shstrtab =
		{
			.p = p + sh[eh->e_shstrndx].sh_offset,
			.n = sh[eh->e_shstrndx].sh_size,
		};

		char *name = shstrtab.p + sh[i].sh_name;
		//printf("% 16zu\t%s\n", sec.n, name);
		if (!strcmp(name, ".dynstr"))
			dynstr = sec;
		else if (!strcmp(name, ".gnu.version_r"))
			verneed = sec;
		else if (!strcmp(name, ".strtab"))
			strtab = sec;
		else if (!strcmp(name, ".symtab"))
			symtab = sec;
	}

	if (!dynstr.p)
		die("no .dynstr");
	if (!verneed.p)
		die("no .gnu.version_r");
	if (!symtab.p)
		die("no .symtab");
	if (!strtab.p)
		die("no .strtab");

	delsymver(dynstr, verneed, "libc.so.6",  "GLIBC_2.28");
	makeweak(strtab, symtab, "fcntl64@@GLIBC_2.28");

	r = pwrite(fd, p, n, 0);
	if (r < 0)
		die("pwrite: %m");
	if (r < n)
		die("partial write");

	printf("all clear, now run `hacknode node script.js`\n");
}

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

__asm__(
	".globl		_start;				"
	"_start:					"
	"endbr64;					"
	"mov		%rsp,%rdi;			"
	"jmp		go;				"
);

__asm__(".symver dlvsym,dlvsym@GLIBC_2.2.5");

__attribute__((section(".interp")))
const char interp[] = "/lib64/ld-linux-x86-64.so.2";
