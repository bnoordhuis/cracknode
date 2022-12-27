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
#include <elf.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct buf
{
	char	*p;
	size_t	n;
};

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
			errx(1, "%s: bad symbol type %02x", name, s->st_info);
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

int
main(int argc, char **argv)
{
	struct stat	s;
	int		fd;
	ssize_t		n, r;
	char		*p;

	if (argc < 2)
	{
		printf("usage: cracknode /path/to/node\n");
		return 1;
	}

	fd = open(argv[1], O_RDWR);
	if (fd < 0)
		err(1, "open %s", argv[1]);

	if (fstat(fd, &s))
		err(1, "fstat %s", argv[1]);

	n = s.st_size;
	p = mmap(0, n, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED)
		err(1, "mmap %s", argv[1]);

	if (memcmp(p, "\177ELF", 4))
		err(1, "bad ELF magic");

	Elf64_Ehdr *eh = (void *) p;

	if (eh->e_type != ET_EXEC)
		err(1, "not an executable");

	if (eh->e_machine != EM_X86_64)
		err(1, "not an x86_64 executable");

	Elf64_Shdr *sh = (void *) &p[eh->e_shoff];

	if (eh->e_shstrndx == 0)
		errx(1, "no section name table");

	if (eh->e_shstrndx == 0xFFFF)
		errx(1, "TODO handle big section name table");

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
		errx(1, "no .dynstr");
	if (!verneed.p)
		errx(1, "no .gnu.version_r");
	if (!symtab.p)
		errx(1, "no .symtab");
	if (!strtab.p)
		errx(1, "no .strtab");

	delsymver(dynstr, verneed, "libc.so.6",  "GLIBC_2.28");
	makeweak(strtab, symtab, "fcntl64@@GLIBC_2.28");

	r = pwrite(fd, p, n, 0);

	if (r < 0)
		err(1, "pwrite");

	if (r < n)
		errx(1, "partial write");

	close(fd);
	printf("all clear, now run `hacknode node script.js`\n");

	return 0;
}
