/*
 * Copyright (c) 2017, 2019 Fabio Scotoni
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <unistd.h>

#include "util.h"
#include "logging.h"

_Noreturn void
oom(void)
{
	fputs("Out of memory!", stderr);
	exit(1);
}

void *
smalloc(size_t size)
{
	void *ret;

	if ((ret = malloc(size)) == NULL)
		oom();

	return ret;
}

void *
scalloc(size_t nmemb, size_t size)
{
	void *ret;

	if ((ret = calloc(nmemb, size)) == NULL)
		oom();

	return ret;
}

int
ensure_read(int fd, unsigned char *buf, size_t nbytes)
{
	size_t total = 0;
	ssize_t nr;

	do {
		nr = read(fd, buf + total, nbytes - total);
		if (nr > 0) {
			total += (size_t)nr;
		} else if (nr == 0) {
			break;
		} else if (errno != EINTR) {
			log_fatal(SS_INT, 
					"unable to read from /dev/urandom: %s",
					strerror(errno));
			return -1;
		}
	} while (total < nbytes);

	return 0;
}

void *
randombytes(void *buf, size_t nbytes)
{
	/* XXX: ASSUMPTION: /dev/urandom is actually /dev/urandom. */
	int fd;

	if ((fd = open("/dev/urandom", O_RDONLY)) == -1) {
		log_fatal(SS_INT, "unable to open /dev/urandom: %s",
				strerror(errno));
		return NULL;
	}

	if (ensure_read(fd, buf, nbytes) != 0) {
		close(fd);
		return NULL;
	}

	close(fd);
	return buf;
}

void
split_args(char *line, size_t max_args, size_t *argc, char **argv,
		bool colonize)
{
	char *eol = line + strlen(line);
	size_t narg = 0;
	size_t len;

	for (char *p = strtok(line, " ");
			p != NULL && narg < max_args;
			p = strtok(NULL, " ")) {
		if (*p == ':' && colonize) {
			len = strlen(p);
			/* Heal the '\0' introduced by strtok for the colon arg
			 * if the colon arg has a space.
			 */
			if (p + len != eol)
				p[strlen(p)] = ' ';
			argv[narg++] = ++p;
			break;
		}
		argv[narg++] = p;
	}

	*argc = narg;
}

int
util_rebind_stdfd(void)
{
	int fd;

	if ((fd = open("/dev/null", O_RDWR, 0)) == -1) {
		log_fatal(SS_INT, "unable to open /dev/null: %s",
				strerror(errno));
		return -1;
	}

	dup2(fd, fileno(stdin));
	dup2(fd, fileno(stdout));
	dup2(fd, fileno(stderr));

	return 0;
}

/*
 * We should strip ANSI escape sequences from user-controlled fields for
 * security reasons, but to prevent general terminal weirdness, we'll strip
 * everything below ' '.
 * cf. https://security.stackexchange.com/a/56391
 */
char *
stripesc(char *s)
{
	for (char *p = s; *p != '\0'; ++p) {
		if (*p < ' ')
			*p = '_';
	}

	return s;
}

