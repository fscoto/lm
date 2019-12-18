/*
 * Written in 2017, 2019 by Fabio Scotoni
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide.  This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along
 * with this software.  If not, see
 * <https://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef LM_UTIL_H
#define LM_UTIL_H

#include <stdnoreturn.h>

_Noreturn void oom(void);
void *smalloc(size_t size);
void *scalloc(size_t nmemb, size_t size);
void *randombytes(void *buf, size_t nbytes);
void split_args(char *line, size_t max_args, size_t *argc, char **argv,
		bool colonize);
int util_rebind_stdfd(void);
char *stripesc(char *s);

#endif

