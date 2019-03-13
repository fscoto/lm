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

