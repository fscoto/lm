/*
 * Written in 2019 by Fabio Scotoni
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide.  This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along
 * with this software.  If not, see
 * <https://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ini.h"
#include "util.h"

int
ini_open(struct IniContext *ctx, const char *path)
{
	if ((ctx->f = fopen(path, "rt")) == NULL)
		return -1;

	ctx->section = NULL;
	ctx->lp = NULL;
	ctx->ll = 0;

	return 0;
}

/* jump over whitespace */
#define SJUMP(p) do {\
	while (*(p) != '\0' && *(p) != '\n' && (*(p) == ' ' || *(p) == '\t'))\
		++(p);\
} while (0)
#define TJUMP(p) do {\
	while (*(p) != '\0' && *(p) != '\n' && *(p) != ' ' && *(p) != '\t')\
		++(p);\
} while (0)

/* key, value only valid until next invocation */
int
ini_next(struct IniContext *ctx, const char **section, const char **key, const char **value)
{
	char *p, *q;
	ssize_t nr;

	while ((nr = getline(&ctx->lp, &ctx->ll, ctx->f)) != -1) {
		/* comment */
		if (*ctx->lp == ';' || *ctx->lp == '#' || *ctx->lp == '\n')
			continue;
		p = ctx->lp;
		/* section header, no whitespace stripping */
		if (*p == '[') {
			free(ctx->section);
			++p;
			if ((p = strchr(p, ']')) == NULL)
				return -1;
			*p = '\0';
			ctx->section = sstrdup(ctx->lp + 1);
			SJUMP(p);
			continue;
		}

		/* value */
		SJUMP(p);
		q = p;
		/* no whitespace in key */
		TJUMP(q);
		*q = '\0';
		*key = p;
		p = ++q;
		SJUMP(p);
		if (*p != '=')
			return -2;
		++p;
		SJUMP(p);
		/* value can contain spaces */
		q = strchr(p, '\n');
		if (q != NULL)
			*q = '\0';
		*value = p;
		break;
	}

	*section = ctx->section;
	if (nr == -1) {
		if (errno != 0) {
			ini_close(ctx);
			return -1;
		}

		/* EOF */
		return 1;
	}

	return 0;
}

void
ini_close(struct IniContext *ctx)
{
	free(ctx->section);
	free(ctx->lp);
	fclose(ctx->f);
	memset(ctx, 0, sizeof(*ctx));
}

#if 0
#include <err.h>
int
main(void)
{
	struct IniContext ctx;
	const char *section, *key, *value;

	if (ini_open(&ctx, "lm.ini") != 0) {
		errx(1, "ini_open");
	}

	for (;;) {
		int ret;
		switch ((ret = ini_next(&ctx, &section, &key, &value))) {
		case 0:
			printf("[%s] %s = %s\n", (section ? section : "(null)"), key, value);
			break;
		case 1:
			puts("EOF");
			goto endloop;
		default:
			errx(1, "ini_next: %d", ret);
		}
	}

endloop:
	ini_close(&ctx);
}
#endif

