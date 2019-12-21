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

#ifndef LM_INI_H
#define LM_INI_H

struct IniContext {
	FILE *f;
	char *section;
	/* cache line buffer */
	char *lp;
	size_t ll;
};

int ini_open(struct IniContext *ctx, const char *path);
int ini_next(struct IniContext *ctx, const char **section,
		const char **key, const char **value);
void ini_close(struct IniContext *ctx);

#endif

