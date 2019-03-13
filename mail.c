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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "mail.h"
#include "monocypher.h"
#include "lm.h"
#include "entities.h"

static void
split_and_msg(const struct User *u, char *buf)
{
	reply(u, "----- Start virtual e-mail -----");
	for (char *p = strtok(buf, "\n");
			p != NULL;
			p = strtok(NULL, "\n"))
		reply(u, p);
	reply(u, "----- End virtual e-mail -----");
}

int
mail(const struct User *u, const char *email, const char *fmt, ...)
{
	char buf[1024];
	va_list ap;
	FILE *p;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (*config.mail.sendmailcmd == '\0') {
		split_and_msg(u, buf);
		crypto_wipe(buf, sizeof(buf));
		return 0;
	}

	if ((p = popen(config.mail.sendmailcmd, "w")) == NULL) {
		crypto_wipe(buf, sizeof(buf));
		return -1;
	}

	fprintf(p, "From: \"%s\" <%s>\n", config.mail.fromname, config.mail.fromemail);
	fprintf(p, "To: <%s>\n", email);
	fprintf(p, "Subject: Message from %s\n", config.user.nick);
	fprintf(p, "%s", buf);
	fprintf(p, "\n.\n");
	pclose(p);

	/* We send some confidential messages via e-mail; wiping them is
	 * probably a good idea.
	 */
	crypto_wipe(buf, sizeof(buf));

	return 0;
}

