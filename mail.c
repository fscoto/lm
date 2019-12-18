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

