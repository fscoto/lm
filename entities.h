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

#ifndef LM_ENTITIES_H
#define LM_ENTITIES_H

#include <stdbool.h>

/* These can be controlled on the ircd via CFLAGS=-DTHINGLEN=..., but we'll
 * assume that nobody does that.
 */
#define NICK_LEN	(15)
#define USER_LEN	(10)
#define HOST_LEN	(63)
#define REAL_LEN	(63)
#define SOCKIP_LEN	(45)
#define ACCOUNT_LEN	(12)

struct User {
	unsigned long uid;
	unsigned int sid;
	char nick[NICK_LEN + 1];
	char ident[USER_LEN + 1];
	char host[HOST_LEN + 1];
	char gecos[HOST_LEN + 1];
	char sockip[SOCKIP_LEN + 1];
	char account[ACCOUNT_LEN + 1];
	bool is_oper;
};

static inline bool
user_authed(const struct User *u)
{
	return (*u->account != '\0');
}


/* We have to track servers because we otherwise wouldn't know that users
 * disappeared in a SQUIT.
 * We have to track users because we otherwise wouldn't be able to prevent
 * users from re-authenticating.
 * We have to prevent users from re-authenticating because otherwise the remote
 * will send annoying "Protocol violation from services: ..." messages.
 */
struct Server {
	/* Exact count depends on the SERVER/S message.
	 * This is an array.
	 */
	struct User *users;
	/* Server that introduced this server. */
	struct Server *uplink;
	/* Name of the server.
	 * SQ requires us to know it because for some reason ircu still sends
	 * the server name instead of numeric, despite it being unable to link
	 * with P09 for a long time.
	 */
	char name[HOST_LEN + 1];
};

#endif

