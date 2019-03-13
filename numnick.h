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

#ifndef LM_NUMNICK_H
#define LM_NUMNICK_H

#include <stdint.h>

#include "entities.h"

struct Server *numnick_server(const char *numnick);
struct User *numnick_user(const char *numnick);
struct Server *numnick_register_server(const char *numnick, const char *name,
		struct Server *uplink);
struct User *numnick_register_user(const char *numnick, const char *nick,
		const char *ident, const char *host, const char *gecos,
		const char *ip_numeric, const char *accname, bool is_oper);
void numnick_deregister_user(const char *numnick);
void deregister_server_by_name(const char *name);
char *user_numnick(char out[static 6], const struct User *u);
int decode_token(uint8_t bToken[60], const char szToken[81]);
void encode_token(char szToken[81], const uint8_t bToken[60]);

#endif

