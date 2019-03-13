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

#ifndef LM_LM_H
#define LM_LM_H

#include <stdint.h>

#include "entities.h"

struct Config {
	struct {
		char name[64];
		char desc[51];
		char numeric[3];
	} server;
	struct {
		char nick[16];
		char ident[11];
		char host[64];
		char gecos[51];
		char numnick[6];
	} user;
	struct {
		char addrport[64];
		char theirpass[21];
		char mypass[21];
		char l_numeric[3];
	} uplink;
	struct {
		char sendmailcmd[255];
		char fromemail[255];
		char fromname[50];
	} mail;
};

extern struct Config config;

void send_line(const char *fmt, ...);
void reply(const struct User *u, const char *fmt, ...);
void s2s_line(const char *fmt, ...);
void lm_exit(void);
void lm_send_hasher_request(const char *password, const uint8_t *salt);

#endif

