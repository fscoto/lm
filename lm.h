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

