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

#ifndef LM_NUMNICK_H
#define LM_NUMNICK_H

#include <stdint.h>

#include "entities.h"

struct Server *numnick_server(const char *numnick);
struct User *numnick_user(const char *numnick);
void decode_ip_numeric_into_user(struct User *u, const char *ip_numeric);
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

