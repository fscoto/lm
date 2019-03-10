#ifndef LM_NUMNICK_H
#define LM_NUMNICK_H

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

#endif

