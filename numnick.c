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

#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "numnick.h"
#include "logging.h"
#include "entities.h"
#include "util.h"

static struct Server servers[4096];

static const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz0123456789[]";
static const unsigned char table[] = {
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/*   */ 255,
	/* ! */ 255,
	/* " */ 255,
	/* # */ 255,
	/* $ */ 255,
	/* % */ 255,
	/* & */ 255,
	/* ' */ 255,
	/* ( */ 255,
	/* ) */ 255,
	/* * */ 255,
	/* + */ 255,
	/* , */ 255,
	/* - */ 255,
	/* . */ 255,
	/* / */ 255,
	/* 0 */  52,
	/* 1 */  53,
	/* 2 */  54,
	/* 3 */  55,
	/* 4 */  56,
	/* 5 */  57,
	/* 6 */  58,
	/* 7 */  59,
	/* 8 */  60,
	/* 9 */  61,
	/* : */ 255,
	/* ; */ 255,
	/* < */ 255,
	/* = */ 255,
	/* > */ 255,
	/* ? */ 255,
	/* @ */ 255,
	/* A */   0,
	/* B */   1,
	/* C */   2,
	/* D */   3,
	/* E */   4,
	/* F */   5,
	/* G */   6,
	/* H */   7,
	/* I */   8,
	/* J */   9,
	/* K */  10,
	/* L */  11,
	/* M */  12,
	/* N */  13,
	/* O */  14,
	/* P */  15,
	/* Q */  16,
	/* R */  17,
	/* S */  18,
	/* T */  19,
	/* U */  20,
	/* V */  21,
	/* W */  22,
	/* X */  23,
	/* Y */  24,
	/* Z */  25,
	/* [ */  62,
	/* \ */ 255,
	/* ] */  63,
	/* ^ */ 255,
	/* _ */ 255,
	/* ` */ 255,
	/* a */  26,
	/* b */  27,
	/* c */  28,
	/* d */  29,
	/* e */  30,
	/* f */  31,
	/* g */  32,
	/* h */  33,
	/* i */  34,
	/* j */  35,
	/* k */  36,
	/* l */  37,
	/* m */  38,
	/* n */  39,
	/* o */  40,
	/* p */  41,
	/* q */  42,
	/* r */  43,
	/* s */  44,
	/* t */  45,
	/* u */  46,
	/* v */  47,
	/* w */  48,
	/* x */  49,
	/* y */  50,
	/* z */  51,
	/* { */ 255,
	/* | */ 255,
	/* } */ 255,
	/* ~ */ 255,
	/*   */ 255,
};

/* ASSUMPTIONS:
 * 
 * - strlen(numnick) == 2
 * - Every character in numnick is in A-Za-z0-9[]
 */
struct Server *
numnick_server(const char *numnick)
{
	const unsigned char *s = (const unsigned char *)numnick;
	unsigned int server;

	server = table[s[0]] * 64 + table[s[1]];
	return &servers[server];
}

/* ASSUMPTIONS:
 * 
 * - strlen(numnick) == 5
 * - Every character in numnick is in A-Za-z0-9[]
 * - The server entry exists in the array
 */
struct User *
numnick_user(const char *numnick)
{
	const unsigned char *s = (const unsigned char *)numnick;
	unsigned long user;
	unsigned int server;

	server = table[s[0]] * 64 + table[s[1]];
	user = table[s[2]] * 4096
		+ table[s[3]] * 64 + table[s[4]];

	return &servers[server].users[user];
}

struct Server *
numnick_register_server(const char *numnick, const char *name,
		struct Server *uplink)
{
	const unsigned char *s = (const unsigned char *)numnick;
	size_t server;
	size_t usercount;

	server = table[s[0]] * 64 + table[s[1]];
	usercount = table[s[2]] * 4096
		+ table[s[3]] * 64 + table[s[4]];

	log_network("server %s (%s/%zu) linking", name, numnick, server);

	servers[server].users = scalloc(usercount, sizeof(*servers[server].users));
	servers[server].uplink = uplink;
	snprintf(servers[server].name, sizeof(servers[server].name),
			"%s", name);
	return &servers[server];
}

void
decode_ip_numeric_into_user(struct User *u, const char *ip_numeric)
{
	const unsigned char *ipn = (const unsigned char *)ip_numeric;
	size_t len = strlen(ip_numeric);
	void *addr;
	struct in_addr addr4;
	struct in6_addr addr6;
	short af;

	if (len == 6) {
		af = AF_INET;
		addr = &addr4;

		addr4.s_addr = htonl((table[ipn[0]] * (64UL*64*64*64*64)) +
			(table[ipn[1]] * (64UL*64*64*64)) +
			(table[ipn[2]] * (64UL*64*64)) +
			(table[ipn[3]] * (64UL*64)) +
			(table[ipn[4]] * (64UL)) +
			table[ipn[5]]);
	} else {
		size_t skipped;
		size_t o = 0;
		unsigned short hextets[8];

		af = AF_INET6;
		addr = &addr6;

		/*
		 * 1:2::3 -> AABAAC_AAD
		 * three characters per hextet
		 * max 24 encoded chars
		 * _ for longest AAA (0) sequence, aligns with three chars
		 */
		for (size_t i = 0; i < len; i += 3) {
			if (ipn[i] == '_') {
				/* + 1 to adjust for '_' itself */
				skipped = 24 - len + 1;
				/* adjust for hextets */
				skipped /= 3;
				for (size_t j = 0; j < skipped; ++j)
					hextets[o++] = 0;

				/*
				 * adjust input offset
				 * for the i += 3 on continue
				 */
				i -= 2;
				continue;
			}

			hextets[o++] = (table[ipn[i]] * (64 * 64)) +
					(table[ipn[i + 1]] * (64)) +
					table[ipn[i + 2]];
		}

		for (size_t i = 0;
				i < sizeof(hextets)/sizeof(hextets[0]);
				++i) {
			addr6.s6_addr[(2 * i)]     = hextets[i] >> 8;
			addr6.s6_addr[(2 * i) + 1] = hextets[i] & 0xFF;
		}
	}

	inet_ntop(af, addr, u->sockip, sizeof(u->sockip));
}

struct User *
numnick_register_user(const char *numnick, const char *nick, const char *ident,
		const char *host, const char *gecos, const char *ip_numeric,
		const char *accname, bool is_oper)
{
	struct User *u = numnick_user(numnick);
	const unsigned char *s = (const unsigned char *)numnick;

	u->sid = table[s[0]] * 64 + table[s[1]];
	u->uid = table[s[2]] * 4096
		+ table[s[3]] * 64 + table[s[4]];

	log_debug(SS_NET, "registering user %s (%s!%s@%s[=%s]/%s)", numnick,
			nick, ident, host, ip_numeric, gecos);

	if (accname != NULL)
		snprintf(u->account, sizeof(u->account), "%s", accname);
#define FILLFIELD(field)	do {\
	snprintf(u->field, sizeof(u->field), "%s", field);\
} while (0)
	FILLFIELD(nick);
	FILLFIELD(ident);
	FILLFIELD(host);
	FILLFIELD(gecos);
#undef FILLFIELD
	/* gecos is untrusted user input and may have escape sequences that may
	 * become a security vulnerability later in the code.
	 * I'd rather discard part of the gecos here than have to carry the risk
	 * of a log entry becoming an issue later on.
	 */
	(void)stripesc(u->gecos);
	decode_ip_numeric_into_user(u, ip_numeric);
	u->is_oper = is_oper;

	return u;
}

void
numnick_deregister_user(const char *numnick)
{
	struct User *u = numnick_user(numnick);

	if (u == NULL) {
		log_error(SS_INT, "unknown numnick %s!", numnick);
		return;
	}

	log_debug(SS_NET, "deregistering user %s", numnick);
	memset(u, 0, sizeof(*u));
}

static void
deregister_server_recurse(struct Server *s)
{
	if (s == NULL) {
		/* That's me! We'll get an EOF event to handle, though, so we
		 * can ignore a delink for ourselves.
		 */
		return;
	}

	/* Find servers that are linked to this one.
	 * This is slow, but we rarely have to do this anyway.
	 */
	for (size_t i = 0; i < 4096; ++i) {
		if (servers[i].uplink == s) {
			log_debug(SS_NET, "server %s (%c%c/%u) "
					"linked to %s, removing",
					servers[i].name,
					alphabet[i >> 6], alphabet[i & 63], i,
					s->name);
			deregister_server_recurse(&servers[i]);
		}
	}

	free(s->users);
	memset(s, 0, sizeof(*s));
}

void
deregister_server_by_name(const char *name)
{
	log_network("server %s delinking", name);

	/* Find server that is called like the given name.
	 * This is *super* slow, but we rarely have to do this anyway.
	 */
	for (size_t i = 0; i < 4096; ++i) {
		if (!strcasecmp(servers[i].name, name)) {
			deregister_server_recurse(&servers[i]);
			return;
		}
	}

	log_warn(SS_INT, "cannot deregister unknown server %s", name);
}

char *
user_numnick(char out[static 6], const struct User *u)
{
	unsigned long val = ((unsigned long)u->sid << 18) | u->uid;
	for (size_t i = 5; i > 0; --i) {
		out[i - 1] = alphabet[(val & 63)];
		val >>= 6;
	}
	out[5] = '\0';

	return out;
}

static uint32_t
decode_token_quintuplet(const char t[4])
{
	uint32_t a, b, c, d;

	if ((size_t)t[0] > sizeof(table) ||
			(size_t)t[1] > sizeof(table) ||
			(size_t)t[2] > sizeof(table) ||
			(size_t)t[3] > sizeof(table) ||

			(a = table[(size_t)t[3]]) == 255 ||
			(b = table[(size_t)t[2]]) == 255 ||
			(c = table[(size_t)t[1]]) == 255 ||
			(d = table[(size_t)t[0]]) == 255)
		return 0xffffffffLU;

	return (a * 64UL*64*64) +
		(b * 64UL*64) +
		(c * 64UL) +
		d;
}

static void
store24_le(uint8_t out[3], uint32_t n)
{
	out[0] =  n        & 0xff;
	out[1] = (n >>  8) & 0xff;
	out[2] = (n >> 16) & 0xff;
}

static uint32_t
load24_le(const uint8_t in[3])
{
	return (uint32_t)in[0] |
		((uint32_t)in[1] <<  8) |
		((uint32_t)in[2] << 16);
}

int
decode_token(uint8_t bToken[60], const char szToken[81])
{
	/*
	 * Base 64 is aligned with bytes when the length of the message in bits is
	 * divisible by 6 and 8.
	 * The smallest such unit is three bytes (24 bits).
	 * The token is thus divided into units of three bytes and each of those are
	 * encoded or decoded separately into or from units of four characters.
	 * Token format:
	 *   24 bytes nonce ||
	 *   16 bytes MAC ||
	 *   8 bytes timestamp ||
	 *   ACCOUNT_LEN bytes account name
	 *   total: 60 bytes (480 bits), divisible by 6 and 8,
	 *   encoded length: 80 bytes (640 bits).
	 */
	static uint8_t buf[60];
	uint32_t n;
	uint8_t *out = buf;

	memset(bToken, 0, sizeof(buf));

	if (strlen(szToken) != 80)
		return -1;

	while (*szToken) {
		if ((n = decode_token_quintuplet(szToken)) == 0xffffffffLU)
			return -1;
		szToken += 4;
		store24_le(out, n);
		out += 3;
	}

	/* do not write bToken unless success;
	 * do not let partial attacker data near the validation
	 */
	memcpy(bToken, buf, sizeof(buf));
	return 0;
}

void
encode_token(char szToken[81], const uint8_t bToken[60])
{
	uint32_t n;

	for (size_t i = 0; i < 60; i += 3) {
		n = load24_le(bToken + i);
		*szToken++ = alphabet[ n        & 63];
		*szToken++ = alphabet[(n >>  6) & 63];
		*szToken++ = alphabet[(n >> 12) & 63];
		*szToken++ = alphabet[(n >> 18) & 63];
	}
	*szToken = '\0';
}
