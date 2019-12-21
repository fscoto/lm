/* token.c: Utility functions for tokens.
 *
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

/*
 * Tokens consist of base 64 encoded set of fields,
 * see decode_token() in numnick.c
 *
 * Tokens expire after TOKEN_EXPIRY seconds.
 *
 * The token key is regenerated every time LM is restarted.
 * This means less configuration for the operator (which is good, they can't
 * break security with weak/stolen secrets), but this means tokens are not
 * portable across restarts (which is bad, making no sense to users).
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "token.h"
#include "logging.h"
#include "monocypher.h"
#include "numnick.h"
#include "entities.h"
#include "util.h"

static unsigned char token_key[32];
static bool has_token_key;

static void
store32_le(uint8_t out[4], uint64_t in)
{
	out[0] =  in        & 0xff;
	out[1] = (in >>  8) & 0xff;
	out[2] = (in >> 16) & 0xff;
	out[3] = (in >> 24) & 0xff;
}

static void
store64_le(uint8_t out[8], uint64_t in)
{
	store32_le(out    , in      );
	store32_le(out + 4, in >> 32);
}

static uint32_t
load32_le(const uint8_t s[4])
{
	return (uint32_t)s[0]
		| ((uint32_t)s[1] <<  8)
		| ((uint32_t)s[2] << 16)
		| ((uint32_t)s[3] << 24);
}

static uint64_t
load64_le(const uint8_t s[8])
{
	return load32_le(s) | ((uint64_t)load32_le(s + 4) << 32);
}

char *
token_create(char token[static TOKEN_LEN + 1], const char *account)
{
	uint64_t now;
	uint8_t buf[60];
	uint8_t *nonce = buf,
		*mac = nonce + 24,
		*text = mac + 16,
		*bNow = text,
		*bAccount = text + sizeof(uint64_t),
		*text_end = bAccount + ACCOUNT_LEN;

	if (!has_token_key) {
		if (randombytes(token_key, sizeof(token_key)) == NULL) {
			log_fatal(SS_INT, "randombytes() for %zu bytes failed",
					sizeof(token_key));
			return NULL;
		}
		has_token_key = true;
	}

	memset(buf, 0, sizeof(buf));

	if (randombytes(nonce, 24) == NULL) {
		log_fatal(SS_INT, "randomybtes() for 24 bytes failed");
		return NULL;
	}

	now = (uint64_t)time(NULL);
	store64_le(bNow, now);
	for (size_t i = 0, len = strlen(account); i < len; ++i)
		bAccount[i] = (uint8_t)account[i];

	crypto_lock(mac, text, token_key, nonce, text, (size_t)(text_end - text));
	encode_token(token, buf);

	if (crypto_unlock(text, token_key, nonce, mac, text,
				(size_t)(text_end - text)) != 0) {
		log_fatal(SS_INT, "unable to verify fresh token");
		return NULL;
	}

	return token;
}

enum TokenValidationStatus
token_validate(const char *token, char account_out[static ACCOUNT_LEN + 1])
{
	uint64_t then;
	uint8_t buf[60];
	uint8_t *nonce = buf,
		*mac = nonce + 24,
		*text = mac + 16,
		*bNow = text,
		*bAccount = text + sizeof(uint64_t),
		*text_end = bAccount + ACCOUNT_LEN;

	if (!has_token_key)
		/* technically a lie, but has least friction for users */
		return TVS_EXPIRED;

	if (decode_token(buf, token) != 0)
		return TVS_BAD;

	if (crypto_unlock(text, token_key, nonce, mac, text,
				(size_t)(text_end - text)) != 0)
		return TVS_BAD;

	then = load64_le(bNow);
	if (then + TOKEN_EXPIRY < (unsigned long long)time(NULL))
		return TVS_EXPIRED;

	memset(account_out, '\0', ACCOUNT_LEN + 1);
	for (size_t i = 0; i < ACCOUNT_LEN; ++i)
		account_out[i] = (char)bAccount[i];

	return TVS_OK;
}

