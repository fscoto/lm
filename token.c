/* token.c: Utility functions for tokens.
 *
 * Tokens consist of an 8-byte BLAKE2b hash with key over the:
 * a. current timestamp (as 64-bit little-endian integer), and
 * b. account name (no trailing '\0').
 *
 * The signature is then base-16 encoded with a custom alphabet to prevent
 * offensive tokens (e.g. B00B135).
 *
 * Result (example): 1512137612:account:KKYLNDRTFMYTRNFH
 *
 * Tokens expire after TOKEN_EXPIRY seconds.
 * The signature is very short, but it only needs to hold up for 15 minutes.
 *
 * The token key is regenerated every time LM is restarted.
 * This means less configuration for the user (which is good, they can't break
 * security with weak secrets), but this means tokens are not portable across
 * restarts (which is bad, making no sense to users).
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

static void
encode_sig(char encoded_sig[17], const unsigned char sig[8])
{
	/* Custom alphabet to maybe throw off attackers and avoid accidental
	 * generation of words like B00B135.
	 */
	static const char *base16alphabet = "CDFHKLMNPRTVWXYZ";
	for (size_t i = 0; i < 16; i += 2) {
		encoded_sig[i    ] = base16alphabet[sig[i/2] >> 4];
		encoded_sig[i + 1] = base16alphabet[sig[i/2] & 15];
	}
	encoded_sig[16] = '\0';
}

static int
decode_char(int c)
{
	switch (c) {
	case 'C': return 0;
	case 'D': return 1;
	case 'F': return 2;
	case 'H': return 3;
	case 'K': return 4;
	case 'L': return 5;
	case 'M': return 6;
	case 'N': return 7;
	case 'P': return 8;
	case 'R': return 9;
	case 'T': return 10;
	case 'V': return 11;
	case 'W': return 12;
	case 'X': return 13;
	case 'Y': return 14;
	case 'Z': return 15;
	default: return -1;
	}
}

static int
decode_sig(unsigned char sig[8], const char encoded_sig[17])
{
	int low, high;

	for (size_t i = 0; i < 16; i += 2) {
		if ((high = decode_char(encoded_sig[i])) == -1 ||
				(low = decode_char(encoded_sig[i + 1])) == -1)
			return -1;
		sig[i / 2] = (unsigned char)((high << 4) | low);
	}

	return 0;
}

char *
token_create(char buf[static TOKEN_LEN + 1], const char *account)
{
	crypto_blake2b_ctx ctx;
	uint64_t now;
	uint8_t now_bytes[8];
	uint8_t sig[8];
	char encoded_sig[17];

	if (!has_token_key) {
		if (randombytes(token_key, sizeof(token_key)) == NULL) {
			log_fatal(SS_INT, "randombytes() for %zu bytes failed",
					sizeof(token_key));
			return NULL;
		}
	}

	now = time(NULL);
	store64_le(now_bytes, now);
	crypto_blake2b_general_init(&ctx, sizeof(sig), token_key,
			sizeof(token_key));
	crypto_blake2b_update(&ctx, now_bytes, sizeof(now_bytes));
	crypto_blake2b_update(&ctx, (const unsigned char *)account,
			strlen(account));
	crypto_blake2b_final(&ctx, sig);
	encode_sig(encoded_sig, sig);

	snprintf(buf, TOKEN_LEN + 1, "%llu:%s:%s", (unsigned long long)now,
			account, encoded_sig);
	return buf;
}

enum TokenValidationStatus
token_validate(const char *token, char account_out[static ACCOUNT_LEN + 1])
{
	crypto_blake2b_ctx ctx;
	char *encoded_time, *account, *encoded_sig;
	char *endp;
	uint64_t mysig, theirsig;
	uint64_t then;
	uint8_t buf[8];
	char t[TOKEN_LEN];

	if (strlen(token) > TOKEN_LEN)
		return TVS_BAD;

	strcpy(t, token);

	encoded_time = strtok(t, ":");
	if ((account = strtok(NULL, ":")) == NULL)
		return TVS_BAD;
	if (strlen(account) > ACCOUNT_LEN)
		return TVS_BAD;
	if ((encoded_sig = strtok(NULL, ":")) == NULL)
		return TVS_BAD;
	if (strlen(encoded_sig) != 2 * sizeof(buf))
		return TVS_BAD;
	if (decode_sig(buf, encoded_sig) != 0)
		return TVS_BAD;
	errno = 0;
	then = strtoull(encoded_time, &endp, 10);
	if (encoded_time[0] == '\0' || *endp != '\0')
		return TVS_BAD;
	if (errno == ERANGE && then == ULLONG_MAX)
		return TVS_BAD;

	theirsig = load64_le(buf);

	store64_le(buf, then);
	crypto_blake2b_general_init(&ctx, sizeof(buf), token_key,
			sizeof(token_key));
	crypto_blake2b_update(&ctx, buf, sizeof(buf));
	crypto_blake2b_update(&ctx, (const uint8_t *)account, strlen(account));
	crypto_blake2b_final(&ctx, buf);
	mysig = load64_le(buf);

	if (theirsig != mysig)
		return TVS_BAD;

	if (then + TOKEN_EXPIRY < (unsigned long long)time(NULL))
		return TVS_EXPIRED;

	strcpy(account_out, account);

	return TVS_OK;
}

