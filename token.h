#ifndef LM_TOKEN_H
#define LM_TOKEN_H

#include "entities.h"

/* 30 minutes */
#define TOKEN_EXPIRY	(30*60)
/* 
 * +20 for strlen(2**64), for the timestamp
 * +16 for the encoded signature
 * +2 for 2x ':'
 */
#define TOKEN_LEN	(ACCOUNT_LEN+20+16+2)

enum TokenValidationStatus {
	TVS_OK,
	TVS_BAD,
	TVS_EXPIRED
};

char *token_create(char buf[static TOKEN_LEN + 1], const char *account);
enum TokenValidationStatus token_validate(const char *token,
		char account_out[static ACCOUNT_LEN + 1]);

#endif

