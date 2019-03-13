#ifndef LM_TOKEN_H
#define LM_TOKEN_H

#include "entities.h"

/* 30 minutes */
#define TOKEN_EXPIRY	(30*60)
/* see comment in numnick.c:decode_token() */
#define TOKEN_LEN	(80)

enum TokenValidationStatus {
	TVS_OK,
	TVS_BAD,
	TVS_EXPIRED
};

char *token_create(char buf[static TOKEN_LEN + 1], const char *account);
enum TokenValidationStatus token_validate(const char *token,
		char account_out[static ACCOUNT_LEN + 1]);

#endif

