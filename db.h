#ifndef LM_DB_H
#define LM_DB_H

#include <stdint.h>

#include "entities.h"

#define EMAIL_LEN	(254)
#define PASSWORD_LEN	(128)

#define HASH_LEN	(32)
#define SALT_LEN	(16)

enum DBError {
	DBE_OK = 0,
	DBE_SQLITE,
	DBE_ACCOUNT_NAME_TOO_LONG,
	DBE_EMAIL_TOO_LONG,
	DBE_MTA,
	DBE_DESYNC,
	DBE_PW_MISMATCH,
	DBE_NO_SUCH_ACCOUNT,
	DBE_ACCOUNT_IN_USE,
	DBE_CRYPTO,
	DBE_BUSY
};

enum DBError db_create_account(const struct User *u, const char *name,
		const char *email);
enum DBError db_confirm_account(const char *account);
void db_check_auth(const char *account, char *password,
		void (*theircallback)(enum DBError dbe, const char *account, time_t ts, void *arg),
		void *theirarg);
void db_hash_response(uint8_t *theirhash);
void db_change_password(const char *account, const char *password,
		void (*theircallback)(enum DBError dbe, const char *account, time_t ts, void *arg),
		void *theirarg);
enum DBError db_get_account_by_email(const char *email,
		char account[static ACCOUNT_LEN]);
enum DBError db_get_email_by_account(const char *account,
		char email[static EMAIL_LEN]);
void db_purge_expired(void);
int db_init(void);
void db_fini(void);

#endif

