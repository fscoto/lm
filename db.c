#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "db.h"
#include "lm.h"
#include "logging.h"
#include "mail.h"
#include "monocypher.h"
#include "sqlite3.h"
#include "entities.h"
#include "token.h"
#include "util.h"

#define HASH_LEN	(32)
#define SALT_LEN	(16)

/* In case argon2i ever gets broken or we need to change the default parameters
 * for argon2i, it's best we encode this information already.
 */
enum PasswordAlgorithm {
	PA_ARGON2I
};

static sqlite3 *db;

static inline int
prepare(const char *query, sqlite3_stmt **s)
{
	return sqlite3_prepare_v2(db, query, strlen(query), s, NULL);
}

static void
hash_password(unsigned char hash[static HASH_LEN], const char *password,
		const unsigned char salt[static SALT_LEN])
{
	/* 100 megabytes; 100000 blocks @ 1024 bytes each */
	void *work_area = smalloc(102400000LU);
	crypto_argon2i(hash, HASH_LEN,
			work_area, 100000,
			3,
			(const unsigned char *)password, strlen(password),
			(const unsigned char *)salt, SALT_LEN);
	free(work_area);
}

int
db_init(void)
{
#define LM_STRINGIFY_(x) #x
#define LM_STRINGIFY(x) LM_STRINGIFY_(x)
	const char *create_query =
		"CREATE TABLE IF NOT EXISTS accounts ("
		"    id INTEGER PRIMARY KEY NOT NULL,"
		"    name VARCHAR(12) UNIQUE NOT NULL,"
		"    email VARCHAR(254) UNIQUE NOT NULL,"
		"    pwalgo SMALLINT NOT NULL,"
		"    pwsalt BLOB NOT NULL,"
		"    pwhash BLOB NOT NULL,"
		"    created INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),"
		"    expires INTEGER NOT NULL DEFAULT (strftime('%s', 'now') + "
			LM_STRINGIFY(TOKEN_EXPIRY) ")"
		")";
#undef LM_STRINGIFY_
#undef LM_STRINGIFY
	char *errmsg = NULL;

	if (sqlite3_open("lm.db", &db) != 0) {
		log_fatal(SS_SQL, "unable to open lm.db: %s\n",
				sqlite3_errmsg(db));
		return -1;
	}

	if (sqlite3_exec(db, create_query, NULL, NULL, &errmsg) != SQLITE_OK) {
		log_fatal(SS_SQL, "unable to create table accounts: %s\n",
				errmsg);
		return -1;
	}

	log_info(SS_SQL, "database lm.db opened");
	return 0;
}

enum DBError
db_check_auth(const char *account, const char *password, time_t *ts)
{
	sqlite3_stmt *s;
	const unsigned char *salt;
	const unsigned char *myhash;
	int sqlite_ret;
	enum DBError ret;
	unsigned char theirhash[HASH_LEN];

	log_debug(SS_SQL, "auth check for %s with %s (TS: %llu)...");

	prepare("SELECT pwsalt, pwhash, created FROM accounts WHERE "
			"LOWER(name) = LOWER(?) AND expires = 0 LIMIT 1", &s);
	sqlite3_bind_text(s, 1, account, strlen(account), SQLITE_STATIC);

	sqlite_ret = sqlite3_step(s);
	if (sqlite_ret == SQLITE_DONE) {
		crypto_wipe((unsigned char *)password, strlen(password));
		sqlite3_finalize(s);
		return DBE_NO_SUCH_ACCOUNT;
	} else if (sqlite_ret != SQLITE_ROW) {
		log_error(SS_SQL, "unable to SELECT: %s",
				sqlite3_errstr(sqlite_ret));
		crypto_wipe((unsigned char *)password, strlen(password));
		sqlite3_finalize(s);
		return DBE_SQLITE;
	}

	salt = sqlite3_column_blob(s, 0);
	myhash = sqlite3_column_blob(s, 1);
	if (sqlite3_column_bytes(s, 0) != SALT_LEN) {
		log_error(SS_SQL, "SALT_LEN desync");
		sqlite3_finalize(s);
		crypto_wipe((unsigned char *)password, strlen(password));
		return DBE_DESYNC;
	}
	if (sqlite3_column_bytes(s, 1) != HASH_LEN) {
		log_error(SS_SQL, "HASH_LEN desync");
		sqlite3_finalize(s);
		crypto_wipe((unsigned char *)password, strlen(password));
		return DBE_DESYNC;
	}
	hash_password(theirhash, password, salt);
	crypto_wipe((unsigned char *)password, strlen(password));
	if (crypto_verify32(theirhash, myhash) != 0) {
		ret = DBE_PW_MISMATCH;
		log_debug(SS_SQL, "auth check for %s failed", account);
	} else {
		ret = DBE_OK;
		log_debug(SS_SQL, "auth check for %s succeeded (TS: %llu)",
				account,
				(unsigned long long)sqlite3_column_int64(s, 2));
	}
	crypto_wipe(theirhash, HASH_LEN);
	if (ts != NULL)
		*ts = (time_t)sqlite3_column_int64(s, 2);
	sqlite3_finalize(s);

	return ret;
}

enum DBError
db_create_account(const struct User *u, const char *name, const char *email)
{
	sqlite3_stmt *s;
	size_t name_len;
	size_t email_len;
	int sqlite_ret;
	enum DBError ret;

	log_debug(SS_SQL, "creating account for %s with e-mail %s",
			name, email);

	if ((name_len = strlen(name)) > ACCOUNT_LEN)
		return DBE_ACCOUNT_NAME_TOO_LONG;

	if ((email_len = strlen(email)) > EMAIL_LEN)
		return DBE_EMAIL_TOO_LONG;

	prepare("INSERT INTO accounts(name, email, pwalgo, pwsalt, pwhash) "
			"VALUES (?, ?, -1, '', '')", &s);
	sqlite3_bind_text(s, 1, name, name_len, SQLITE_STATIC);
	sqlite3_bind_text(s, 2, email, email_len, SQLITE_STATIC);

	if ((sqlite_ret = sqlite3_step(s)) != SQLITE_DONE) {
		if (sqlite3_extended_errcode(db) == SQLITE_CONSTRAINT_UNIQUE) {
			ret = DBE_ACCOUNT_IN_USE;
		} else {
			ret = DBE_SQLITE;
			log_error(SS_SQL, "unable to INSERT: %s",
					sqlite3_errstr(sqlite_ret));
		}
		sqlite3_finalize(s);
		return ret;
	}

	return DBE_OK;
}

enum DBError
db_change_password(const char *account, const char *password)
{
	sqlite3_stmt *s;
	int sqlite_ret;
	unsigned char hash[HASH_LEN];
	unsigned char salt[SALT_LEN];

	log_debug(SS_SQL, "updating password for %s to be %s",
			account, password);

	if (randombytes(salt, sizeof(salt)) == NULL)
		return DBE_CRYPTO;
	hash_password(hash, password, salt);
	crypto_wipe((unsigned char *)password, strlen(password));

	prepare("UPDATE accounts SET pwalgo = ?, pwsalt = ?, pwhash = ?, "
			"expires = 0 WHERE LOWER(name) = LOWER(?)", &s);
	sqlite3_bind_int(s, 1, PA_ARGON2I);
	sqlite3_bind_blob(s, 2, salt, SALT_LEN, SQLITE_STATIC);
	sqlite3_bind_blob(s, 3, hash, HASH_LEN, SQLITE_STATIC);
	sqlite3_bind_text(s, 4, account, strlen(account), SQLITE_STATIC);

	if ((sqlite_ret = sqlite3_step(s)) != SQLITE_DONE) {
		log_error(SS_SQL, "unable to UPDATE: %s",
				sqlite3_errstr(sqlite_ret));
		sqlite3_finalize(s);
		return DBE_SQLITE;
	}

	sqlite3_finalize(s);
	return DBE_OK;
}

enum DBError db_get_account_by_email(const char *email,
		char account[static ACCOUNT_LEN])
{
	sqlite3_stmt *s;
	int sqlite_ret;

	prepare("SELECT name FROM accounts WHERE "
			"LOWER(email) = LOWER(?) AND "
			"expires = 0 LIMIT 1", &s);
	sqlite3_bind_text(s, 1, email, strlen(email), SQLITE_STATIC);

	log_debug(SS_SQL, "selecting account name for e-mail %s", email);

	sqlite_ret = sqlite3_step(s);
	if (sqlite_ret == SQLITE_DONE) {
		sqlite3_finalize(s);
		return DBE_NO_SUCH_ACCOUNT;
	} else if (sqlite_ret != SQLITE_ROW) {
		log_error(SS_SQL, "unable to SELECT: %s",
				sqlite3_errstr(sqlite_ret));
		sqlite3_finalize(s);
		return DBE_SQLITE;
	}

	strcpy(account, (const char *)sqlite3_column_text(s, 0));
	sqlite3_finalize(s);
	return DBE_OK;
}

enum DBError db_get_email_by_account(const char *account,
		char email[static EMAIL_LEN])
{
	sqlite3_stmt *s;
	int sqlite_ret;

	prepare("SELECT email FROM accounts WHERE "
			"LOWER(name) = LOWER(?) "
			"AND expires = 0 LIMIT 1", &s);
	sqlite3_bind_text(s, 1, account, strlen(account), SQLITE_STATIC);

	log_debug(SS_SQL, "selecting e-mail for account %s", account);

	sqlite_ret = sqlite3_step(s);
	if (sqlite_ret == SQLITE_DONE) {
		sqlite3_finalize(s);
		return DBE_NO_SUCH_ACCOUNT;
	} else if (sqlite_ret != SQLITE_ROW) {
		log_error(SS_SQL, "unable to SELECT: %s",
				sqlite3_errstr(sqlite_ret));
		sqlite3_finalize(s);
		return DBE_SQLITE;
	}

	strcpy(email, (const char *)sqlite3_column_text(s, 0));
	sqlite3_finalize(s);
	return DBE_OK;
}

void
db_purge_expired(void)
{
	sqlite3_stmt *s;
	uint64_t now = time(NULL);
	int sqlite_ret;

	prepare("DELETE FROM accounts WHERE expires < ? AND expires != 0", &s);
	sqlite3_bind_int64(s, 1, (uint64_t)now);

	log_debug(SS_SQL, "purging accounts where expires < %llu "
			"&& expires != 0", (unsigned long long)now);

	if ((sqlite_ret = sqlite3_step(s)) != SQLITE_DONE) {
		log_error(SS_SQL, "unable to DELETE: %s",
				sqlite3_errstr(sqlite_ret));
	}

	sqlite3_finalize(s);
}

void
db_fini(void)
{
	sqlite3_close(db);
	log_info(SS_SQL, "database lm.db closed");
}

