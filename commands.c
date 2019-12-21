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

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "commands.h"
#include "db.h"
#include "lm.h"
#include "logging.h"
#include "numnick.h"
#include "mail.h"
#include "monocypher.h"
#include "entities.h"
#include "token.h"
#include "util.h"

/* IRC effects; named after mdoc(7) macros */
#define C_AR	"\037"
#define C_NM	"\002"
#define C_SY	"\002"

#define NCOMMANDS	(9)
/* Four for RESETPASS. */
#define MAX_ARGS	(4)

enum CommandStatus {
	CS_OK		=  0,
	CS_FAILURE	= -1,
	CS_SYNTAX	= -2,
	CS_INTERNAL	= -3
};

struct Command;
typedef enum CommandStatus (*CommandHandlerType)(const struct Command *cmd,
		struct User *source, size_t argc, char *argv[]);

struct Command {
	const char *name;
	const char *desc;
	const char *usage;
	const char *help;
	const CommandHandlerType handler;
	size_t nprivargs;
	size_t privargs[MAX_ARGS];
};

static const struct Command commands[NCOMMANDS];

static void
usage(const struct User *u, const struct Command *cmd)
{
	reply(u, "Usage: " C_NM "%s %s", cmd->name, cmd->usage);
}

/* ':' restriction in case a network has a /AUTH command and a client naively
 * forwards the colon.
 */
static bool
is_valid_password(const char *password)
{
	return (strlen(password) < PASSWORD_LEN && *password != ':');
}

/* https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#email-address-validation */
static bool
is_valid_email(const char *email)
{
	char *at;

	if (strlen(email) > EMAIL_LEN)
		return false;

	if ((at = strchr(email, '@')) == NULL)
		return false;

	if (at - 1 - email > 64)
		return false;

	/* 255 exceeds EMAIL_LEN anyway, though. */
	if (strlen(at + 1) > 255)
		return false;

	return true;
}

static void
cmd_auth_cb(enum DBError dbe, const char *account, time_t ts, void *arg)
{
	struct User *source = arg;
	char numnick[6];

	switch (dbe) {
	case DBE_OK:
		strcpy(source->account, account);
		s2s_line("AC %s %s %llu",
				user_numnick(numnick, source), source->account,
				(unsigned long long)ts);
		reply(source, "Password accepted; you are now authenticated "
				"as %s.", source->account);
		break;
	case DBE_PW_MISMATCH:
	case DBE_NO_SUCH_ACCOUNT:
		reply(source, "Invalid credentials.");
		log_audit("%s%s!%s@%s(%s)=%s/%s failed auth for "
				"%saccount %s",
			source->is_oper ? "*" : "", source->nick, source->ident,
			source->host, source->sockip, source->account,
			source->gecos,
			(dbe == DBE_NO_SUCH_ACCOUNT) ? "non-existent " : "",
			account);
		break;
	default:
		reply(source, "An error was encountered when fetching "
				"the account.");
		reply(source, "Please contact an IRC operator with this "
				"error code: %d.", dbe);
		break;
	}
}

static enum CommandStatus
cmd_auth(const struct Command *cmd, struct User *source,
		size_t argc, char *argv[])
{
	/* ircu actually enforces this */
	if (user_authed(source)) {
		reply(source, "You cannot reauthenticate.");
		reply(source, "You must reconnect if you want to "
				"authenticate to another account.");
		return CS_FAILURE;
	}

	if (argc < 2) {
		usage(source, cmd);
		return CS_SYNTAX;
	}

	db_check_auth(argv[0], argv[1], cmd_auth_cb, source);
	return CS_OK;
}

static enum CommandStatus
cmd_showcommands(const struct Command *cmd, struct User *source,
		size_t argc, char *argv[])
{
	reply(source, "The following commands are recognized.");
	reply(source, "For details on a specific command, use HELP "
			C_AR "command" C_AR ".");
	for (size_t i = 0; i < NCOMMANDS; ++i) {
		/* 13 because strlen("SHOWCOMMANDS") + 1 */
		reply(source, "%-13s %s", commands[i].name, commands[i].desc);
	}
	reply(source, "End of command listing.");
	if (source->is_oper)
		reply(source, "You are an " C_SY "IRC operator" C_SY ".");
	return CS_OK;
}

static enum CommandStatus
cmd_help(const struct Command *cmd, struct User *source,
		size_t argc, char *argv[])
{
	char *splittext;

	if (argc == 0) {
		cmd_showcommands(cmd, source, 0, NULL);
		return CS_OK;
	}

	for (size_t i = 0; i < NCOMMANDS; ++i) {
		if (strcasecmp(commands[i].name, argv[0]))
			continue;

		usage(source, &commands[i]);

		splittext = smalloc(strlen(commands[i].help) + 1);
		strcpy(splittext, commands[i].help);

		for (char *p = strtok(splittext, "\n");
				p != NULL;
				p = strtok(NULL, "\n"))
			reply(source, p);

		free(splittext);
		return CS_OK;
	}

	reply(source, "No such command " C_NM "%s" C_NM ".", argv[0]);
	return CS_FAILURE;
}

static enum CommandStatus
cmd_hello(const struct Command *cmd, struct User *source,
		size_t argc, char *argv[])
{
	size_t account_len;
	enum DBError dbe;
	char token[TOKEN_LEN + 1];
	char *account, *email;

	if (user_authed(source)) {
		reply(source, "You are already registered.");
		return CS_FAILURE;
	}

	if (argc < 3) {
		usage(source, cmd);
		return CS_SYNTAX;
	}

	account = argv[0];
	email = argv[1];
	account_len = strlen(account);

	/* Arbitrary restriction to make accounts also valid nicks. */
	if (*account >= '0' && *account <= '9') {
		reply(source, "Username must not start with a number.");
		return CS_FAILURE;
	}

	for (char *p = account; *p != '\0'; ++p) {
		if (*p < '0' ||
				(*p > '9' && *p < 'A') ||
				(*p > 'Z' && *p < 'a') ||
				*p > 'z') {
			reply(source, "Username must be alphanumeric "
					"(A-Za-z0-9).");
			return CS_FAILURE;
		}
	}

	/* One-character usernames reserved for services. */
	if (account_len < 2) {
		reply(source, "Username too short, minimum 2 characters.");
		return CS_FAILURE;
	}

	if (account_len > ACCOUNT_LEN) {
		reply(source, "Username too long, maximum %d characters.",
				ACCOUNT_LEN);
		return CS_FAILURE;
	}

	if (strlen(email) > EMAIL_LEN) {
		reply(source, "E-mail address too long, maximum %d characters.",
				EMAIL_LEN);
		return CS_FAILURE;
	}

	if (!is_valid_email(email)) {
		reply(source, "The given e-mail address is invalid.");
		return CS_FAILURE;
	}

	if (strcasecmp(email, argv[2])) {
		reply(source, "E-mail addresses mismatch. Make sure that you "
				"type the e-mail addresses");
		reply(source, "correctly both times.");
		return CS_FAILURE;
	}

	switch ((dbe = db_create_account(source, account, email))) {
	case DBE_ACCOUNT_IN_USE:
		reply(source, "Username or e-mail already in use.");
		return CS_FAILURE;
	case DBE_OK:
		break;
	default:
		reply(source, "An error was encountered when creating "
				"your account.");
		reply(source, "Please contact an IRC operator with this "
				"error code: %d.", dbe);
		return CS_INTERNAL;
	}

	if (token_create(token, account) == NULL) {
		/* We only get here on randombytes() failure. */
		reply(source, "An error was encountered when creating "
				"your account.");
		reply(source, "Please contact an IRC operator with this "
				"error code: RND.");
		return CS_INTERNAL;
	}

	if (mail(source, email,
				"Dear %s,\n"
				"\n"
				"Thank you for signing up with %s.\n"
				"You must still confirm your account.\n"
				"If you did not request this, please ignore "
				"this message.\n"
				"To confirm your account, use this command:\n"
				"/msg %s@%s CONFIRM %s newpassword "
				"newpassword\n"
				"where \"newpassword\" is the new password to "
				"use.",
				account,
				config.user.nick,
				config.user.nick,
				config.server.name,
				token) != 0) {
		reply(source, "An error was encountered sending e-mail.");
		reply(source, "Please contact an IRC operator.");
		return CS_INTERNAL;
	}

	reply(source, "Account created successfully.");
	reply(source, C_SY "Your account still needs to be confirmed in the "
			"next 30 minutes" C_SY ".");
	reply(source, "Please check your e-mail inbox for further"
			" instructions.");
	return CS_OK;
}

static void
cmd_confirm_cb(enum DBError dbe, const char *account, time_t ts,
		void *arg)
{
	const struct User *source = arg;

	(void)ts;

	if (dbe != DBE_OK) {
		reply(source, "An error was encountered when setting "
				"your password.");
		reply(source, "Please contact an IRC operator with this "
				"error code: %d.", dbe);
	}

	log_audit("%s%s!%s@%s(%s)=%s/%s changed password for account %s "
			"(registered)",
		source->is_oper ? "*" : "", source->nick, source->ident,
		source->host, source->sockip, source->account,
		source->gecos,
		account);
	reply(source, "Registration confirmed successfully.");
}

static enum CommandStatus
cmd_confirm(const struct Command *cmd, struct User *source,
		size_t argc, char *argv[])
{
	char account[ACCOUNT_LEN + 1];

	if (user_authed(source)) {
		reply(source, "You are already registered.");
		return CS_FAILURE;
	}

	if (argc < 3) {
		usage(source, cmd);
		return CS_SYNTAX;
	}

	switch (token_validate(argv[0], account)) {
	case TVS_OK:
		break;
	case TVS_BAD:
		reply(source, "Invalid token. Please make sure that you have "
				"copied it correctly.");
		return CS_FAILURE;
	case TVS_EXPIRED:
		/*
		 * Special case: LM restart, where we literally lost the user
		 * info.
		 * The user will have to wait the 30 (plus up to five) minutes
		 * out until the stale account is purged from the database.
		 */
		reply(source, "Your token has expired.");
		reply(source, "Please use " C_NM "HELLO" C_NM " again.");
		return CS_FAILURE;
	}

	if (!is_valid_password(argv[1])) {
		reply(source, "Invalid password.");
		reply(source, "A password must not exceed %d bytes in "
				"length or start with ':'.", PASSWORD_LEN);
		return CS_FAILURE;
	}

	if (!strcmp(argv[1], "newpassword")) {
		reply(source, "Please do not just copy and paste the command.");
		reply(source, "Replace \"newpassword\" with the new password "
				"you want to use.");
		return CS_FAILURE;
	}

	if (strcmp(argv[1], argv[2])) {
		reply(source, "The new passwords do not match.");
		return CS_FAILURE;
	}

	db_change_password(account, argv[1],
		cmd_confirm_cb, source);
	return CS_OK;
}

struct NewPassInfo {
	struct User *source;
	char newpass[PASSWORD_LEN];
};

static void
password_change_cb(enum DBError dbe, const char *account, time_t ts,
		void *arg)
{
	const struct User *source = arg;

	(void)ts;

	if (dbe != DBE_OK) {
		reply(source, "An error was encountered when changing "
				"your password.");
		reply(source, "Please contact an IRC operator with this "
				"error code: %d.", dbe);
	}

	log_audit("%s%s!%s@%s(%s)=%s/%s changed password for account %s",
		source->is_oper ? "*" : "", source->nick, source->ident,
		source->host, source->sockip, source->account,
		source->gecos,
		account);
	reply(source, "Password for account %s changed succesfully.", account);
}

static void
cmd_newpass_auth_cb(enum DBError dbe, const char *account, time_t ts, void *arg)
{
	struct NewPassInfo *npi = arg;

	(void)ts;

	switch (dbe) {
	case DBE_OK:
		break;
	case DBE_PW_MISMATCH:
		log_audit("%s%s!%s@%s(%s)=%s/%s failed NEWPASS auth for "
				"account %s",
			npi->source->is_oper ? "*" : "", npi->source->nick,
			npi->source->ident,
			npi->source->host, npi->source->sockip,
			npi->source->account,
			npi->source->gecos,
			account);
		reply(npi->source, "Old password incorrect.");
		goto clean;
	default:
		reply(npi->source, "An error was encountered when fetching "
				"your account.");
		reply(npi->source, "Please contact an IRC operator with this "
				"error code: %d.", dbe);
		goto clean;
	}

	db_change_password(npi->source->account, npi->newpass,
		password_change_cb, npi->source);

clean:
	crypto_wipe(npi, sizeof(*npi));
	free(npi);
}

static enum CommandStatus
cmd_newpass(const struct Command *cmd, struct User *source,
		size_t argc, char *argv[])
{
	struct NewPassInfo *npi = smalloc(sizeof(*npi));

	if (!user_authed(source)) {
		reply(source, "You must be authenticated to use this command.");
		return CS_FAILURE;
	}

	if (argc < 3) {
		usage(source, cmd);
		return CS_SYNTAX;
	}

	if (!is_valid_password(argv[1])) {
		reply(source, "Invalid password.");
		reply(source, "A password must not exceed %d bytes in "
				"length or start with ':'.", PASSWORD_LEN);
		return CS_FAILURE;
	}

	if (strcmp(argv[1], argv[2]) != 0) {
		reply(source, "The new passwords do not match.");
		return CS_FAILURE;
	}

	npi->source = source;
	/* is_valid_password() does a length check already */
	strcpy(npi->newpass, argv[1]);

	db_check_auth(source->account, argv[0], cmd_newpass_auth_cb,
			npi);

	crypto_wipe(argv[0], strlen(argv[0]));
	crypto_wipe(argv[1], strlen(argv[1]));
	crypto_wipe(argv[2], strlen(argv[2]));
	return CS_OK;
}

static enum CommandStatus
cmd_lostpass(const struct Command *cmd, struct User *source,
		size_t argc, char *argv[])
{
	enum DBError dbe;
	char account[ACCOUNT_LEN + 1];
	char email[EMAIL_LEN + 1];
	char token[TOKEN_LEN + 1];

	if ((source->is_oper && argc < 1) ||
			(!source->is_oper && argc < 2)) {
		usage(source, cmd);
		return CS_SYNTAX;
	}

	/* Due to the way the e-mail shim works, only opers may reset passwords
	 * if e-mail support is disabled.
	 * Otherwise, any user could reset any other user's password.
	 */
	if (!source->is_oper && *config.mail.sendmailcmd == '\0') {
		reply(source, "E-mails are disabled.");
		reply(source, "If you have lost your password, "
				"contact an IRC operator.");
		return CS_FAILURE;
	}

	if (!source->is_oper) {
		switch ((dbe = db_get_account_by_email(argv[1], account))) {
		case DBE_OK:
			break;
		case DBE_NO_SUCH_ACCOUNT:
			reply(source, "E-mail %s not associated with any account.",
					argv[1]);
			return CS_FAILURE;
		default:
			reply(source, "An error was encountered when fetching "
					"account data.");
			reply(source, "Please contact an IRC operator with this "
					"error code: %d.", dbe);
			return CS_INTERNAL;
		}

		if (user_authed(source)
				&& strcasecmp(account, source->account)) {
			reply(source, "E-mail address mismatch "
					"for your account.");
			return CS_FAILURE;
		}

		strcpy(email, argv[1]);
	} else {
		strcpy(account, argv[0]);
		switch ((dbe = db_get_email_by_account(account, email))) {
		case DBE_OK:
			break;
		case DBE_NO_SUCH_ACCOUNT:
			reply(source, "No such account %s.", account);
			return CS_FAILURE;
		default:
			reply(source, "An error was encountered when fetching "
					"account data.");
			reply(source, "Please contact an IRC operator with this "
					"error code: %d.", dbe);
			return CS_INTERNAL;
		}
	}

	if (token_create(token, account) == NULL) {
		/* We only get here on randombytes() failure. */
		reply(source, "An error was encountered when creating "
				"your account.");
		reply(source, "Please contact an IRC operator with this "
				"error code: RND.");
		return CS_INTERNAL;
	}

	if (mail(source, email,
				"Dear %s,\n"
				"\n"
				"A password reset for your account has been "
				"requested.\n"
				"If you did not request this, please ignore "
				"this message.\n"
				"To change your password, use this command:\n"
				"/msg %s@%s RESETPASS %s newpassword "
				"newpassword\n"
				"where \"newpassword\" is the new password to "
				"use.",
				account,
				config.user.nick,
				config.server.name,
				token) != 0) {
		reply(source, "An error was encountered sending e-mail.");
		reply(source, "Please contact an IRC operator.");
		return CS_INTERNAL;
	}

	reply(source, "A password reset e-mail has been sent to %s.", email);
	reply(source, "Please check your e-mail account for further "
			"instructions.");
	return CS_OK;
}

static enum CommandStatus
cmd_resetpass(const struct Command *cmd, struct User *source,
		size_t argc, char *argv[])
{
	char account[ACCOUNT_LEN + 1];

	if (argc < 3) {
		usage(source, cmd);
		return CS_SYNTAX;
	}

	switch (token_validate(argv[0], account)) {
	case TVS_OK:
		break;
	case TVS_BAD:
		reply(source, "Invalid token. Please make sure that you have "
				"copied it correctly.");
		return CS_FAILURE;
	case TVS_EXPIRED:
		reply(source, "Your token has expired.");
		reply(source, "If you still need to reset your password, use "
				"LOSTPASS again.");
		return CS_FAILURE;
	}

	if (user_authed(source) && strcasecmp(source->account, account)) {
		reply(source, "Invalid token for your account %s.",
				source->account);
		return CS_FAILURE;
	}

	if (!is_valid_password(argv[1])) {
		reply(source, "Invalid password.");
		reply(source, "A password must not exceed %d bytes in "
				"length or start with ':'.", PASSWORD_LEN);
		return CS_FAILURE;
	}

	if (!strcmp(argv[1], "newpassword")) {
		reply(source, "Please do not just copy and paste the command.");
		reply(source, "Replace \"newpassword\" with the new password "
				"you want to use.");
		return CS_FAILURE;
	}

	if (strcmp(argv[1], argv[2])) {
		reply(source, "The new passwords do not match.");
		return CS_FAILURE;
	}

	db_change_password(source->account, argv[1],
		password_change_cb, source);
	crypto_wipe(argv[1], strlen(argv[1]));
	crypto_wipe(argv[2], strlen(argv[2]));

	return CS_OK;
}

static enum CommandStatus
cmd_registerchan(const struct Command *cmd, struct User *source,
		size_t argc, char *argv[])
{
	if (!user_authed(source)) {
		reply(source, "You must be authenticated to use this command.");
		return CS_FAILURE;
	}

	if (argc < 1) {
		usage(source, cmd);
		return CS_SYNTAX;
	}

	if (*argv[0] != '#') {
		reply(source, "The channel must start with #.");
		return CS_FAILURE;
	}

	/* Arbitrary value that L uses. */
	if (strlen(argv[0]) > 29) {
		reply(source, "Channel name too long.");
		reply(source, "The channel name may be at most 29 characters, "
				"including the #.");
		return CS_FAILURE;
	}

	/* L keeps its numeric predictable. */
	send_line("%sAAA P %sAAA :addchan %s #%s #%s",
			config.server.numeric, config.uplink.l_numeric,
			argv[0], source->account, source->account);
	return CS_OK;
}

static const char *
cstoa(enum CommandStatus cs) {
	switch (cs) {
	case CS_OK:
		return "OK";
	case CS_FAILURE:
		return "FAILURE";
	case CS_SYNTAX:
		return "SYNTAX";
	case CS_INTERNAL:
		return "INTERNAL";
	}
}

static bool
is_priv_arg(const struct Command *cmd, size_t pos)
{
	for (size_t i = 0; i < cmd->nprivargs; ++i) {
		if (cmd->privargs[i] == pos)
			return true;
	}

	return false;
}

static const struct Command commands[] = {
/* Roughly ordered by expected frequency;
 * text width for help/usage: 72
 */
{
"AUTH",
"Authenticates you to services.",
C_AR "username" C_AR " " C_AR "password",
"Authenticates you with the given username and password.\n"
"If you have lost your password, use the LOSTPASS command.",
cmd_auth,
1,
{1}
},
{
"HELP",
"Shows help messages.",
"[" C_AR "command" C_AR "]",
"If used with no argument, this will list all commands.\n"
"If " C_AR "command" C_AR " is given, a help text for the given command\n"
"will be shown.",
cmd_help,
0,
{(size_t)-1}
},
{
"SHOWCOMMANDS",
"Lists all commands.",
"",
"Lists all commands.\n",
cmd_showcommands,
0,
{(size_t)-1}
},
{
"HELLO",
"Creates a new account.",
C_AR "username" C_AR " " C_AR "e-mail address" C_AR " " C_AR "e-mail address",
"Creates a new user for yourself.\n"
"Usernames may only contain alphanumeric characters (A-Za-z0-9).\n"
"An e-mail containing the initial password wil be sent to the given\n"
"e-mail address.\n"
"You must type your e-mail address twice to ensure there are no spelling\n"
"mistakes.\n",
cmd_hello,
0,
{(size_t)-1}
},
{
"CONFIRM",
"Confirms a new account's e-mail address.",
C_AR "token" C_AR " " C_AR "new password" C_AR " " C_AR "new password",
"Confirms your e-mail address.\n"
C_AR "token" C_AR " will have been sent to you in an e-mail through the\n"
C_NM "HELLO" C_NM " command.\n"
/* PASSWORD_LEN */
"A password must not exceed 128 bytes in length, start with ':' or\n"
"contain ' '.\n"
"If you are sure your client will always send text in the same encoding,\n"
"you may use characters outside the ASCII range, such as emoji.",
cmd_confirm,
2,
{1, 2}
},
{
"NEWPASS",
"Changes your password.",
C_AR "old password" C_AR " " C_AR "new password" C_AR " " C_AR "new password",
"Changes your account password.\n"
/* PASSWORD_LEN */
"A password must not exceed 128 bytes in length, start with ':' or\n"
"contain ' '.\n"
"If you are sure your client will always send text in the same encoding,\n"
"you may use characters outside the ASCII range, such as emoji.",
cmd_newpass,
3,
{0, 1, 2}
},
{
"LOSTPASS",
"Starts the password reset procedure.",
C_AR "username" C_AR " " C_AR "e-mail address",
"Generates a password reset token you can use to change your password\n"
"if you have forgotten your password.",
cmd_lostpass,
0,
{(size_t)-1}
},
{
"RESETPASS",
"Resets your password after LOSTPASS.",
C_AR "token" C_AR " " C_AR "new password" C_AR " " C_AR "new password",
"Resets your password after LOSTPASS.\n"
C_AR "token" C_AR "will have been sent to you in an e-mail.\n"
/* PASSWORD_LEN */
"A password must not exceed 128 bytes in length, start with ':' or\n"
"contain ' '.\n"
"If you are sure your client will always send text in the same encoding,\n"
"you may use characters outside the ASCII range, such as emoji.",
cmd_resetpass,
2,
{1, 2}
},
{
"REGISTERCHAN",
"Registers a channel with L.",
C_AR "#channel",
"Registers the given " C_AR "#channel" C_AR " with L.\n"
"The name of the " C_AR "#channel" C_AR " must not be longer than \n"
"29 characters, including the # itself.\n"
"You will receive a notice from L that confirms or denies your registration.\n"
"If you receive no notice from L, make sure the "
	C_AR "#channel" C_AR " exists.\n",
cmd_registerchan,
0,
{(size_t)-1}
}
};

void
handle_privmsg(char *source, size_t argc, char *argv[])
{
	/* dest message
	 * 0    1
	 *
	 * dest may be a numnick or nick@server.
	 */
	struct User *u = numnick_user(source);
	const struct Command *cmd = NULL;
	char *cmd_argv[MAX_ARGS];
	char *cmdname;
	size_t cmd_argc;
	size_t logofs;
	enum CommandStatus cs;
	char logbuf[BUFSIZ];

	if (*argv[1] == '\0')
		return;

	snprintf(logbuf, sizeof(logbuf), "%s%s!%s@%s(%s)=%s/%s got ",
			u->is_oper ? "*" : "", u->nick, u->ident, u->host,
			u->sockip, u->account, u->gecos);
	stripesc(logbuf);
	logofs = strlen(logbuf);

	split_args(argv[1], MAX_ARGS, &cmd_argc, cmd_argv, false);
	cmdname = cmd_argv[0];

	for (size_t i = 0; i < NCOMMANDS; ++i) {
		if (!strcasecmp(commands[i].name, cmdname)) {
			cmd = &commands[i];
			cs = cmd->handler(cmd, u, cmd_argc - 1, cmd_argv + 1);

			logofs += (size_t)snprintf(logbuf + logofs,
					sizeof(logbuf) - logofs,
					"%s with %s (", cstoa(cs), cmd->name);

			/* Obscure password fields from the logs. */
			for (size_t j = 1; j < cmd_argc; ++j) {
				logofs += (size_t)snprintf(logbuf + logofs,
						sizeof(logbuf) - logofs,
						"%s",
						is_priv_arg(cmd, j - 1) ?
							"[HIDDEN]" :
							stripesc(cmd_argv[j]));
				if (j != cmd_argc - 1)
					logbuf[logofs++] = ' ';
			}
			logbuf[logofs++] = ')';
			logbuf[logofs++] = '\0';

			log_audit("%s", logbuf);
			return;
		}
	}

	reply(u, "Unknown command " C_NM "%s" C_NM ".", cmdname);
	log_audit("%sUNKCMD with %s ()", logbuf, cmdname);
}

