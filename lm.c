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

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/util.h>

#ifdef HAS_OPENBSD
#include <err.h>
#endif
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "lm.h"
#include "db.h"
#include "commands.h"
#include "ini.h"
#include "logging.h"
#include "monocypher.h"
#include "numnick.h"
#include "util.h"

/* newserv defines this to be 20, but ircu makes it 15.
 * We'll be going with 15 since we target ircu.
 */
#define MAX_ARGS	(15)

static struct event_base *ev_base;
static struct User *L_user;
static struct bufferevent *irc_bev;
static struct bufferevent *hasher_bev;
static struct Server *me;
static bool initial_link = true;
static bool event_loop_running = false;
static char uplink_numeric[3];

static pid_t hasher_pid;

struct Config config;

static int
read_config_ini_cb(void *arg, const char *section, const char *key,
		const char *value)
{
	struct Config *c = arg;

#define IS_KEY_AND_COPY(s, k)	if (!strcmp(section, (#s)) \
		&& !strcmp(key, (#k))) {\
	snprintf(c->s.k, sizeof(c->s.k), "%s", value);\
} else
	IS_KEY_AND_COPY(server, name)
	IS_KEY_AND_COPY(server, desc)
	IS_KEY_AND_COPY(server, numeric)
	IS_KEY_AND_COPY(user, nick)
	IS_KEY_AND_COPY(user, ident)
	IS_KEY_AND_COPY(user, host)
	IS_KEY_AND_COPY(user, gecos)
	/* NOT: numnick */
	IS_KEY_AND_COPY(uplink, addrport)
	IS_KEY_AND_COPY(uplink, theirpass)
	IS_KEY_AND_COPY(uplink, mypass)
	IS_KEY_AND_COPY(uplink, l_numeric)
	IS_KEY_AND_COPY(mail, sendmailcmd)
	IS_KEY_AND_COPY(mail, fromemail)
	IS_KEY_AND_COPY(mail, fromname)
	{
		log_warn(SS_INT, "unknown configuration directive %s:%s",
				section, key);
	}
#undef IS_KEY
	return 1;
}

static void
read_config(void)
{
	char my_server_numnick_info[6];

	memset(&config, 0, sizeof(config));

	if (ini_parse("lm.ini", read_config_ini_cb, &config) != 0) {
		log_fatal(SS_INT, "unable to parse lm.ini");
		return;
	}

	config.user.numnick[0] = config.server.numeric[0];
	config.user.numnick[1] = config.server.numeric[1];
	config.user.numnick[2] = 'A';
	config.user.numnick[3] = 'A';
	config.user.numnick[4] = 'A';

#define ERROR_IF_MISSING(s, k) do {\
	if (*config.s.k == '\0')\
		log_fatal(SS_INT, "lm.conf missing directive " #s ":" #k);\
} while(0)
	ERROR_IF_MISSING(server, name);
	ERROR_IF_MISSING(server, desc);
	ERROR_IF_MISSING(server, numeric);
	ERROR_IF_MISSING(user, nick);
	ERROR_IF_MISSING(user, ident);
	ERROR_IF_MISSING(user, host);
	ERROR_IF_MISSING(user, gecos);
	ERROR_IF_MISSING(uplink, addrport);
	ERROR_IF_MISSING(uplink, theirpass);
	ERROR_IF_MISSING(uplink, mypass);
	ERROR_IF_MISSING(uplink, l_numeric);
	/* NOT: mail:*; e-mail is optional!
	 * However, if sendmailcmd is set, fromemail and fromname
	 * must be set
	 */
	if (*config.mail.sendmailcmd != '\0') {
		ERROR_IF_MISSING(mail, fromemail);
		ERROR_IF_MISSING(mail, fromname);
	}
#undef ERROR_IF_MISSING

	my_server_numnick_info[0] = config.server.numeric[0];
	my_server_numnick_info[1] = config.server.numeric[1];
	my_server_numnick_info[2] = 'A';
	my_server_numnick_info[3] = 'A';
	my_server_numnick_info[4] = 'B';
	my_server_numnick_info[5] = '\0';
	me = numnick_register_server(my_server_numnick_info, config.server.name,
			NULL);
}

void
send_line(const char *fmt, ...)
{
	va_list ap;
	int len;
	char buf[512];

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf) - 3, fmt, ap);
	va_end(ap);
	if (len < 0 || (unsigned long)len > sizeof(buf) - 3)
		log_fatal(SS_INT, "vsnprintf failure");
#ifdef PROTODEBUG
	printf(">> %s\n", buf);
#endif
	buf[len]     = '\r';
	buf[len + 1] = '\n';
	len += 2;
	evbuffer_expand(bufferevent_get_output(irc_bev), (size_t)len);
	evbuffer_add(bufferevent_get_output(irc_bev), buf, (size_t)len);
}

void
s2s_line(const char *fmt, ...)
{
	va_list ap;
	int len;
	/* -3 for "YY " */
	char buf[509];

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf) - 3, fmt, ap);
	va_end(ap);
	if (len < 0 || (unsigned long)len > sizeof(buf) - 3)
		log_fatal(SS_INT, "vsnprintf failure");
	send_line("%s %s", config.server.numeric, buf);
}

void
reply(const struct User *u, const char *fmt, ...)
{
	va_list ap;
	int len;
	/* Due to the s2c protocol semantics requiring the following format,
	 * we'll lose some message space:
	 *
	 *     :srcnick!ident@host NOTICE destnick :msg
	 *
	 * We don't want to track users' nicks, however.
	 * NICKLEN is a configurable feature on ircu, so we cannot make an
	 * educated worst-case guess, either.
	 * For the sake of simplicity, user messages are just cut off at 256
	 * characters.
	 */
	char buf[256];
	char numnick[6];

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (len < 0 || (unsigned long)len > sizeof(buf))
		log_fatal(SS_INT, "vsnprintf failure in reply");
	send_line("%s O %s :%s", config.user.numnick, user_numnick(numnick, u),
			buf);
}

static void
disconnect()
{
	log_info(SS_NET, "started disconnecting");
	if (irc_bev != NULL) {
		bufferevent_free(irc_bev);
		irc_bev = NULL;
	}

	log_info(SS_NET, "freed IRC bev");
	if (event_loop_running) {
		event_base_loopexit(ev_base, NULL);
		event_loop_running = false;
	}
	log_info(SS_NET, "exited event loop");
}

static void
reap_hasher(void)
{
	if (hasher_pid != 0) {
		int fd;

		fd = bufferevent_getfd(hasher_bev);
		log_info(SS_INT, "shutting down the hasher socket %d", fd);
		shutdown(fd, SHUT_RDWR);
		log_info(SS_INT, "freeing the hasher bufferevent");
		bufferevent_free(hasher_bev);
		log_info(SS_INT, "freed the hasher bufferevent");
		/*
		 * Cannot kill the hasher after pledge() because missing proc,
		 * but it should come home anyway because we closed its socket.
		 */
#ifndef HAS_OPENBSD
		/* Just in case it got stuck. */
		(void)kill(hasher_pid, SIGTERM);
#endif
		log_info(SS_INT, "waiting on hasher to die...");
		(void)wait(NULL);
		log_info(SS_INT, "hasher dead");
		hasher_pid = 0;
	}
}

static void
conn_event_cb(struct bufferevent *b, short revents, void *arg)
{
	time_t now = time(NULL);

	if (revents & BEV_EVENT_CONNECTED) {
		send_line("PASS :%s", config.uplink.mypass);
		send_line(
			"SERVER %s 1 %llu %llu J10 %sAAB +s6 :%s",
			config.server.name,
			(unsigned long long)now,
			(unsigned long long)now,
			config.server.numeric,
			config.server.desc);
	} else if (revents & BEV_EVENT_ERROR) {
		log_fatal(SS_INT, "socket error from uplink: %s",
				evutil_socket_error_to_string(
					EVUTIL_SOCKET_ERROR()));
	} else if (revents & BEV_EVENT_EOF) {
		log_fatal(SS_INT, "EOF received from uplink");
	}
}

static void
handle_end_of_burst(char *source, size_t argc, char *argv[])
{
	s2s_line("EA");
}

static void
handle_ping(char *source, size_t argc, char *argv[])
{
	/* !1511550062.367626 lm.services.invalid 1511550062.367626
	 * 0                  1                2
	 */
	char *szSeconds, *szMSeconds;
	unsigned long long seconds, mseconds, diff;
	struct timeval now;

	if (argc < 3) {
		s2s_line("Z %s", argv[argc - 1]);
		return;
	}

	gettimeofday(&now, NULL);

	szSeconds = argv[2];
	if ((szMSeconds = strchr(szSeconds, '.')) == NULL) {
		diff = 0;
	} else {
		seconds = strtoull(szSeconds, NULL, 10);
		mseconds = strtoull(szMSeconds + 1, NULL, 10);
		diff = (now.tv_sec - seconds) * 1000
			+ (now.tv_usec - mseconds) / 1000;
	}

	s2s_line("Z %s %s %s %llu %llu.%llu", source, config.server.numeric,
			argv[2], diff,
			(unsigned long long)now.tv_sec,
			(unsigned long long)now.tv_usec/1000);
}

static void
handle_mode(char *source, size_t argc, char *argv[])
{
	/* nick :+og
	 * 0       1
	 */
	bool adding;
	struct User *u;

	if (*argv[0] == '#'
			|| argc < 2
			|| (*argv[1] != '-' && *argv[1] != '+'))
		return;

	/* argv[0] is not a numnick, but the source is.
	 * Since third parties can't set the only umode we care about, a lookup
	 * by source is sufficient.
	 */
	if ((u = numnick_user(source)) == NULL)
		return;

	adding = (*argv[1] == '+');

	for (const char *p = argv[1]; *p != '\0'; ++p) {
		switch(*p) {
		case '+':
			adding = true;
			break;
		case '-':
			adding = false;
			break;
		case 'o':
			u->is_oper = adding;
			break;
		case ' ':
			return;
		default:
			break;
		}
	}
}

static void
handle_nick(char *source, size_t argc, char *argv[])
{
	/* nick 1 1511454503 ident host +oiwgrx accname(setbyumode+r) B]AAAB ABAAA :gecos
	 * 0    1 2          3     4    5       ?6                    7      8     9
	 * nick 1 1511592719 ~nick host B]AAAB ABAAD :nick
	 * 0    1 2          3     4    5      6     7
	 *
	 * newnick ts
	 * 0       1
	 */
	char *accname = NULL;
	char *p;
	struct User *u;
	bool is_oper = false;

	if (argc < 8) {
		if ((u = numnick_user(source)) == NULL) {
			log_error(SS_INT, "Unknown numeric %s", source);
			return;
		}
		/* Uplink figures out the ts collision already. */
		snprintf(u->nick, sizeof(u->nick), "%s", argv[0]);
		return;
	}

	/* Non-burst new user message has no umode parameter(s) */
	if (*argv[5] == '+') {
		if (strchr(argv[5], 'r') != NULL) {
			accname = argv[6];
			/* Account TS, we don't care. */
			if ((p = strchr(accname, ':')) != NULL)
				*p = '\0';
		}
		if (strchr(argv[5], 'o') != NULL)
			is_oper = true;
	}
	u = numnick_register_user(argv[argc - 2],
			argv[0], argv[3], argv[4], argv[argc - 1],
			argv[argc - 3], accname, is_oper);
	if (!strcmp(source, config.uplink.l_numeric))
		L_user = u;
}

static void
handle_quit(char *source, size_t argc, char *argv[])
{
	numnick_deregister_user(source);
}

static void
handle_server(char *source, size_t argc, char *argv[])
{
	/* server.name 1 1511454497 1511546930 J10 ABA]] +h6 :Server description
	 * 0           1 2          3          4   5     6   7
	 */
	numnick_register_server(argv[5], argv[0],
			initial_link ? me : numnick_server(source));
}

static void
handle_squit(char *source, size_t argc, char *argv[])
{
	/* We're ignoring link ts because our uplink will figure that out for
	 * us.
	 */
	deregister_server_by_name(argv[0]);
}

static void
handle_whois(char *source, size_t argc, char *argv[])
{
	/* servernumeric nick
	 * 0             1
	 */
	s2s_line("311 %s %s %s %s * :%s",
			source, config.user.nick, config.user.ident,
			config.user.host, config.user.gecos);
	s2s_line("312 %s %s %s :%s",
			source, config.user.nick, config.server.name,
			config.server.desc);
	s2s_line("313 %s %s :is an IRC Operator",
			source, config.user.nick);
	s2s_line("330 %s %s %s :is logged in as",
			source, config.user.nick, config.user.nick);
	s2s_line("318 %s %s :End of /WHOIS list.",
			source, config.user.nick);
}

static void
handle_initial_lines(char *line)
{
	char *argv[MAX_ARGS];
	size_t argc;

	if (!strncmp(line, "PASS :", 6)) {
		if (!strcmp(line + 7, config.uplink.theirpass)) {
			send_line("ERROR :Closing Link: Password mismatch");
			log_fatal(SS_NET, "uplink sent wrong password");
		}
	} else if (!strncmp(line, "SERVER ", 7)) {
		split_args(line, MAX_ARGS, &argc, argv, true);
		handle_server(NULL, argc - 1, argv + 1);
		/* Account timestamp chosen arbitrarily */
		s2s_line("N %s 1 %llu %s %s +iodkr %s:1512141208 ]]]]]] "
				"%s :%s",
				config.user.nick,
				(unsigned long long)time(NULL),
				config.user.ident,
				config.user.host,
				config.user.nick,
				config.user.numnick,
				config.user.gecos);
		s2s_line("EB");
		initial_link = false;
		uplink_numeric[0] = argv[6][0];
		uplink_numeric[1] = argv[6][1];
	} else {
		/* This shouldn't happen.
		 * If it does, silently ignore and pray we'll live.
		 */
	}
}

static void
handle_line(char *line)
{
	char *argv[MAX_ARGS];
	size_t argc;

	/* We need to handle:
	 *
	 * - EB (detect end of burst with uplink)
	 * - G (pong)
	 * - M (oper tracking)
	 * - N (user creation, nick changes)
	 * - P (commands)
	 * - Q (user removal)
	 * - S/SERVER (server creation)
	 * - SQ (server/user removal)
	 * - W (whois responses; users will want that)
	 *
	 * Everything else is irrelevant.
	 * L does not set a mode to indicate channel registration, which means
	 * we'd either have to track channel creations and destructions, joins,
	 * parts, quits and kills to track if L is or isn't present on a channel
	 * or we're just a really, really dumb terminal that sends L an addchan
	 * command even though a channel is already registered.
	 * For the sake of simplicity, the latter option was chosen.
	 *
	 * KILLs are irrelevant because they are propagated as quits.
	 * Our own client is +k and thus cannot be killed.
	 *
	 * We do not need to listen for AC because we assume we're the only
	 * server that can authenticate users.
	 * The only way we'd hear of authentication is during the N message with
	 * user mode +r.
	 */
	static const struct {
		const char *token;
		void (*handler)(char *source, size_t argc, char *argv[]);
	} handlers[] = {
		/* Roughly ordered by expected frequency/urgency in burst */
		{"EB", handle_end_of_burst},
		{"G",  handle_ping},
		{"M",  handle_mode},
		{"N",  handle_nick},
		{"P",  handle_privmsg},
		{"Q",  handle_quit},
		{"S",  handle_server},
		{"SQ", handle_squit},
		{"W",  handle_whois}
	};

	if (initial_link) {
		/* First two messages are special. */
		handle_initial_lines(line);
		return;
	}

	/* ASSUMPTION (valid for P10):
	 *
	 * - Every message has a source
	 * - Every message has a command
	 */
	split_args(line, MAX_ARGS, &argc, argv, true);
	for (size_t i = 0; i < sizeof(handlers)/sizeof(*handlers); ++i) {
		if (!strcmp(handlers[i].token, argv[1]))
			handlers[i].handler(argv[0], argc - 2, argv + 2);
	}
}

static void
conn_read_cb(struct bufferevent *b, void *arg)
{
	char *line;
	size_t len;

	/* P10 uses \n as line separator, rather than \r\n as used in c2s and
	 * some other s2s protocols.
	 */
	while ((line = evbuffer_readln(bufferevent_get_input(b), &len,
					EVBUFFER_EOL_CRLF)) != NULL) {
		if (*line == '\0')
			continue;

#ifdef PROTODEBUG
		printf("<< %s\n", line);
#endif
		handle_line(line);
		free(line);
	}
}

static void
connect_remote(void)
{
	struct sockaddr addr;
	int addrlen = (int)sizeof(addr);
	int sfd;

	if (evutil_parse_sockaddr_port(config.uplink.addrport, &addr, &addrlen)
			!= 0)
		log_fatal(SS_INT, "unable to parse uplink address");

	if ((sfd = socket(addr.sa_family, SOCK_STREAM, 0)) == -1) {
		log_fatal(SS_INT, "unable to create socket: %s",
				strerror(errno));
	}

	if ((irc_bev = bufferevent_socket_new(ev_base, -1, BEV_OPT_CLOSE_ON_FREE))
			== NULL)
		oom();

	if (bufferevent_socket_connect(irc_bev, &addr, addrlen) == -1) {
		close(sfd);
		bufferevent_free(irc_bev);
		log_fatal(SS_INT, "unable to connect: %s",
				evutil_socket_error_to_string(
					EVUTIL_SOCKET_ERROR()));
	}

	bufferevent_setcb(irc_bev, conn_read_cb, NULL, conn_event_cb, NULL);
	bufferevent_enable(irc_bev, EV_READ | EV_WRITE);
}

static void
signal_cb(evutil_socket_t sfd, short revents, void *arg)
{
	struct event *self = arg;

	log_info(SS_INT, "Received signal %d! Disconnecting...",
			event_get_signal(self));
	disconnect();
	log_info(SS_INT, "Disconnected");
}

static void
heartbeat_cb(evutil_socket_t sfd, short revents, void *arg)
{
	db_purge_expired();
}

static void
help(const char *name)
{
	fprintf(stderr, "Usage: %s [-dhn]\n"
			"\n"
			"  -d      show debug messages (implies -n)\n"
			"  -h      show this help message\n"
			"  -n      no fork; log to stdout\n",
			name);
}

void
lm_exit(void)
{
	if (event_loop_running) {
		disconnect();
		reap_hasher();
	} else {
		exit(1);
	}
}

static void
daemonize(void)
{
	switch (fork()) {
	case 0:
		break;
	case -1:
		log_fatal(SS_INT, "unable to fork: %s", strerror(errno));
		exit(1);
	default:
		exit(0);
		break;
	}

	if (setsid() == -1)
		log_fatal(SS_INT, "unable to setsid: %s", strerror(errno));

	util_rebind_stdfd();
#ifdef HAS_OPENBSD
	setproctitle("main");
#endif
}

void
lm_send_hasher_request(const char *password, const uint8_t *salt)
{
	uint8_t buf[PASSWORD_LEN + SALT_LEN + sizeof(uint8_t)];

	memset(buf, 0, sizeof(buf));

	memcpy(buf, password, strlen(password));
	memcpy(buf + PASSWORD_LEN, salt, SALT_LEN);
	buf[PASSWORD_LEN + SALT_LEN] = (uint8_t)strlen(password);

	/* caller wipes password and salt */

	evbuffer_expand(bufferevent_get_output(hasher_bev), sizeof(buf));
	evbuffer_add(bufferevent_get_output(hasher_bev), buf, sizeof(buf));

	crypto_wipe(buf, sizeof(buf));
}

static void
hasher(int fd)
{
	void *work_area = smalloc(102400000LU);
	uint8_t hash[HASH_LEN];
	uint8_t buf[PASSWORD_LEN + SALT_LEN + sizeof(uint8_t)];
	uint8_t *password = buf;
	uint8_t *salt = buf + PASSWORD_LEN;
	uint8_t *pwlen = buf + PASSWORD_LEN + SALT_LEN;

#ifdef HAS_OPENBSD
	setproctitle("hasher");
#endif
#ifdef HAS_OPENBSD
	if (pledge("stdio", "") != 0)
		exit(1);
#endif

	/* The hasher is in the position of only having to read and write from
	 * the one fd -- synchronous handling is good enough.
	 */

	/* read password and salt */
	errno = 0;
	while (recv(fd, buf, sizeof(buf), MSG_WAITALL)
			== (ssize_t)sizeof(buf)) {
		/* hash */
		crypto_argon2i(hash, HASH_LEN,
				work_area, 100000,
				3,
				password, *pwlen,
				salt, SALT_LEN);
		crypto_wipe(buf, sizeof(buf));
		/* write hash */
		if (write(fd, hash, HASH_LEN) != HASH_LEN) {
			log_error(SS_INT, "unable to write hash: %s",
					strerror(errno));
			crypto_wipe(hash, sizeof(hash));
			exit(1);
		}
		crypto_wipe(hash, sizeof(hash));
		log_debug(SS_INT, "sent hash");
	}
	free(work_area);
	if (errno != 0)
		log_error(SS_INT, "unable to read hasher fd: %s",
				strerror(errno));
	exit(errno == 0);
}

static void
hasher_read_cb(struct bufferevent *b, void *arg)
{
	int nr;
	uint8_t buf[HASH_LEN];

	while ((nr = evbuffer_remove(bufferevent_get_input(b), buf,
				sizeof(buf))) == (int)sizeof(buf)) {
		log_debug(SS_INT, "got hash (len %d)", nr);
		/* This assumes response order matching outgoing order. */
		db_hash_response(buf);
	}
}

static void
hasher_event_cb(struct bufferevent *b, short revents, void *arg)
{
	if (revents & BEV_EVENT_ERROR) {
		log_fatal(SS_INT, "socket error from hasher: %s",
				evutil_socket_error_to_string(
					EVUTIL_SOCKET_ERROR()));
	} else if (revents & BEV_EVENT_EOF) {
		log_fatal(SS_INT, "EOF received from hasher");
	}
}

static int
lm_fork_hasher(void)
{
	int fdv[2];
	pid_t pid;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fdv) != 0)
		log_fatal(SS_INT, "unable to get socketpair: %s",
				strerror(errno));

	switch ((pid = fork())) {
	case 0:
		hasher(fdv[0]);
		break;
	case -1:
		log_fatal(SS_INT, "unable to fork: %s", strerror(errno));
		return -1;
	default:
		if ((hasher_bev = bufferevent_socket_new(ev_base, fdv[1],
						BEV_OPT_CLOSE_ON_FREE))
				== NULL)
			oom();

		bufferevent_setcb(hasher_bev, hasher_read_cb, NULL,
				hasher_event_cb, NULL);
		bufferevent_enable(hasher_bev, EV_READ | EV_WRITE);
		hasher_pid = pid;
		break;
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	struct event sigev_int, sigev_term, ev_heartbeat;
	/* 5 minutes */
	struct timeval heartbeat_freq = {300, 0};
	int c;
	bool dofork = true, debug = false;

#ifdef HAS_OPENBSD
	/* unveil(2) the files we need */
	if (unveil("lm.log", "wc") != 0)
		err(1, "unveil lm.log");
	if (unveil("lm.db", "rwc") != 0)
		err(1, "unveil lm.db");
	if (unveil("lm.db-journal", "rwc") != 0)
		err(1, "unveil lm.db-journal");
	if (unveil("lm.db-shm", "rwc") != 0)
		err(1, "unveil lm.db-shm");
	if (unveil("lm.db-wal", "rwc") != 0)
		err(1, "unveil lm.db-wal");
	if (unveil("lm.ini", "r") != 0)
		err(1, "unveil lm.ini");
	if (unveil("/dev/urandom", "r") != 0)
		err(1, "unveil /dev/urandom");
	if (unveil("/dev/null", "rw") != 0)
		err(1, "unveil /dev/null");
	if (unveil("/etc/resolv.conf", "r") != 0)
		err(1, "unveil /etc/resolv.conf");
	if (pledge("stdio rpath cpath wpath flock fattr proc exec inet unix dns unveil", NULL) != 0)
		err(1, "pledge 1");
#endif

	while ((c = getopt(argc, argv, "dhn")) != -1) {
		switch (c) {
		case 'd':
			dofork = false;
			debug = true;
			break;
		case 'h':
			help(argv[0]);
			return 0;
		case 'n':
			dofork = false;
			break;
		}
	}

	if (log_init(!dofork, debug) != 0)
		return 1;

	read_config();
#ifdef HAS_OPENBSD
	if (*config.mail.sendmailcmd != '\0') {
		if (unveil(config.mail.sendmailcmd, "x") != 0)
			err(1, "unveil %s", config.mail.sendmailcmd);
	}
	if (pledge("stdio rpath cpath wpath flock fattr proc exec inet unix dns", NULL) != 0)
		err(1, "pledge 2");
#endif
	if (db_init() != 0)
		return 1;

	/*
	 * We *must* fork before creating the event base.
	 * libevent may use kqueue(2) as the backend.
	 * The kqueue becomes invalid on fork because it cannot be inherited by
	 * the child process and the parent proceeds to exit on fork,
	 * and it is created in event_base_new().
	 * This failure is silent and just makes libevent be confused
	 * internally;
	 * it does not bubble up to the application layer.
	 *
	 * This has the unfortunate side effect that we also must do the
	 * log_switchover() after the fork and fd rebind,
	 * making it appear that lm started successfully when it hasn't,
	 * but it beats not correctly starting at all.
	 */
	if (dofork) {
		log_info(SS_INT, "forking into the background");
		daemonize();
	}

	log_switchover();

	if ((ev_base = event_base_new()) == NULL)
		oom();
	connect_remote();

	if (lm_fork_hasher() != 0)
		return 1;
#ifdef HAS_OPENBSD
	if (*config.mail.sendmailcmd != '\0') {
		if (pledge("stdio rpath cpath wpath flock fattr proc exec inet unix", NULL)
				!= 0)
			err(1, "pledge 3");
	} else {
		if (pledge("stdio rpath cpath wpath flock fattr inet unix", NULL) != 0)
			err(1, "pledge 4");
	}
#endif
	event_assign(&sigev_int, ev_base, SIGINT, EV_SIGNAL,
			signal_cb, &sigev_int);
	event_assign(&sigev_term, ev_base, SIGTERM, EV_SIGNAL,
			signal_cb, &sigev_term);
	event_assign(&ev_heartbeat, ev_base, -1, EV_PERSIST, heartbeat_cb, NULL);
	event_add(&sigev_int, NULL);
	event_add(&sigev_term, NULL);
	event_add(&ev_heartbeat, &heartbeat_freq);
	event_loop_running = true;
	event_base_dispatch(ev_base);

	disconnect();
	reap_hasher();
	event_base_free(ev_base);
	db_fini();
	log_fini();
	return 0;
}

