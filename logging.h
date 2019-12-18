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

#ifndef LM_LOGGING_H
#define LM_LOGGING_H

#include <stdarg.h>
#include <stdbool.h>

enum LogSubsystem {
	/* internal log: e.g. numnick inconsistencies, fallback category */
	SS_INT,
	/* sqlite3 issues */
	SS_SQL,
	/* audit log: actions taken by users */
	SS_AUD,
	/* IRC network log: opering up, server link, protocol debug */
	SS_NET
};

enum LogLevel {
	/* debug: verbose; compromises privacy; cannot be written to file */
	LV_DEBUG,
	/* info: informational messages to prove the program is running and
	 * doing something
	 */
	LV_INFO,
	/* warning: a recoverable condition that may warrant closer inspection,
	 * but is likely harmless
	 */
	LV_WARN,
	/* error: an irrecoverable error condition that does not threaten the
	 * stability of the entirety of lm
	 */
	LV_ERROR,
	/* fatal: if encountered, an exit will be scheduled */
	LV_FATAL
};

void vlog_generic(enum LogSubsystem ss, enum LogLevel, const char *fmt,
		va_list ap);
void log_fatal(enum LogSubsystem ss, const char *fmt, ...);
void log_error(enum LogSubsystem ss, const char *fmt, ...);
void log_warn(enum LogSubsystem ss, const char *fmt, ...);
void log_info(enum LogSubsystem ss, const char *fmt, ...);
void log_debug(enum LogSubsystem ss, const char *fmt, ...);

/* Defaulting to INFO for network and audit logs */
void log_network(const char *fmt, ...);
void log_audit(const char *fmt, ...);

int log_init(bool usestdout, bool debug);
void log_switchover(void);
void log_fini(void);

#endif

