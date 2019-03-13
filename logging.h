/*
 * Copyright (c) 2017, 2019 Fabio Scotoni
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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

