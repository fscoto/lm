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
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

#include "logging.h"
#include "lm.h"

static FILE *logfile, *waiting_logfile;
static enum LogLevel min_level;

static const char *
subsystem_name(enum LogSubsystem ss)
{
	switch (ss) {
	case SS_INT:
		return "lm";
	case SS_SQL:
		return "sqlite";
	case SS_AUD:
		return "audit";
	case SS_NET:
		return "network";
	}
}

static const char *
level_name(enum LogLevel level)
{
	switch (level) {
	case LV_FATAL:
		return "FATAL";
	case LV_ERROR:
		return "ERROR";
	case LV_WARN:
		return "WARN";
	case LV_INFO:
		return "INFO";
	case LV_DEBUG:
		return "DEBUG";
	}
}

void
vlog_generic(enum LogSubsystem ss, enum LogLevel level, const char *fmt,
		va_list ap)
{
	time_t now = time(NULL);
	char timebuf[24];

	/* Start with stderr until we switch to stdout because log before event
	 * loop is almost always fatal or relevant to the user.
	 */
	if (logfile == NULL)
		logfile = stderr;

	if (strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S UTC",
				gmtime(&now))
			== 0)
		strcpy(timebuf, "UNKNOWN TIME");
	fprintf(logfile, "[%s] %-5s %-7s - ", timebuf, level_name(level),
			subsystem_name(ss));
	vfprintf(logfile, fmt, ap);
	putc('\n', logfile);
	fflush(logfile);

	if (level == LV_FATAL)
		lm_exit();
}

#define MKLOGFUNC(name, level) \
	void log_##name(enum LogSubsystem ss, const char *fmt, ...)\
{\
	va_list ap;\
	if (level < min_level)\
		return;\
	va_start(ap, fmt);\
	vlog_generic(ss, (level), fmt, ap);\
	va_end(ap);\
}

MKLOGFUNC(fatal, LV_FATAL)
MKLOGFUNC(error, LV_ERROR)
MKLOGFUNC(warn, LV_WARN)
MKLOGFUNC(info, LV_INFO)
MKLOGFUNC(debug, LV_DEBUG)
#undef MKLOGFUNC

#define MKLOGFUNCFORSUBSYS(name, ss, level) \
	void log_##name(const char *fmt, ...)\
{\
	va_list ap;\
	va_start(ap, fmt);\
	vlog_generic((ss), (level), fmt, ap);\
	va_end(ap);\
}
MKLOGFUNCFORSUBSYS(network, SS_NET, LV_INFO)
MKLOGFUNCFORSUBSYS(audit, SS_AUD, LV_INFO)
#undef MKLOGFUNCFORSUBSYS

int
log_init(bool usestdout, bool debug)
{
	FILE *f;

	if (debug)
		min_level = LV_DEBUG;
	else
		min_level = LV_INFO;

	if (usestdout) {
		logfile = stdout;
		log_info(SS_INT, "minimum log level set to %d (%s)", min_level,
				level_name(min_level));

		return 0;
	}

	log_info(SS_INT, "opening log file lm.log");
	/* 't' would be a lie since we may take channel names as-is, which may
	 * include channels that are invalid in any encoding.
	 */
	if ((f = fopen("lm.log", "ab")) == NULL) {
		log_fatal(SS_INT, "unable to open lm.log: %s", strerror(errno));
		return -1;
	}

	waiting_logfile = f;
	log_info(SS_INT, "minimum log level set to %d (%s)", min_level,
			level_name(min_level));

	return 0;
}

void
log_switchover(void)
{
	if (waiting_logfile != NULL)
		logfile = waiting_logfile;
}

void
log_fini(void)
{
	if (logfile == stdout || logfile == stderr || logfile == NULL)
		return;

	log_info(SS_INT, "closing log file lm.log");
	fclose(logfile);
}

