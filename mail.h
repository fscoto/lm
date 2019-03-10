#ifndef LM_MAIL_H
#define LM_MAIL_H

#include "entities.h"

int mail(const struct User *u, const char *email, const char *fmt, ...);

#endif

