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

#ifndef LM_MAIL_H
#define LM_MAIL_H

#include "entities.h"

int mail(const struct User *u, const char *email, const char *fmt, ...);

#endif

