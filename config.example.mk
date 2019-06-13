# compilation
CC      = gcc
CFLAGS  = -std=c11 -D_DEFAULT_SOURCE
# debug: CFLAGS += -g -O0
CFLAGS += -O2
# dev: CFLAGS += -Wall -Wextra -Wpedantic -Wno-unused-parameter
# BSD: CFLAGS += -I/usr/local/include
# OpenBSD 6.5+: CFLAGS += -DHAS_OPENBSD

# linking
# BSD: LDFLAGS = -L/usr/local/lib

# libevent must be libevent2; Solaris may need additional libraries
LDLIBS  = -levent -lpthread -ldl
#OpenBSD: LDLIBS  = -levent_core -levent_openssl -lpthread

