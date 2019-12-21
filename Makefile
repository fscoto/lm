.POSIX:
.SUFFIXES:

include config.mk

EXTERNAL_CFLAGS = -O2 -std=c99
MONOCYPHER_CFLAGS = -O3 -std=c99

OBJS = commands.o db.o lm.o logging.o mail.o numnick.o util.o token.o ini.o \
	   sqlite3.o monocypher.o

all: lm

lm: $(OBJS)
	$(CC) $(LDFLAGS) -o lm $(OBJS) $(LDLIBS)

commands.o: commands.c db.h lm.h mail.h monocypher.h numnick.h token.h entities.h util.h
db.o: db.c db.h lm.h logging.h mail.h monocypher.h sqlite3.h token.h entities.h util.h
ini.o: ini.c ini.h util.h
lm.o: lm.c lm.h commands.h ini.h logging.h numnick.h util.h
logging.o: logging.c logging.h lm.h
mail.o: mail.c mail.h monocypher.h lm.h entities.h
numnick.o: numnick.c numnick.h logging.h entities.h util.h
token.o: token.c token.h monocypher.h entities.h util.h
util.o: util.c util.h logging.h

sqlite3.o: sqlite3.c sqlite3.h
	$(CC) $(EXTERNAL_CFLAGS) -c $<

monocypher.o: monocypher.c monocypher.h
	$(CC) $(MONOCYPHER_CFLAGS) -c $<

clean:
	rm -f lm *.o

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) -c $<

