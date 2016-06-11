UNAME = $(shell uname)
CFLAGS += -Wall -Wextra -ansi -pedantic -std=c99
ifeq ($(UNAME), Darwin)
	CFLAGS += -mmacosx-version-min=10.7
	LIBS = -ledit -ltermcap -framework Security -framework CoreFoundation
	OBJS = envchain.o envchain_osx.o
else
	CFLAGS += `pkg-config --cflags libsecret-1`
	LIBS = -lreadline `pkg-config --libs libsecret-1`
	OBJS = envchain.o envchain_linux.o
endif

DESTDIR ?= /usr

all: envchain
envchain: $(OBJS)
	$(CC) $(LDCFLAGS) -o envchain $(OBJS) $(LIBS)

%.o: %.c envchain.h
	$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<

clean:
	rm -f envchain $(OBJS)

install: all
	install -d $(DESTDIR)/./bin
	install -m755 ./envchain $(DESTDIR)/./bin/envchain
