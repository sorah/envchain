CFLAGS += -Wall -Wextra -ansi -pedantic -std=c99 -mmacosx-version-min=10.7
LIBS = -ledit -ltermcap -framework Security -framework CoreFoundation

DESTDIR ?= /usr

all: envchain
envchain: envchain.c
	$(CC) $(CFLAGS) $(LIBS) envchain.c -o envchain

clean:
	rm -f envchain

install: all
	install -d $(DESTDIR)/./bin
	install -m755 ./envchain $(DESTDIR)/./bin/envchain
