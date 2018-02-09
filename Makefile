UNAME = $(shell uname)
CFLAGS += -Wall -Wextra -ansi -pedantic -std=c99
ifeq ($(UNAME), Darwin)
	CFLAGS += -mmacosx-version-min=10.7
	LDLIBS += -ledit -ltermcap -framework Security -framework CoreFoundation
	OBJS += envchain_osx.o
else
	CFLAGS += -DSECRET_API_SUBJECT_TO_CHANGE `pkg-config --cflags libsecret-1`
	LDLIBS += -lreadline `pkg-config --libs libsecret-1`
	OBJS += envchain_linux.o
endif

DESTDIR ?= /usr

all: envchain
envchain: $(OBJS)

clean:
	rm -f envchain $(OBJS)

install: envchain
	install -d $(DESTDIR)/./bin
	install -m755 ./$< $(DESTDIR)/./bin/$<
