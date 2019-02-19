include Makefile.config

PREFIX ?= $(prefix)
ATHEME ?= $(source)

ATHEME_CFLAGS = -I$(ATHEME)/include -I$(ATHEME)/libmowgli-2/src/libmowgli -DDATADIR=\"$(PREFIX)/etc\"

SOURCES = $(wildcard *.c)
MODULES = $(patsubst %.c,%.so,$(SOURCES))

default: $(MODULES)

clean:
	rm -f $(MODULES)

ifneq ($(WERROR),)
CFLAGS_WERROR = -Werror
endif

%.so: %.c syn.h
	gcc -std=c99 -Wall $(CFLAGS_WERROR) -O1 -ggdb3 -fPIC $(ATHEME_CFLAGS) -shared -o$@ $<

util.so: util.c auxiliary/siphash.c
	gcc -std=c99 -Wall $(CFLAGS_WERROR) -O1 -ggdb3 -fPIC $(ATHEME_CFLAGS) -shared -o$@ $^

.PHONY: install

install: $(MODULES)
	install -d $(PREFIX)/modules/syn
	for m in $(MODULES); do \
	    install $${m} $(PREFIX)/modules/syn/$${m}.tmp; \
	    mv $(PREFIX)/modules/syn/$${m}.tmp $(PREFIX)/modules/syn/$${m} || exit $$?;  \
	done
	install -d $(PREFIX)/help/syn
	install -t $(PREFIX)/help/syn help/*




