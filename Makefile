PREFIX ?= $(shell brew --prefix 2>/dev/null || echo /usr/local)

CC ?= clang
CFLAGS ?= -O2
CFLAGS += -std=c11 -D_DARWIN_C_SOURCE -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
          $(shell pkg-config --cflags libssh) -Ibuild
LDLIBS += $(shell pkg-config --libs libssh)

SRC := src/main.c src/supervisor.c src/conn.c src/auth.c src/sandbox.c src/spawn.c src/web.c
OBJ := $(SRC:src/%.c=build/%.o)
WEB := web/panel.html web/panel.css web/panel.js web/term.html web/term.css web/term.js \
       web/vendor/xterm.js web/vendor/xterm.css web/vendor/addon-fit.js \
       web/vendor/fonts/MesloLGS-NF-Regular.woff web/vendor/fonts/MesloLGS-NF-Bold.woff

bin/rt: $(OBJ) | bin
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDLIBS)

build/%.o: src/%.c src/rt.h | build
	$(CC) $(CFLAGS) -c -o $@ $<

build/supervisor.o: build/web.h

build/web.h: $(WEB) | build
	cd web && for f in $(WEB:web/%=%); do xxd -i $$f; done > ../$@

bin build:
	mkdir -p $@

install: bin/rt
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 755 bin/rt $(DESTDIR)$(PREFIX)/bin/rt
	install -m 755 rtc $(DESTDIR)$(PREFIX)/bin/rtc
	install -m 644 man/rt.1 $(DESTDIR)$(PREFIX)/share/man/man1/rt.1
	ln -sf rt $(DESTDIR)$(PREFIX)/bin/remote
	printf '.so man1/rt.1\n' > $(DESTDIR)$(PREFIX)/share/man/man1/remote.1

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/rt $(DESTDIR)$(PREFIX)/bin/remote \
	      $(DESTDIR)$(PREFIX)/bin/rtc \
	      $(DESTDIR)$(PREFIX)/share/man/man1/rt.1 $(DESTDIR)$(PREFIX)/share/man/man1/remote.1

clean:
	rm -rf bin build

.PHONY: install uninstall clean
