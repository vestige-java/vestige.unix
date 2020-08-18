
DESTDIR=/
PREFIX=/usr
bindir=$(PREFIX)/bin
sbindir=$(PREFIX)/sbin
datadir=$(PREFIX)/share

build:
	find . -name '._*' -delete

install:
	mkdir -p $(DESTDIR)/usr/lib/systemd/system
	mkdir -p $(DESTDIR)/$(sbindir)
	cp systemd/vestige.service $(DESTDIR)/usr/lib/systemd/system/vestige.service
	cp sbin/vestige $(DESTDIR)/$(sbindir)/vestige

uninstall:
	$(RM) $(DESTDIR)/$(sbindir)/vestige
	$(RM) $(DESTDIR)/%{_unitdir}/vestige.service
	