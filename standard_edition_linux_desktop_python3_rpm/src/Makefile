
DESTDIR=/
PREFIX=/usr
bindir=$(PREFIX)/bin
datadir=$(PREFIX)/share

build:
	find . -name '._*' -delete

install:
	mkdir -p $(DESTDIR)/$(bindir)
	mkdir -p $(DESTDIR)/$(datadir)/applications
	mkdir -p $(DESTDIR)/$(datadir)/icons
	cp vestige.desktop $(DESTDIR)/$(datadir)/applications/
	cp vestige $(DESTDIR)/$(bindir)/vestige
	cp -r hicolor $(DESTDIR)/$(datadir)/icons/
	$(RM) -r $(DESTDIR)/etc/vestige/Makefile $(DESTDIR)/etc/vestige/vestige.desktop $(DESTDIR)/etc/vestige/vestige_gtk_launcher.py $(DESTDIR)/etc/vestige/hicolor

uninstall:
	$(RM) $(DESTDIR)/$(bindir)/vestige
	$(RM) -r $(DESTDIR)/etc/vestige
	