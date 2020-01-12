
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
	cp vestige $(DESTDIR)/$(datadir)/vestige/
	cp vestige.desktop $(DESTDIR)/$(datadir)/applications/
	cp vestige_gtk_launcher.py $(DESTDIR)/$(bindir)/vestige
	cp -r hicolor $(DESTDIR)/$(datadir)/icons/
	$(RM) -r $(DESTDIR)/etc/vestige/Makefile $(DESTDIR)/etc/vestige/vestige.desktop $(DESTDIR)/etc/vestige/vestige_gtk_launcher.py $(DESTDIR)/etc/vestige/hicolor

uninstall:
	$(RM) $(DESTDIR)/$(bindir)/vestige
	$(RM) -r $(DESTDIR)/etc/vestige
	$(RM) -r $(DESTDIR)/$(datadir)/vestige
	