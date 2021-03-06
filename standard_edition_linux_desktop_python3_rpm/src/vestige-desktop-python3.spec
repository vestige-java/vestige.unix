Name:           vestige-desktop-python3
Version:        1.0.2
Release:        1
Summary:        Java Application Manager

License:        GPLv3+
URL:            http://gaellalire.fr/vestige/

Source0:        vestige-desktop-python3.tar.gz

BuildArchitectures: noarch

Conflicts: vestige-desktop-python2

Requires:  vestige >= 8.0.0 python3-nss python3-dbus libappindicator-gtk3

%define __jar_repack %{nil}

%description

%prep
%setup -q


%build
make


%install
rm -rf $RPM_BUILD_ROOT
%make_install

%posttrans
/usr/bin/gtk-update-icon-cache -q -t -f %{_datadir}/icons/hicolor || :

%files
%{_datadir}/applications/vestige.desktop
%{_datadir}/icons/hicolor/16x16/apps/vestige.png
%{_datadir}/icons/hicolor/192x192/apps/vestige.png
%{_datadir}/icons/hicolor/22x22/apps/vestige.png
%{_datadir}/icons/hicolor/36x36/apps/vestige.png
%{_datadir}/icons/hicolor/42x42/apps/vestige.png
%{_datadir}/icons/hicolor/512x512/apps/vestige.png
%{_datadir}/icons/hicolor/64x64/apps/vestige.png
%{_datadir}/icons/hicolor/72x72/apps/vestige.png
%{_datadir}/icons/hicolor/8x8/apps/vestige.png
%{_datadir}/icons/hicolor/96x96/apps/vestige.png
%{_datadir}/icons/hicolor/24x24/apps/vestige.png
%{_datadir}/icons/hicolor/32x32/apps/vestige.png
%{_datadir}/icons/hicolor/48x48/apps/vestige.png
%{_datadir}/icons/hicolor/128x128/apps/vestige.png
%{_datadir}/icons/hicolor/256x256/apps/vestige.png
%{_datadir}/icons/hicolor/scalable/apps/vestige.svg
%{_bindir}/vestige


%doc



%changelog
