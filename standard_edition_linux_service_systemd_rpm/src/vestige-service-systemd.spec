Name:           vestige-service-systemd
Version:        1.0.0
Release:        1
Summary:        Java Application Manager Service

License:        GPLv3+
URL:            http://gaellalire.fr/vestige/

Source0:        vestige-service-systemd.tar.gz

BuildArchitectures: noarch

BuildRequires: systemd

Requires(pre): /usr/sbin/useradd, /usr/bin/getent

Requires: vestige >= 8.0.0 nc coreutils util-linux bash

%pre
/usr/bin/getent group vestige || /usr/sbin/groupadd -r vestige
/usr/bin/getent passwd vestige || /usr/sbin/useradd -g vestige -r -m -s /sbin/nologin vestige

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


%files
/usr/lib/systemd/system/vestige.service
/usr/sbin/vestige


%doc



%changelog
