Name:           vaultsign
Version:        3.0.0
Release:        1%{?dist}
Summary:        HashiCorp Vault OIDC Authentication & SSH Key Signing GUI
License:        MIT
URL:            https://github.com/dem0n1337/vaultsign
Source0:        %{name}-%{version}.tar.gz

# Built from a Go/Wails source tree.
BuildRequires:  golang >= 1.23
BuildRequires:  nodejs >= 18
BuildRequires:  npm
BuildRequires:  gcc
BuildRequires:  pkgconfig(webkit2gtk-4.1)
BuildRequires:  pkgconfig(gtk+-3.0)

# Runtime: Wails renders through the system WebView (no Python).
Requires:       webkit2gtk4.1
Requires:       gtk3

%description
VaultSign provides a modern desktop GUI (Wails + React) for HashiCorp Vault /
OpenBao OIDC authentication and SSH certificate signing. It talks to Vault via
the native Go API and to ssh-agent over its socket directly (no vault/ssh-add
subprocesses). Features: multiple profiles, live role fetching, an animated
certificate-expiry ring, desktop notifications, system tray, and a headless CLI.

%prep
%setup -q

%build
export PATH=$PATH:$(go env GOPATH)/bin
go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0
wails build -tags webkit2_41 -clean

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_datadir}/applications
mkdir -p %{buildroot}%{_datadir}/icons/hicolor/scalable/apps
mkdir -p %{buildroot}%{_datadir}/metainfo
mkdir -p %{buildroot}%{_mandir}/man1

install -m 0755 build/bin/vaultsign %{buildroot}%{_bindir}/vaultsign
install -m 0644 vaultsign.desktop %{buildroot}%{_datadir}/applications/io.github.dem0n1337.vaultsign.desktop
install -m 0644 icons/vaultsign.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/vaultsign.svg
install -m 0644 packaging/io.github.dem0n1337.vaultsign.metainfo.xml %{buildroot}%{_datadir}/metainfo/
install -m 0644 vaultsign.1 %{buildroot}%{_mandir}/man1/vaultsign.1

%files
%{_bindir}/vaultsign
%{_datadir}/applications/io.github.dem0n1337.vaultsign.desktop
%{_datadir}/icons/hicolor/scalable/apps/vaultsign.svg
%{_datadir}/metainfo/io.github.dem0n1337.vaultsign.metainfo.xml
%{_mandir}/man1/vaultsign.1*

%changelog
* Mon May 25 2026 Jakub Demovic <jakub.demovic96@gmail.com> - 3.0.0-1
- Rewrite from Python/GTK4 to Go (Wails + React). Native Vault API and
  ssh-agent integration; modern UI; headless CLI retained.
