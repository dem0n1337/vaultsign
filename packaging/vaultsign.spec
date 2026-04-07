Name:           vaultsign
Version:        2.0.0
Release:        1%{?dist}
Summary:        HashiCorp Vault OIDC Authentication & SSH Key Signing GUI
License:        MIT
URL:            https://github.com/dem0n1337/vaultsign
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
Requires:       python3 >= 3.10
Requires:       gtk4
Requires:       libadwaita
Requires:       python3-gobject

%description
VaultSign provides a GTK4/libadwaita GUI for HashiCorp Vault OIDC
authentication and SSH certificate signing. It replaces manual CLI
workflows with a desktop application supporting multiple profiles,
role selection, certificate monitoring, and automatic notifications.

%install
mkdir -p %{buildroot}/opt/vaultsign
mkdir -p %{buildroot}/opt/vaultsign/icons
mkdir -p %{buildroot}/usr/local/bin
mkdir -p %{buildroot}/usr/share/applications
mkdir -p %{buildroot}/usr/share/icons/hicolor/scalable/apps

cp -r %{_sourcedir}/*.py %{buildroot}/opt/vaultsign/
cp %{_sourcedir}/vaultsign %{buildroot}/opt/vaultsign/
chmod +x %{buildroot}/opt/vaultsign/vaultsign

ln -sf /opt/vaultsign/vaultsign %{buildroot}/usr/local/bin/vaultsign
cp %{_sourcedir}/vaultsign.desktop %{buildroot}/usr/share/applications/
cp %{_sourcedir}/icons/vaultsign.svg %{buildroot}/usr/share/icons/hicolor/scalable/apps/

%files
/opt/vaultsign/
/usr/local/bin/vaultsign
/usr/share/applications/vaultsign.desktop
/usr/share/icons/hicolor/scalable/apps/vaultsign.svg

%changelog
* Fri Mar 20 2026 VaultSign Contributors <vaultsign@example.com> - 2.0.0-1
- Initial RPM release with all v2 features
