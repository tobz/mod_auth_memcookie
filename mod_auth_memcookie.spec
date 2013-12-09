%{!?_httpd_confdir: %{expand: %%global _httpd_confdir %%{_sysconfdir}/httpd/conf.d}}
%{!?_httpd_moddir:  %{expand: %%global _httpd_moddir  %%{_libdir}/httpd/modules}}

Name:           mod_auth_memcookie
Version:        1.0.0
Release:        1%{?dist}
Summary:        Apache module for cookie-based authentication using memcache

License:        Apache
URL:            http://github.com/tobz/mod_auth_memcookie/

BuildRequires:  httpd-devel
BuildRequires:  libmemcached-devel
Requires:       httpd
Requires:       libmemcached

%description
mod_auth_memcookie is an Apache module that provides cookie-based authentication using memcache.  It can be used standalone
for a custom login solution, or single sign-on solution.  It is also the basis of projects like apache-google-apps-sso which
use it to provide single sign-on for your sites using Google Apps for authentication.


%prep
%setup -q


%build
%configure
%{__make} %{?_smp_mflags}


%install
# The install target of the Makefile isn't used because that uses apxs
# which tries to enable the module in the build host httpd instead of in
# the build root.
%{__mkdir_p} %{buildroot}%{_sysconfdir}/httpd/conf.d
%{__mkdir_p} %{buildroot}%{_libdir}/httpd/modules
%{__install} -m 700 -d %{buildroot}%{_localstatedir}/lib/%{name}

%{__install} -d -m0755 %{buildroot}%{_sysconfdir}/httpd/conf.d
%{__cat} > %{buildroot}%{_sysconfdir}/httpd/conf.d/mod_auth_memcookie.conf << 'EOF'

EOF
%{__install} -m 755 src/.libs/mod_auth_memcookie.so %{buildroot}%{_libdir}/httpd/modules


%clean
%{__rm} -rf %{buildroot}


%files
%doc AUTHORS COPYING README NEWS UPGRADE
%{_libdir}/httpd/modules/mod_auth_memcookie.so

%config(noreplace) %{_sysconfdir}/httpd/conf.d/*.conf

%attr(700,apache,root) %dir %{_localstatedir}/lib/%{name}


%changelog
* Sun Dec 08 2013 Toby Lawrence <tobias.lawrence@gmail.com> - 1.0.0
* Initial release of the module after significant cleanup.
