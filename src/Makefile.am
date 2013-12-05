noinst_LTLIBRARIES = libmodauthmemcookie.la
noinst_DATA = mod_auth_memcookie.la

INCLUDES = ${APACHE_CFLAGS} -I/usr/include/libmemcached
AM_LDFLAGS = ${APR_LDFLAGS} -lmemcached

libmodauthmemcookie_la_SOURCES = mod_auth_memcookie.c

AM_CCFLAGS = -Wall

install-exec-local:
	${APXS} -i -a -n 'authmemcookie' mod_auth_memcookie.la

mod_auth_memcookie.la: libmodauthmemcookie.la
	${APXS} -c -o $@ $< ${APACHE_CFLAGS}
