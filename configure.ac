AC_INIT([mod_auth_memcookie], [1.0.0], [tobias.lawrence@gmail.com])
AC_DEFINE([PACKAGE_URL],["https://github.com/tobz/mod_auth_openid"],[project url])
AM_CONFIG_HEADER(src/config.h)
AM_INIT_AUTOMAKE([mod_auth_memcookie],[1.0.0])

AC_CONFIG_MACRO_DIR([acinclude.d])

AC_PROG_CC
AC_LANG_C
AC_CANONICAL_HOST
AC_PROG_INSTALL
AM_PROG_LIBTOOL

AC_HEADER_STDC

# this will look for apxs command - put it in $APXS, fail on failure
AX_WITH_APXS()

# find apr-config binary
AC_ARG_WITH(apr_config, AC_HELP_STRING([[--with-apr-config=FILE]], [Path to apr-config program]),
			[ apr_config="$withval" ],
			[AC_PATH_PROGS(apr_config,
				[apr-config apr-0-config apr-1-config], 
				[no], 
				[$PATH:/usr/sbin/:/usr/local/apache2/bin]
			)]
)

if test "$apr_config" = "no"; then
   AC_MSG_ERROR(Could not find the apr-config program.  You can specify a location with the --with-apr-config=FILE option.  It may be named apr-0-config or apr-1-config and can be found in your apache2 bin directory.)
fi

$apr_config --cflags &> /dev/null
if test "$?" != "0"; then
  AC_MSG_ERROR($apr_config is not a valid apr-config program)
fi

APR_LDFLAGS="`${apr_config} --link-ld --libs`"
AC_SUBST(APR_LDFLAGS)

APACHE_CFLAGS="-I`${APXS} -q INCLUDEDIR` -I`${apr_config} --includedir`"
AC_SUBST(APACHE_CFLAGS)

# make sure we haz pthread because libmemcached might need it.
AC_CHECK_LIB([pthread], [pthread_once])

# now check for libmemcached, and alter the LDFLAGS to include -lpthread when it does the test.
saved_LIBS="$LIBS"
LIBS="$saved_LIBS -lpthread"
AC_CHECK_LIB([memcached], [memcached_create])
LIBS="$saved_LIBS"

AC_CONFIG_FILES([
 Makefile
 src/Makefile
])
AC_OUTPUT
