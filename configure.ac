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

# Make sure we can find the apxs binary.  Resuting location will be in $APXS, and we'll fail
# if we can't find it.
AX_WITH_APXS()

# Make sure we can find the apr-config binary.  We need this for the proper build flags.  Failed out
# if we can't find it.
AC_ARG_WITH(apr_config, AC_HELP_STRING([--with-apr-config=FILE], [Path to apr-config program]),
    [apr_config="$withval"],
    [AC_PATH_PROGS(apr_config, [apr-config apr-0-config apr-1-config], [no], [$PATH:/usr/sbin/:/usr/local/apache2/bin])]
)

if test "$apr_config" = "no"; then
    AC_MSG_ERROR(Could not find the apr-config program.  You can specify a location with the --with-apr-config=FILE option.  It may be named apr-0-config or apr-1-config and can be found in your apache2 bin directory.)
fi

# Make sure this is the binary we expect it to be.
$apr_config --cflags &> /dev/null
if test "$?" != "0"; then
    AC_MSG_ERROR($apr_config is not a valid apr-config program)
fi

# Now pull in the linker flags and library flags from apr-config.
APR_LDFLAGS="`${apr_config} --link-ld --libs`"
AC_SUBST(APR_LDFLAGS)

# Pull in the include paths for Apache.
APACHE_CFLAGS="-I`${APXS} -q INCLUDEDIR` -I`${apr_config} --includedir`"
AC_SUBST(APACHE_CFLAGS)

# Make sure we have pthread available to us.  libmemcached seems to be depend on it and it's not
# already linked in so we need to provide it when trying to link against libmemcached, including
# our library check.
AC_CHECK_LIB([pthread], [pthread_once])

# Check for libmemcached now, temporarily overriding LIBS to make sure that pthread
# gets linked in when testing the libmemcached library.  Set back LIBS to its original
# value after we're done.
saved_LIBS="$LIBS"
LIBS="$saved_LIBS -lpthread"
AC_CHECK_LIB([memcached], [memcached_create])
LIBS="$saved_LIBS"

AC_CONFIG_FILES([
 Makefile
 src/Makefile
])
AC_OUTPUT
