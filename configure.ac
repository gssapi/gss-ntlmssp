AC_PREREQ(2.59)

m4_include([version.m4])
AC_INIT([gssntlmssp],
        VERSION_NUMBER,
        [simo@samba.org])

m4_ifdef([AC_USE_SYSTEM_EXTENSIONS],
    [AC_USE_SYSTEM_EXTENSIONS],
    [AC_GNU_SOURCE])

CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE"

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects tar-pax])
AM_PROG_CC_C_O
AM_PROG_AR
AC_PROG_INSTALL
LT_INIT([disable-static])

AC_SUBST([PRERELEASE_VERSION],
         PRERELEASE_VERSION_NUMBER)

AC_DEFINE([PRERELEASE_VERSION], "PRERELEASE_VERSION_NUMBER",
          [Prerelease version number of package])

AM_CONDITIONAL([GIT_CHECKOUT], [git log -1 &>/dev/null])

m4_pattern_allow([AM_SILENT_RULES])
AM_SILENT_RULES

AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_prog_gcc" = yes])

AC_CHECK_HEADERS(stdint.h dlfcn.h)
AC_CONFIG_HEADER(config.h)

AC_CHECK_TYPES([errno_t], [], [], [[#include <errno.h>]])

m4_include([build_macros.m4])
BUILD_WITH_SHARED_BUILD_DIR

AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[#include <pthread.h>]],
        [[pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;]])],
    [AC_DEFINE([HAVE_PTHREAD], [1], [Pthread mutexes available.])],
    [AC_MSG_WARN([Pthread library not found! Clients will not be thread safe...])])

#Include here cause WITH_INIT_DIR requires $osname set in platform.m4
m4_include([external/platform.m4])

m4_include(conf_macros.m4)
WITH_DISTRO_VERSION
WITH_TEST_DIR
WITH_MANPAGES
WITH_XML_CATALOG
WITH_WBCLIENT
WITH_WINBIND_TLS_CONTEXT

m4_include([external/pkg.m4])
m4_include([external/docbook.m4])
m4_include([external/sizes.m4])
m4_include([external/ax_pthread.m4])
m4_include([external/m4_ax_check_openssl.m4])
m4_include([external/ax_check_zlib.m4])
m4_include([external/wbclient.m4])

AX_PTHREAD(,[AC_MSG_ERROR([Could not find Pthreads support])])

LIBS="$PTHREAD_LIBS $LIBS"
LIBS="$PTHREAD_CFLAGS $CFLAGS"
CC="$PTHREAD_CC"

AC_CHECK_HEADERS([gssapi/gssapi.h],,[AC_MSG_ERROR([Could not find GSSAPI headers])])
AC_PATH_PROG(KRB5_CONFIG, krb5-config, failed)
if test x$KRB5_CONFIG = xfailed; then
    AC_MSG_ERROR([Could not find GSSAPI development libraries])
else
    GSSAPI_CFLAGS="`$KRB5_CONFIG --cflags gssapi`"
    GSSAPI_LIBS="`$KRB5_CONFIG --libs gssapi`"
fi
AC_CHECK_LIB(gssapi_krb5, gss_import_cred,,
             [AC_MSG_ERROR([GSSAPI library does not support gss_import_cred])],
             [$GSSAPI_LIBS])
AC_CHECK_LIB(gssapi_krb5, gss_export_cred,,
             [AC_MSG_ERROR([GSSAPI library does not support gss_export_cred])],
             [$GSSAPI_LIBS])

AC_SUBST([GSSAPI_CFLAGS])
AC_SUBST([GSSAPI_LIBS])

AC_CHECK_HEADERS([unicase.h uniconv.h],,
                 [AC_MSG_ERROR([Could not find libunistring headers])])
UNISTRING_LIBS="-lunistring"
AC_CHECK_LIB(unistring, u8_toupper,,
             [AC_MSG_ERROR([libunistring does not support u8_toupper])],
             [$UNISTRING_LIBS])

AC_SUBST([UNISTRING_LIBS])

AX_CHECK_OPENSSL(,[AC_MSG_ERROR([Could not find OpenSSL support])])

CRYPTO_LIBS="$OPENSSL_LIBS"
AC_SUBST([CRYPTO_LIBS])

AX_CHECK_ZLIB(,[AC_MSG_ERROR([Could not find Zlib support])])

if test x$HAVE_WBCLIENT != x; then
    AM_CHECK_WBCLIENT
fi

if test x$HAVE_NLS != x; then
    AC_CHECK_FUNC(dgettext, [],
                  AC_CHECK_LIB(intl, dgettext, [],
                               AC_ERROR([Could not find dgettext() function])))
    AC_PATH_PROG(MSGFMT, msgfmt)
    if test x$MSGFMT = x; then
        AC_ERROR([Could not find msgfmt])
    fi
fi
RAWLINGUAS=`sed -e "/^#/d" -e "s/#.*//" "${srcdir}/po/LINGUAS"`
# Remove newlines
LINGUAS=`echo $RAWLINGUAS`
AC_SUBST(LINGUAS)

if test x$HAVE_MANPAGES != x; then
    CHECK_XML_TOOLS
    CHECK_STYLESHEET([$SGML_CATALOG_FILES],
                     [http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl],
                     [Docbook XSL templates])
    AC_CHECK_PROG([PO4A],[po4a],[po4a],[no])
fi
AM_CONDITIONAL([HAVE_MANPAGES], [test "x$HAVE_MANPAGES" != "x"])
AM_CONDITIONAL([HAVE_PO4A], [test "x$PO4A" != "xno"])

AC_PATH_PROG([DOXYGEN], [doxygen], [false])
AM_CONDITIONAL([HAVE_DOXYGEN], [test x$DOXYGEN != xfalse ])

abs_build_dir=`pwd`
AC_DEFINE_UNQUOTED([ABS_BUILD_DIR], ["$abs_build_dir"], [Absolute path to the build directory])
AC_SUBST([abs_builddir], $abs_build_dir)

abs_src_dir=`cd $srcdir && pwd`
AC_DEFINE_UNQUOTED([ABS_SRC_DIR], ["$abs_src_dir"], [Absolute path to the source directory])
AC_SUBST([abs_srcdir], $abs_src_dir)

AC_CONFIG_FILES([Makefile man/Makefile po/Makefile
                 contrib/gssntlmssp.spec examples/mech.ntlmssp])
AC_OUTPUT
