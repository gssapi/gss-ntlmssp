SUBDIRS =
#SUBDIRS += po

if HAVE_MANPAGES
SUBDIRS += man
endif
if HAVE_NLS
SUBDIRS += po
endif

# Some old versions of automake don't define builddir
builddir ?= .

DOXYGEN = @DOXYGEN@

DISTSETUPOPTS =
if HAVE_DEBIAN
DISTSETUPOPTS += --install-layout=deb
endif

gssconfdir = $(sysconfdir)/gss
gssntlmsspdir = $(libdir)/gssntlmssp
localedir = @localedir@

pkgconfigdir = $(libdir)/pkgconfig

AM_CFLAGS =
if WANT_AUX_INFO
    AM_CFLAGS += -aux-info $@.X
endif
if HAVE_GCC
    AM_CFLAGS += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith \
                 -Wcast-qual -Wcast-align -Wwrite-strings \
                 -Werror-implicit-function-declaration \
                 -fno-strict-aliasing
endif
if HAVE_NLS
    AM_CFLAGS += -DLOCALEDIR="\"$(localedir)\""
endif

dist_pkgconfig_DATA =

ACLOCAL_AMFLAGS = -I m4 -I .

check_PROGRAMS = \
    ntlmssptest

gssntlmssp_LTLIBRARIES = \
    gssntlmssp.la

dist_noinst_SCRIPTS = tests/scripts/dlopen.sh

dist_noinst_DATA =

###############################
# Global compilation settings #
###############################

AM_CPPFLAGS = \
    -Wall \
    -Iinclude \
    -I.. \
    -I$(srcdir)/include \
    -I$(srcdir) \
    -Iinclude \
    -I. \
    -DLIBDIR=\"$(libdir)\" \
    -DVARDIR=\"$(localstatedir)\" \
    -DSHLIBEXT=\"$(SHLIBEXT)\" \
    -DSYSCONFDIR=\"$(sysconfdir)\" \
    -DLOCALEDIR=\"$(localedir)\"

#EXTRA_DIST = build/config.rpath

GN_MECHGLUE_LIBS = $(GSSAPI_LIBS) $(CRYPTO_LIBS) $(WBC_LIBS)

GN_MECHGLUE_OBJ = \
    src/crypto.c \
    src/ntlm_crypto.c \
    src/ntlm.c \
    src/debug.c \
    src/gss_err.c \
    src/gss_spi.c \
    src/gss_names.c \
    src/gss_creds.c \
    src/gss_sec_ctx.c \
    src/gss_signseal.c \
    src/gss_serialize.c \
    src/external.c \
    src/gss_auth.c \
    src/gss_ntlmssp.c

if BUILD_WBCLIENT
   GN_MECHGLUE_OBJ += src/winbind.c
endif

dist_noinst_HEADERS = \
    src/crypto.h \
    src/ntlm_common.h \
    src/ntlm.h \
    src/debug.h \
    src/gss_ntlmssp.h \
    src/gss_ntlmssp_winbind.h

gssapidir = $(includedir)/gssapi
dist_gssapi_HEADERS = \
    src/gssapi_ntlmssp.h

POTFILES = src/gss_err.c

####################
# Program Binaries #
####################

gssntlmssp_la_SOURCES = \
    $(GN_MECHGLUE_OBJ)
gssntlmssp_la_CFLAGS = \
    $(WBC_CFLAGS) \
    $(AM_CFLAGS)
gssntlmssp_la_LDFLAGS = \
    $(GN_MECHGLUE_LIBS) \
    -export-symbols-regex '^gss(spi|)_' \
    -avoid-version \
    -module

ntlmssptest_SOURCES = \
    $(GN_MECHGLUE_OBJ) \
    tests/ntlmssptest.c
ntlmssptest_CFLAGS = \
    $(WBC_CFLAGS) \
    $(AM_CFLAGS)
ntlmssptest_LDFLAGS = \
    -L$(libdir)
ntlmssptest_LDADD = \
    $(GN_MECHGLUE_LIBS) \
    $(UNISTRING_LIBS)

dist_noinst_DATA += \
    m4

noinst_PROGRAMS = ntlmssptest

################
# TRANSLATIONS #
################
update-po:
if HAVE_MANPAGES
	$(MAKE) -C man update-po
endif
#	$(MAKE) -C po update-po

#######################
# Installation Extras #
#######################

installgssntlmsspdirs::
	mkdir -p \
    $(DESTDIR)$(libdir)/gssntlmssp \
    $(DESTDIR)$(mandir)

CLEANFILES = *.X */*.X */*/*.X

tests: all $(check_PROGRAMS)

# RPM-related tasks

RPMBUILD ?= $(PWD)/rpmbuild

dist_noinst_DATA += \
    m4 \
    contrib/gssntlmssp.spec.in \
    BUILD.txt \
    COPYING

rpmroot:
	mkdir -p $(RPMBUILD)/BUILD
	mkdir -p $(RPMBUILD)/RPMS
	mkdir -p $(RPMBUILD)/SOURCES
	mkdir -p $(RPMBUILD)/SPECS
	mkdir -p $(RPMBUILD)/SRPMS

po/$(PACKAGE).pot: $(POTFILES)
	@echo "Regenerating $@" ; rm -f $@ && \
	xgettext --directory=$(top_srcdir) --from-code=UTF-8 \
	  --sort-by-file --add-comments --keyword=_ --keyword=N_ \
	  --package-name="@PACKAGE@" --package-version="@VERSION@" \
	  --msgid-bugs-address="simo@samba.org" \
	  -o $@ $(POTFILES)

rpms: dist-gzip rpmroot
	cp $(builddir)/contrib/gssntlmssp.spec $(RPMBUILD)/SPECS
	cp $(distdir).tar.gz $(RPMBUILD)/SOURCES
	cd $(RPMBUILD); \
	rpmbuild --define "_topdir $(RPMBUILD)" -ba SPECS/gssntlmssp.spec

if GIT_CHECKOUT
prerelease-rpms:
	cp $(srcdir)/version.m4 $(srcdir)/version.m4.orig
	sed -e "s/m4_define(\[PRERELEASE_VERSION_NUMBER\], \[.*\])/m4_define(\[PRERELEASE_VERSION_NUMBER\], \[.`date +%Y%m%d.%H%M`.git`git log -1 --pretty=format:%h`\])/" < $(srcdir)/version.m4.orig > $(srcdir)/version.m4
	$(MAKE) rpms
	mv $(srcdir)/version.m4.orig $(srcdir)/version.m4
endif

# make srpms will use the old digest algorithm to be compatible
# with RHEL5
srpm: dist-gzip rpmroot
	cp $(builddir)/contrib/gssntlmssp.spec $(RPMBUILD)/SPECS
	cp $(distdir).tar.gz $(RPMBUILD)/SOURCES
	cd $(RPMBUILD); \
	rpmbuild --define "_topdir $(RPMBUILD)" \
	         --define _source_filedigest_algorithm=1 \
	         -bs SPECS/gssntlmssp.spec

if GIT_CHECKOUT
prerelease-srpm:
	cp $(srcdir)/version.m4 $(srcdir)/version.m4.orig
	sed -e "s/m4_define(\[PRERELEASE_VERSION_NUMBER\], \[.*\])/m4_define(\[PRERELEASE_VERSION_NUMBER\], \[.`date +%Y%m%d.%H%M`.git`git log -1 --pretty=format:%h`\])/" < $(srcdir)/version.m4.orig > $(srcdir)/version.m4
	$(MAKE) srpm
	mv $(srcdir)/version.m4.orig $(srcdir)/version.m4
endif

####################
# Testing          #
####################

TESTS = ntlmssptest tests/env1.sh tests/env2.sh

test_gssntlmssp:
	TMPDIR=tests/scripts/ ./tests/scripts/dlopen.sh ./.libs/gssntlmssp.so || exit 1
