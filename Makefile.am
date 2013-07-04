SUBDIRS =
#SUBDIRS += po

if HAVE_MANPAGES
SUBDIRS += man
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

GN_MECHGLUE_LIBS = $(GSSAPI_LIBS) $(CRYPTO_LIBS)

GN_MECHGLUE_OBJ = \
    src/crypto.c \
    src/ntlm_crypto.c \
    src/ntlm.c \
    src/gss_ntlmssp.c

dist_noinst_HEADERS = \
    src/crypto.h \
    src/ntlm_common.h \
    src/ntlm.h \
    src/gss_ntlmssp.h

####################
# Program Binaries #
####################

gssntlmssp_la_SOURCES = \
    $(GN_MECHGLUE_OBJ)
gssntlmssp_la_CFLAGS = \
    $(AM_FLAGS)
gssntlmssp_la_LDFLAGS = \
    $(GN_MECHGLUE_LIBS) \
    -avoid-version \
    -module

ntlmssptest_SOURCES = \
    tests/ntlmssptest.c

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

if HAVE_DOXYGEN
docs:
	$(DOXYGEN) doxy.config
else
docs:
	@echo "Doxygen not installed, cannot generate documentation"
	@exit 1
endif

install-exec-hook: installgssntlmsspdirs
	mkdir -p doc $(DESTDIR)/$(docdir); cp -a doc $(DESTDIR)/$(docdir)/

clean-local:
	rm -Rf doc

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

test_gssntlmssp:
	TMPDIR=tests/scripts/ ./tests/scripts/dlopen.sh ./.libs/gssntlmssp.so || exit 1
