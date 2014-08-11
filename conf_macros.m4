AC_DEFUN([WITH_DISTRO_VERSION],
  [ AC_ARG_WITH([distro-version],
                [AC_HELP_STRING([--with-distro-version=VERSION],
                                [Distro version number []]
                               )
                ]
               )
    AC_DEFINE_UNQUOTED(DISTRO_VERSION, "$with_distro_version",
                           [Distro version number])
  ])

AC_DEFUN([WITH_MANPAGES],
  [ AC_ARG_WITH([manpages],
                [AC_HELP_STRING([--with-manpages],
                                [Whether to regenerate man pages from DocBook sources [yes]]
                               )
                ],
                [],
                with_manpages=yes
               )
    if test x"$with_manpages" = xyes; then
        HAVE_MANPAGES=1
        AC_SUBST(HAVE_MANPAGES)
    fi
  ])
AM_CONDITIONAL([BUILD_MANPAGES], [test x$with_manpages = xyes])

AC_DEFUN([WITH_XML_CATALOG],
  [ AC_ARG_WITH([xml-catalog-path],
                [AC_HELP_STRING([--with-xml-catalog-path=PATH],
                                [Where to look for XML catalog [/etc/xml/catalog]]
                               )
                ]
               )
    SGML_CATALOG_FILES="/etc/xml/catalog"
    if test x"$with_xml_catalog_path" != x; then
        SGML_CATALOG_FILES="$with_xml_catalog_path"
    fi
    AC_SUBST([SGML_CATALOG_FILES])
  ])

AC_DEFUN([WITH_TEST_DIR],
  [ AC_ARG_WITH([test-dir],
                [AC_HELP_STRING([--with-test-dir=PATH],
                                [Directory used for make check temporary files [$builddir]]
                               )
                ]
               )
    TEST_DIR=$with_test_dir
    AC_SUBST(TEST_DIR)
    AC_DEFINE_UNQUOTED(TEST_DIR, "$with_test_dir", [Directory used for 'make check' temporary files])
  ])

AC_ARG_ENABLE([nls],
              [AS_HELP_STRING([--disable-nls],
                              [do not use Native Language Support])],
              [use_nls=$enableval],
              [use_nls=yes])
if test x"$use_nls" = "xyes"; then
    HAVE_NLS=1
    AC_SUBST(HAVE_NLS)
    AC_DEFINE_UNQUOTED(HAVE_NLS, 1, [Buils with Native Language Support])
fi
AM_CONDITIONAL([HAVE_NLS], [test x"$use_nls" = xyes])

AC_ARG_ENABLE([all-experimental-features],
              [AS_HELP_STRING([--enable-all-experimental-features],
                              [build all experimental features])],
              [build_all_experimental_features=$enableval],
              [build_all_experimental_features=no])

AC_DEFUN([WITH_WBCLIENT],
         [AC_ARG_WITH([wbclient],
                      [AC_HELP_STRING([--with-wbclient],
                                      [Build with WBClient support [yes]])
                      ],
                      [],
                      with_wbclient=yes)

          if test x"$with_wbclient" = xyes; then
              HAVE_WBCLIENT=1
              AC_SUBST(HAVE_WBCLIENT)
              AC_DEFINE_UNQUOTED(HAVE_WBCLIENT, 1, [Build with WBClient support])
          fi

          AM_CONDITIONAL([BUILD_WBCLIENT], [test x"$with_wbclient" = xyes])
         ])
