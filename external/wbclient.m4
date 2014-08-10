dnl A macro to check the availability of Winbind client libraries
AC_DEFUN([AM_CHECK_WBCLIENT],
         [
          PKG_CHECK_MODULES(WBC, wbclient,
                            [AC_DEFINE([HAVE_WBCLIENT], [1],
                                       [Wbclient support is available])
                            ],
                            AC_MSG_ERROR("wbclient headers not found"))
          AC_SUBST(WBC_CFLAGS)
          AC_SUBST(WBC_LIBS)
         ])
