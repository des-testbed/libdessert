AC_DEFUN([AC_CHECK_PCAP],[
AC_MSG_CHECKING([Searching for pcap headers])
AC_CHECK_HEADER([pcap.h],[],[AC_MSG_ERROR([pcap headers not found])])

AC_MSG_CHECKING([Searching for pcap lib])
dnl AC_CHECK_PROG([PCAP_LIBS],[pcap-config],[`pcap-config --libs`],[none])
dnl pcap-config has a bug and the return value cannot be used with libtool
AC_CHECK_PROG([PCAP_LIBS],[pcap-config],[`echo "-L/usr/lib -lpcap"`],[none])

dnl AC_CHECK_PROG([PCAP_CFLGAS],[pcap-config],[`pcap-config --cflags`],[none])
AC_CHECK_PROG([PCAP_CFLGAS],[pcap-config],[`pcap-config --cflags`],[none])
if test x"${PCAP_LIBS}" = "xnone"; then
AC_MSG_WARN([pcap-config not found, please install or upgrade the development package of libpcap; configure will continue but build may fail!!!])
AC_SUBST([PCAP_LIBS],[`echo "-L/usr/lib -lpcap"`],[none])
AC_SUBST([PCAP_CFLGAS],[`echo "-I/usr/include"`],[none])
else
AC_MSG_RESULT([found pcap])
fi
])
