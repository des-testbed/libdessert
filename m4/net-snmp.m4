AC_DEFUN([AC_CHECK_NET_SNMP],[
AC_MSG_CHECKING([Searching for net-snmp lib])
AC_CHECK_PROG([SNMP_LIBS],[net-snmp-config],[`net-snmp-config --agent-libs`],[none])
AC_CHECK_PROG([SNMP_CFLGAS],[net-snmp-config],[`net-snmp-config --cflags`],[none])
if test x"${SNMP_LIBS}" = "xnone"; then
AC_MSG_ERROR([net-snmp-config not found, please install the development package of net-snmp])
else
AC_MSG_RESULT([found net-snmp-config])
fi
])
