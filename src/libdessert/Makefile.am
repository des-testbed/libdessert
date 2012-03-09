AM_CPPFLAGS = -I$(top_srcdir)/include \
              @PCAP_CFLAGS@ \
              @PTHREAD_CFLAGS@

lib_LTLIBRARIES = libdessert.la

libdessert_la_SOURCES = dessert_core.c \
                        dessert_meshiface.c \
                        dessert_periodic.c \
                        dessert_signals.c \
                        dessert_cli.c \
                        dessert_log.c \
                        dessert_msg.c \
                        dessert_sysiface.c \
                        dessert_utils.c \
                        dessert_ping.c \
                        dessert_trace.c \
                        dessert_filter.c \
                        dessert_internal.h

libdessert_la_LIBADD =  @PCAP_LIBS@ \
                        @CLI_LIBS@ \
                        @PTHREAD_LIBS@

if !ANDROID
    libdessert_la_SOURCES += dessert_monitor.c
else
    AM_CPPFLAGS += -DANDROID
    ## libdessert_la_LIBADD += pthreadex.a ## TODO: check why this is here
endif

libdessert_la_LDFLAGS = -version-number @LIBDESSERT_LIBRARY_VERSION@ -Wl,--no-undefined

if WITH_NET_SNMP
    AM_CPPFLAGS += -I../snmp \
                   @SNMP_CFLAGS@

    libdessert_la_SOURCES += dessert_agentx.c

    libdessert_la_LIBADD += ../snmp/libdessertsnmp.la \
                            @SNMP_LIBS@
endif
