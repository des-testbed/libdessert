
AM_CPPFLAGS = -I$(top_srcdir)/include \
              -I../libdessert \
              @SNMP_CFLAGS@

noinst_LTLIBRARIES = libdessertsnmp.la

libdessertsnmp_la_SOURCES = \
        dessertAppParamsTable.c \
        dessertAppParamsTable.h \
        dessertAppParamsTable_oids.h \
        dessertAppParamsTable_data_access.c \
        dessertAppParamsTable_data_access.h \
        dessertAppParamsTable_data_get.c \
        dessertAppParamsTable_data_get.h \
        dessertAppParamsTable_data_set.c \
        dessertAppParamsTable_data_set.h \
		dessertAppParamsTable_enums.h \
        dessertAppParamsTable_interface.c \
        dessertAppParamsTable_interface.h \
        dessertAppStatsTable.c \
        dessertAppStatsTable.h \
        dessertAppStatsTable_enums.h \
        dessertAppStatsTable_oids.h \
        dessertAppStatsTable_data_access.c \
        dessertAppStatsTable_data_access.h \
        dessertAppStatsTable_data_get.c \
        dessertAppStatsTable_data_get.h \
        dessertAppStatsTable_data_set.c \
        dessertAppStatsTable_data_set.h \
        dessertAppStatsTable_interface.c \
        dessertAppStatsTable_interface.h \
        dessertMeshifTable.c \
        dessertMeshifTable.h \
        dessertMeshifTable_enums.h \
        dessertMeshifTable_oids.h \
        dessertMeshifTable_data_access.c \
        dessertMeshifTable_data_access.h \
        dessertMeshifTable_data_get.c \
        dessertMeshifTable_data_get.h \
        dessertMeshifTable_data_set.c \
        dessertMeshifTable_data_set.h \
        dessertMeshifTable_interface.c \
        dessertMeshifTable_interface.h \
        dessertObjects.c \
        dessertObjects.h \
        dessertSysifTable.c \
        dessertSysifTable.h \
        dessertSysifTable_enums.h \
        dessertSysifTable_oids.h \
        dessertSysifTable_interface.h \
        dessertSysifTable_data_access.c \
        dessertSysifTable_data_access.h \
        dessertSysifTable_data_get.c \
        dessertSysifTable_data_get.h \
        dessertSysifTable_data_set.c \
        dessertSysifTable_data_set.h \
        dessertSysifTable_interface.c \
        dessertSysifTable_subagent.c

libdessertsnmp_la_LDFLAGS = -avoid-version
