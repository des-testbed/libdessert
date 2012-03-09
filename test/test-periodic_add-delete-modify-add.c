
#include "../dessert_internal.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "../dessert.h"
#include "../snmp/dessertObjects.h"
#include "../snmp/dessertMeshifTable.h"
#include "../snmp/dessertSysifTable.h"
#include "../snmp/dessertAppStatsTable.h"
#include "../snmp/dessertAppParamsTable.h"

int callback1(void *data, struct timeval *scheduled, struct timeval *interval) {
	dessert_debug("callback1");
	return 0;
}

int callback2(void *data, struct timeval *scheduled, struct timeval *interval) {
	dessert_debug("callback2");
	return 0;
}

int callback3(void *data, struct timeval *scheduled, struct timeval *interval) {
	dessert_debug("callback3");
	return 0;
}

int main(int argc, char** argv) {

	dessert_init("BUG", 0x01, DESSERT_OPT_NODAEMONIZE, NULL);

	struct timeval callback_interval;
	callback_interval.tv_sec = 1;
	callback_interval.tv_usec = 0;

	dessert_periodic_t* per = dessert_periodic_add(callback1, NULL, NULL, &callback_interval);


	dessert_periodic_add(callback2, NULL, NULL, &callback_interval);
	dessert_periodic_add(callback3, NULL, NULL, &callback_interval);

	dessert_periodic_del(per);
	callback_interval.tv_sec = 3;
	dessert_periodic_add(callback1, NULL, NULL, &callback_interval);

	dessert_run();

}
