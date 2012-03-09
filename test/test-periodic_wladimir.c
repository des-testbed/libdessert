
#include "../dessert_internal.h"

#define HELLO_INTERVAL				1 // sec
#define RREQ_RETRIES				2
#define NODE_TRAVERSAL_TIME			40 // milliseconds
#define NET_DIAMETER				20
#define NET_TRAVERSAL_TIME			2 * NODE_TRAVERSAL_TIME * NET_DIAMETER
#define BLACKLIST_TIMEOUT			RREQ_RETRIES * NET_TRAVERSAL_TIME

int p1(void *data, struct timeval *scheduled, struct timeval *interval) {
	dessert_debug("p1");
	return 0;
}

int p2(void *data, struct timeval *scheduled, struct timeval *interval) {
	dessert_debug("p2");
	return 0;
}

int main(int argc, char** argv) {
	dessert_init("BUG", 0x01, DESSERT_OPT_NODAEMONIZE, NULL);

	struct timeval int1;
	int1.tv_sec = HELLO_INTERVAL;
	int1.tv_usec = 0;
	dessert_periodic_add(p1, NULL, NULL, &int1);


	struct timeval int2;
	int2.tv_sec = BLACKLIST_TIMEOUT / 1000;
	int2.tv_usec = (BLACKLIST_TIMEOUT % 1000) * 1000;
	dessert_debug("%i sek %i microsek", BLACKLIST_TIMEOUT / 1000, (BLACKLIST_TIMEOUT % 1000) * 1000);
	dessert_periodic_add(p2, NULL, NULL, &int2);

	dessert_run();
	return 0;
}

