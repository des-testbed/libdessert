#include "../dessert.h"

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

int callback4(void *data, struct timeval *scheduled, struct timeval
*interval) { dessert_debug("callback4");
	return 0;
}

int main(int argc, char** argv) {

	dessert_logcfg(DESSERT_LOG_DEBUG | DESSERT_LOG_NOSTDERR | DESSERT_LOG_NOSYSLOG
					| DESSERT_LOG_NORBUF | DESSERT_LOG_NOFILE);

	dessert_init("BUG", 0x01, DESSERT_OPT_NODAEMONIZE, NULL);




	struct timeval callback1_interval;
	callback1_interval.tv_sec = 1;
	callback1_interval.tv_usec = 0;
	dessert_periodic_add(callback1, NULL, NULL, &callback1_interval);

	struct timeval callback2_interval;
	callback2_interval.tv_sec = 5;
	callback2_interval.tv_usec = 0;
	dessert_periodic_add(callback2, NULL, NULL, &callback2_interval);

	struct timeval callback3_interval;
	callback3_interval.tv_sec = 16;
	callback3_interval.tv_usec = 0;
	dessert_periodic_add(callback3, NULL, NULL, &callback3_interval);

	struct timeval callback4_schedule;
	gettimeofday(&callback4_schedule, NULL);
	TIMEVAL_ADD(&callback4_schedule, 1, 500000);

	dessert_periodic_add(callback4, NULL, &callback4_schedule,
		NULL);

	dessert_cli_run(1023);
	dessert_run();

}
