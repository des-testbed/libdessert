#include "../dessert.h"
#include "../utlist.h"
#include <pthread.h>

int main(int argc, char** argv) {

	dessert_meshif_t *iface;

	dessert_init("TEST", 0x01, DESSERT_OPT_NODAEMONIZE, NULL);

	MESHIFLIST_ITERATOR_START(iface){
		/* do something*/
	} MESHIFLIST_ITERATOR_STOP;

	pthread_rwlock_rdlock(&dessert_cfglock);
	DL_FOREACH(dessert_meshiflist_get(), iface) {
		{;}
	}
	pthread_rwlock_unlock(&dessert_cfglock);


	dessert_run();

	return 0;
}
