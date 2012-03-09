#include "../dessert.h"
#include "../utlist.h"
#include <string.h>

/* *****************************************************************************
 *
 * SNMP table: DESSERT-MIB::dessertAppStatsTable
 *
 *                  Name             Desc NodeOrLink   ValueType MacAddress1 MacAddress2 TruthValue Integer32 Unsigned32  Counter64      OctetString
 *                                             none        bool           ?           ?      false         ?          ?          ?                ?
 *                                             none        bool           ?           ?      false         ?          ?          ?                ?
 *             true_get             TRUE       none        bool           ?           ?       true         ?          ?          ?                ?
 *            false_get            FALSE       none        bool           ?           ?      false         ?          ?          ?                ?
 *            int32_get             -200       none       int32           ?           ?          ?      -200          ?          ?                ?
 *           uint32_get              100       none      uint32           ?           ?          ?         ?        100          ?                ?
 *          counter_get       4294967296       none   counter64           ?           ?          ?         ?          ? 4294967296                ?
 *      octetstring_get aaaaaaaaaaaaaaaa       none octetstring           ?           ?          ?         ?          ?          ? aaaaaaaaaaaaaaaa
 *       int32_link_get    link n1 to n2       link       int32 1:1:1:1:1:1 2:2:2:2:2:2          ?      -200          ?          ?                ?
 *   counter64_node_get          node n1       node   counter64 1:1:1:1:1:1           ?          ?         ?          ? 4294967296                ?
 * uint32_link_bulk_get    link n1 to n2       link      uint32 1:1:1:1:1:1 2:2:2:2:2:2          ?         ?        100          ?                ?
 * uint32_link_bulk_get    link n2 to n3       link      uint32 2:2:2:2:2:2 3:3:3:3:3:3          ?         ?        100          ?                ?
 *
 **************************************************************************** */


uint8_t  b_true    = DESSERT_APPSTATS_BOOL_TRUE;
uint8_t  b_false   = DESSERT_APPSTATS_BOOL_FALSE;
int32_t  int32     =  -200;
uint32_t uint32    = 100;
uint64_t counter64 = 4294967296; /* 2^32 - you need >32 bits for that */

uint8_t n1[6] = {0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
uint8_t n2[6] = {0x2, 0x2, 0x2, 0x2, 0x2, 0x2 };
uint8_t n3[6] = {0x3, 0x3, 0x3, 0x3, 0x3, 0x3 };
uint8_t n4[6] = {0x4, 0x4, 0x4, 0x4, 0x4, 0x4 };
uint8_t n5[6] = {0x5, 0x5, 0x5, 0x5, 0x5, 0x5 };
uint8_t n6[6] = {0x6, 0x6, 0x6, 0x6, 0x6, 0x6 };

int uninizialised_get_appstats_cb(dessert_agentx_appstats_t *appstat){

	return DESSERT_OK;
}

int uninizialised_bulk__get_appstats_cb(dessert_agentx_appstats_t *appstat){

	return DESSERT_OK;
}


int true_get_appstats_cb(dessert_agentx_appstats_t *appstat){

	appstat->value_type = DESSERT_APPSTATS_VALUETYPE_BOOL;
	strncpy(appstat->name,"true_get",256);
	strncpy(appstat->desc,"TRUE", 256);
	appstat->bool = b_true;

	return DESSERT_OK;
}



int false_get_appstats_cb(dessert_agentx_appstats_t *appstat){

	appstat->value_type = DESSERT_APPSTATS_VALUETYPE_BOOL;
	strncpy(appstat->name,"false_get",256);
	strncpy(appstat->desc,"FALSE", 256);
	appstat->bool = b_false;

	return DESSERT_OK;
}



int int32_get_appstats_cb(dessert_agentx_appstats_t *appstat){

	appstat->value_type = DESSERT_APPSTATS_VALUETYPE_INT32;
	strncpy(appstat->name,"int32_get",256);
	strncpy(appstat->desc,"-200", 256);
	appstat->int32 = int32;

	return DESSERT_OK;
}



int uint32_get_appstats_cb(dessert_agentx_appstats_t *appstat){

	appstat->value_type = DESSERT_APPSTATS_VALUETYPE_UINT32;
	strncpy(appstat->name,"uint32_get",256);
	strncpy(appstat->desc,"100", 256);
	appstat->uint32 = uint32;

	return DESSERT_OK;
}

int counter64_get_appstats_cb(dessert_agentx_appstats_t *appstat){

	appstat->value_type = DESSERT_APPSTATS_VALUETYPE_COUNTER64;
	strncpy(appstat->name,"counter_get",256);
	strncpy(appstat->desc,"4294967296", 256);
	appstat->counter64 = counter64;

	return DESSERT_OK;
}


int octetstring_get_appstats_cb(dessert_agentx_appstats_t *appstat){

	appstat->value_type = DESSERT_APPSTATS_VALUETYPE_OCTETSTRING;
	strncpy(appstat->name,"octetstring_get",256);
	strncpy(appstat->desc,"aaaaaaaaaaaaaaaa", 256);

#define OCTETSTRING_LENGTH 16

	appstat->octetstring = malloc(sizeof(char) * OCTETSTRING_LENGTH);
	memset(appstat->octetstring, 'a', OCTETSTRING_LENGTH);
	appstat->octetstring_len = OCTETSTRING_LENGTH;

	memcpy(appstat->macaddress1, n1, ETHER_ADDR_LEN); /* should NOT show up */
	memcpy(appstat->macaddress2, n2, ETHER_ADDR_LEN); /* should NOT show up */

	return DESSERT_OK;
}

int int32_link_get_appstats_cb(dessert_agentx_appstats_t *appstat){

	appstat->value_type = DESSERT_APPSTATS_VALUETYPE_INT32;
	appstat->node_or_link = DESSERT_APPSTATS_NODEORLINK_LINK;
	strncpy(appstat->name,"int32_link_get",256);
	strncpy(appstat->desc,"link n1 to n2", 256);

	memcpy(appstat->macaddress1, n1, ETHER_ADDR_LEN);
	memcpy(appstat->macaddress2, n2, ETHER_ADDR_LEN);
	appstat->int32 = int32;

	return DESSERT_OK;
}

int counter64_node_get_appstats_cb(dessert_agentx_appstats_t *appstat){

	appstat->value_type = DESSERT_APPSTATS_VALUETYPE_COUNTER64;
	appstat->node_or_link = DESSERT_APPSTATS_NODEORLINK_NODE;
	strncpy(appstat->name,"counter64_node_get",256);
	strncpy(appstat->desc,"node n1", 256);

	memcpy(appstat->macaddress1, n1, ETHER_ADDR_LEN);
	appstat->counter64 = counter64;

	return DESSERT_OK;
}

int uint32_link_bulk_get_appstats_cb(dessert_agentx_appstats_t *appstat) {

	assert(  appstat->prev       == appstat       );
	assert(  appstat->next       == NULL          );

	/* first */

	appstat->value_type = DESSERT_APPSTATS_VALUETYPE_UINT32;
	appstat->node_or_link = DESSERT_APPSTATS_NODEORLINK_LINK;
	strncpy(appstat->name,"uint32_link_bulk_get",256);
	strncpy(appstat->desc,"link n1 to n2", 256);

	memcpy(appstat->macaddress1, n1, ETHER_ADDR_LEN);
	memcpy(appstat->macaddress2, n2, ETHER_ADDR_LEN);
	appstat->uint32 = uint32;

	/* second */

	dessert_agentx_appstats_t *next_appstat = dessert_agentx_appstats_new();

	next_appstat->value_type = DESSERT_APPSTATS_VALUETYPE_UINT32;
	next_appstat->node_or_link = DESSERT_APPSTATS_NODEORLINK_LINK;
	strncpy(next_appstat->name,"uint32_link_bulk_get",256);
	strncpy(next_appstat->desc,"link n2 to n3", 256);

	memcpy(next_appstat->macaddress1, n2, ETHER_ADDR_LEN);
	memcpy(next_appstat->macaddress2, n3, ETHER_ADDR_LEN);
	next_appstat->uint32 = uint32;

	DL_APPEND(appstat, next_appstat);

	assert(  next_appstat->prev  == appstat       );
	assert(  next_appstat->next  == NULL          );
	assert(  appstat->prev       == next_appstat  );
	assert(  appstat->next       == next_appstat  );

	return DESSERT_OK;
}

int main(int argc, char** argv) {

	dessert_init("TEST", 0x01, DESSERT_OPT_NODAEMONIZE, NULL);


	dessert_agentx_appstats_add(uninizialised_get_appstats_cb);
	dessert_agentx_appstats_add_bulk(uninizialised_bulk__get_appstats_cb);

	dessert_agentx_appstats_add(true_get_appstats_cb);
	dessert_agentx_appstats_add(false_get_appstats_cb);
	dessert_agentx_appstats_add(int32_get_appstats_cb);
	dessert_agentx_appstats_add(uint32_get_appstats_cb);
	dessert_agentx_appstats_add(counter64_get_appstats_cb);
	dessert_agentx_appstats_add(octetstring_get_appstats_cb);
	dessert_agentx_appstats_add(int32_link_get_appstats_cb);
	dessert_agentx_appstats_add(counter64_node_get_appstats_cb);

	dessert_agentx_appstats_add_bulk(uint32_link_bulk_get_appstats_cb);

	dessert_run();

	return 0;
}
