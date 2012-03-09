#include "../dessert.h"
#include "../dessert_internal.h"
#include <string.h>


uint8_t b_true  = DESSERT_APPPARAMS_BOOL_TRUE;
uint8_t b_false = DESSERT_APPPARAMS_BOOL_FALSE;
int32_t int32   =  -200;
uint32_t uint32 = 100;

int true_get_appparams_cb(dessert_agentx_appparams_t *appparam){

	dessert_debug("true_get_cb called");

	appparam->value_type = DESSERT_APPPARAMS_VALUETYPE_BOOL;
	strncpy(appparam->name,"true_get",256);
	strncpy(appparam->desc,"TRUE", 256);
	appparam->bool = b_true;

	return DESSERT_OK;
}

int true_set_appparams_cb(dessert_agentx_appparams_t *appparam){

	dessert_debug("true_set_cb called");

	if (appparam->value_type != DESSERT_APPPARAMS_VALUETYPE_BOOL) {
		return DESSERT_ERR;
	}

	dessert_debug("old value: %d", b_true);
	b_true = appparam->bool;
	dessert_debug("new value: %d", b_true);

	return DESSERT_OK;
}

int false_get_appparams_cb(dessert_agentx_appparams_t *appparam){

	dessert_debug("false_get_cb called");

	appparam->value_type = DESSERT_APPPARAMS_VALUETYPE_BOOL;
	strncpy(appparam->name,"false_get",256);
	strncpy(appparam->desc,"FALSE", 256);
	appparam->bool = b_false;

	return DESSERT_OK;
}

int false_set_appparams_cb(dessert_agentx_appparams_t *appparam){

	dessert_debug("false_set_cb called");

	if (appparam->value_type != DESSERT_APPPARAMS_VALUETYPE_BOOL) {
		return DESSERT_ERR;
	}

	dessert_debug("old value: %d", b_true);
	b_false = appparam->bool;
	dessert_debug("new value: %d", b_true);

	return DESSERT_OK;
}

int int32_get_appparams_cb(dessert_agentx_appparams_t *appparam){

	dessert_debug("int32_get_cb called");

	appparam->value_type = DESSERT_APPPARAMS_VALUETYPE_INT32;
	strncpy(appparam->name,"int32_get",256);
	strncpy(appparam->desc,"-200", 256);
	appparam->int32 = int32;

	return DESSERT_OK;
}

int int32_set_appparams_cb(dessert_agentx_appparams_t *appparam){

	dessert_debug("int32_set_cb called");

	if (appparam->value_type != DESSERT_APPPARAMS_VALUETYPE_INT32) {
		return DESSERT_ERR;
	}

	dessert_debug("old value: %d", int32);
	int32 = appparam->int32;
	dessert_debug("new value: %d", int32);

	return DESSERT_OK;
}

int uint32_get_appparams_cb(dessert_agentx_appparams_t *appparam){

	dessert_debug("uint32_get_cb called");

	appparam->value_type = DESSERT_APPPARAMS_VALUETYPE_UINT32;
	strncpy(appparam->name,"uint32_get",256);
	strncpy(appparam->desc,"0", 256);
	appparam->uint32 = uint32;

	return DESSERT_OK;
}

int uint32_set_appparams_cb(dessert_agentx_appparams_t *appparam){

	dessert_debug("uint32_set_cb called");

	if (appparam->value_type != DESSERT_APPPARAMS_VALUETYPE_UINT32) {
		return DESSERT_ERR;
	}

	dessert_debug("old value: %u", uint32);
	uint32 = appparam->uint32;
	dessert_debug("new value: %u", uint32);

	return DESSERT_OK;
}

int octetstring_get_appparams_cb(dessert_agentx_appparams_t *appparam){

	dessert_debug("octetstring_get_appparams_cb called");

	appparam->value_type = DESSERT_APPPARAMS_VALUETYPE_OCTETSTRING;
	strncpy(appparam->name,"octetstring_get",256);
	strncpy(appparam->desc,"bytes", 256);

#define OCTETSTRING_LENGTH 16

	appparam->octetstring = malloc(sizeof(char) * OCTETSTRING_LENGTH);
	memset(appparam->octetstring, 'a', OCTETSTRING_LENGTH);
	appparam->octetstring_len = OCTETSTRING_LENGTH;

	return DESSERT_OK;
}

int octetstring_set_appparams_cb(dessert_agentx_appparams_t *appparam){

	dessert_debug("octetstring_set_appparams_cb called");

	if (appparam->value_type != DESSERT_APPPARAMS_VALUETYPE_OCTETSTRING) {
		return DESSERT_ERR;
	}

	dessert_debug("new value-LEN: %d", appparam->octetstring_len);

	return DESSERT_OK;

}


int main(int argc, char** argv) {

	_dessert_agentx_init_subagent();


	dessert_agentx_appparams_add(true_get_appparams_cb, true_set_appparams_cb);
	dessert_agentx_appparams_add(false_get_appparams_cb, false_set_appparams_cb);
	dessert_agentx_appparams_add(int32_get_appparams_cb, int32_set_appparams_cb);
	dessert_agentx_appparams_add(uint32_get_appparams_cb, uint32_set_appparams_cb);
	dessert_agentx_appparams_add(octetstring_get_appparams_cb, octetstring_set_appparams_cb);

	sleep(500);
	//while(1){};
	return 0;
}
