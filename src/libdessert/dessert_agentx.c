/******************************************************************************
 Copyright 2009, The DES-SERT Team, Freie Universitaet Berlin (FUB).
 All rights reserved.

 These sources were originally developed by David Gutzmann
 at Freie Universitaet Berlin (http://www.fu-berlin.de/),
 Computer Systems and Telematics / Distributed, Embedded Systems (DES) group
 (http://cst.mi.fu-berlin.de/, http://www.des-testbed.net/)
 ------------------------------------------------------------------------------
 This program is free software: you can redistribute it and/or modify it under
 the terms of the GNU General Public License as published by the Free Software
 Foundation, either version 3 of the License, or (at your option) any later
 version.

 This program is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

 You should have received a copy of the GNU General Public License along with
 this program. If not, see http://www.gnu.org/licenses/ .
 ------------------------------------------------------------------------------
 For further information and questions please use the web site
 http://www.des-testbed.net/
 *******************************************************************************/

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "dessert_internal.h"
#include "dessert.h"

/* global data storage // P U B L I C */

/* global data storage // P R I V A T E */
pthread_rwlock_t _dessert_appstats_cblist_lock = PTHREAD_RWLOCK_INITIALIZER;
dessert_agentx_appstats_cb_entry_t* _dessert_appstats_cblist = NULL;

pthread_rwlock_t _dessert_appparams_cblist_lock = PTHREAD_RWLOCK_INITIALIZER;
dessert_agentx_appparams_cb_entry_t* _dessert_appparams_cblist = NULL;

/* local data storage*/
int keep_snmp_running = 1;

pthread_mutex_t _dessert_agentx_appparams_nextindex_mutex =
    PTHREAD_MUTEX_INITIALIZER;
uint8_t _dessert_agentx_appparams_nextindex = 0;

/* internal functions forward declarations*/
static void* _dessert_agentx_worker(void* arg);
static dessert_agentx_appstats_cb_entry_t* _dessert_agentx_appstats_add(
    dessert_agentx_appstatscb_get_t* c, uint8_t bulknobulk_flag);
static uint8_t _dessert_agentx_appparams_new_index(void);

/******************************************************************************
 *
 * EXTERNAL / PUBLIC
 *
 * NET - S N M P // A G E N T _ X
 *
 ******************************************************************************/

/******************************************************************************
 * appStats
 ******************************************************************************/

/** Creates and initializes a new dessert_agentx_appstats_t.
 *
 * @return the new dessert_agentx_appstats_t
 *
 * @warning A dessert_agentx_appstats_t allocated with this function must be
 * freed with dessert_agentx_appstats_destroy().
 *
 * @see dessert_agentx_appstats_destroy()
 *
 * @par Description:\n
 *
 */
dessert_agentx_appstats_t* dessert_agentx_appstats_new() {
    dessert_agentx_appstats_t* appstat;

    appstat = malloc(sizeof(dessert_agentx_appstats_t));

    appstat->prev = appstat;
    appstat->next = NULL;

    memset(appstat->name, 0, sizeof(appstat->name));
    memset(appstat->desc, 0, sizeof(appstat->desc));

    appstat->value_type = DESSERT_APPSTATS_VALUETYPE_BOOL;
    appstat->node_or_link = DESSERT_APPSTATS_NODEORLINK_NONE;
    memset(appstat->macaddress1, 0, ETHER_ADDR_LEN);
    memset(appstat->macaddress2, 0, ETHER_ADDR_LEN);

    appstat->boolean = DESSERT_APPSTATS_BOOL_FALSE;

    return appstat;
}

/** Frees a dessert_agentx_appstats_t.
 *
 * @param appstat the dessert_agentx_appstats_t to be freed
 *
 * @warning Only use this method to free a dessert_agentx_appstats_t which was allocated with dessert_agentx_appstats_new().
 *
 * @see dessert_agentx_appstats_new()
 *
 * @par Description:\n
 */
void dessert_agentx_appstats_destroy(dessert_agentx_appstats_t* appstat) {
    free(appstat);
}

/** Adds an application statistics callback.
 *
 * @param[in] *c the callback to add
 *
 * @retval pointer to the corresponding callback entry on success
 * @retval NULL otherwise
 *
 * @par Description:\n
 *
 */
dessert_agentx_appstats_cb_entry_t* dessert_agentx_appstats_add(
    dessert_agentx_appstatscb_get_t* c) {

    return (_dessert_agentx_appstats_add(c, DESSERT_APPSTATS_CB_NOBULK));
}

/** Adds an application statistics bulk callback.
 *
 * @param[in] *c the callback to add
 *
 * @retval pointer to the corresponding callback entry on success
 * @retval NULL otherwise
 *
 * @par Description:\n
 *
 */
dessert_agentx_appstats_cb_entry_t* dessert_agentx_appstats_add_bulk(
    dessert_agentx_appstatscb_get_t* c) {

    return (_dessert_agentx_appstats_add(c, DESSERT_APPSTATS_CB_BULK));
}

/** Deletes an application statistics callback.
 *
 * @param *e pointer to a callback entry
 *
 * @retval DESSERT_OK on success
 * @retval DESSERT_ERR otherwise
 *
 * @see dessert_agentx_appstats_add()
 * @see dessert_agentx_appstats_add_bulk()
 *
 * @par Description:\n
 */
int dessert_agentx_appstats_del(dessert_agentx_appstats_cb_entry_t* e) {

    if(e == NULL) {
        return DESSERT_ERR;
    }

    pthread_rwlock_wrlock(&_dessert_appstats_cblist_lock);
    DL_DELETE(_dessert_appstats_cblist, e);
    pthread_rwlock_unlock(&_dessert_appstats_cblist_lock);

    free(e);

    return DESSERT_OK;
}

/******************************************************************************
 * appParams
 ******************************************************************************/

/** Creates and initializes a new dessert_agentx_appparams_t.
 *
 * @return the new dessert_agentx_appparams_t
 *
 * @warning A dessert_agentx_appparams_t allocated with this function must be
 * freed with dessert_agentx_appparams_destroy().
 *
 * @see dessert_agentx_appparams_destroy()
 *
 * @par Description:\n
 *
 */
dessert_agentx_appparams_t* dessert_agentx_appparam_new() {
    dessert_agentx_appparams_t* appparam;

    appparam = malloc(sizeof(dessert_agentx_appparams_t));

    memset(appparam->name, 0, sizeof(appparam->name));
    memset(appparam->desc, 0, sizeof(appparam->desc));

    appparam->value_type = DESSERT_APPPARAMS_VALUETYPE_BOOL;

    appparam->boolean = DESSERT_APPSTATS_BOOL_FALSE;

    return appparam;
}

/** Frees a dessert_agentx_appparams_t.
 *
 * @param appparam the dessert_agentx_appparams_t to be freed
 *
 * @warning Only use this method to free a dessert_agentx_appparams_t which was
 * allocated with dessert_agentx_appparams_new().
 *
 * @see dessert_agentx_appparams_new()
 *
 * @par Description:\n
 */
void dessert_agentx_appparam_destroy(dessert_agentx_appparams_t* appparam) {
    free(appparam);
}

/** Adds an application parameter callback.
 *
 * @param[in] *get getter function
 * @param[in] *set setter function
 *
 * @retval pointer to the corresponding callback entry on success
 * @retval NULL otherwise
 *
 * @par Description:\n
 *
 */
dessert_agentx_appparams_cb_entry_t* dessert_agentx_appparams_add(
    dessert_agentx_appparamscb_get_t* get,
    dessert_agentx_appparamscb_set_t* set) {

    dessert_agentx_appparams_cb_entry_t* e;

    e = malloc(sizeof(dessert_agentx_appparams_cb_entry_t));

    if(e == NULL) {
        dessert_err("failed to allocate buffer for new dessert_agentx_appparams_entry_t");
        return (NULL);
    }

    e->index = _dessert_agentx_appparams_new_index();
    e->get = get;
    e->set = set;

    pthread_rwlock_wrlock(&_dessert_appparams_cblist_lock);
    DL_APPEND(_dessert_appparams_cblist, e);
    pthread_rwlock_unlock(&_dessert_appparams_cblist_lock);

    return (e);
}

/** Deletes an application parameter callback.
 *
 * @param *e pointer to a callback entry
 *
 * @retval DESSERT_OK on success
 * @retval DESSERT_ERR otherwise
 *
 * @see dessert_agentx_appparams_add()
 *
 * @par Description:\n
 */
int dessert_agentx_appparams_del(dessert_agentx_appparams_cb_entry_t* e) {

    if(e == NULL) {
        return DESSERT_ERR;
    }

    pthread_rwlock_wrlock(&_dessert_appparams_cblist_lock);
    DL_DELETE(_dessert_appparams_cblist, e);
    pthread_rwlock_unlock(&_dessert_appparams_cblist_lock);

    /* TODO: invalidate row*/

    return DESSERT_OK;
}

/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * NET - S N M P // A G E N T _ X
 *
 ******************************************************************************/

/******************************************************************************
 * appStats
 ******************************************************************************/

void _dessert_agentx_appstats_free(dessert_agentx_appstats_t* appstat) {
    if(appstat->value_type == DESSERT_APPSTATS_VALUETYPE_OCTETSTRING
       && appstat->octetstring != NULL) {
        free(appstat->octetstring);
    }

    dessert_agentx_appstats_destroy(appstat);
}

void _dessert_agentx_appstats_free_list(
    dessert_agentx_appstats_t** appstats_list) {
    dessert_agentx_appstats_t* appstat;
    dessert_agentx_appstats_t* tbf;

    for(appstat = (*appstats_list); appstat;) {
        tbf = appstat;
        appstat = appstat->next;
        _dessert_agentx_appstats_free(tbf);
    }
}

int _dessert_agentx_appstats_harvest_callbacks(
    dessert_agentx_appstats_t** appstats_list) {
    dessert_agentx_appstats_cb_entry_t* cbe;
    dessert_agentx_appstats_t* new_appstat;
    dessert_agentx_appstats_t* appstat;
    int res = 0;

    pthread_rwlock_rdlock(&_dessert_appstats_cblist_lock);
    DL_FOREACH(_dessert_appstats_cblist, cbe) {

        new_appstat = dessert_agentx_appstats_new();

        if(new_appstat == NULL) {
            dessert_err("failed to allocate buffer for new dessert_agentx_appstats_entry_t");

            dessert_err("freeing appstats harvested so far...");
            _dessert_agentx_appstats_free_list(appstats_list);

            return DESSERT_ERR;
        }

        res = cbe->c(new_appstat);

        if(res == DESSERT_OK) {
            if(cbe->isbulk_flag & DESSERT_APPSTATS_CB_NOBULK) {

                DL_APPEND(*appstats_list, new_appstat);
            }
            else {   // DESSERT_APPSTATS_BULK
                dessert_agentx_appstats_t temp;
                DL_FOREACH(new_appstat, appstat) {
                    temp.next = appstat->next;
                    temp.prev = appstat->prev;
                    DL_APPEND(*appstats_list, appstat);
                    appstat = &temp;
                }
            }
        }
        else {
            dessert_err("freeing list of appstats received from callback...");
            _dessert_agentx_appstats_free_list(&new_appstat);
            pthread_rwlock_unlock(&_dessert_appstats_cblist_lock);
            dessert_agentx_appstats_del(cbe);
            pthread_rwlock_rdlock(&_dessert_appstats_cblist_lock);
        }

    }
    pthread_rwlock_unlock(&_dessert_appstats_cblist_lock);

    return DESSERT_OK;
}

/******************************************************************************
 * appParams
 ******************************************************************************/

void _dessert_agentx_appparams_free(dessert_agentx_appparams_t* appparam) {
    if(appparam->value_type == DESSERT_APPPARAMS_VALUETYPE_OCTETSTRING
       && appparam->octetstring != NULL) {
        free(appparam->octetstring);
    }

    dessert_agentx_appparam_destroy(appparam);
}

void _dessert_agentx_appparams_free_list(
    dessert_agentx_appparams_t** appparams_list) {
    dessert_agentx_appparams_t* appparam;
    dessert_agentx_appparams_t* tbf;

    for(appparam = (*appparams_list); appparam;) {
        tbf = appparam;
        appparam = appparam->next;
        _dessert_agentx_appparams_free(tbf);
    }
}

int _dessert_agentx_appparams_harvest_callbacks(
    dessert_agentx_appparams_t** appparams_list) {
    dessert_agentx_appparams_cb_entry_t* cbe;
    dessert_agentx_appparams_t* new_appparam;
    int res = 0;

    pthread_rwlock_rdlock(&_dessert_appparams_cblist_lock);
    DL_FOREACH(_dessert_appparams_cblist, cbe) {
        new_appparam = dessert_agentx_appparam_new();

        if(new_appparam == NULL) {
            dessert_err("failed to allocate buffer for new dessert_agentx_appparams_entry_t");

            dessert_err("freeing appstats harvested so far...");
            _dessert_agentx_appparams_free_list(appparams_list);

            return DESSERT_ERR;
        }

        res = cbe->get(new_appparam);
        new_appparam->index = cbe->index;

        if(res == DESSERT_OK) {
            DL_APPEND(*appparams_list, new_appparam);
        }
        else {
            _dessert_agentx_appparams_free(new_appparam);
            pthread_rwlock_unlock(&_dessert_appparams_cblist_lock);
            dessert_agentx_appparams_del(cbe);
            pthread_rwlock_rdlock(&_dessert_appparams_cblist_lock);
        }

    } // DL_FOREACH

    pthread_rwlock_unlock(&_dessert_appparams_cblist_lock);

    return DESSERT_OK;
}

dessert_agentx_appparamscb_set_t* _dessert_agentx_appparams_getsettercbforindex(
    int index) {
    dessert_agentx_appparams_cb_entry_t* cbe;

    pthread_rwlock_rdlock(&_dessert_appparams_cblist_lock);
    DL_FOREACH(_dessert_appparams_cblist, cbe)

    if(cbe->index == index) {
        break;
    }

    pthread_rwlock_unlock(&_dessert_appparams_cblist_lock);

    if(cbe->index == index)

    {
        return cbe->set;
    }
    else {

        return NULL;
    }
}

/******************************************************************************
 * other
 ******************************************************************************/

/** setup and initialize net-snmp subagent (via agent x)*/
void _dessert_agentx_init_subagent() {
    /**************************************************************************
     * setup snmp handling....
     *************************************************************************/

    pthread_t snmp_worker;

    snmp_enable_calllog();
    //debug_register_tokens("trace");
    //debug_register_tokens("tdomain");
    debug_register_tokens(AGENT);
    //debug_register_tokens("snmp_agent");
    //debug_register_tokens("helper:table:req");

    debug_register_tokens("dessertAppParamsTable");
    debug_register_tokens("verbose:dessertAppParamsTable");
    debug_register_tokens("internal:dessertAppParamsTable");

    debug_register_tokens("dessertAppParamsTable");
    debug_register_tokens("verbose:dessertAppStatsTable");
    debug_register_tokens("internal:dessertAppStatsTable");

    snmp_set_do_debugging(1);

    netsnmp_log_handler* logh;

    logh = netsnmp_register_loghandler(NETSNMP_LOGHANDLER_FILE, LOG_DEBUG);

    if(logh) {
        logh->pri_max = LOG_EMERG;
        logh->token = strdup("/tmp/dessertAGENTX.log");
    }

    netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);

    //SOCK_STARTUP;
    init_agent(AGENT);

    /*
     * initialize the scalars
     */
    init_dessertObjects();

    /*
     * init dessert{Mesh, Sys}ifTable mib code
     */
    init_dessertMeshifTable();
    init_dessertSysifTable();

    /*
     * init dessertApp{Stats, Param}Table mib code
     */
    init_dessertAppParamsTable();
    init_dessertAppStatsTable();

    init_snmp(AGENT);
    DEBUGMSGTL((AGENT, "Initialized agent and snmp.\n"));

    pthread_create(&snmp_worker, NULL, _dessert_agentx_worker, NULL);
}

void dessert_agentx_stop_subagent() {
    keep_snmp_running = 0;
}

/******************************************************************************
 *
 * LOCAL
 *
 * NET - S N M P // A G E N T _ X
 *
 ******************************************************************************/

static dessert_agentx_appstats_cb_entry_t* _dessert_agentx_appstats_add(
    dessert_agentx_appstatscb_get_t* c, uint8_t bulknobulk_flag) {

    dessert_agentx_appstats_cb_entry_t* e;

    e = malloc(sizeof(dessert_agentx_appstats_cb_entry_t));

    if(e == NULL) {
        dessert_err("failed to allocate buffer for new dessert_agentx_appstats_entry_t");
        return (NULL);
    }

    e->isbulk_flag |= bulknobulk_flag;
    e->c = c;

    pthread_rwlock_wrlock(&_dessert_appstats_cblist_lock);
    DL_APPEND(_dessert_appstats_cblist, e);
    pthread_rwlock_unlock(&_dessert_appstats_cblist_lock);

    return (e);
}

static uint8_t _dessert_agentx_appparams_new_index(void) {
    uint8_t index;

    pthread_mutex_lock(&_dessert_agentx_appparams_nextindex_mutex);
    index = _dessert_agentx_appparams_nextindex++;
    pthread_mutex_unlock(&_dessert_agentx_appparams_nextindex_mutex);

    return index;
}

static void* _dessert_agentx_worker(void* arg) {
    DEBUGMSGTL((AGENT, "snmp_worker running...\n"));
    dessert_info("snmp_worker running...");

    while(keep_snmp_running) {
        /*
         * if you use select(), see snmp_select_info() in snmp_api(3)
         */
        /*
         * --- OR ---
         */
        agent_check_and_process(1); /* 0 == don't block */
    }

    dessert_info("snmp_worker exiting...");

    return (NULL);
}
