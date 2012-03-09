/******************************************************************************
 Copyright 2009, The DES-SERT Team, Freie Universitaet Berlin (FUB).
 All rights reserved.

 These sources were originally developed by Philipp Schmidt
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

#ifndef DESSERT_INTERNAL_H
#define DESSERT_INTERNAL_H

/* load needed libs - quite dirty */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#ifndef ANDROID
#include <sys/sysctl.h>
#endif
#include <net/route.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <libcli.h>
#include <uthash.h>
#include <utlist.h>

#include "dessert.h"

#ifdef HAVE_CONFIG_H
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include "config.h"
#endif
/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * C O R E
 *
 ******************************************************************************/

/** flag for _dessert_status - program is daemon */
#define _DESSERT_STATUS_DAEMON   0x1

/** Minimum size of packets; used to optimize token bucket
 *  \TODO What is the minimum packet size? This value is only a rough guess!
 */
#define _DESSERT_MIN_PACKET_SIZE 10

/** global status flag holder */
extern int         _dessert_status;

dessert_frameid_t _dessert_newframeid(void);

int _dessert_cli_cmd_shutdown(struct cli_def* cli, char* command, char* argv[], int argc);

//this should be in utlist.h in the future
#ifndef DL_LENGTH
#define DL_LENGTH(head,len,tmp) \
do { \
  len=0; \
  DL_FOREACH(head,tmp) \
    len++; \
} while (0)
#endif

/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * C L I - C O M M A N D   L I N E   I N T E R F A C E
 *
 ******************************************************************************/

int _dessert_cli_init(void);

/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * S I G N A L   H A N D L I N G
 *
 ******************************************************************************/

dessert_result _dessert_signals_init(void);

/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * L O G   F A C I L I T Y
 *
 ******************************************************************************/

/** maximum size of a log line */
#define DESSERT_LOGLINE_MAX 4096

dessert_per_result_t _dessert_flush_log(void* data, struct timeval* scheduled, struct timeval* interval);

int _dessert_cli_cmd_set_loglevel(struct cli_def* cli, char* command, char* argv[], int argc);
int _dessert_cli_cmd_show_loglevel(struct cli_def* cli, char* command, char* argv[], int argc);
int _dessert_cli_cmd_logging(struct cli_def* cli, char* command, char* argv[], int argc);
int _dessert_cli_logging_file(struct cli_def* cli, char* command, char* argv[], int argc);
int _dessert_cli_no_logging_file(struct cli_def* cli, char* command, char* argv[], int argc);
int _dessert_cli_logging_ringbuffer(struct cli_def* cli, char* command, char* argv[], int argc);
int _dessert_cli_no_logging_ringbuffer(struct cli_def* cli, char* command, char* argv[], int argc);
int _dessert_cli_log_interval(struct cli_def* cli, char* command, char* argv[], int argc);
int _dessert_cli_cmd_show_rules(struct cli_def* cli, char* command, char* argv[], int argc);
int _dessert_cli_cmd_rule_add(struct cli_def* cli, char* command, char* argv[], int argc);
int _dessert_cli_cmd_rule_rm(struct cli_def* cli, char* command, char* argv[], int argc);
int _dessert_cli_cmd_rule_default(struct cli_def* cli, char* command, char* argv[], int argc);
int _dessert_cli_cmd_tokenbucket(struct cli_def* cli, char* command, char* argv[], int argc);
int _dessert_cli_cmd_show_tokenbucket(struct cli_def* cli, char* command, char* argv[], int argc);
int _dessert_cli_cmd_tokenbucket_policy(struct cli_def* cli, char* command, char* argv[], int argc);
int _dessert_cli_cmd_tokenbucket_max(struct cli_def* cli, char* command, char* argv[], int argc);
int _dessert_cmd_print_tasks(struct cli_def* cli, char* command, char* argv[], int argc);
int _dessert_cli_cmd_showuptime(struct cli_def* cli, char* command, char* argv[], int argc);
int _dessert_closeLogFile();

/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * M E S H - I N T E R F A C E S
 *
 ******************************************************************************/

/** callback list entry for dessert mesh interface callbacks */
typedef struct dessert_meshrxcbe {
    /** pointer to callback to call */
    dessert_meshrxcb_t* c;
    /** priority - lowest first */
    int prio;
    /** next entry in list */
    struct dessert_meshrxcbe* next;
} dessert_meshrxcbe_t;

/** msg queue **/
typedef struct msg_queue {
    dessert_msg_t*    msg;
    uint64_t          len;
    struct msg_queue* next;
} dessert_msg_queue_t;

static char* _dessert_policy2str[] = {
    "drop",
    "queue_ordered",
    "queue_unordered"
};

dessert_result _dessert_meshif_gethwaddr(dessert_meshif_t* meshif);
int _dessert_meshrxcb_runall(dessert_msg_t* msg_in, uint32_t len, dessert_msg_proc_t* proc_in, dessert_meshif_t* meshif, dessert_frameid_t id);
dessert_cb_result dessert_mesh_filter(dessert_msg_t* msg, dessert_meshif_t* iface);
dessert_per_result_t _dessert_token_dispenser(void* data, struct timeval* scheduled, struct timeval* interval);

/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * S Y S - I N T E R F A C E S
 *
 ******************************************************************************/

int _dessert_getHWAddr(char* device, char* hwaddr);

/** callback list entry for tun/tap callbacks */
typedef struct dessert_sysrxcbe {
    /** pointer to callback to call */
    dessert_sysrxcb_t* c;
    /** priority - lowest first */
    int prio;
    /** next entry in list */
    struct dessert_sysrxcbe* next;
} dessert_sysrxcbe_t;

extern dessert_sysif_t* _dessert_sysif;

/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * M E S S A G E   H A N D L I N G
 *
 ******************************************************************************/

/** size of a dessert_msg struct */
#define DESSERT_MSGLEN sizeof(struct dessert_msg)

/** size of a dessert_msg_proc struct */
#define DESSERT_MSGPROCLEN sizeof(struct dessert_msg_proc)

// maximum frame size to assemble as dessert_msg
// #define DESSERT_MAXFRAMEBUFLEN DESSERT_MAXFRAMELEN

/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * P E R I O D I C   T A S K S
 *
 ******************************************************************************/

void _dessert_periodic_init(void);

typedef struct {
    void* ptr;
    char* name;
    UT_hash_handle hh;
} dessert_ptr2name_t;

dessert_ptr2name_t* _dessert_func2name;

/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * NET - S N M P // A G E N T _ X
 *
 ******************************************************************************/

/******************************************************************************
 * #defines
 ******************************************************************************/

#define AGENT "dessertAGENTX"

#define DESSERT_AGENTX_SYSIFTABLE_CACHE_TIMEOUT		10
#define DESSERT_AGENTX_MESHIFTABLE_CACHE_TIMEOUT	10
#define DESSERT_AGENTX_APPSTATSTABLE_CACHE_TIMEOUT	10
#define DESSERT_AGENTX_APPPARAMTABLE_CACHE_TIMEOUT	 1

/******************************************************************************
 * globals
 ******************************************************************************/

extern pthread_rwlock_t _dessert_appstats_cblist_lock;
extern dessert_agentx_appstats_cb_entry_t* _dessert_appstats_cblist;

extern pthread_rwlock_t _dessert_appparams_cblist_lock;
extern dessert_agentx_appparams_cb_entry_t* _dessert_appparams_cblist;

/******************************************************************************
 * functions
 ******************************************************************************/
int _dessert_agentx_appstats_harvest_callbacks(dessert_agentx_appstats_t** appstats_list);
void _dessert_agentx_appstats_free(dessert_agentx_appstats_t* appstat);
void _dessert_agentx_appstats_free_list(dessert_agentx_appstats_t** appstats_list);

int _dessert_agentx_appparams_harvest_callbacks(dessert_agentx_appparams_t** appparams_list);
void _dessert_agentx_appparams_free(dessert_agentx_appparams_t* appparam);
void _dessert_agentx_appparams_free_list(dessert_agentx_appparams_t** appparams_list);
dessert_agentx_appparamscb_set_t* _dessert_agentx_appparams_getsettercbforindex(int index);

void _dessert_agentx_init_subagent(void);
void dessert_agentx_stop_subagent(void);


#endif /* DESSERT_INTERNAL_H */
