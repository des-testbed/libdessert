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

#include "dessert_internal.h"
#include "dessert.h"

#define print_default \
    _default_rule == DESSERT_MSG_KEEP ? _whitelist_str : _blacklist_str

pthread_rwlock_t dessert_filterlock = PTHREAD_RWLOCK_INITIALIZER;

typedef struct mac_entry {
    char mac[6];
    double p;
    dessert_meshif_t* iface;
    struct mac_entry* prev;
    struct mac_entry* next;
} mac_entry_t;

static mac_entry_t* _dessert_whitelist = NULL;
static mac_entry_t* _dessert_blacklist = NULL;
static const char* _whitelist_str = "accept";
static const char* _blacklist_str = "drop";
static dessert_cb_result _default_rule = DESSERT_MSG_KEEP;

static mac_entry_t* find_in_list(char* mac, dessert_meshif_t* iface, mac_entry_t* list) {
    mac_entry_t* elt = NULL;
    DL_FOREACH(list, elt) {
        if(elt->iface == iface && memcmp(elt->mac, mac, 6) == 0) {
            dessert_debug("matching rule: " MAC ", %6s", elt->mac, elt->iface->if_name);
            if(random() < (((long double) elt->p)*((long double) RAND_MAX))) {
                return elt;
            }
            return NULL;
        }
    }
    return NULL;
}

/**
 * Adds a rule to a list
 *
 * @param mac   6 byte MAC address of the src
 * @param iface rx interface; may be NULL to select all interfaces
 * @param list  add rule to this list
 * @param cli   current CLI for printing messages
 *
 * @return true if rule added, else false
 */
bool dessert_filter_rule_add(char* mac, dessert_meshif_t* iface, double p, enum dessert_filter list, struct cli_def* cli) {
    mac_entry_t** cur = NULL;
    mac_entry_t** other = NULL;

    switch(list) {
        case DESSERT_WHITELIST:
            cur = &_dessert_whitelist;
            other = &_dessert_blacklist;
            break;
        case DESSERT_BLACKLIST:
            cur = &_dessert_blacklist;
            other = &_dessert_whitelist;
            break;
        default:
            dessert_warning("unknown filter: %d", list);
            return false;
    }

    pthread_rwlock_wrlock(&dessert_filterlock);

    if(find_in_list(mac, iface, *cur)) {
        print_log(LOG_WARNING, cli, MAC " is already in the list", EXPLODE_ARRAY6(mac));
        goto fail;
    }

//     if(find_in_list(mac, iface, *other)) {
//         print_log(LOG_WARNING, cli, MAC " is already in the other list. Please remove it first", EXPLODE_ARRAY6(mac));
//         goto fail;
//     }

    mac_entry_t* new_entry = malloc(sizeof(mac_entry_t));

    if(new_entry == NULL) {
        print_log(LOG_CRIT, cli, "could not allocate memory");
        goto fail;
    }

    memcpy(new_entry->mac, mac, sizeof(new_entry->mac));
    new_entry->iface = iface;
    new_entry->p = p;

    DL_APPEND(*cur, new_entry);

    pthread_rwlock_unlock(&dessert_filterlock);
    return true;

fail:
    pthread_rwlock_unlock(&dessert_filterlock);
    return false;
}

/**
 * Removes a rule from a list
 *
 * @param mac   6 byte MAC address of the src
 * @param iface rx interface; may be NULL to select all interfaces
 * @param list  remove rule from this list
 * @param cli   current CLI for printing messages
 *
 * @return true if rule found and removed, else false
 */
bool dessert_filter_rule_rm(char* mac, dessert_meshif_t* iface, enum dessert_filter list, struct cli_def* cli) {
    pthread_rwlock_wrlock(&dessert_filterlock);
    mac_entry_t** cur = NULL;

    switch(list) {
        case DESSERT_WHITELIST:
            cur = &_dessert_whitelist;
            break;
        case DESSERT_BLACKLIST:
            cur = &_dessert_blacklist;
            break;
        default:
            dessert_warning("unknown filter: %d", list);
            return false;
    }

    pthread_rwlock_wrlock(&dessert_filterlock);
    mac_entry_t* del = find_in_list(mac, iface, *cur);

    if(del == NULL) {
        print_log(LOG_CRIT, cli, MAC " not found in list", EXPLODE_ARRAY6(mac));
        goto fail;
    }

    DL_DELETE(*cur, del);
    free(del);

    pthread_rwlock_unlock(&dessert_filterlock);
    return true;

fail:
    pthread_rwlock_unlock(&dessert_filterlock);
    return false;
}

/**
 * CLI command to show all  filter rules
 */
int _dessert_cli_cmd_show_rules(struct cli_def* cli, char* command, char* argv[], int argc) {
    pthread_rwlock_rdlock(&dessert_filterlock);
    mac_entry_t* elt = NULL;
    cli_print(cli, "\n[%s]", _whitelist_str);
    cli_print(cli, "%4s\t%17s\t%10s\t%5s", "#", "MAC", "meshif", "p");
    uint16_t i = 0;
    DL_FOREACH(_dessert_whitelist, elt) {
        cli_print(cli, "%4d\t"MAC"\t%10s\t%.3f", i, EXPLODE_ARRAY6(elt->mac), elt->iface->if_name, elt->p);
        i++;
    }
    cli_print(cli, "\n[%s]", _blacklist_str);
    cli_print(cli, "%4s\t%17s\t%10s\t%5s", "#", "MAC", "meshif", "p");
    i = 0;
    DL_FOREACH(_dessert_blacklist, elt) {
        cli_print(cli, "%4d\t"MAC"\t%10s\t%.3f", i, EXPLODE_ARRAY6(elt->mac), elt->iface->if_name, elt->p);
        i++;
    }

    cli_print(cli, "\n[default]: %s", print_default);
    pthread_rwlock_unlock(&dessert_filterlock);
    return CLI_OK;
}

enum { PARAM_LIST = 0, PARAM_MAC, PARAM_IFNAME, PARAM_P, PARAM_NUM };

/**
 * CLI command to set default rule
 */
int _dessert_cli_cmd_rule_default(struct cli_def* cli, char* command, char* argv[], int argc) {
    if(argc != 1) {
        cli_print(cli, "usage: rule default [accept|drop]");
        goto fail;
    }

    pthread_rwlock_rdlock(&dessert_filterlock);
    if(strncmp(_whitelist_str, argv[0], sizeof(_whitelist_str)) == 0) {
        _default_rule = DESSERT_MSG_KEEP;
    }
    else {
        if(strncmp(_blacklist_str, argv[0], sizeof(_blacklist_str)) == 0) {
            _default_rule = DESSERT_MSG_DROP;
        }
        else {
            print_log(LOG_ERR, cli, "could not parse default rule: %s", argv[0]);
            goto fail;
        }
    }

    pthread_rwlock_unlock(&dessert_filterlock);
    return CLI_OK;

fail:
    pthread_rwlock_unlock(&dessert_filterlock);
    cli_print(cli, "failed to set default rule");
    return CLI_ERROR;
}

/**
 * CLI command to add a filter rule
 */
int _dessert_cli_cmd_rule_add(struct cli_def* cli, char* command, char* argv[], int argc) {
    if(argc != PARAM_NUM) {
        cli_print(cli, "usage: rule add accept|drop] [MAC] [MESHIF] [PROBABILITY]");
        goto fail;
    }

    char mac[6] = "      ";
    double p = 1.0;
    dessert_meshif_t* iface = NULL;
    enum dessert_filter list = -1;

    if(strncmp(_whitelist_str, argv[PARAM_LIST], sizeof(_whitelist_str)) == 0) {
        list = DESSERT_WHITELIST;
    }
    else {
        if(strncmp(_blacklist_str, argv[PARAM_LIST], sizeof(_blacklist_str)) == 0) {
            list = DESSERT_BLACKLIST;
        }
        else {
            print_log(LOG_ERR, cli, "could not parse list: %s", argv[0]);
            goto fail;
        }
    }

    if(sscanf(argv[PARAM_MAC], MAC, &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        print_log(LOG_ERR, cli, "could not parse MAC: %17s", argv[PARAM_MAC]);
        goto fail;
    }

    iface = dessert_ifname2meshif(argv[PARAM_IFNAME]);
    if(iface == NULL) {
        if(argv[PARAM_IFNAME][0] == '*') {
           ;
        }
        else {
            print_log(LOG_ERR, cli, "could not parse iterface name: %17s", argv[PARAM_IFNAME]);
            goto fail;
        }
    }

    if(sscanf(argv[PARAM_P], "%lf", &p) != 1) {
        print_log(LOG_ERR, cli, "could not parse probability: %17s", argv[PARAM_P]);
        goto fail;
    }
    if(p <= 0.0 || p > 1.0) {
        print_log(LOG_ERR, cli, "invalid probability: %lf", p);
        goto fail;
    }

    // single interface
    if(iface) {
        if(dessert_filter_rule_add(mac, iface, p, list, cli)) {
            cli_print(cli, "added " MAC " to %s", EXPLODE_ARRAY6(mac), list==DESSERT_WHITELIST ? _whitelist_str : _blacklist_str);
        }
        else {
            goto fail;
        }
    }
    else {
        MESHIFLIST_ITERATOR_START(iface)
        if(dessert_filter_rule_add(mac, iface, p, list, cli)) {
            cli_print(cli, "added " MAC " to %s", EXPLODE_ARRAY6(mac), list==DESSERT_WHITELIST ? _whitelist_str : _blacklist_str);
        }
        MESHIFLIST_ITERATOR_STOP;
    }
    return CLI_OK;

fail:
    cli_print(cli, "failed to add");
    return CLI_ERROR;
}

/**
 * CLI command to remove a filter rule
 */
int _dessert_cli_cmd_rule_rm(struct cli_def* cli, char* command, char* argv[], int argc) {
    if(argc != PARAM_NUM-1) {
        cli_print(cli, "usage: rule rm [accept|drop] [MAC] [MESHIF]");
        goto fail;
    }

    char mac[6] = "      ";
    dessert_meshif_t* iface = NULL;
    enum dessert_filter list = -1;

    if(strncmp(_whitelist_str, argv[PARAM_LIST], sizeof(_whitelist_str)) == 0) {
        list = DESSERT_WHITELIST;
    }
    else {
        if(strncmp(_blacklist_str, argv[PARAM_LIST], sizeof(_blacklist_str)) == 0) {
            list = DESSERT_BLACKLIST;
        }
        else {
            print_log(LOG_ERR, cli, "could not parse list: %s", argv[PARAM_LIST]);
            goto fail;
        }
    }

    if(sscanf(argv[PARAM_MAC], MAC, &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        print_log(LOG_ERR, cli, "could not parse MAC: %17s", argv[PARAM_MAC]);
        goto fail;
    }

    iface = dessert_ifname2meshif(argv[PARAM_IFNAME]);
    if(iface == NULL) {
        if(argv[PARAM_IFNAME][0] == '*') {
            ;
        }
        else {
            print_log(LOG_ERR, cli, "could not parse iterface name: %17s", argv[PARAM_IFNAME]);
            goto fail;
        }
    }

    // single interface
    if(iface) {
        if(dessert_filter_rule_rm(mac, iface, list, cli)) {
            cli_print(cli, "removed " MAC " from %s", EXPLODE_ARRAY6(mac), list==DESSERT_WHITELIST ? _whitelist_str : _blacklist_str);
        }
        else {
            goto fail;
        }
    }
    else {
        MESHIFLIST_ITERATOR_START(iface)
        if(dessert_filter_rule_rm(mac, iface, list, cli)) {
            cli_print(cli, "removed " MAC " from %s", EXPLODE_ARRAY6(mac), list==DESSERT_WHITELIST ? _whitelist_str : _blacklist_str);
        }
        MESHIFLIST_ITERATOR_STOP;
    }
    return CLI_OK;

fail:
    cli_print(cli, "failed to remove");
    return CLI_ERROR;
}

/**
 * mesh iface callback of the MAC filter
 *
 * Filter frames based on the layer 2 source address and the mesh interface where the frame was received.
 * The rules are checked in the following order:
 * 1) whitelist (accept)
 * 2) blacklist (drop)
 * 3) default rule
 *
 * Please note that the filter is fairly simple and that the first matching rule is used.
 * Therefore a less specific rule can overwrite a more specific one.
 */
dessert_cb_result dessert_mesh_filter(dessert_msg_t* msg, dessert_meshif_t* iface) {
    char* mac = (char *) msg->l2h.ether_shost;

    pthread_rwlock_rdlock(&dessert_filterlock);

    if(find_in_list(mac, iface, _dessert_whitelist)) {
        dessert_trace("accepting frame from " MAC, EXPLODE_ARRAY6(mac));
        pthread_rwlock_unlock(&dessert_filterlock);
        return DESSERT_MSG_KEEP;
    }

    if(find_in_list(mac, iface, _dessert_blacklist)) {
        dessert_trace("dropped frame from " MAC, EXPLODE_ARRAY6(mac));
        pthread_rwlock_unlock(&dessert_filterlock);
        return DESSERT_MSG_DROP;
    }

    dessert_trace("using default (%s) for frame from " MAC, print_default, EXPLODE_ARRAY6(mac));
    pthread_rwlock_unlock(&dessert_filterlock);
    return _default_rule;
}
