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

/* global data storage // P U B L I C */
/* nothing here - yet */

/* global data storage // P R I V A T E */
/* nothing here - yet */

/* local data storage*/
dessert_meshif_t* _dessert_meshiflist = NULL;

pthread_mutex_t _dessert_meshiflist_mutex = PTHREAD_MUTEX_INITIALIZER;
int _dessert_meshiflist_len = 0;
int _dessert_meshiflist_perm_count = 0;
int _dessert_meshiflist_current_perm = 0;
dessert_meshif_t** *_dessert_meshiflist_perms = NULL;

dessert_meshrxcbe_t* _dessert_meshrxcblist;
int _dessert_meshrxcblistver = 0;

/* internal functions forward declarations*/
static void _dessert_packet_process(uint8_t* args, const struct pcap_pkthdr* header, const uint8_t* packet);
static void* _dessert_meshif_add_thread(void* arg);
static inline int _dessert_meshsend_if2(dessert_msg_t* msg, dessert_meshif_t* iface, dessert_msg_queue_t* qe);
static void _dessert_meshif_cleanup(dessert_meshif_t* meshif);
static void _dessert_meshiflist_update_permutations(void);
static inline void list2array(dessert_meshif_t* l, dessert_meshif_t** a, int len);
static inline int fact(int i);
static inline void permutation(int k, int len, dessert_meshif_t** a);

/******************************************************************************
 *
 * EXTERNAL / PUBLIC
 *
 * M E S H - I N T E R F A C E S
 *
 ******************************************************************************/

/******************************************************************************
 * sending messages
 ******************************************************************************/

/** Sends a \b dessert \b message via the specified interface or all interfaces.
 *
 * The original message buffer will not be altered, and the ethernet src address
 * will be set correctly
 *
 * @param[in] *msgin message to send
 * @param[in] *iface interface to send from - use NULL for all interfaces
 *
 * @retval DESSERT_OK on success
 * @retval EINVAL     if message is broken
 * @retval EIO        if message was not sent successfully
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshsend(const dessert_msg_t* msgin, dessert_meshif_t* iface) {
    dessert_msg_t* msg;
    int res;

    /* check message - we only send valid messages! */
    if(dessert_msg_check(msgin, msgin->hlen + msgin->plen)) {
        dessert_warn("will not send invalid message - aborting");
        return EINVAL;
    }

    /* clone message */
    dessert_msg_clone(&msg, msgin, true);
    res = dessert_meshsend_fast(msg, iface);
    dessert_msg_destroy(msg);

    return res;
}

/** Sends a \b dessert \b message via all interfaces, except via the specified interface.
 *
 * The original message buffer will not be altered, and the ethernet src address will be set correctly.
 *
 * @param[in] *msgin message to send
 * @param[in] *iface interface NOT to send from - use NULL for all interfaces

 * @retval DESSERT_OK on success
 * @retval EINVAL     if message is broken
 * @retval EIO        if message was not sent successfully
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshsend_allbutone(const dessert_msg_t* msgin, dessert_meshif_t* iface) {
    dessert_msg_t* msg;
    int res;

    /* check message - we only send valid messages! */
    if(dessert_msg_check(msgin, msgin->hlen + msgin->plen)) {
        dessert_warn("will not send invalid message - aborting");
        return EINVAL;
    }

    /* clone message */
    dessert_msg_clone(&msg, msgin, true);
    res = dessert_meshsend_fast_allbutone(msg, iface);
    dessert_msg_destroy(msg);

    return res;
}

/** Sends a \b dessert \b message via the interface which is identified by the given hardware address.
 *
 * The original message buffer will not be altered, and the ethernet src address
 * will be set correctly.
 *
 * @param[in] *msgin message to send
 * @param[in] *hwaddr hardware address of the interface to send from
 *
 * @retval DESSERT_OK on success
 * @retval EINVAL     if message is broken
 * @retval EIO        if message was not sent successfully
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshsend_hwaddr(const dessert_msg_t* msgin, const uint8_t hwaddr[ETHER_ADDR_LEN]) {
    dessert_msg_t* msg;
    int res;

    /* check message - we only send valid messages! */
    if(dessert_msg_check(msgin, msgin->hlen + msgin->plen)) {
        dessert_warn("will not send invalid message - aborting");
        return EINVAL;
    }

    /* clone message */
    dessert_msg_clone(&msg, msgin, true);
    res = dessert_meshsend_fast_hwaddr(msg, hwaddr);
    dessert_msg_destroy(msg);

    return res;
}

/** Sends a \b dessert \b message via all interfaces in a randomized fashion.
 *
 * The original message buffer will not be altered, and the ethernet src address
 * will be set correctly.
 *
 * @param[in] *msgin message to send
 *
 * @retval DESSERT_OK on success
 * @retval EINVAL     if message is broken
 * @retval EIO        if message was not sent successfully
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshsend_randomized(const dessert_msg_t* msgin) {
    dessert_msg_t* msg;
    int res;

    /* check message - we only send valid messages! */
    if(dessert_msg_check(msgin, msgin->hlen + msgin->plen)) {
        dessert_warn("will not send invalid message - aborting");
        return EINVAL;
    }

    /* clone message */
    dessert_msg_clone(&msg, msgin, true);
    res = dessert_meshsend_fast_randomized(msg);
    dessert_msg_destroy(msg);

    return res;
}

/** Sends a \b dessert \b message fast via the specified interface or all interfaces.
 *
 * This method is faster than dessert_meshsend(), but does not check the message
 * and may alter the message buffer.
 *
 * @param[in] *msg message to send
 * @param[in] *iface interface to send from
 *
 * @retval DESSERT_OK on success
 * @retval EINVAL     if message is broken
 * @retval EIO        if message was not sent successfully
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshsend_fast(dessert_msg_t* msg, dessert_meshif_t* iface) {
    int res = 0;

    /* we have no iface - send on all! */
    if(iface == NULL) {
        pthread_rwlock_rdlock(&dessert_cfglock);
        DL_FOREACH(_dessert_meshiflist, iface) {
            /* set shost */
            memcpy(msg->l2h.ether_shost, iface->hwaddr, ETHER_ADDR_LEN);
            /* send */
            res = _dessert_meshsend_if2(msg, iface, NULL);

            if(res) {
                break;
            }
        }
        pthread_rwlock_unlock(&dessert_cfglock);
    }
    else {
        /* set shost */
        memcpy(msg->l2h.ether_shost, iface->hwaddr, ETHER_ADDR_LEN);
        /* send */
        res = _dessert_meshsend_if2(msg, iface, NULL);
    }

    return (res);
}

/** Sends a \b dessert \b message fast via all interfaces, except  the specified interface.
 *
 * This method is faster than dessert_meshsend_allbutone(), but does not check the message
 * and may alter the message buffer.
 *
 * @param[in] *msg message to send
 * @param[in] *iface interface to NOT send from - use NULL for all interfaces
 *
 * @retval DESSERT_OK on success
 * @retval EINVAL     if message is broken
 * @retval EIO        if message was not sent successfully
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshsend_fast_allbutone(dessert_msg_t* msg, dessert_meshif_t* iface) {
    dessert_meshif_t* curr_iface;
    int res = 0;

    /* we have no iface - send on all! */
    if(iface == NULL) {
        pthread_rwlock_rdlock(&dessert_cfglock);
        DL_FOREACH(_dessert_meshiflist, curr_iface) {
            /* set shost */
            memcpy(msg->l2h.ether_shost, iface->hwaddr, ETHER_ADDR_LEN);
            /* send */
            res = _dessert_meshsend_if2(msg, iface, NULL);

            if(res) {
                break;
            }
        }
        pthread_rwlock_unlock(&dessert_cfglock);
    }
    else {
        pthread_rwlock_rdlock(&dessert_cfglock);
        DL_FOREACH(_dessert_meshiflist, curr_iface) {

            /* skip if it is the 'allbutone' interface */
            if(curr_iface == iface) {
                curr_iface = curr_iface->next;
            }

            /* set shost */
            memcpy(msg->l2h.ether_shost, iface->hwaddr, ETHER_ADDR_LEN);
            /* send */
            res = _dessert_meshsend_if2(msg, iface, NULL);

            if(res) {
                break;
            }
        }
        pthread_rwlock_unlock(&dessert_cfglock);
    }

    return (res);
}

/** Sends a \b dessert \b message fast via the interface specified by the given
 *  hardware address.
 *
 * This method is faster than dessert_meshsend_hwaddr(), but does not check the message
 * and may alter the message buffer.
 *
 * @param[in] *msg message to send
 * @param[in] *hwaddr hardware address of the interface to send from
 *
 * @retval DESSERT_OK on success
 * @retval EINVAL     if message is broken
 * @retval EIO        if message was not sent successfully
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshsend_fast_hwaddr(dessert_msg_t* msg, const uint8_t hwaddr[ETHER_ADDR_LEN]) {
    int res;
    dessert_meshif_t* meshif;

    pthread_rwlock_rdlock(&dessert_cfglock);
    DL_FOREACH(_dessert_meshiflist, meshif) {
        if(memcmp(meshif->hwaddr, hwaddr, ETHER_ADDR_LEN) == 0) {
            break;
        }
    }
    pthread_rwlock_unlock(&dessert_cfglock);

    if(likely(meshif != NULL)) {
        /* set shost */
        memcpy(msg->l2h.ether_shost, meshif->hwaddr, ETHER_ADDR_LEN);
        /* send */
        res = _dessert_meshsend_if2(msg, meshif, NULL);
    }
    else {
        dessert_err("No such interface - aborting");
        return ENODEV;
    }

    return (res);
}

/** Sends a \b dessert \b message fast via all interfaces in a randomized fashion.
 *
 * This method is faster than dessert_meshsend_randomized(), but does not check
 * the message and may alter the message buffer.
 *
 * @param[in] *msgin message to send
 *
 * @retval DESSERT_OK on success
 * @retval EINVAL     if message is broken
 * @retval EIO        if message was not sent successfully
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshsend_fast_randomized(dessert_msg_t* msgin) {
    int i;
    int res = 0;

    pthread_mutex_lock(&_dessert_meshiflist_mutex);

    for(i = 0; i < _dessert_meshiflist_len; i++) {
        res = dessert_meshsend_fast(msgin, _dessert_meshiflist_perms[_dessert_meshiflist_current_perm][i]);

        if(res) {
            break;
        }
    }

    if(_dessert_meshiflist_perm_count > 0) {
        _dessert_meshiflist_current_perm = (_dessert_meshiflist_current_perm + 1) % _dessert_meshiflist_perm_count;
    }

    pthread_mutex_unlock(&_dessert_meshiflist_mutex);

    return res;
}

/** Sends a @b dessert @b message @a msg via the specified interface @a iface or
 *  all interfaces.
 *
 * This method is faster than dessert_meshsend(), but does not check the message
 * and may alter the message buffer. In contrast to dessert_meshsend_fast() it
 * does not write the ether_shost address.
 *
 * @param[in] *msg message to send
 * @param[in] *iface interface to send from
 *
 * @retval DESSERT_OK on success
 * @retval EINVAL     if message is broken
 * @retval EIO        if message was not sent successfully
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshsend_raw(dessert_msg_t* msg, dessert_meshif_t* iface) {
    int res = 0;

    if(iface == NULL) {
        pthread_rwlock_rdlock(&dessert_cfglock);
        DL_FOREACH(_dessert_meshiflist, iface) {
            res = _dessert_meshsend_if2(msg, iface, NULL);

            if(res) {
                break;
            }
        }
        pthread_rwlock_unlock(&dessert_cfglock);
    }
    else {
        res = _dessert_meshsend_if2(msg, iface, NULL);
    }

    return (res);
}

/******************************************************************************
 * meshrx-callback handling
 ******************************************************************************/

/** Removes all occurrences of the given callback function @a c from the meshrx
 *  pipeline.
 *
 * @param[in] c callback function pointer
 *
 * @retval DESSERT_OK  on success
 * @retval DESSERT_ERR otherwise
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshrxcb_del(dessert_meshrxcb_t* c) {
    int count = 0;
    dessert_meshrxcbe_t* i, *last;

    pthread_rwlock_wrlock(&dessert_cfglock);

    if(_dessert_meshrxcblist == NULL) {
        count++;
        goto dessert_meshrxcb_del_out;
    }

    while(_dessert_meshrxcblist->c == c) {
        count++;
        i = _dessert_meshrxcblist;
        _dessert_meshrxcblist = _dessert_meshrxcblist->next;
        free(i);

        if(_dessert_meshrxcblist == NULL) {
            goto dessert_meshrxcb_del_out;
        }
    }

    for(i = _dessert_meshrxcblist; i->next != NULL; i = i->next) {
        if(i->c == c) {
            count++;
            last->next = i->next;
            free(i);
            i = last;
        }

        last = i;
    }

dessert_meshrxcb_del_out:
    _dessert_meshrxcblistver++;
    pthread_rwlock_unlock(&dessert_cfglock);
    return ((count > 0) ? DESSERT_OK : DESSERT_ERR);
}

/** Adds a callback function to the meshrx pipeline.
 *
 * The callback going to get called if a packet is received via a dessert interface.
 *
 * @param[in] c    callback function
 * @param[in] prio priority of the function - lower first!
 *
 * @retval DESSERT_OK on success
 * @retval -errno     on error
 *
 * %DESCRIPTION:
 *
 **/
int dessert_meshrxcb_add(dessert_meshrxcb_t* c, int prio) {
    dessert_meshrxcbe_t* cb, *i;

    cb = (dessert_meshrxcbe_t*) malloc(sizeof(dessert_meshrxcbe_t));

    if(cb == NULL) {
        return (-errno);
    }

    pthread_rwlock_wrlock(&dessert_cfglock);

    cb->c = c;
    cb->prio = prio;
    cb->next = NULL;

    if(_dessert_meshrxcblist == NULL) {
        _dessert_meshrxcblist = cb;
        _dessert_meshrxcblistver++;

        pthread_rwlock_unlock(&dessert_cfglock);
        return DESSERT_OK;
    }

    if(_dessert_meshrxcblist->prio > cb->prio) {
        cb->next = _dessert_meshrxcblist;
        _dessert_meshrxcblist = cb;
        _dessert_meshrxcblistver++;

        pthread_rwlock_unlock(&dessert_cfglock);
        return DESSERT_OK;
    }

    /* find right place for callback */
    for(i = _dessert_meshrxcblist; i->next != NULL && i->next->prio <= cb->prio; i = i->next) {
        ;
    }

    /* insert it */
    cb->next = i->next;
    i->next = cb;
    _dessert_meshrxcblistver++;

    pthread_rwlock_unlock(&dessert_cfglock);
    return DESSERT_OK;
}

/******************************************************************************
 * mesh interface handling
 ******************************************************************************/

/**
 * Find dessert_meshif_t with matching name
 *
 * @param ifname name of the interface
 * @return pointer to the dessert_meshif if found, else null
 */
dessert_meshif_t* dessert_ifname2meshif(char* ifname) {
    dessert_meshif_t* iface = NULL;
    bool b = false;
    MESHIFLIST_ITERATOR_START(iface)
        if(strcmp(iface->if_name, ifname) == 0) {
            b = true;
            break;
        }
    MESHIFLIST_ITERATOR_STOP;
    return b ? &(*iface) : NULL;
}

/** Returns the head of the list of mesh interfaces (_desert_meshiflist).
 *
 * @retval pointer  if list is not empty
 * @retval NULL     otherwise
 *
 * %DESCRIPTION:
 *
 */
dessert_meshif_t* dessert_meshiflist_get() {
    return _dessert_meshiflist;
}

/** Looks for mesh interface with name @a dev in the list of mesh interfaces and
 *  returns a pointer to it.
 *
 * @param[in] *dev interface name
 *
 * @retval pointer if the interface is found
 * @retval NULL otherwise
 *
 * %DESCRIPTION:
 *
 **/
dessert_meshif_t* dessert_meshif_get_name(const char* dev) {
    dessert_meshif_t* meshif = NULL;

    /* search dev name in iflist */
    //meshif = _dessert_meshiflist;
    pthread_rwlock_rdlock(&dessert_cfglock);
    DL_FOREACH(_dessert_meshiflist, meshif) {
        if(strncmp(meshif->if_name, dev, IF_NAMESIZE) == 0) {
            break;
        }
    }
    pthread_rwlock_unlock(&dessert_cfglock);

    return (meshif);
}

/** Looks for mesh interface with hardware address @a hwaddr in the list of mesh
 *  interfaces and returns a pointer to it.
 *
 * @param[in] *hwaddr interface hardware address
 *
 * @retval pointer if the interface is found
 * @retval NULL otherwise
 *
 * %DESCRIPTION:
 *
 */
dessert_meshif_t* dessert_meshif_get_hwaddr(const uint8_t hwaddr[ETHER_ADDR_LEN]) {
    dessert_meshif_t* meshif = NULL;

    pthread_rwlock_rdlock(&dessert_cfglock);
    DL_FOREACH(_dessert_meshiflist, meshif) {
        if(memcmp(meshif->hwaddr, hwaddr, ETHER_ADDR_LEN) == 0) {
            break;
        }
    }
    pthread_rwlock_unlock(&dessert_cfglock);
    return meshif;
}

/** Removes the corresponding dessert_meshif struct from _dessert_meshiflist and does some cleanup.
 *
 * @param[in] dev interface name to remove from list
 *
 * @retval DESSERT_OK  on success
 * @retval -errno      on error
 *
 * %DESCRIPTION:
 *
 */
int dessert_meshif_del(const char* dev) {
    dessert_meshif_t* meshif;
    //    dessert_meshif_t *meshif_prev; TODO MESHIF_HASH

    /* lock the list */
    pthread_rwlock_wrlock(&dessert_cfglock);
    /* search dev name in iflist */
    DL_FOREACH(_dessert_meshiflist, meshif) {
        if(strncmp(meshif->if_name, dev, IF_NAMESIZE) == 0) {
            break;
        }
    }

    if(meshif == NULL) {
        pthread_rwlock_unlock(&dessert_cfglock);
        return (ENODEV);
    }

    /* remove it from list */
    DL_DELETE(_dessert_meshiflist, meshif);
    _dessert_meshiflist_update_permutations();
    pthread_rwlock_unlock(&dessert_cfglock);

    /* tell pcap not to further process packets */
    pcap_breakloop(meshif->pcap);

    /* the remaining cleanup is done in the interface thread using _dessert_meshif_cleanup */
    return DESSERT_OK;
}

/** initialize a token bucket with default values **/
static void _dessert_init_tb(token_bucket_t* tb) {
    tb->tokens = 0;
    tb->max_tokens = UINT64_MAX;
    tb->tokens_per_msec = 0;
    tb->periodic = NULL;
    tb->policy = DESSERT_TB_DROP;
    tb->queue = NULL;
    tb->queue_len = 0;
    tb->max_queue_len = 0;
    pthread_mutex_init(&(tb->mutex), NULL);
}

/** Initializes given mesh interface, starts up the packet processor thread.

 * @param[in] *dev interface name
 * @param[in] flags { #DESSERT_IF_PROMISC, #DESSERT_IF_NOPROMISC, #DESSERT_IF_FILTER, #DESSERT_IF_NOFILTER }
 *
 * @retval DESSERT_OK   on success
 * @retval DESSERT_ERR  on error
 *
 * %DESCRIPTION:
 *
 */
int dessert_meshif_add(const char* dev, uint8_t flags) {
    dessert_meshif_t* meshif;

    uint8_t promisc = (flags & DESSERT_IF_NOPROMISC) ? 0 : 1;
    struct bpf_program fp; /* filter program for libpcap */
    char fe[64]; /* filter expression for libpcap */

    snprintf(fe, 64, "ether proto 0x%04x", DESSERT_ETHPROTO);

    /* init new interface entry */
    meshif = (dessert_meshif_t*) malloc(sizeof(dessert_meshif_t));

    if(meshif == NULL) {
        return (-errno);
    }

    memset((void*) meshif, 0, sizeof(dessert_meshif_t));
    strncpy(meshif->if_name, dev, IF_NAMESIZE);
    meshif->if_name[IF_NAMESIZE - 1] = '\0';
    meshif->if_index = if_nametoindex(dev);
    _dessert_init_tb(&(meshif->token_bucket));
    pthread_mutex_init(&(meshif->cnt_mutex), NULL);

    /* check if interface exists */
    if(!meshif->if_index) {
        dessert_err("interface %s - no such interface", meshif->if_name);
        goto dessert_meshif_add_err;
    }

    /* initialize libpcap */
    meshif->pcap = pcap_open_live(meshif->if_name, 2500, promisc, 10, meshif->pcap_err); ///< \todo remove magic number

    if(meshif->pcap == NULL) {
        dessert_err("pcap_open_live failed for interface %s(%d):\n%s", meshif->if_name, meshif->if_index, meshif->pcap_err);
        goto dessert_meshif_add_err;
    }

    if(pcap_datalink(meshif->pcap) != DLT_EN10MB) {
        dessert_err("interface %s(%d) is not an ethernet interface!", meshif->if_name, meshif->if_index);
        goto dessert_meshif_add_err;
    }

    /* pcap filter */
    if(!(flags & DESSERT_IF_NOFILTER)) {
        if(pcap_compile(meshif->pcap, &fp, fe, 0, 0) == -1) {
            dessert_err("couldn't parse filter %s: %s\n", fe, pcap_geterr(meshif->pcap));
            goto dessert_meshif_add_err;
        }

        if(pcap_setfilter(meshif->pcap, &fp) == -1) {
            dessert_err("couldn't install filter %s: %s\n", fe, pcap_geterr(meshif->pcap));
            goto dessert_meshif_add_err;
        }

        /* else { TODO: pcap_freecode() } */
    }

    /* get hardware address */
    if(_dessert_meshif_gethwaddr(meshif) != 0) {
        dessert_err("failed to get hwaddr of interface %s(%d)", meshif->if_name, meshif->if_index);
        goto dessert_meshif_add_err;
    }

    /* check whether we need to set defsrc (default source) */
    if(memcmp(dessert_l25_defsrc, ether_null, ETHER_ADDR_LEN) == 0) {
        memcpy(dessert_l25_defsrc, meshif->hwaddr, ETHER_ADDR_LEN);
        dessert_info("set dessert_l25_defsrc to hwaddr " MAC, EXPLODE_ARRAY6(dessert_l25_defsrc));
    }

    dessert_info("starting worker thread for interface %s(%d) hwaddr " MAC, meshif->if_name, meshif->if_index, EXPLODE_ARRAY6(meshif->hwaddr));

    /* start worker thread */
    if(pthread_create(&(meshif->worker), NULL, _dessert_meshif_add_thread, (void*) meshif)) {
        dessert_err("creating worker thread failed for interface %s(%d)", meshif->if_name, meshif->if_index);
        goto dessert_meshif_add_err;
    }

    /* prepend to interface list */
    pthread_rwlock_wrlock(&dessert_cfglock);
    DL_PREPEND(_dessert_meshiflist, meshif);
    _dessert_meshiflist_update_permutations();
    pthread_rwlock_unlock(&dessert_cfglock);

    return (DESSERT_OK);

dessert_meshif_add_err:

    if(meshif->pcap != NULL) {
        pcap_close(meshif->pcap);
    }

    free(meshif);
    return (DESSERT_ERR);
}

/*****************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * M E S H - I N T E R F A C E S
 *
 ******************************************************************************/

/** Run all registered callbacks.
 *
 * @internal
 *
 * @return the return status of the last callback called
 *
 * @warning  Use with care - never register as callback!
 *
 * %DESCRIPTION:
 *
 */
dessert_cb_result _dessert_meshrxcb_runall(dessert_msg_t* msg_in, uint32_t len, dessert_msg_proc_t* proc_in, dessert_meshif_t* meshif, dessert_frameid_t id) {
    dessert_msg_t* msg = msg_in;
    dessert_msg_proc_t* proc = proc_in;
    dessert_meshrxcbe_t* cb;
    int res = DESSERT_MSG_KEEP;
    dessert_meshrxcb_t** cbl = NULL;
    int cbllen = 0;
    int cblcur = -1;

    /* copy callbacks to internal list to release dessert_cfglock before invoking callbacks*/
    pthread_rwlock_rdlock(&dessert_cfglock);
    cbllen = 0;

    for(cb = _dessert_meshrxcblist; cb != NULL; cb = cb->next) {
        cbllen++;
    }

    cbl = malloc(cbllen * sizeof(dessert_meshrxcb_t*));

    if(cbl == NULL) {
        dessert_err("failed to allocate memory for internal callback list");
        pthread_rwlock_unlock(&dessert_cfglock);
        return DESSERT_MSG_DROP;
    }

    cblcur = 0;

    for(cb = _dessert_meshrxcblist; cb != NULL; cb = cb->next) {
        cbl[cblcur++] = cb->c;
    }

    pthread_rwlock_unlock(&dessert_cfglock);

    /* call the interested */
    res = DESSERT_MSG_KEEP;
    cblcur = 0;

    while(res > DESSERT_MSG_DROP && cblcur < cbllen) {
    _dessert_packet_process_cbagain:
        res = cbl[cblcur](msg, len, proc, meshif, id);

        if(res == DESSERT_MSG_NEEDNOSPARSE && msg == msg_in) {
            dessert_msg_clone(&msg, msg_in, false);
            len = dessert_maxlen;
            goto _dessert_packet_process_cbagain;
        }
        else if(res == DESSERT_MSG_NEEDNOSPARSE && msg != msg_in) {
            dessert_warn("bogus DESSERT_MSG_NEEDNOSPARSE returned from callback!");
        }

        if(res == DESSERT_MSG_NEEDMSGPROC && proc == NULL) {
            proc = malloc(DESSERT_MSGPROCLEN);
            memset(proc, 0, DESSERT_MSGPROCLEN);
            goto _dessert_packet_process_cbagain;
        }
        else if(res == DESSERT_MSG_NEEDMSGPROC && proc != NULL) {
            dessert_warn("bogus DESSERT_MSG_NEEDMSGPROC returned from callback!");
        }

        cblcur++;
    }

    free(cbl);

    if(msg != msg_in) {
        dessert_msg_destroy(msg);
    }

    if(proc != proc_in) {
        free(proc);
    }

    return (res);
}

/** Get the hardware address of the ethernet device behind meshif.
 *
 * @internal
 *
 * @param *meshif pointer to dessert_meshif_t to query
 *
 * @retval DESSERT_OK on success, else DESSERT_ERR
 *
 * \warning This is a platform depended function!
 *
 * %DESCRIPTION:
 *
 **/
dessert_result _dessert_meshif_gethwaddr(dessert_meshif_t* meshif) {
    /* we need some socket to do that */
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    struct ifreq ifr;
    /* set interface options and get hardware address */
    strncpy(ifr.ifr_name, meshif->if_name, sizeof(ifr.ifr_name));

    if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) >= 0) {
        memcpy(meshif->hwaddr, &ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
        close(sockfd);
        return (DESSERT_OK);
    }
    else {
        dessert_err("could not read hwaddr");
        close(sockfd);
        return (DESSERT_ERR);
    }
}

/******************************************************************************
 *
 * LOCAL
 *
 * M E S H - I N T E R F A C E S
 *
 ******************************************************************************/

static inline void _dessert_lock_bucket(dessert_meshif_t* meshif) {
    pthread_mutex_lock(&(meshif->token_bucket.mutex));
}

static inline void _dessert_unlock_bucket(dessert_meshif_t* meshif) {
    pthread_mutex_unlock(&(meshif->token_bucket.mutex));
}

/** Function to send packet via a single interface.
 *
 * @internal
 *
 * @param[in] *msg the message to send
 * @param[in] *iface the interface the message should be send via
 * @param[in] *eq queue element if the message was scheduled for transmission by the token bucket
 *
 * @retval DESSERT_OK on success or if packet was dropped due to traffic shaping
 * @retval EINVAL if *iface is NULL
 * @retval EIO if there was a problem sending the message
 * @retval ENOSR if the message had to be queued
 *
 * %DESCRIPTION:
 *
 */
static inline int _dessert_meshsend_if2(dessert_msg_t* msg, dessert_meshif_t* iface, dessert_msg_queue_t* qe) {
    int msglen = (int) (ntohs(msg->hlen) + ntohs(msg->plen));

    /* check for null meshInterface */
    if(iface == NULL) {
        dessert_err("NULL-pointer specified as interface - programming error!");
        return EINVAL;
    }

    // traffic shaping with token bucket
    /// \todo maybe we should move the lock into the if's body?
    _dessert_lock_bucket(iface); //// [LOCK]
    if(iface->token_bucket.periodic != NULL) {
        if(iface->token_bucket.tokens >= (uint64_t) msglen) {
            dessert_debug("consuming %d bytes for %s",  msglen, iface->if_name);
            iface->token_bucket.tokens -= msglen;
        }
        else {
            switch(iface->token_bucket.policy) {
                case DESSERT_TB_QUEUE_ORDERED:
                    ; // fall through
                case DESSERT_TB_QUEUE_UNORDERED: {
                    if(iface->token_bucket.max_queue_len != 0
                        && iface->token_bucket.queue_len >= iface->token_bucket.max_queue_len) {
                        break;
                    }
                    if(qe == NULL) { // packet was not scheduled by the token bucket
                        dessert_msg_t* cloned = NULL;
                        if(dessert_msg_clone(&cloned, msg, true) != DESSERT_OK) {
                            dessert_crit("could not clone msg");
                            break;
                        }
                        qe = malloc(sizeof(dessert_msg_queue_t));
                        if(qe == NULL) {
                            dessert_crit("could not allocate memory");
                            break;
                        }
                        qe->msg = &(*cloned);
                        qe->len = msglen;
                        qe->next = NULL;
                        LL_APPEND(iface->token_bucket.queue, qe);
                    }
                    else {
                        LL_PREPEND(iface->token_bucket.queue, qe); // prepend if the packet was aready queued
                    }
                    iface->token_bucket.queue_len++;
                    _dessert_unlock_bucket(iface); //// [UNLOCK]
                    return ENOSR;
                }
                case DESSERT_TB_DROP:
                    ; // fall through
                default:
                    ; // do nothing
            }
            _dessert_unlock_bucket(iface); //// [UNLOCK]
            return DESSERT_OK;
        }
    }
    _dessert_unlock_bucket(iface); //// [UNLOCK]

    /* send packet - temporally setting DESSERT_RX_FLAG_SPARSE */
    uint8_t oldflags = msg->flags;
    msg->flags &= ~DESSERT_RX_FLAG_SPARSE;
    int res = pcap_inject(iface->pcap, (uint8_t*) msg, msglen);
    msg->flags = oldflags;

    if(res != msglen) {
        if(res == -1) {
            dessert_warn("couldn't send message: %s\n", pcap_geterr(iface->pcap));
        }
        else {
            dessert_warn("couldn't send message: sent only %d of %d bytes\n", res, msglen);
        }

        return (EIO);
    }

    pthread_mutex_lock(&(iface->cnt_mutex));
    iface->opkts++;
    iface->obytes += res;
    pthread_mutex_unlock(&(iface->cnt_mutex));

    return (DESSERT_OK);
}

/** Callback doing the main work for packets received through a dessert interface.
 *
 * @internal
 *
 * @param arg    - meshif-pointer carried by libpcap in something else
 * @param header - pointer to the header by libpcap
 * @param packet - pointer to the packet by libpcap
 *
 * %DESCRIPTION:
 *
 */
static void _dessert_packet_process(uint8_t* args, const struct pcap_pkthdr* header, const uint8_t* packet) {
    dessert_meshif_t* meshif = (dessert_meshif_t*) args;
    dessert_msg_t* msg = (dessert_msg_t*) packet;
    uint32_t len = header->caplen;
    dessert_frameid_t id;
    dessert_msg_proc_t proc;

    /* is it something I understand? */
    if(ntohs(msg->l2h.ether_type) != DESSERT_ETHPROTO) {
        dessert_debug("got packet with ethertype %04x - discarding", ntohs(msg->l2h.ether_type));
        return;
    }

    /* check message */
    if(header->caplen < header->len) {
        dessert_warn("packet too short - check pcap_open_live() parameters");
        return;
    }

    if(header->caplen < DESSERT_MSGLEN) {
        dessert_notice("packet too short - shorter than DESSERT_MSGLEN");
        return;
    }

    /* generate frame id */
    id = _dessert_newframeid();
    memset(&proc, 0, DESSERT_MSGPROCLEN);

    /* count packet */
    pthread_mutex_lock(&(meshif->cnt_mutex));
    meshif->ipkts++;
    meshif->ibytes += header->caplen;
    pthread_mutex_unlock(&(meshif->cnt_mutex));

    if(dessert_mesh_filter(msg, meshif) != DESSERT_MSG_KEEP) {
        return;
    }
    _dessert_meshrxcb_runall(msg, len, &proc, meshif, id);
    /* do not free the packet's memory as it is managed by libpcap! */
}

/** Internal routine called before interface thread finishes.
 *
 * @internal
 *
 * @param *meshif the interface to be cleaned up
 *
 * %DESCRIPTION:
 *
 */
static void _dessert_meshif_cleanup(dessert_meshif_t* meshif) {
    pcap_close(meshif->pcap);
    free(meshif);
}

/** Internal thread function running the capture loop.
 *
 * @internal
 *
 * @param *arg a void pointer representing a dessert_meshif_t interface
 *
 * %DESCRIPTION:
 */
static void* _dessert_meshif_add_thread(void* arg) {
    dessert_meshif_t* meshif = (dessert_meshif_t*) arg;
    pcap_loop(meshif->pcap, -1, _dessert_packet_process, (uint8_t*) meshif);
    _dessert_meshif_cleanup(meshif);
    return (NULL);
}

/** Internal function to update the lookup table of permutations of the current _dessert_meshiflist.
 *
 * @internal
 *
 * %DESCRIPTION: \n
 */
static void _dessert_meshiflist_update_permutations() {
    int i, r;

    pthread_mutex_lock(&_dessert_meshiflist_mutex);
    dessert_meshif_t* tmp;
    DL_LENGTH(_dessert_meshiflist, _dessert_meshiflist_len, tmp);

    dessert_meshif_t** a =  calloc(sizeof(a), _dessert_meshiflist_len);
    list2array(_dessert_meshiflist, a, _dessert_meshiflist_len);

    _dessert_meshiflist_perm_count = fact(_dessert_meshiflist_len);

    if(_dessert_meshiflist_perms != NULL) {
        free(_dessert_meshiflist_perms);
    }

    _dessert_meshiflist_perms = calloc(sizeof(dessert_meshif_t**) * _dessert_meshiflist_perm_count + sizeof(dessert_meshif_t*) * _dessert_meshiflist_perm_count * _dessert_meshiflist_len, 1);

    for(i = 0; i < _dessert_meshiflist_perm_count; ++i) {
        _dessert_meshiflist_perms[i] = (dessert_meshif_t**)(((char*) _dessert_meshiflist_perms)
            + sizeof(dessert_meshif_t**)
            * _dessert_meshiflist_perm_count + i
            * _dessert_meshiflist_len * sizeof(dessert_meshif_t*));
    }

    for(r = 0; r < _dessert_meshiflist_perm_count; r++) {
        memcpy(_dessert_meshiflist_perms[r], a, sizeof(dessert_meshif_t*) * _dessert_meshiflist_len);
    }

    free(a);

    for(r = 0; r < _dessert_meshiflist_perm_count; r++) {
        permutation(r, _dessert_meshiflist_len, _dessert_meshiflist_perms[r]);
    }

    pthread_mutex_unlock(&_dessert_meshiflist_mutex);
}

/** Internal function to copy the element pointers of the _dessert_meshiflist to an array.
 *
 * @internal
 *
 * @param[in] *l a pointer to the list head
 * @param[out] **a a pointer to an array of dessert_meshif_t
 *
 * %DESCRIPTION: \n
 */
static inline void list2array(dessert_meshif_t* l, dessert_meshif_t** a, int len) {
    dessert_meshif_t* t;
    int i = 0;
    DL_FOREACH(l, t) {
        a[i++] = t;

        if(--len == 0) {
            break;
        }
    }
}

/** Internal function to compute the factorial of a given number.
 *
 * @internal
 *
 * @param[in] i the number
 *
 * @return the factorial
 *
 * %DESCRIPTION: \n
 */
static inline int fact(int i) {
    int fact = 1;

    while(i > 0) {
        fact *= i--;
    }

    return fact;
}

/** Internal function to produce a permutation of @a a.
 *
 * @internal
 *
 * @param[in]  k the permutation to generate
 * @param[in]  len the number of elements in the array
 * @param[out] the array to permute
 *
 * @note Algorithm adopted from the Wikipedia article on
 * <a href="http://en.wikipedia.org/wiki/Permutation">Permutations</a>.
 *
 * %DESCRIPTION: \n
 */
static inline void permutation(int k, int len, dessert_meshif_t** a) {
    dessert_meshif_t* temp;
    int j;

    for(j = 2 ; j <= len; j++) {
        temp = a[(k%j)];
        a[(k%j)] = a[j-1];
        a[j-1] = temp;
        k = k / j;
    }
}

/** Send packets that are in a token bucket queue
 *
 * To minimize the malloc and free calls, this function will schedule only
 * packets for sending if the tokens are sufficient. All other packets remain
 * queued.
 *
 * If, due to some reason, tokens are spent after the function has scheduled the
 * packets and before they are actually handed to _dessert_meshsend_if2, reordering
 * will take place as unsendable packets are append to the queue again.
 *
 * As _dessert_meshsend_if2 is required to lock the token bucket mutex, we have to
 * release it in this function at some point.
 *
 * @param meshif interface whose queue shall be handled
 */
static void _dessert_send_queued_msgs(dessert_meshif_t* meshif) {
    _dessert_lock_bucket(meshif); //// [LOCK]
    uint64_t tokens = meshif->token_bucket.tokens;
    dessert_msg_queue_t* elt = NULL;
    dessert_msg_queue_t* tmp = NULL;
    dessert_msg_queue_t* scheduled = NULL;
    // copy all packets that can be sent with the tokens
    LL_FOREACH_SAFE(meshif->token_bucket.queue, elt, tmp) {
        if(tokens >= elt->len) {
            LL_DELETE(meshif->token_bucket.queue, elt); // always first delete entries!!!
            LL_APPEND(scheduled, elt);
            tokens -= elt->len;
            meshif->token_bucket.queue_len--;
        }
        else {
            if(tokens <= _DESSERT_MIN_PACKET_SIZE) {
                break;
            }
            switch(meshif->token_bucket.policy) {
                case DESSERT_TB_QUEUE_ORDERED:
                    break; // do not consider futher packets to ensure the packet order
                case DESSERT_TB_QUEUE_UNORDERED:
                    continue; // let's see if there are some smaller packets that can be sent
                default:
                    dessert_warning("unknown token bucket policy");
                    break;
            }
        }
    }
    _dessert_unlock_bucket(meshif); //// [UNLOCK]
    LL_FOREACH_SAFE(scheduled, elt, tmp) {
        LL_DELETE(scheduled, elt); // always first delete entries!!!
        dessert_cb_result r = _dessert_meshsend_if2(elt->msg, meshif, elt);
        if(r == DESSERT_OK) {
            dessert_msg_destroy(elt->msg);
            free(elt);
        }
    }
}

/** Fill token bucket
 *
 * Periodic task that puts new tokens in a token bucket. Ensures that the bucket capacity
 * it not exceeded. When a queueing policy is used and packets are in the queue, they
 * are immediately scheduled for transmission.
 *
 * @param data pointer to the meshif to handle
 * @return DESSERT_PER_UNREGISTER if invalid data pointer, else DESSERT_PER_KEEP
 */
dessert_per_result_t _dessert_token_dispenser(void* data, struct timeval* scheduled, struct timeval* interval) {
    if(data == NULL) {
        dessert_err("invalid pointer to meshif");
        return DESSERT_PER_UNREGISTER;
    }
    dessert_meshif_t* meshif = (dessert_meshif_t*) data;
    token_bucket_t* tb = &(meshif->token_bucket);

    _dessert_lock_bucket(meshif); //// [LOCK]
    uint64_t tokens = min(max(tb->max_tokens - (tb->tokens), 0), tb->tokens_per_msec);
    //dessert_trace("adding %"PRIi64" tokens to %s (%"PRIi64"/%"PRIi64")", tokens, meshif->if_name, tb->tokens, tb->max_tokens);
    tb->tokens += tokens;
    _dessert_unlock_bucket(meshif); //// [UNLOCK]

    if(tb->policy != DESSERT_TB_DROP) {
        _dessert_send_queued_msgs(meshif); // spend tokens immediately on queued packets
    }
    return DESSERT_PER_KEEP;
}

/** print tocken bucket information to cli **/
static void _dessert_print_tb(struct cli_def* cli, uint8_t i, dessert_meshif_t* meshif) {
    if(meshif == NULL) {
        return;
    }

    cli_print(cli, "%5d\t%10s\t%20llu\t%20llu\t%16s\t%6d/%-6d\t%10s",
        i,
        meshif->if_name,
        (long long unsigned int) meshif->token_bucket.max_tokens,
        (long long unsigned int) meshif->token_bucket.tokens_per_msec*1000,
        _dessert_policy2str[meshif->token_bucket.policy],
        meshif->token_bucket.queue_len,
        meshif->token_bucket.max_queue_len,
        meshif->token_bucket.periodic == NULL ? "disabled" : "enabled"
        );
}

int _dessert_cli_cmd_show_tokenbucket(struct cli_def* cli, char* command, char* argv[], int argc) {
    dessert_meshif_t* meshif = NULL;
    cli_print(cli, "%5s\t%10s\t%20s\t%20s\t%16s\t%13s\t%10s", "#", "meshif", "size [B]", "rate [B/s]", "policy", "queue length", "state");
    uint8_t i = 0;
    MESHIFLIST_ITERATOR_START(meshif)
        _dessert_print_tb(cli, i, meshif);
        i++;
    MESHIFLIST_ITERATOR_STOP;
    return CLI_OK;
}

/** Convert unit symbol to multiplier
 *
 * Example: 'k' = 1000
 *
 * @param c character to convert
 * @param cli cli for error message
 * @return multiplier, 1 on error
 */
static uint32_t eval_multiplier(char* c, struct cli_def* cli) {
    if(c != NULL) {
        switch(*c) {
            case 'k':
            case 'K':
                return 1000;
            case 'm':
            case 'M':
                return 1000*1000;
            default:
                cli_print(cli, "unsupported multiplier: %s (%x)", c, c[0]);
        }
    }
    return 1;
}

/** Set tocken bucket policy
 *
 */
int _dessert_cli_cmd_tokenbucket_policy(struct cli_def* cli, char* command, char* argv[], int argc) {
    if(argc != 2) {
        cli_print(cli, "USAGE: %s [MESHIF] [%s, %s, %s]", command, _dessert_policy2str[DESSERT_TB_DROP], _dessert_policy2str[DESSERT_TB_QUEUE_ORDERED], _dessert_policy2str[DESSERT_TB_QUEUE_UNORDERED]);
        return CLI_ERROR;
    }

    dessert_meshif_t* meshif = dessert_ifname2meshif(argv[0]);
    if(meshif == NULL) {
        cli_print(cli, "ERROR: could not find interface: %s", argv[0]);
        return CLI_ERROR;
    }

    dessert_tb_policy_t policy;
    if(strcmp(_dessert_policy2str[DESSERT_TB_DROP], argv[1]) == 0) {
        policy = DESSERT_TB_DROP;
    }
    else if(strcmp(_dessert_policy2str[DESSERT_TB_QUEUE_ORDERED], argv[1]) == 0) {
        policy = DESSERT_TB_QUEUE_ORDERED;
    }
    else if(strcmp(_dessert_policy2str[DESSERT_TB_QUEUE_UNORDERED], argv[1]) == 0) {
        policy = DESSERT_TB_QUEUE_UNORDERED;
    }
    else {
        cli_print(cli, "ERROR: unsupported policy: %s", argv[1]);
        return CLI_ERROR;
    }

    _dessert_lock_bucket(meshif); //// [LOCK]
    meshif->token_bucket.policy = policy;
    cli_print(cli, "INFO: set policy: %s", argv[1]);
    _dessert_unlock_bucket(meshif); //// [UNLOCK]
    return CLI_OK;
}

/** Set tocken bucket policy
 *
 */
int _dessert_cli_cmd_tokenbucket_max(struct cli_def* cli, char* command, char* argv[], int argc) {
    if(argc != 2) {
        cli_print(cli, "USAGE: %s [MESHIF] [MAX_LEN]", command);
        return CLI_ERROR;
    }

    dessert_meshif_t* meshif = dessert_ifname2meshif(argv[0]);
    if(meshif == NULL) {
        cli_print(cli, "ERROR: could not find interface: %s", argv[0]);
        return CLI_ERROR;
    }

    char *next_char = NULL;
    uint32_t max_len = strtoul(argv[1], &next_char, 10);
    if(max_len && *next_char != '\0') {
        max_len *= eval_multiplier(next_char, cli);
    }

    _dessert_lock_bucket(meshif); //// [LOCK]
    meshif->token_bucket.max_queue_len = max_len;
    cli_print(cli, "INFO: set maximum queue length: %" PRIu32 "", max_len);
    if(max_len < meshif->token_bucket.queue_len) {
        cli_print(cli, "WARNING: there are currently more packets in the queue: %" PRIu32 "", meshif->token_bucket.queue_len);
    }
    _dessert_unlock_bucket(meshif); //// [UNLOCK]
    return CLI_OK;
}

/** Activate, modify, or deactive token bucket
 *
 */
int _dessert_cli_cmd_tokenbucket(struct cli_def* cli, char* command, char* argv[], int argc) {
    enum { PARAM_MESHIF=0, PARAM_SIZE, PARAM_RATE, NUM_PARAMS};

    if(argc != NUM_PARAMS) {
        cli_print(cli, "USAGE: %s [MESHIF] [BUCKETSIZE (bytes)] [RATE (bytes/s)]", command);
        return CLI_ERROR;
    }

    dessert_meshif_t* meshif = dessert_ifname2meshif(argv[PARAM_MESHIF]);
    if(meshif == NULL) {
        cli_print(cli, "ERROR: could not find interface: %s", argv[PARAM_MESHIF]);
        return CLI_ERROR;
    }

    char *next_char = NULL;
    uint64_t size = strtoul(argv[PARAM_SIZE], &next_char, 10);
    if(size && *next_char != '\0') {
        size *= eval_multiplier(next_char, cli);
    }
    uint64_t rate = strtoul(argv[PARAM_RATE], &next_char, 10);
    if(rate && *next_char != '\0') {
        rate *= eval_multiplier(next_char, cli);
    }

    _dessert_lock_bucket(meshif); //// [LOCK]
    /* deaktivate token bucket */
    if(size == 0 || rate == 0) {
        if(meshif->token_bucket.periodic != NULL) {
            if(dessert_periodic_del(meshif->token_bucket.periodic) == -1) {
                cli_print(cli, "ERROR: token bucket not activated for interface: %s", meshif->if_name);
            }
            meshif->token_bucket.periodic = NULL;
            cli_print(cli, "INFO: deactivated token bucket for interface: %s", meshif->if_name);
        }
        else {
            cli_print(cli, "ERROR: no active token bucket for: %s", meshif->if_name);
        }
        goto out;
    }

    /* enforce minimum rate of 1kByte/s */
    if(size < 1000) {
        cli_print(cli, "ERROR: size smaller than 1000: %" PRIu64 "", size);
        goto fail;
    }
    if(rate < 1000) {
        cli_print(cli, "ERROR: rate smaller than 1000: %" PRIu64 "", size);
        goto fail;
    }

    /* modify tocken bucket */
    meshif->token_bucket.max_tokens = size;
    meshif->token_bucket.tokens_per_msec = min(rate/1000, size);
    if(rate != meshif->token_bucket.tokens_per_msec*1000) {
        meshif->token_bucket.tokens = min(meshif->token_bucket.max_tokens, meshif->token_bucket.tokens);
        cli_print(cli, "WARNING: rate rounded to: %" PRIu64 "", meshif->token_bucket.tokens_per_msec);
    }

    /* activate token bucket */
    if(meshif->token_bucket.periodic == NULL) {
        struct timeval interval;
        interval.tv_sec = 0;
        interval.tv_usec = 1000;
        dessert_periodic_t* per = dessert_periodic_add(_dessert_token_dispenser, &(*meshif), NULL, &interval);
        meshif->token_bucket.tokens = meshif->token_bucket.tokens_per_msec;
        meshif->token_bucket.periodic = per;
        cli_print(cli, "INFO: activated token bucket for interface: %s", meshif->if_name);
        goto out;
    }

    cli_print(cli, "INFO: updated token bucket for interface: %s", meshif->if_name);

out:
    _dessert_unlock_bucket(meshif); //// [UNLOCK]
    return CLI_OK;

fail:
    _dessert_unlock_bucket(meshif); //// [UNLOCK]
    return CLI_ERROR;
}

/** Add mesh mesh interface
 *
 * Adds an interface as mesh interface to the daemon. libpcap is
 * used to receive packets in the promiscuous mode.
 * The interface is put in the up state but you still have to configure the wlan parameters
 * manually, e.g., the channel.
 *
 * COMMAND: interface mesh $iface
 *
 * @param cli the handle of the cli structure. This must be passed to all cli functions, including cli_print().
 * @param command the entire command which was entered. This is after command expansion.
 * @param argv the list of arguments entered
 * @param argc the number of arguments entered
 *
 * @retval CLI_OK if interface added and in up state
 * @retval CLI_ERROR on error
 */
int dessert_cli_cmd_addmeshif(struct cli_def* cli, char* command, char* argv[], int argc) {
    uint8_t BUF_SIZE = 255;
    char buf[BUF_SIZE];
    int i;

    if(argc != 1) {
        cli_print(cli, "USAGE: %s [mesh-interface]\n", command);
        return CLI_ERROR;
    }

    dessert_info("initializing mesh interface %s", argv[0]);
    snprintf(buf, BUF_SIZE, "ifconfig %s up", argv[0]);
    i = system(buf);

    if(i != 0) {
        dessert_crit("running ifconfig on mesh interface %s returned %d", argv[0], i);
        return CLI_ERROR;
    }

    i = dessert_meshif_add(argv[0], DESSERT_IF_PROMISC);

    if(i == DESSERT_OK) {
        return CLI_OK;
    }

    return CLI_ERROR;
}

/** Drop messages with Ethernet extension
 *
 * Drop all DES-SERT messages with an Ethernet extension.
 *
 * @param *msg dessert_msg_t frame received
 * @param len length of the buffer pointed to from dessert_msg_t
 * @param *proc local processing buffer passed along the callback pipeline - may be NULL
 * @param *meshif interface received packet on - may be NULL
 * @param id unique internal frame id of the packet
 *
 * @retval DESSERT_MSG_DROP if Ethernet extension is available
 * @retval DESSERT_MSG_KEEP if Ethernet extension is missing
 */
dessert_cb_result dessert_mesh_drop_ethernet(dessert_msg_t* msg, uint32_t len, dessert_msg_proc_t* proc, dessert_meshif_t* meshif, dessert_frameid_t id) {
    struct ether_header* eth = dessert_msg_getl25ether(msg);

    if(eth != NULL) {  // has Ethernet extension
        dessert_debug("dropped DES-SERT message with Ethernet extension");
        return DESSERT_MSG_DROP;
    }

    return DESSERT_MSG_KEEP;
}

/** Drop messages without Ethernet extension
 *
 * Drop all DES-SERT messages with an Ethernet extension.
 *
 * @param *msg dessert_msg_t frame received
 * @param len length of the buffer pointed to from dessert_msg_t
 * @param *proc local processing buffer passed along the callback pipeline - may be NULL
 * @param *meshif interface received packet on - may be NULL
 * @param id unique internal frame id of the packet
 *
 * @retval DESSERT_MSG_KEEP if Ethernet extension is available
 * @retval DESSERT_MSG_DROP if Ethernet extension is missing
 */
dessert_cb_result dessert_mesh_drop_ip(dessert_msg_t* msg, uint32_t len, dessert_msg_proc_t* proc, dessert_meshif_t* meshif, dessert_frameid_t id) {
    struct ether_header* eth = dessert_msg_getl25ether(msg);

    if(eth == NULL) {  // has no Ethernet extension
        dessert_debug("dropped DES-SERT message with Ethernet extension");
        return DESSERT_MSG_DROP;
    }

    return DESSERT_MSG_KEEP;
}

/** Enable IP-based tracing
 *
 * This extension decrements the TTL in IPv4 or the Hop-Limit field in IPv6 datagrams. If the
 * value drops to 1, the datagram in the DES-SERT message is decapsulated and handed to the
 * IP implementation of the operating system. Depending on the configuration, the IP
 * implementation will send an ICMP time-exceeded message. This enables tracing despite
 * the transparent underlay routing applied in DES-SERT.
 *
 * @param *msg dessert_msg_t frame received
 * @param len length of the buffer pointed to from dessert_msg_t
 * @param *proc local processing buffer passed along the callback pipeline - may be NULL
 * @param *meshif interface received packet on - may be NULL
 * @param id unique internal frame id of the packet
 *
 * @retval DESSERT_MSG_KEEP if TTL or Hop Limit > 1
 * @retval DESSERT_MSG_DROP if TTL or Hop Limit <= 1
 */
dessert_cb_result dessert_mesh_ipttl(dessert_msg_t* msg, uint32_t len, dessert_msg_proc_t* proc, dessert_meshif_t* meshif, dessert_frameid_t id) {
    void* payload;
    struct ether_header* eth = dessert_msg_getl25ether(msg);

    // TODO: works currently only with encapsulated Ethernet frames
    if(eth == NULL) {
        return DESSERT_MSG_KEEP;
    }

    if(proc->lflags & DESSERT_RX_FLAG_L25_DST) {
        // the packet got here, so we can ignore the TTL value
        return DESSERT_MSG_KEEP;
    }

    if(!(proc->lflags & DESSERT_RX_FLAG_L2_DST)) {
        return DESSERT_MSG_KEEP;
    }

    // IPv4
    if(eth->ether_type == htons(ETHERTYPE_IP) && dessert_msg_getpayload(msg, &payload)) {
        struct iphdr* ip = (struct iphdr*) payload;

        // decrement TTL each hop
        if(ip->ttl > 1) {
            ip->ttl--;
            ip->check = (ip->check + 1);
        }
        /*
        * TTL == 1, let the IP implementation handle the situation and send an
        * ICMP time exceeded message
        */
        else {
            struct ether_header* eth;
            uint32_t eth_len;
            eth_len = dessert_msg_ethdecap(msg, &eth);

            /*
            * Fake destination ether address or the host will not evaluate the packet.
            * Multicast and broadcast frames can be ignored.
            */
            if(!(proc->lflags & DESSERT_RX_FLAG_L25_BROADCAST
                 || proc->lflags & DESSERT_RX_FLAG_L25_MULTICAST)) {
                memcpy(&(eth->ether_dhost), &(_dessert_sysif->hwaddr), ETHER_ADDR_LEN);
            }

            dessert_syssend(eth, eth_len);
            free(eth);
            return DESSERT_MSG_DROP;
        }
    }
    // IPv6
    else if(eth->ether_type == htons(ETHERTYPE_IPV6) && dessert_msg_getpayload(msg, &payload)) {
        struct ip6_hdr* ip = (struct ip6_hdr*) payload;

        // decrement Hop Limit each hop
        if(ip->ip6_ctlun.ip6_un1.ip6_un1_hlim) {
            ip->ip6_ctlun.ip6_un1.ip6_un1_hlim--;
        }
        /*
        * Hop Limit == 1, let the IP implementation handle the situation and send an
        * ICMPv6 time exceeded message
        */
        else {
            struct ether_header* eth;
            uint32_t eth_len;
            eth_len = dessert_msg_ethdecap(msg, &eth);

            /*
            * Fake destination ether address or the host will not evaluate the packet.
            * Multicast and broadcast frames can be ignored.
            */
            if(!(proc->lflags & DESSERT_RX_FLAG_L25_BROADCAST
                 || proc->lflags & DESSERT_RX_FLAG_L25_MULTICAST)) {
                memcpy(&(eth->ether_dhost), &(_dessert_sysif->hwaddr), ETHER_ADDR_LEN);
            }

            dessert_syssend(eth, eth_len);
            free(eth);
            return DESSERT_MSG_DROP;
        }
    }

    return DESSERT_MSG_KEEP;
}
