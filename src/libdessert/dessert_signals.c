/******************************************************************************
 Copyright 2010, The DES-SERT Team, Freie Universitaet Berlin (FUB).
 All rights reserved.

 These sources were originally developed by Bastian Blywis
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

pthread_t _dessert_signal_thread;
pthread_mutex_t _dessert_signal_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct sig_handlercb {
    dessert_signalcb_t* callback;
    struct sig_handlercb* next;
} sig_handlercb_t;

typedef struct sig_handler {
    int signal;             // key
    sig_handlercb_t* list;  // list of callbacks
    UT_hash_handle hh;      // handle for hash table usage
} sig_handler_t;

sig_handler_t* _sig_handlers_map = NULL;

static uint8_t _signal_supported(int signal) {
    uint32_t i;

    for(i = 0; i < sizeof(dessert_supported_signals) / sizeof(int); i++) {
        if(dessert_supported_signals[i] == signal) {
            return 1;
        }
    }

    return 0;
}

/** Add signal callback
 *
 * Add a callback function to handle a specifc signal.
 *
 * @param signal number of the signal as specified in signal.h
 * @param callback callback function to call on the signal
 * @return -1 on error, else 0
 */
int dessert_signalcb_add(int signal, dessert_signalcb_t* callback) {
    pthread_mutex_lock(&_dessert_signal_mutex);
    sig_handler_t* sig_handlers = NULL;

    if(callback == NULL) {
        dessert_err("callback is NULL");
        goto add_failed;
    }

    if(!_signal_supported(signal)) {
        dessert_err("signal %d is not supported currently", signal);
        goto add_failed;
    }

    /* Find the entry in the hash map */
    HASH_FIND_INT(_sig_handlers_map, &signal, sig_handlers);

    if(sig_handlers == NULL) {
        sig_handlers = malloc(sizeof(sig_handler_t));
        sig_handlers->signal = signal;
        sig_handlers->list = NULL;

        if(sig_handlers == NULL) {
            dessert_err("failed to allocate new sig_handler entry");
            goto add_failed;
        }

        HASH_ADD_INT(_sig_handlers_map, signal, sig_handlers);
    }

    /* Insert new handler in list */
    sig_handlercb_t* new_cb = malloc(sizeof(sig_handlercb_t));

    if(new_cb == NULL) {
        dessert_err("failed to allocate new sig_handlercb_t entry");
        goto add_failed;
    }

    new_cb->callback = callback;
    LL_APPEND(sig_handlers->list, new_cb);
    pthread_mutex_unlock(&_dessert_signal_mutex);
    dessert_notice("registered signal handler for signal %d", signal);
    return 0;

add_failed:
    pthread_mutex_unlock(&_dessert_signal_mutex);
    dessert_err("could not add signal handler callback");
    return -1;
}

/** Remove signal callback
 *
 * Remove a callback function registered to handle a specifc signal.
 *
 * @param signal number of the signal as specified in signal.h. Currently
 * the signals specified in dessert_supported_signals are supported.
 * @param callback callback function to deregister
 * @return -1 on error, else 0
 */
int dessert_signalcb_del(int signal, dessert_signalcb_t* callback) {
    sig_handler_t* sig_handlers = NULL;
    pthread_mutex_lock(&_dessert_signal_mutex);
    HASH_FIND_INT(_sig_handlers_map, &signal, sig_handlers);

    if(sig_handlers == NULL) {
        dessert_warn("cannot remove signal callback, none registered for signal %d", signal);
        goto del_failed;
    }

    sig_handlercb_t* del_cb = NULL;
    sig_handlercb_t* iter = NULL;
    LL_FOREACH(sig_handlers->list, iter) {
        if(iter->callback == callback) {
            del_cb = iter;
            break;
        }
    }

    if(del_cb) {
        LL_DELETE(sig_handlers->list, del_cb);
        free(del_cb);
    }
    else {
        dessert_warn("cannot remove signal callback, callback not found");
        goto del_failed;
    }

    pthread_mutex_unlock(&_dessert_signal_mutex);
    return 0;

del_failed:
    pthread_mutex_unlock(&_dessert_signal_mutex);
    dessert_err("could not remove signal callback");
    return -1;
}

void* dessert_signal_thread(void* param) {
    sigset_t signal_mask_catch;
    sigemptyset(&signal_mask_catch);

    uint32_t i;

    for(i = 0; i < sizeof(dessert_supported_signals) / sizeof(int); i++) {
        sigaddset(&signal_mask_catch, dessert_supported_signals[i]);
    }

    dessert_info("signal thread started");
    int sig_caught;

    while(1) {
        int rc = sigwait(&signal_mask_catch, &sig_caught);

        if(rc != 0) {
            dessert_crit("sigwait returned = %d", rc);
            continue;
        }

        switch(sig_caught) {
            case SIGTERM:
                dessert_debug("caught SIGTERM, preparing to exit main thread");
                break;
            case SIGINT:
                dessert_debug("caught SIGINT, preparing to exit main thread");
                break;
            case SIGHUP:
                dessert_debug("caught SIGHUP");
                break;
            case SIGUSR1:
                dessert_debug("caught SIGUSR1");
                break;
            case SIGUSR2:
                dessert_debug("caught SIGUSR2");
                break;
            default:
                dessert_crit("\nUnexpected signal: %d\n", sig_caught);
                continue;
        }

        sig_handler_t* sig_handlers = NULL;
        HASH_FIND_INT(_sig_handlers_map, &sig_caught, sig_handlers);

        if(sig_handlers) {
            sig_handlercb_t* cur;
            LL_FOREACH(sig_handlers->list, cur) {
                dessert_debug("calling callback for signal %d", sig_caught);
                cur->callback(sig_caught);
            }
        }

        switch(sig_caught) {
            case SIGINT:
            case SIGTERM:
                dessert_debug("exiting main thread");
                dessert_exit();
                break;
            default:
                break;
        }
    }

    dessert_emerg("signal thread exited");
    return NULL;
}

dessert_result _dessert_signals_init() {
    sigset_t signal_mask_block;
    sigemptyset(&signal_mask_block);
    sigaddset(&signal_mask_block, SIGTERM);
    sigaddset(&signal_mask_block, SIGHUP);
    sigaddset(&signal_mask_block, SIGINT);
    int rc = pthread_sigmask(SIG_BLOCK, &signal_mask_block, NULL);

    if(rc != 0) {
        dessert_err("could not set sigmask to block signals");
    }

    pthread_create(&_dessert_signal_thread, NULL, dessert_signal_thread, NULL);
    return DESSERT_OK;
}
