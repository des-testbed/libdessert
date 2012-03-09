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

#include "dessert.h"
#include "dessert_internal.h"
#include <sys/stat.h>

/* global data storage // P U B L I C */
char dessert_proto[DESSERT_PROTO_STRLEN + 1];
uint32_t dessert_maxlen = ETH_FRAME_LEN;
uint8_t dessert_ver;
uint8_t dessert_l25_defsrc[ETHER_ADDR_LEN];
u_char ether_broadcast[ETHER_ADDR_LEN];
u_char ether_null[ETHER_ADDR_LEN];
pthread_rwlock_t dessert_cfglock = PTHREAD_RWLOCK_INITIALIZER;

/* global data storage // P R I V A T E */
int _dessert_status = 0x0;
struct timeval _dessert_started = { 0, 0};

/* local data storage*/
dessert_frameid_t _dessert_nextframeid = 0;
pthread_mutex_t _dessert_nextframeid_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _dessert_exit_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t _dessert_exit_do = PTHREAD_COND_INITIALIZER;
int _dessert_exit_code = 0;
char* dessert_pidfile_name = NULL;

/* internal functions forward declarations*/
static void _dessert_cleanup(void);
static void _dessert_daemonize(void);
static int _dessert_pid(char* pidfile);

/******************************************************************************
 *
 * EXTERNAL / PUBLIC
 *
 * C O R E
 *
 ******************************************************************************/

static void _dessert_register_ptr_names() {
    dessert_register_ptr_name(_dessert_flush_log, "dessert_flush_log");
    dessert_register_ptr_name(_dessert_token_dispenser, "_dessert_token_dispenser");
}

/** Initializes dessert framework and sets up logging
 * @arg *proto 4 char string for protocol name
 * @arg version version number of protocol
 * @arg opts @see DESSERT_OPT_*
 * @returns DESSERT_OK on success, DESSERT_ERR otherwise
 **/
int dessert_init(const char* proto, int version, uint16_t opts) {
    gettimeofday(&_dessert_started, NULL);
    pthread_rwlock_wrlock(&dessert_cfglock);

    /* save global config */
    memset(dessert_proto, 0x0, DESSERT_PROTO_STRLEN + 1);
    strncpy(dessert_proto, proto, DESSERT_PROTO_STRLEN);
    dessert_ver = version;

    /* initialize pseudo constants */
    memset(ether_broadcast, 255, ETHER_ADDR_LEN);
    memset(ether_null, 0, ETHER_ADDR_LEN);

    pthread_rwlock_unlock(&dessert_cfglock);

    /* daemonize if needed */
    if((opts & DESSERT_OPT_DAEMONIZE) && !(opts & DESSERT_OPT_NODAEMONIZE)) {
        _dessert_daemonize();
    }

    /* initialize all event thread, sets sigmask */
    _dessert_signals_init();

    /* initialize cli */
    _dessert_cli_init();

    /* start periodic thread */
    _dessert_periodic_init();

    _dessert_register_ptr_names();

#ifdef WITH_NET_SNMP
    /* initialize net-snmp subagent */
    _dessert_agentx_init_subagent();
#endif

    return DESSERT_OK;
}


/** Write pid to file
 *
 * Write the process id to a file.
 *
 * @param pidfile filename of pid file
 * @return DESSERT_OK if pid written and file closed, else DESSERT_ERR
 */
int dessert_pid(char* pidfile) {
    FILE* fd;

    if(dessert_pidfile_name != NULL) {
        dessert_warn("pid file already written to: %s\n", dessert_pidfile_name);
        return DESSERT_ERR;
    }

    fd = fopen(pidfile, "w");

    if(fd == 0) {
        dessert_warn("could not open pid file");
        return DESSERT_ERR;
    }
    else {
        int r;
        r = fprintf(fd, "%d\n", getpid());

        if(r < 0) {
            dessert_warn("could not write to pid file");
            return DESSERT_ERR;
        }

        if(fclose(fd) != 0) {
            dessert_warn("failed to close pid file");
        }
    }

    dessert_pidfile_name = pidfile;
    dessert_debug("wrote pid to file: %s", dessert_pidfile_name);
    return DESSERT_OK;
}

/** main loop - wait until dessert_exit() is called or killed
 * @return arg to dessert_exit
 */
int dessert_run() {
    pthread_mutex_lock(&_dessert_exit_mutex);
    pthread_cond_wait(&_dessert_exit_do, &_dessert_exit_mutex);
    _dessert_cleanup();
    pthread_mutex_unlock(&_dessert_exit_mutex);
    return (_dessert_exit_code);
}

/**Causes dessert_run() to break out of the main loop.
 */
void dessert_exit() {
    pthread_cond_signal(&_dessert_exit_do);
}

/** generates a new, runtime-unique frame id
 * @returns runtime-unique frame id
 **/
dessert_frameid_t _dessert_newframeid() {
    dessert_frameid_t x;
    pthread_mutex_lock(&_dessert_nextframeid_mutex);
    x = _dessert_nextframeid++;
    pthread_mutex_unlock(&_dessert_nextframeid_mutex);
    return (x);
}

/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * C O R E
 *
 ******************************************************************************/

/** command "shutdown" */
int _dessert_cli_cmd_shutdown(struct cli_def* cli, char* command, char* argv[], int argc) {
    cli_print(cli, "daemon will shut down now!");
    pthread_mutex_lock(&_dessert_exit_mutex);
    pthread_cond_broadcast(&_dessert_exit_do);
    pthread_mutex_unlock(&_dessert_exit_mutex);
    return CLI_OK;
}

/******************************************************************************
 *
 * LOCAL
 *
 * C O R E
 *
 ******************************************************************************/

/** internal function to clean up things */
void _dessert_cleanup(void) {
    /* remove pidfile */
    if(dessert_pidfile_name != NULL) {
        unlink(dessert_pidfile_name);
    }

#ifndef ANDROID
    dessert_monitoring_stop();
#endif
    _dessert_closeLogFile();
#ifdef WITH_NET_SNMP
    /* kill snmp_worker thread */
    dessert_agentx_stop_subagent();
#endif
}

/** internal daemonize helper */
void _dessert_daemonize(void) {
    pid_t pid, sid;

    /* Fork off the parent process */
    pid = fork();

    if(pid < 0) {
        perror("could not create daemon process!");
        exit(EXIT_FAILURE);
    }

    /* If we got a good PID, then
    we can exit the parent process. */
    if(pid > 0) {
        exit(EXIT_SUCCESS);
    }

    /* Change the file mode mask */
    umask(0);

    /* Open any logs here */

    /* Create a new SID for the child process */
    sid = setsid();

    if(sid < 0) {
        perror("could not set sid!");
        exit(EXIT_FAILURE);
    }

    /* Change the current working directory */
    if((chdir("/")) < 0) {
        perror("could not chdir /!");
        exit(EXIT_FAILURE);
    }

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    /* write config */
    pthread_rwlock_wrlock(&dessert_cfglock);
    _dessert_status |= _DESSERT_STATUS_DAEMON;
    pthread_rwlock_unlock(&dessert_cfglock);

    /* adopt logging */
    dessert_logcfg(0x0);
}

int _dessert_cli_cmd_showuptime(struct cli_def* cli, char* command, char* argv[], int argc) {
    uint32_t cur_ms = dessert_cur_ms();
    uint32_t started_ms = dessert_timeval2ms(&_dessert_started);
    uint32_t diff_ms = cur_ms - started_ms;
    uint32_t seconds = diff_ms / (1000);
    uint32_t minutes = diff_ms / (1000*60);
    uint32_t hours   = diff_ms / (1000*60*60);
    uint32_t days    = diff_ms / (1000*60*60*24);
    hours   -= days*24;
    minutes -= hours*60+days*24*60;
    seconds -= minutes*60+hours*3600;
    cli_print(cli, "%2u days, %2u hours, %2u minutes, %2u seconds", days, hours, minutes, seconds);
    return CLI_OK;
}

/** Uptime in ms
 *
 * Get the time since libdessert was initialized.
 *
 * @return uptime in ms
 */
uint32_t dessert_get_uptime_ms() {
    uint32_t cur_ms = dessert_cur_ms();
    uint32_t started_ms = dessert_timeval2ms(&_dessert_started);
    return cur_ms - started_ms;
}
