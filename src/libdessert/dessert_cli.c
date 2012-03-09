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

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 32
#endif

/* global data storage // P U B L I C */

struct cli_def* dessert_cli;

struct cli_command* dessert_cli_show;
struct cli_command* dessert_cli_set;
struct cli_command* dessert_cli_filter;

struct cli_command* dessert_cli_cfg_no;
struct cli_command* dessert_cli_cfg_iface;
struct cli_command* dessert_cli_cfg_no_iface;
struct cli_command* dessert_cli_cfg_logging;
struct cli_command* dessert_cli_cfg_no_logging;

/* global data storage // P R I V A T E */
/* nothing here - yet */

/* local data storage*/
static int _dessert_cli_sock;
/// \todo _dessert_cli_addr* is not used anywhere but in a single function; global vars should be removed
static struct sockaddr_in6 _dessert_cli_addr6;
static struct sockaddr_in _dessert_cli_addr4;
static char _dessert_cli_hostname[HOST_NAME_MAX + DESSERT_PROTO_STRLEN + 1];
static pthread_t _dessert_cli_worker;
static int _dessert_cli_running = 0;
static uint16_t _cli_port = 4519; // should be default port number

/* internal functions forward declarations*/
static void* _dessert_cli_accept_thread(void* arg);
static int _dessert_cli_cmd_showmeshifs(struct cli_def* cli, char* command, char* argv[], int argc);
static int _dessert_cli_cmd_showmonifs(struct cli_def* cli, char* command, char* argv[], int argc);
static int _dessert_cli_cmd_showsysif(struct cli_def* cli, char* command, char* argv[], int argc);
static int _dessert_cli_cmd_showmondb(struct cli_def* cli, char* command, char* argv[], int argc);
static int _dessert_cli_cmd_dessertinfo(struct cli_def* cli, char* command, char* argv[], int argc);
static int _dessert_cli_cmd_setport(struct cli_def* cli, char* command, char* argv[], int argc);
static int _dessert_cli_cmd_pid(struct cli_def* cli, char* command, char* argv[], int argc);
static void _dessert_cli_cmd_showmeshifs_print_helper(struct cli_def* cli, dessert_meshif_t* meshif);
#ifndef ANDROID
static int _dessert_cli_monitoring_start(struct cli_def* cli, char* command, char* argv[], int argc);
static int _dessert_cli_monitor_conf(struct cli_def* cli, char* command, char* argv[], int argc);
#endif
/******************************************************************************
 *
 * EXTERNAL / PUBLIC
 *
 * C L I - C O M M A N D   L I N E   I N T E R F A C E
 *
 ******************************************************************************/

/** Get pointer to config file
 *
 * Try to get a valid file name from the arguments and if this fails,
 * guess config file name based on the daemon's name. This function
 * either terminates the daemon or returns a valid FILE pointer.
 *
 * @param[in] argc number of arguments in list
 * @param[in] argv pointer to a list of arguments
 * @return pointer to config file
 */
FILE* dessert_cli_get_cfg(int argc, char** argv) {
    FILE* cfg;

    const char* path_head = "/etc/";
    const char* path_tail = ".conf";

    char* str = alloca(strlen(argv[0]) + 1);
    strcpy(str, argv[0]);
    char* ptr = strtok(str, "/");
    char* daemon = ptr;

    while(ptr != NULL) {
        daemon = ptr;
        ptr = strtok(NULL, "/");
    }

    if(argc != 2) {
        char* path = alloca(strlen(path_head) + 1 + strlen(path_tail) + 1 + strlen(daemon) + 1);
        strcat(path, path_head);
        strcat(path, daemon);
        strcat(path, path_tail);
        cfg = fopen(path, "r");

        if(cfg == NULL) {
            dessert_err("specify configuration file\nusage: \"%s configfile\"\nusage: \"%s\" if /etc/%s.conf is present", daemon, daemon, daemon);
            exit(1);
        }
    }
    else {
        cfg = fopen(argv[1], "r");

        if(cfg == NULL) {
            dessert_err("failed to open configfile %s", argv[1]);
            exit(2);
        }
        else {
            dessert_info("using file %s as configuration file", argv[1]);
        }
    }

    return cfg;
}

/** Set CLI port
*
* Set the TCP port of the command line interface. The Daemon will
* accept one connection at a time.
*
* @param[in] port TCP port number
*
* @retval DESSERT_OK on success
* @retval DESSERT_ERR otherwise
*/
int dessert_set_cli_port(uint16_t port) {
    if(_dessert_cli_running == 1) {
        dessert_err("CLI is already running!");
        return DESSERT_ERR;
    }

    if(port >= 1024 && port <= 49151) {
        _cli_port = port;
    }
    else {
        port = 0;
        dessert_err("Port number has to be in [1024, 49151]");
    }

    dessert_notice("CLI on port %d", _cli_port);
    return (port == 0 ? DESSERT_ERR : DESSERT_OK);
}

/** Start up the command line interface.
 *
 * @retval DESSERT_OK on success
 * @retval -errno otherwise
 *
 * %DESCRIPTION:
 *
 */
int dessert_cli_run() {
    _dessert_cli_running = 1;
    int on = 1;

    /* listen for connections */
    _dessert_cli_sock = socket(AF_INET6, SOCK_STREAM, 0);
    setsockopt(_dessert_cli_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    memset(&_dessert_cli_addr6, 0, sizeof(_dessert_cli_addr6));
    _dessert_cli_addr6.sin6_family = AF_INET6;
    _dessert_cli_addr6.sin6_addr = in6addr_any;
    _dessert_cli_addr6.sin6_port = htons(_cli_port);

    if(bind(_dessert_cli_sock, (struct sockaddr*) &_dessert_cli_addr6, sizeof(_dessert_cli_addr6))) {
        dessert_err("cli IPv6 socket bind to port %d failed - %s", _cli_port, strerror(errno));
        dessert_notice("trying IPv4 socket");

        _dessert_cli_sock = socket(AF_INET, SOCK_STREAM, 0);
        setsockopt(_dessert_cli_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        memset(&_dessert_cli_addr4, 0, sizeof(_dessert_cli_addr4));
        _dessert_cli_addr4.sin_family = AF_INET;
        _dessert_cli_addr4.sin_addr.s_addr = INADDR_ANY;
        _dessert_cli_addr4.sin_port = htons(_cli_port);

        if(bind(_dessert_cli_sock, (struct sockaddr*) &_dessert_cli_addr4, sizeof(_dessert_cli_addr4))) {
            dessert_err("cli IPv4 socket bind to port %d failed - %s", _cli_port, strerror(errno));
            return -errno;
        }
    }

    listen(_dessert_cli_sock, 8);
    dessert_debug("starting worker thread for CLI on port %d", _cli_port);
    pthread_create(&_dessert_cli_worker, NULL, _dessert_cli_accept_thread, &_dessert_cli_sock);
    return DESSERT_OK;
}

/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * C L I - C O M M A N D   L I N E   I N T E R F A C E
 *
 ******************************************************************************/

static void _dessert_cli_init_anchors() {
    dessert_cli_show = cli_register_command(
        dessert_cli,
        NULL,
        "show",
        NULL,
        PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC,
        "Display information.");

    dessert_cli_set = cli_register_command(
        dessert_cli,
        NULL,
        "set",
        NULL,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Configure parameter.");

    dessert_cli_filter = cli_register_command(
        dessert_cli,
        NULL,
        "rule",
        NULL,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Manipulate the packet filter.");

    dessert_cli_cfg_no = cli_register_command(dessert_cli,
        NULL,
        "no",
        NULL,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Negate command.");

    dessert_cli_cfg_iface = cli_register_command(dessert_cli,
        NULL,
        "interface",
        NULL,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Add or configure interfaces.");
}


/** internal function to initialize libcli */
int _dessert_cli_init() {
    dessert_cli = cli_init();

    /* set host name */
    memset(_dessert_cli_hostname, 0x0, HOST_NAME_MAX + DESSERT_PROTO_STRLEN + 1);
    gethostname(_dessert_cli_hostname, HOST_NAME_MAX);
    strncpy(_dessert_cli_hostname + strlen(_dessert_cli_hostname), ":", 1);
    strncpy(_dessert_cli_hostname + strlen(_dessert_cli_hostname), dessert_proto, DESSERT_PROTO_STRLEN);
    cli_set_hostname(dessert_cli, _dessert_cli_hostname);

    _dessert_cli_init_anchors();

    /* packet filter */
    cli_register_command(dessert_cli,
        dessert_cli_filter,
        "add",
        _dessert_cli_cmd_rule_add,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Add MAC to filter.");

    cli_register_command(dessert_cli,
        dessert_cli_filter,
        "rm",
        _dessert_cli_cmd_rule_rm,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Remove MAC from filter.");

    cli_register_command(dessert_cli,
        dessert_cli_filter,
        "default",
        _dessert_cli_cmd_rule_default,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Set default rule.");

    cli_register_command(dessert_cli,
        dessert_cli_show,
        "rules",
        _dessert_cli_cmd_show_rules,
        PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC,
        "Show packet filter rules.");

    cli_register_command(dessert_cli,
        dessert_cli_show,
        "dessert-info",
        _dessert_cli_cmd_dessertinfo,
        PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC,
        "Display information about this daemon.");

    cli_register_command(dessert_cli,
        dessert_cli_show,
        "logging",
        _dessert_cli_cmd_logging,
        PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC,
        "Show logging ringbuffer.");

    cli_register_command(dessert_cli,
        dessert_cli_show,
        "loglevel",
        _dessert_cli_cmd_show_loglevel,
        PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC,
        "Show loglevel.");

    cli_register_command(dessert_cli,
        dessert_cli_show,
        "tasks",
        _dessert_cmd_print_tasks,
        PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC,
        "Show registered tasks.");

    cli_register_command(dessert_cli,
        dessert_cli_show,
        "meshifs",
        _dessert_cli_cmd_showmeshifs,
        PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC,
        "Show list of registered mesh interfaces.");

    cli_register_command(dessert_cli,
        dessert_cli_show,
        "sysif",
        _dessert_cli_cmd_showsysif,
        PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC,
        "Show list of registered sys (TUN/TAP) interface.");

    cli_register_command(dessert_cli,
        dessert_cli_show,
        "uptime",
        _dessert_cli_cmd_showuptime,
        PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC,
        "Time since the daemon was started");

    /* initialize config mode commands */
#ifndef ANDROID
    cli_register_command(dessert_cli,
        dessert_cli_show,
        "monifs",
        _dessert_cli_cmd_showmonifs,
        PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC,
        "Show list of registered monitor interfaces.");

    cli_register_command(dessert_cli,
        dessert_cli_show,
        "mondb",
        _dessert_cli_cmd_showmondb,
        PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC,
        "Show content of monitor database.");

    cli_register_command(dessert_cli,
        dessert_cli_cfg_iface,
        "monitor",
        _dessert_cli_monitoring_start,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Create monitor interface for a IEEE 802.11 device.");

    cli_register_command(dessert_cli,
        dessert_cli_show,
        "monitor_conf",
        _dessert_cli_monitor_conf,
        PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC,
        "Configure monitor database.");
#endif

    dessert_cli_cfg_no_iface = cli_register_command(dessert_cli,
        dessert_cli_cfg_no,
        "interface",
        NULL,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Remove interface or negate interface config.");

    cli_register_command(dessert_cli,
        dessert_cli_set, "loglevel",
        _dessert_cli_cmd_set_loglevel,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Set loglevel: [debug, info, notice, warning, error, critical, emergency]");

    cli_register_command(dessert_cli,
        dessert_cli_set,
        "log_flush",
        _dessert_cli_log_interval,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Set log file flush interval [s].");

    dessert_cli_cfg_logging = cli_register_command(dessert_cli,
        NULL,
        "logging",
        NULL,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Change logging configuration.");

    dessert_cli_cfg_no_logging = cli_register_command(dessert_cli,
        dessert_cli_cfg_no,
        "logging",
        NULL,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Disable logging to...");

    cli_register_command(dessert_cli,
        dessert_cli_cfg_logging,
        "ringbuffer",
        _dessert_cli_logging_ringbuffer,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Set logging ringbuffer size [lines].");

    cli_register_command(dessert_cli,
        dessert_cli_cfg_no_logging,
        "ringbuffer",
        _dessert_cli_logging_ringbuffer,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Disable logging to ringbuffer.");

    cli_register_command(dessert_cli,
        dessert_cli_cfg_logging,
        "file",
        _dessert_cli_logging_file,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Set logfile and enable file logging.");

    cli_register_command(dessert_cli,
        dessert_cli_cfg_no_logging,
        "file",
        _dessert_cli_no_logging_file,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Disable logging to file.");

    cli_register_command(dessert_cli,
        dessert_cli_set,
        "port",
        _dessert_cli_cmd_setport,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Set TCP port for the CLI's telnet interface.");

    struct cli_command* dessert_cli_tb = cli_register_command(dessert_cli,
        dessert_cli_set,
        "tb",
        _dessert_cli_cmd_tokenbucket,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Activate, deactivate, or modify token bucket.");

    cli_register_command(dessert_cli,
        dessert_cli_tb,
        "policy",
        _dessert_cli_cmd_tokenbucket_policy,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Set token bucket policy.");

    cli_register_command(dessert_cli,
        dessert_cli_tb,
        "queue_max",
        _dessert_cli_cmd_tokenbucket_max,
        PRIVILEGE_PRIVILEGED,
        MODE_CONFIG,
        "Set token bucket maximum queue length [packets] (0 = unlimited).");

    cli_register_command(dessert_cli,
        dessert_cli_show,
        "tb",
        _dessert_cli_cmd_show_tokenbucket,
        PRIVILEGE_UNPRIVILEGED,
        MODE_EXEC,
        "Show token bucket configuration.");

    cli_register_command(dessert_cli,
        NULL,
        "pid",
        _dessert_cli_cmd_pid,
        PRIVILEGE_PRIVILEGED, MODE_CONFIG,
        "Write process id to file.");

    /* initialize other commands */
    cli_register_command(dessert_cli,
        NULL,
        "shutdown",
        _dessert_cli_cmd_shutdown,
        PRIVILEGE_PRIVILEGED,
        MODE_EXEC,
        "Shut down daemon.");
    return DESSERT_OK;
}

/******************************************************************************
 *
 * LOCAL
 *
 * C L I - C O M M A N D   L I N E   I N T E R F A C E
 *
 ******************************************************************************/

static int _dessert_cli_cmd_setport(struct cli_def* cli, char* command, char* argv[], int argc) {
    if(_dessert_cli_running == 1) {
        cli_print(dessert_cli, "CLI is already running!");
        return CLI_ERROR;
    }

    return (dessert_set_cli_port((uint16_t) atoi(argv[0])) == DESSERT_ERR ? CLI_ERROR : CLI_OK);
}

static int _dessert_cli_cmd_pid(struct cli_def* cli, char* command, char* argv[], int argc) {
    if(argc != 1) {
        cli_print(cli, "usage: pid /path/to/file.pid");
        return CLI_ERROR;
    }

    if(dessert_pid(argv[0]) == DESSERT_OK) {
        return CLI_OK;
    }

    cli_print(cli, "could not read/write/close file or pid already written: %s", argv[0]);
    return CLI_ERROR;
}

/** command "interface monitor"
* @param[in] arrysize The first parmeter defines the arraysize of a node
* @param[in] timer_range The second parameter defines how long collectes RSSI-Values are guilty
*/
#ifndef ANDROID
static int _dessert_cli_monitor_conf(struct cli_def* cli, char* command, char* argv[], int argc) {
    extern int MAX_AGE;
    extern int MAX_RSSI_VALS;
    cli_print(cli, "max_values=%d, max_age=%d", MAX_RSSI_VALS, MAX_AGE);
    return CLI_OK;
}

static int _dessert_cli_monitoring_start(struct cli_def* cli, char* command, char* argv[], int argc) {
    int max_rssi_vals = 0;
    int max_age = 0;
    int maintenance_interval = 0;

    if(argc >= 1) {
        max_rssi_vals = atoi(argv[0]);

        if(!(0 < max_rssi_vals && max_rssi_vals < INT16_MAX)) {
            max_rssi_vals = 0;
            dessert_warn("max_rssi_values is not in range [1, INT16_MAX], using default instead");
        }
    }

    if(argc >= 2) {
        max_age = atoi(argv[1]);

        if(max_age <= 0) {
            max_age = 0;
            dessert_warn("max age is not positive, using default %d", max_age);
        }
    }

    if(argc >= 3) {
        maintenance_interval = atoi(argv[2]);

        if(maintenance_interval <= 0) {
            maintenance_interval = 0;
            dessert_warn("maintenanceinterval is not positive, using default %d", max_age);
        }
    }

    dessert_monitoring_start(max_rssi_vals, max_age, maintenance_interval); // starts capt. RSSI values
    return CLI_OK;
}
#endif
/**command "show meshifs" */
static int _dessert_cli_cmd_showmeshifs(struct cli_def* cli, char* command, char* argv[], int argc) {
    dessert_meshif_t* meshif = dessert_meshiflist_get();

    if(meshif == NULL) {
        cli_print(dessert_cli, "No mesh interfaces registered!");
        return CLI_ERROR;
    }
    else {
        MESHIFLIST_ITERATOR_START(meshif) {
            _dessert_cli_cmd_showmeshifs_print_helper(cli, meshif);
        }
        MESHIFLIST_ITERATOR_STOP;
        return CLI_OK;
    }
}

/**command "show monifs" */
static int _dessert_cli_cmd_showmonifs(struct cli_def* cli, char* command, char* argv[], int argc) {
    dessert_meshif_t* meshif;
    MESHIFLIST_ITERATOR_START(meshif)

    if(meshif->monitor_active) {
        cli_print(cli, "Monitor device: [mon.%s]", meshif->if_name);
    }

    MESHIFLIST_ITERATOR_STOP;
    return CLI_OK;
}

/**command "show mondb" */
static int _dessert_cli_cmd_showmondb(struct cli_def* cli, char* command, char* argv[], int argc) {
    dessert_print_monitored_database();
    return CLI_OK;
}

/** command "show sysif" */
static int _dessert_cli_cmd_showsysif(struct cli_def* cli, char* command, char* argv[], int argc) {
    dessert_sysif_t* sysif = _dessert_sysif;

    if(sysif == NULL) {
        cli_print(cli, "\nNo system interface registered!");
        return CLI_ERROR;
    }
    else {
        cli_print(cli, "\nStatistics for system interface [%s]", sysif->if_name);
        cli_print(cli, "    MAC address           : [" MAC "]", EXPLODE_ARRAY6(sysif->hwaddr));
        cli_print(cli, "    Packets received      : [%"PRIi64"]", sysif->ipkts);
        cli_print(cli, "    Packets send          : [%"PRIi64"]", sysif->opkts);
        cli_print(cli, "    Bytes received        : [%"PRIi64"]", sysif->ibytes);
        cli_print(cli, "    Bytes send            : [%"PRIi64"]", sysif->obytes);
        return CLI_OK;
    }
}

/** command "show dessert-info" */
static int _dessert_cli_cmd_dessertinfo(struct cli_def* cli, char* command, char* argv[], int argc) {
    cli_print(cli, "\nprotocol running:   %s v %d", dessert_proto, dessert_ver);
    cli_print(cli, "libdessert version: %s", VERSION);
    cli_print(
        cli,
        " ------------------------------------------------------------------------------ ");
    cli_print(
        cli,
        " Copyright 2009, The DES-SERT Team, Freie Universitaet Berlin (FUB).            ");
    cli_print(
        cli,
        " All rights reserved.                                                           ");
    cli_print(
        cli,
        "                                                                                ");
    cli_print(
        cli,
        " These sources were originally developed by Philipp Schmidt                     ");
    cli_print(
        cli,
        " at Freie Universitaet Berlin (http://www.fu-berlin.de/),                       ");
    cli_print(
        cli,
        " Computer Systems and Telematics / Distributed, Embedded Systems (DES) group    ");
    cli_print(
        cli,
        " (http://cst.mi.fu-berlin.de/, http://www.des-testbed.net/)                     ");
    cli_print(
        cli,
        " ------------------------------------------------------------------------------ ");
    cli_print(
        cli,
        " This program is free software: you can redistribute it and/or modify it under  ");
    cli_print(
        cli,
        " the terms of the GNU General Public License as published by the Free Software  ");
    cli_print(
        cli,
        " Foundation, either version 3 of the License, or (at your option) any later     ");
    cli_print(
        cli,
        " version.                                                                       ");
    cli_print(
        cli,
        "                                                                                ");
    cli_print(
        cli,
        " This program is distributed in the hope that it will be useful, but WITHOUT    ");
    cli_print(
        cli,
        " ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS  ");
    cli_print(
        cli,
        " FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. ");
    cli_print(
        cli,
        "                                                                                ");
    cli_print(
        cli,
        " You should have received a copy of the GNU General Public License along with   ");
    cli_print(
        cli,
        " this program. If not, see http://www.gnu.org/licenses/ .                       ");
    cli_print(
        cli,
        " ------------------------------------------------------------------------------ ");
    return CLI_OK;
}

// struct cli_def* _dessert_clone_cli() {
//     struct cli_def *cli;
//     struct cli_command *c;
//
//     if (!(cli = calloc(sizeof(struct cli_def), 1)))
//         return 0;
//
//     cli->buf_size = 1024;
//     if (!(cli->buffer = calloc(cli->buf_size, 1))) {
//         free_z(cli);
//         return 0;
//     }
//
//     cli->commands = dessert_cli->commands;
//
//     cli->privilege = cli->mode = -1;
//     cli_set_privilege(cli, PRIVILEGE_UNPRIVILEGED);
//     cli_set_configmode(cli, MODE_EXEC, 0);
//
//     return cli;
// }
//
// static void *_dessert_cli_thread(void* arg) {
//   int sd = *((int*) arg);
//   struct cli_def* dessert_cli_thread = _dessert_clone_cli();;
//   cli_loop(dessert_cli_thread, sd);
//   close(sd);
//   return NULL;
// }

/** internal thread function running the cli */
static void* _dessert_cli_accept_thread(void* arg) {
    int* s = (int*) arg;
    int sd;

    while((sd = accept(*s, NULL, 0))) {
        //       pthread_t t;
        //       pthread_create(&t, NULL, _dessert_cli_thread, &sd);
        //       pthread_detach(t);
        cli_loop(dessert_cli, sd); /* pass the connection off to libcli */
        close(sd);
    }

    /* we should never get here */
    dessert_warn("sd=%d, closing CLI", sd);
    cli_done(dessert_cli); /* free data structures */

    return NULL;
}

/** internal helper function to _dessert_cli_cmd_showmeshifs */
static void _dessert_cli_cmd_showmeshifs_print_helper(struct cli_def* cli, dessert_meshif_t* meshif) {
    cli_print(cli, "\nStatistics for mesh interface [%s]", meshif->if_name);
    cli_print(cli, "    MAC address           : [" MAC "]", EXPLODE_ARRAY6(meshif->hwaddr));
    cli_print(cli, "    Packets received      : [%"PRIi64"]", meshif->ipkts);
    cli_print(cli, "    Packets send          : [%"PRIi64"]", meshif->opkts);
    cli_print(cli, "    Bytes received        : [%"PRIi64"]", meshif->ibytes);
    cli_print(cli, "    Bytes send            : [%"PRIi64"]", meshif->obytes);
    cli_print(cli, "    Token bucket          : [%s]", meshif->token_bucket.periodic == NULL ? "disabled" : "enabled");
    return;
}
