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
#include <string.h>
#include <netinet/ip.h>

struct cli_def* _dessert_callbacks_cli;

/** Send a ping packet
 *
 * @param cli the handle of the cli structure. This must be passed to all cli functions, including cli_print().
 * @param command the entire command which was entered. This is after command expansion.
 * @param argv the list of arguments entered
 * @param argc the number of arguments entered
 *
 * @retval CLI_OK if ping sent
 * @retval CLI_ERROR on error
 */
int dessert_cli_cmd_ping(struct cli_def* cli, char* command, char* argv[], int argc) {
    u_char ether_trace[ETHER_ADDR_LEN];
    dessert_msg_t* msg;
    dessert_ext_t* ext;
    struct ether_header* l25h;

    if(argc < 1 || argc > 2 ||
       sscanf(argv[0], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
              &ether_trace[0], &ether_trace[1], &ether_trace[2],
              &ether_trace[3], &ether_trace[4], &ether_trace[5]) != 6
      ) {
        cli_print(cli, "usage %s [mac-address in xx:xx:xx:xx:xx:xx notation] ([text])\n", command);
        return CLI_ERROR;
    }

    cli_print(cli, "sending ping packet to " MAC "...\n", EXPLODE_ARRAY6(ether_trace));
    dessert_info("sending ping packet to " MAC, EXPLODE_ARRAY6(ether_trace));

    dessert_msg_new(&msg);

    dessert_msg_addext(msg, &ext, DESSERT_EXT_ETH, ETHER_HDR_LEN);
    l25h = (struct ether_header*) ext->data;
    memcpy(l25h->ether_shost, dessert_l25_defsrc, ETHER_ADDR_LEN);
    memcpy(l25h->ether_dhost, ether_trace, ETHER_ADDR_LEN);
    l25h->ether_type = htons(0x0000);

    if(argc == 2) {
        int len = strlen(argv[1]);
        len = len > DESSERT_MAXEXTDATALEN ? DESSERT_MAXEXTDATALEN : len;
        dessert_msg_addext(msg, &ext, DESSERT_EXT_PING, len);
        memcpy(ext->data, argv[1], len);
    }
    else {
        dessert_msg_addext(msg, &ext, DESSERT_EXT_PING, 5);
        memcpy(ext->data, "ping", 5);
    }

    dessert_meshsend(msg, NULL);
    dessert_msg_destroy(msg);

    _dessert_callbacks_cli = cli;

    return CLI_OK;
}

/** Handle ping packets
 *
 * @param *msg dessert_msg_t frame received
 * @param len length of the buffer pointed to from dessert_msg_t
 * @param *proc local processing buffer passed along the callback pipeline - may be NULL
 * @param *meshif interface received packet on - may be NULL
 * @param id unique internal frame id of the packet
 *
 * @retval DESSERT_MSG_DROP if the ping is destined to this host
 * @retval DESSERT_MSG_KEEP if some other host is the destination
 */
dessert_cb_result dessert_mesh_ping(dessert_msg_t* msg, uint32_t len, dessert_msg_proc_t* proc, dessert_meshif_t* meshif, dessert_frameid_t id) {
    dessert_ext_t* ext;
    struct ether_header* l25h;
    u_char temp[ETHER_ADDR_LEN];

    l25h = dessert_msg_getl25ether(msg);

    if(l25h
       && proc->lflags & DESSERT_RX_FLAG_L25_DST
       && dessert_msg_getext(msg, &ext, DESSERT_EXT_PING, 0)) {

        dessert_debug("got ping packet from " MAC " - sending pong", EXPLODE_ARRAY6(l25h->ether_shost));

        memcpy(temp, l25h->ether_shost, ETHER_ADDR_LEN);
        memcpy(l25h->ether_shost, l25h->ether_dhost, ETHER_ADDR_LEN);
        memcpy(l25h->ether_dhost, temp, ETHER_ADDR_LEN);
        ext->type = DESSERT_EXT_PONG;
        memcpy(ext->data, "pong", 5);
        dessert_meshsend(msg, NULL);

        return DESSERT_MSG_DROP;
    }

    return DESSERT_MSG_KEEP;
}

/** Handle pong packets
 *
 * @param *msg dessert_msg_t frame received
 * @param len length of the buffer pointed to from dessert_msg_t
 * @param *proc local processing buffer passed along the callback pipeline - may be NULL
 * @param *meshif interface received packet on - may be NULL
 * @param id unique internal frame id of the packet
 *
 * @retval DESSERT_MSG_DROP if the pong is destined to this host
 * @retval DESSERT_MSG_KEEP if some other host is the destination
 */
dessert_cb_result dessert_mesh_pong(dessert_msg_t* msg, uint32_t len, dessert_msg_proc_t* proc, dessert_meshif_t* meshif, dessert_frameid_t id) {
    dessert_ext_t* ext;
    struct ether_header* l25h;
    u_char temp[ETHER_ADDR_LEN];

    l25h = dessert_msg_getl25ether(msg);

    if(l25h
       && proc->lflags & DESSERT_RX_FLAG_L25_DST
       && dessert_msg_getext(msg, &ext, DESSERT_EXT_PONG, 0)) {
        dessert_debug("got pong packet from " MAC, EXPLODE_ARRAY6(l25h->ether_shost));

        if(_dessert_callbacks_cli != NULL)
            cli_print(_dessert_callbacks_cli, "\ngot pong packet from " MAC, EXPLODE_ARRAY6(l25h->ether_shost));

        return DESSERT_MSG_DROP;
    }

    return DESSERT_MSG_KEEP;
}
