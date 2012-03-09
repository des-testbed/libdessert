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
#include <errno.h>
#include <string.h>
#include <netinet/ip.h>

struct cli_def* _dessert_callbacks_cli;

/** add initial trace header to dessert message
 * @arg *msg dessert_msg_t message used for tracing
 * @arg type DESSERT_EXT_TRACE_REQ or DESSERT_EXT_TRACE_RPL
 * @arg mode trace mode
 *           use DESSERT_MSG_TRACE_HOST to only record default mac of hosts on the way
 *           use DESSERT_MSG_TRACE_IFACE to also trace input interface and last hop
 * @return DESSERT_OK on success
 **/
int dessert_msg_trace_initiate(dessert_msg_t* msg, uint8_t type, int mode) {

    dessert_ext_t* ext;
    struct ether_header* l25h;

    if(type != DESSERT_EXT_TRACE_REQ && type != DESSERT_EXT_TRACE_RPL) {
        return EINVAL;
    }

    if(mode != DESSERT_MSG_TRACE_HOST && mode != DESSERT_MSG_TRACE_IFACE) {
        return EINVAL;
    }

    if(msg->flags & DESSERT_RX_FLAG_SPARSE) {
        return DESSERT_MSG_NEEDNOSPARSE;
    }

    dessert_msg_addext(msg, &ext, type, mode);
    memcpy((ext->data), dessert_l25_defsrc, ETHER_ADDR_LEN);

    if(mode == DESSERT_MSG_TRACE_IFACE) {
        memcpy((ext->data) + ETHER_ADDR_LEN, msg->l2h.ether_shost,
               ETHER_ADDR_LEN);
        l25h = dessert_msg_getl25ether(msg);

        if(l25h == NULL) {
            memcpy((ext->data) + ETHER_ADDR_LEN, ether_null, ETHER_ADDR_LEN);
        }
        else {
            memcpy((ext->data) + ETHER_ADDR_LEN * 2, l25h->ether_shost,
                   ETHER_ADDR_LEN);
        }
    }

    return DESSERT_OK;

}

/** Trace route to destination
 *
 * Sends a packet with a trace request to a host. You will
 * asynchronously receive a reply if the destination is present in
 * in the network and no packet is lost.
 *
 * @param cli the handle of the cli structure. This must be passed to all cli functions, including cli_print().
 * @param command the entire command which was entered. This is after command expansion.
 * @param argv the list of arguments entered
 * @param argc the number of arguments entered
 *
 * @retval CLI_OK if trace packet sent
 * @retval CLI_ERROR on error
 */
int dessert_cli_cmd_traceroute(struct cli_def* cli, char* command, char* argv[], int argc) {
    u_char ether_trace[ETHER_ADDR_LEN];
    dessert_msg_t* msg;
    dessert_ext_t* ext;
    struct ether_header* l25h;

    if(argc < 1 || argc > 2 ||
       sscanf(argv[0], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
              &ether_trace[0], &ether_trace[1], &ether_trace[2],
              &ether_trace[3], &ether_trace[4], &ether_trace[5]) != 6
      ) {
        cli_print(cli, "usage %s [mac-address in xx:xx:xx:xx:xx:xx notation] ([i])\n", command);
        return CLI_ERROR;
    }

    cli_print(cli, "sending trace packet to " MAC " ...\n", EXPLODE_ARRAY6(ether_trace));
    dessert_info("sending trace packet to " MAC, EXPLODE_ARRAY6(ether_trace));

    dessert_msg_new(&msg);

    dessert_msg_addext(msg, &ext, DESSERT_EXT_ETH, ETHER_HDR_LEN);
    l25h = (struct ether_header*) ext->data;
    memcpy(l25h->ether_shost, dessert_l25_defsrc, ETHER_ADDR_LEN);
    memcpy(l25h->ether_dhost, ether_trace, ETHER_ADDR_LEN);
    l25h->ether_type = htons(0x0000);

    if(argc == 2 && argv[1][0] == 'i') {
        dessert_msg_trace_initiate(msg, DESSERT_EXT_TRACE_REQ, DESSERT_MSG_TRACE_IFACE);
    }
    else {
        dessert_msg_trace_initiate(msg, DESSERT_EXT_TRACE_REQ, DESSERT_MSG_TRACE_HOST);
    }

    dessert_meshsend(msg, NULL);
    dessert_msg_destroy(msg);

    _dessert_callbacks_cli = cli;

    return CLI_OK;
}

/** Handle trace packets
 *
 * Prints the content of a trace request packet and sends the same packet with
 * an appended trace reply extension back if no trace reply is yet present.
 * If there is a trace request and a trace reply extension, both are printed but
 * no packet is send.
 * The whole trace mechanism is basically a ping/pong with additional tracing.
 *
 * @param *msg dessert_msg_t frame received
 * @param len length of the buffer pointed to from dessert_msg_t
 * @param *proc local processing buffer passed along the callback pipeline - may be NULL
 * @param *meshif interface received packet on - may be NULL
 * @param id unique internal frame id of the packet
 *
 * @retval DESSERT_MSG_DROP if this host is the destination of the trace request
 * @retval DESSERT_MSG_KEEP if this host is not the destination of the trace request
 */
dessert_cb_result dessert_mesh_trace(dessert_msg_t* msg, uint32_t len, dessert_msg_proc_t* proc, dessert_meshif_t* meshif, dessert_frameid_t id) {

    struct ether_header* l25h = dessert_msg_getl25ether(msg);

    if(l25h && proc->lflags & DESSERT_RX_FLAG_L25_DST) {
        char buf[1024];
        memset(buf, 0x0, sizeof(buf));

        dessert_ext_t* request_ext;

        if(dessert_msg_getext(msg, &request_ext, DESSERT_EXT_TRACE_REQ, 0)) {

            dessert_msg_trace_dump(msg, DESSERT_EXT_TRACE_REQ, buf, sizeof(buf));

            dessert_debug("trace request from " MAC "\n%s", EXPLODE_ARRAY6(l25h->ether_shost), buf);

            if(_dessert_callbacks_cli != NULL) {
                cli_print(_dessert_callbacks_cli, "\ntrace request from " MAC "\n%s", EXPLODE_ARRAY6(l25h->ether_shost), buf);
            }

            uint8_t temp[ETHER_ADDR_LEN];
            memcpy(temp, l25h->ether_shost, ETHER_ADDR_LEN);
            memcpy(l25h->ether_shost, l25h->ether_dhost, ETHER_ADDR_LEN);
            memcpy(l25h->ether_dhost, temp, ETHER_ADDR_LEN);

            int len = dessert_ext_getdatalen(request_ext) == DESSERT_MSG_TRACE_IFACE ? DESSERT_MSG_TRACE_IFACE : DESSERT_MSG_TRACE_HOST;
            dessert_msg_trace_initiate(msg, DESSERT_EXT_TRACE_RPL, len);
            dessert_meshsend(msg, NULL);
            return DESSERT_MSG_DROP;
        }

        dessert_ext_t* reply_ext;

        if(dessert_msg_getext(msg, &reply_ext, DESSERT_EXT_TRACE_RPL, 0)) {
            dessert_msg_trace_dump(msg, DESSERT_EXT_TRACE_RPL, buf, sizeof(buf));

            dessert_debug("trace reply from " MAC "\n%s", EXPLODE_ARRAY6(l25h->ether_shost), buf);

            if(_dessert_callbacks_cli != NULL) {
                cli_print(_dessert_callbacks_cli, "\ntrace reply from " MAC "\n%s", EXPLODE_ARRAY6(l25h->ether_shost), buf);
            }

            return DESSERT_MSG_DROP;
        }
    }

    return DESSERT_MSG_KEEP;
}

