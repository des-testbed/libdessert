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

/* global data storage // P R I V A T E */

/* local data storage*/

/* internal functions forward declarations*/

/******************************************************************************
 *
 * EXTERNAL / PUBLIC
 *
 * M E S S A G E   H A N D L I N G
 *
 ******************************************************************************/

/** creates a new dessert_msg_t and initializes it.
 * @arg **msgout (out) pointer to return message address
 * @return DESSERT_OK on success, -errno on error
 **/
int dessert_msg_new(dessert_msg_t** msgout) {
    dessert_msg_t* msg = calloc(dessert_maxlen, 1);

    msg->l2h.ether_type = htons(DESSERT_ETHPROTO);
    memset(msg->l2h.ether_dhost, 0xff, ETHER_ADDR_LEN);
    memcpy(msg->proto, dessert_proto, DESSERT_PROTO_STRLEN);
    msg->ver = dessert_ver;
    msg->ttl = 0xff;
    msg->u8 = 0x00;
    msg->u16 = htons(0xbeef);
    msg->hlen = htons(sizeof(dessert_msg_t));
    msg->plen = htons(0);

    *msgout = msg;
    return DESSERT_OK;
}

/** generates a copy of a dessert_msg
 * @arg **msgnew (out) pointer to return message address
 * @arg *msgold pointer to the message to clone
 * @arg sparse whether to allocate DESSERT_MAXFRAMELEN or only hlen+plen
 * @return DESSERT_OK on success, -errno otherwise
 **/
int dessert_msg_clone(dessert_msg_t** msgnew, const dessert_msg_t* msgold, bool sparse) {
    dessert_msg_t* msg;
    uint32_t msglen = ntohs(msgold->hlen) + ntohs(msgold->plen);

    if(sparse) {
        msg = malloc(msglen);
    }
    else {
        uint32_t len = dessert_maxlen;

        if(len < msglen) {
            dessert_warn("msg has size %d but current dessert_maxlen is %d\n The msg will be fragmented.", msglen, dessert_maxlen);
            len = msglen;
        }

        msg = malloc(len);
    }

    if(msg == NULL) {
        dessert_crit("could not allocate memory");
        return (-errno);
    }

    memcpy(msg, msgold, msglen);

    if(sparse) {
        msg->flags |= DESSERT_RX_FLAG_SPARSE;
    }
    else {
        msg->flags &= ~DESSERT_RX_FLAG_SPARSE;
    }

    *msgnew = msg;
    return (DESSERT_OK);
}

/** checks whether a dessert_msg is consistent
 * @arg msg the message to be checked
 * @arg len the length of the buffer
 * @return  DESSERT_OK on success
 * @return -1 of the message is too large for the buffer
 * @return -2 if the message was not intended to this daemon
 * @return -3 if some extension is not consistent
 * %DESCRIPTION:
 */
int dessert_msg_check(const dessert_msg_t* msg, uint32_t len) {
    /* is the message large enough to at least carry the header */
    if(len < DESSERT_MSGLEN) {
        dessert_info("message too short - shorter than DESSERT_MSGLEN");
        return (-1);
    }

    if(ntohs(msg->hlen) + ntohs(msg->plen) > len) {
        dessert_info("message too short - shorter than header + payload");
        return (-1);
    }

    /* right protocol and version */
    /// \todo use memcmp
    if(msg->proto[0] != dessert_proto[0] || msg->proto[1] != dessert_proto[1]
       || msg->proto[2] != dessert_proto[2] || msg->proto[3]
       != dessert_proto[3]) {
        dessert_info("wrong dessert protocol");
        return (-2);
    }

    if(msg->ver != dessert_ver) {
        dessert_info("wrong dessert protocol version");
        return (-2);
    }

    /* now check extensions.... */
    dessert_ext_t* ext = (dessert_ext_t*)((uint8_t*) msg + DESSERT_MSGLEN);

    while((uint8_t*) ext < ((uint8_t*) msg + (uint32_t) ntohs(msg->hlen))) {
        /* does current extension fit into the header? */
        if(((uint8_t*) ext + (uint32_t) ext->len) > ((uint8_t*) msg + (uint32_t) ntohs(msg->hlen))) {
            dessert_info("extension %x too long", ext->type);
            return (-3);
        }

        if(ext->len < 2) {
            dessert_info("extension %x too short", ext->type);
            return (-3);
        }

        ext = (dessert_ext_t*)((uint8_t*) ext + (uint32_t) ext->len);
    }

    /* message is valid */
    return DESSERT_OK;
}

/** dump a dessert_msg_t to a string
 * @arg *msg the message to be dumped
 * @arg len the length of the buffer
 * @arg *buf text output buffer
 * @arg blen text output buffer length
 *
 * \todo remove len parameter
 **/
void dessert_msg_dump(const dessert_msg_t* msg, uint32_t len, char* buf, uint32_t blen) {
    dessert_msg_proc_dump(msg, len, NULL, buf, blen);
}

/** free a dessert_msg
 * @arg *msg message to free
 **/
void dessert_msg_destroy(dessert_msg_t* msg) {
    free(msg);
}

/** creates a new dessert_msg from an Ethernet frame.
 * @arg *eth Ethernet frame to encapsulate
 * @arg len length of the ethernet frame
 * @arg **msgout (out) pointer to return message address
 * @return DESSERT_OK on success, -errno otherwise
 **/
int dessert_msg_ethencap(const struct ether_header* eth, uint32_t eth_len, dessert_msg_t** msgout) {
    /* check len */
    if(eth_len > dessert_maxlen - (DESSERT_MSGLEN + ETHER_HDR_LEN)) {
        dessert_crit("failed to encapsulate ethernet frame of %d bytes (max=%d)", eth_len, dessert_maxlen - (DESSERT_MSGLEN + ETHER_HDR_LEN));
        return (-EMSGSIZE);
    }

    /* create message */
    int res = dessert_msg_new(msgout);

    if(res) {
        return res;
    }

    /* add ether header */
    dessert_ext_t* ext;
    res = dessert_msg_addext(*msgout, &ext, DESSERT_EXT_ETH, ETHER_HDR_LEN);

    if(res) {
        return res;
    }

    memcpy(ext->data, eth, ETHER_HDR_LEN);

    /* copy message */
    void* payload;
    dessert_msg_addpayload(*msgout, &payload, (eth_len - ETHER_HDR_LEN));
    memcpy(payload, ((uint8_t*) eth) + ETHER_HDR_LEN, (eth_len - ETHER_HDR_LEN));

    return (DESSERT_OK);
}

/** creates a new dessert_msg from an ip datagram.
 * @arg *ip datagram to encapsulate
 * @arg len length of the datagram
 * @arg **msgout (out) pointer to return message address
 * @return DESSERT_OK on success, -errno otherwise
 **/
int dessert_msg_ipencap(const uint8_t* ip, uint32_t len, dessert_msg_t** msgout) {
    int res;
    void* payload;
    uint32_t maxlen = dessert_maxlen;

    /* check len */
    if(len > maxlen - DESSERT_MSGLEN) {
        dessert_debug("failed to encapsulate ip datagram of %d bytes (max=%d)", len, maxlen - DESSERT_MSGLEN);
        return (-EMSGSIZE);
    }

    /* create message */
    res = dessert_msg_new(msgout);

    if(res) {
        return res;
    }

    /* copy message */
    dessert_msg_addpayload(*msgout, &payload, len);
    memcpy(payload, ((uint8_t*) ip), len);

    return (DESSERT_OK);
}

/** extracts an ethernet frame from a dessert_msg
 * @arg *msg    pointer to dessert_msg message to decapsulate
 * @arg **ethout (out) pointer to return ethernet message
 * @return eth_len on success, -1 otherwise
 **/
int dessert_msg_ethdecap(const dessert_msg_t* msg, struct ether_header** ethout) {
    dessert_ext_t* ext;
    int res;

    /* create message */
    uint32_t eth_len = ntohs(msg->plen) + ETHER_HDR_LEN;
    *ethout = malloc(eth_len);

    if(*ethout == NULL) {
        return (-1);
    }

    /* copy header */
    res = dessert_msg_getext(msg, &ext, DESSERT_EXT_ETH, 0);

    if(res != 1) {
        free(ethout);
        return (-1);
    }

    memcpy(*ethout, ext->data, ETHER_HDR_LEN);

    /* copy message */
    memcpy(((uint8_t*)(*ethout)) + ETHER_HDR_LEN, (((uint8_t*) msg) + ntohs(msg->hlen)), ntohs(msg->plen));

    return (eth_len);
}

/** extract an ip datagram from a dessert_msg
 * @arg *msg    pointer to dessert_msg message to decapsulate
 * @arg **ip (out) pointer to return datagram
 * @return len of datagram on success, -1 otherwise
 **/
int dessert_msg_ipdecap(const dessert_msg_t* msg, uint8_t** ip) {
    /* create message */
    uint32_t len = ntohs(msg->plen);
    *ip = malloc(len);

    if(*ip == NULL) {
        return (-1);
    }

    /* copy message */
    memcpy(*ip, ((uint8_t*) msg) + ntohs(msg->hlen), ntohs(msg->plen));

    return (len);
}

/** get the ether_header sent as DESSERT_EXT_ETH in a dessert_msg
 * @arg *msg the message
 * @return pointer to ether_header data, NULL if DESSERT_EXT_ETH not present
 **/
struct ether_header* dessert_msg_getl25ether(const dessert_msg_t* msg) {
    dessert_ext_t* ext;
    struct ether_header* l25h;
    int res;

    res = dessert_msg_getext(msg, &ext, DESSERT_EXT_ETH, 0);

    if(res != 1) {
        l25h = NULL;
    }
    else {
        l25h = (struct ether_header*) ext->data;
    }

    return l25h;
}

/** generates a copy of a dessert_msg_proc
 * @arg **procnew (out) pointer to return message address
 * @arg *procold pointer to the message to clone
 * @return DESSERT_OK on success, -errno otherwise
 **/
int dessert_msg_proc_clone(dessert_msg_proc_t** procnew, const dessert_msg_proc_t* procold) {
    if(procold == NULL) {
        *procnew = (dessert_msg_proc_t*) procold;
        return (DESSERT_OK);
    }

    dessert_msg_proc_t* proc;

    proc = malloc(DESSERT_MSGPROCLEN);

    if(proc == NULL) {
        return (-errno);
    }

    memcpy(proc, procold, DESSERT_MSGPROCLEN);

    *procnew = proc;
    return (DESSERT_OK);
}

/** dump a dessert_msg_t to a string
 * @arg *msg the message to be dumped
 * @arg len the length of the buffer
 * @arg *proc the processing buffer
 * @arg *buf text output buffer
 * @arg blen text output buffer length
 *
 * \todo remove len parameter
 **/
void dessert_msg_proc_dump(const dessert_msg_t* msg, uint32_t len, const dessert_msg_proc_t* proc, char* buf, uint32_t blen) {
    dessert_ext_t* ext;
    int extidx = 0;

    struct ether_header* l25h;

#define _dessert_msg_check_append(...) snprintf(buf+strlen(buf), blen-strlen(buf), __VA_ARGS__)
    memset((void*) buf, 0, blen);

    _dessert_msg_check_append("\tl2_dhost: " MAC "\n", EXPLODE_ARRAY6(msg->l2h.ether_dhost));
    _dessert_msg_check_append("\tl2_shost: " MAC "\n", EXPLODE_ARRAY6(msg->l2h.ether_shost));
    _dessert_msg_check_append("\tl2_type:   %x\n\n", ntohs(msg->l2h.ether_type));

    _dessert_msg_check_append("\tproto:     ");
    strncpy(buf + strlen(buf), msg->proto, DESSERT_PROTO_STRLEN);
    _dessert_msg_check_append("\n\tver:       %d\n", msg->ver);

    _dessert_msg_check_append("\tflags:    ");

    if(msg->flags & DESSERT_RX_FLAG_SPARSE) {
        _dessert_msg_check_append(" SPARSE");
    }

    _dessert_msg_check_append("\n\tttl:  %x\n", (msg->ttl));
    _dessert_msg_check_append("\tu8:  %x\n", (msg->u8));
    _dessert_msg_check_append("\tu16:  %x\n", ntohs(msg->u16));
    _dessert_msg_check_append("\thlen:      %d\n", ntohs(msg->hlen));
    _dessert_msg_check_append("\tplen:      %d\n\n", ntohs(msg->plen));

    /* get l2.5 header if possible */
    if((l25h = dessert_msg_getl25ether(msg)) != NULL) {
        _dessert_msg_check_append("\tl25 proto: ethernet\n");

        _dessert_msg_check_append("\tl25_dhost: " MAC "\n", EXPLODE_ARRAY6(l25h->ether_dhost));
        _dessert_msg_check_append("\tl25_shost: " MAC "\n", EXPLODE_ARRAY6(l25h->ether_shost));
        _dessert_msg_check_append("\tl25_type:  %x\n\n", ntohs(l25h->ether_type));

    }

    /* we have a trace */
    if(dessert_msg_trace_dump(msg, DESSERT_EXT_TRACE_REQ, buf, blen - strlen(buf)) > 1) {
        _dessert_msg_check_append("\n");
    }

    if(dessert_msg_trace_dump(msg, DESSERT_EXT_TRACE_RPL, buf, blen - strlen(buf)) > 1) {
        _dessert_msg_check_append("\n");
    }

    /* now other extensions.... */
    ext = (dessert_ext_t*)((uint8_t*) msg + DESSERT_MSGLEN);

    while((uint8_t*) ext < ((uint8_t*) msg + (uint32_t) ntohs(msg->hlen))) {
        _dessert_msg_check_append("\textension %d:\n", extidx);

        /* does current extension fit into the header? */
        if((((uint8_t*) ext + (uint32_t) ext->len) > ((uint8_t*) msg + (uint32_t) ntohs(msg->hlen)))
           || (ext->len < 2)) {
            _dessert_msg_check_append("\t\tbroken extension - giving up!\n");
            break;
        }

        _dessert_msg_check_append("\t\ttype:      0x%02x\n", ext->type);
        _dessert_msg_check_append("\t\tlen:       %d\n", ext->len);

        if(ext->type != DESSERT_EXT_ETH && ext->type != DESSERT_EXT_TRACE_REQ) {
            _dessert_msg_check_append("\t\tdata:      ");
            unsigned int i;

            for(i = 0; i < dessert_ext_getdatalen(ext); i++) {
                _dessert_msg_check_append("0x%x ", ext->data[i]);

                if(i % 12 == 1 && i != 1) {
                    _dessert_msg_check_append("\t\t           ");
                }
            }
        }

        _dessert_msg_check_append("\n");

        ext = (dessert_ext_t*)((uint8_t*) ext + (uint32_t) ext->len);
        extidx++;
    }

    if(proc != NULL) {
        _dessert_msg_check_append("\tlocal processing header:\n");
        _dessert_msg_check_append("\tlflags:    ");

        if(proc->lflags & DESSERT_RX_FLAG_L25_SRC) {
            _dessert_msg_check_append(" DESSERT_FLAG_SRC_SELF");
        }

        if(proc->lflags & DESSERT_RX_FLAG_L25_DST) {
            _dessert_msg_check_append(" DESSERT_FLAG_DST_MULTICAST");
        }

        if(proc->lflags & DESSERT_RX_FLAG_L25_MULTICAST) {
            _dessert_msg_check_append(" DESSERT_FLAG_DST_SELF");
        }

        if(proc->lflags & DESSERT_RX_FLAG_L25_BROADCAST) {
            _dessert_msg_check_append(" DESSERT_FLAG_DST_BROADCAST");
        }

        if(proc->lflags & DESSERT_RX_FLAG_L2_SRC) {
            _dessert_msg_check_append(" DESSERT_FLAG_PREVHOP_SELF");
        }

        if(proc->lflags & DESSERT_RX_FLAG_L2_DST) {
            _dessert_msg_check_append(" NEXTHOP_SELF");
        }

        if(proc->lflags & DESSERT_RX_FLAG_L2_BROADCAST) {
            _dessert_msg_check_append(" NEXTHOP_BROADCAST");
        }
    }
}

/** free a dessert_prc_msg
 * @arg *proc processing buffer to free
 **/
void dessert_msg_proc_destroy(dessert_msg_proc_t* proc) {
    free(proc);
}

/** add or replace payload to a dessert_msg
 * @arg *msg the message the payload should be added to
 * @arg **payload (out) the pointer to place the payload
 * @arg len the length of the payload
 * @return DESSERT_OK on success, DESSERT_ERR otherwise
 **/
dessert_result dessert_msg_addpayload(dessert_msg_t* msg, void** payload, int len) {
    /* check payload */
    if((unsigned int) len > dessert_maxlen - ntohs(msg->hlen)) {
        return DESSERT_ERR; /* too big */
    }

    /* export payload pointer */
    *payload = ((uint8_t*) msg + ntohs(msg->hlen));
    msg->plen = htons(len);

    return DESSERT_OK;
}

/** Append dummy payload
 *
 * Force a minumum size of the packet. This function should be called only
 * when all extensions have already been appended. Do not call this function
 * when there is already a payload! If the packet is aready large enough,
 * no payload is appended.
 *
 * @param msg packet that shall have a minimum size
 * @param min_size minimum size
 * @return DESSERT_ERR on error, else DESSERT_OK
 */
dessert_result dessert_msg_dummy_payload(dessert_msg_t* msg, uint32_t min_size) {
    void* payload;
    uint32_t msglen = ntohs(msg->hlen) + ntohs(msg->plen);
    uint32_t size = max(min_size - msglen, 0);
    if(dessert_msg_addpayload(msg, &payload, size) == DESSERT_OK) {
        memset(payload, 0xA, size);
    }
    else {
        dessert_warn("could not append dummy payload");
        return DESSERT_ERR;
    }
    return DESSERT_OK;
}

/** Retrieves a pointer to the payload of a dessert message @a msg.
 *
 * @param[in] *msg the message the payload should be retrieved from
 * @param[out] **payload the pointer to place the payload in
 *
 * @return the length of the payload in bytes if any, 0 otherwise
 */
int dessert_msg_getpayload(dessert_msg_t* msg, void** payload) {

    /* test if payload is present in msg */
    if(msg->plen == 0) {
        *payload = NULL;
        return 0;
    }

    *payload = (uint8_t*) msg + ntohs(msg->hlen);

    return msg->plen;
}


/** add an extension record to a dessert_msg
 * @arg *msg  the message the extension should be added to
 * @arg **ext (out) the extension pointer to the reserved extension space
 * @arg type the type of the extension
 * @arg len  the length of the ext data (without 2 byte extension header)
 * @return DESSERT_OK on success, -2 if ext too big or message too large (incl. ext), -3 if extension smaller than ext header
 **/
int dessert_msg_addext(dessert_msg_t* msg, dessert_ext_t** ext, uint8_t type, uint32_t len) {

    /* check if sparse message */
    if((msg->flags & DESSERT_RX_FLAG_SPARSE) > 0) {
        dessert_crit("tried to add extension to a sparse message - use dessert_msg_clone() first!");
        return -1;
    }

    /* add DESSERT_EXTLEN to len for convenience*/
    len += DESSERT_EXTLEN;

    /* check ext */
    if(len > dessert_maxlen - ntohs(msg->hlen) - ntohs(msg->plen)) {
        dessert_crit("message would be too large after adding extension!");
        return -2; /* too big */
    }
    else if(len < DESSERT_EXTLEN) {
        dessert_crit("extension too small!");
        return -3; /* too small */
    }
    else if(len > min(DESSERT_MAXEXTDATALEN + DESSERT_EXTLEN, 256)) { // min() for misconfiguration
        dessert_crit("extension too big!");
        return -2; /* too big */
    }

    /* move payload if necessary */
    if(ntohs(msg->plen) > 0) {
        memmove(((uint8_t*) msg + ntohs(msg->hlen) + len), ((uint8_t*) msg + ntohs(msg->hlen)), ntohs(msg->plen));
    }

    /* get ext addr */
    *ext = (dessert_ext_t*)((uint8_t*) msg + ntohs(msg->hlen));

    /* update msg hlen */
    msg->hlen = htons(ntohs(msg->hlen) + len);

    /* copy in extension data */
    (*ext)->len = len;
    (*ext)->type = type;

    return DESSERT_OK;
}

/** remove an extension record from a dessert_msg
 * @arg *msg  the message the extension should be added to
 * @arg *ext (out) the extension pointer to the extension to be removed
 * @return DESSERT_OK on success, else DESSERT_ERR
 **/
dessert_result dessert_msg_delext(dessert_msg_t* msg, dessert_ext_t* ext) {
    /* check ext */
    if((((uint8_t*) ext) < ((uint8_t*) msg))
       || (((uint8_t*) ext) > (((uint8_t*) msg) + ntohs(msg->hlen)))) {
        dessert_debug("extension not within packet header - won't remove");
        return DESSERT_ERR;
    }

    msg->hlen = htons(ntohs(msg->hlen) - ext->len);

    memmove(ext, ((uint8_t*) ext) + ext->len, (ntohs(msg->hlen) + ntohs(msg->plen)) - (((uint8_t*) ext) - ((uint8_t*) msg)));

    return DESSERT_OK;
}

/** Resizes a given extension record @a ext within in a @b dessert @b message
 *  @a msg to the new length @a new_len.
 *
 * @param[in] *msg the message
 * @param[in] *ext the extension record
 * @param[in] new_len the new length of the extension record
 *
 * @retval DESSERT_OK on success, -2 if ext too big or message too large (incl. ext), -3 if extension smaller than ext header
 *
 * %DESCRIPTION:
 **/
int dessert_msg_resizeext(dessert_msg_t* msg, dessert_ext_t* ext, uint32_t new_len) {
    int old_len = ext->len;

    /* check ext */
    if(new_len > dessert_maxlen - ntohs(msg->hlen) - ntohs(msg->plen) - old_len) {
        dessert_debug("message would be too large after adding extension!");
        return -2; /* too big */
    }
    else if(new_len < DESSERT_EXTLEN) {
        dessert_debug("extension too small!");
        return -3; /* too small */
    }
    else if(new_len > 255) {
        dessert_debug("extension too big!");
        return -2; /* too big */
    }

    memmove(((uint8_t*)ext) + new_len, ((uint8_t*)ext) + ext->len, ntohs(msg->hlen) + ntohs(msg->plen) - (((uint8_t*) ext) - ((uint8_t*) msg)) - ext->len);

    msg->hlen = htons(ntohs(msg->hlen) - (ext->len - new_len));
    ext->len = new_len;

    return DESSERT_OK;
}

/** get an specific or all extensions
 *
 * @arg *msg the message
 * @arg **ext (out) pointer to extracted extension
 *                  sets *ext=NULL if  extension not found
 *                  may be NULL in this case only count/existence matters
 * @arg type type of the ext to retrieve - use DESSERT_EXT_ANY to get any ext
 * @arg index the index of the extension of that type, starting with 0
 * @return  0 if the message has no such extension,
 * @return count of extensions of that type if count > index
 * @return -count of extensions of that type if count <= index
 **/
int dessert_msg_getext(const dessert_msg_t* msg, dessert_ext_t** ext, uint8_t type, int index) {
    int i = 0;
    dessert_ext_t* exti;

    if(ext != NULL) {
        *ext = NULL;
    }

    exti = (dessert_ext_t*)((uint8_t*) msg + DESSERT_MSGLEN);

    while((uint8_t*) exti < ((uint8_t*) msg + (uint32_t) ntohs(msg->hlen))) {
        /* does current extension fit into the header? */
        if(type == exti->type || type == DESSERT_EXT_ANY) {
            if(i == index && ext != NULL) {
                *ext = exti;
            }

            i++;
        }

        exti = (dessert_ext_t*)(((uint8_t*) exti) + (uint32_t) exti->len);
    }

    if(i <= index) {
        i = -i;
    }

    return (i);
}

/** Get a specific or all extensions
 *
 * @arg *msg the message
 * @arg type type of the ext to retrieve - use DESSERT_EXT_ANY to get any ext
 * @return  0 if the message has no such extension,
 * @return count of extensions of that type
 **/
int dessert_msg_get_ext_count(const dessert_msg_t* msg, uint8_t type) {
    return dessert_msg_getext(msg, NULL, type, 0);
}

/** callback that checks whether a dessert_msg is consistent
 * @arg *msg dessert_msg_t frame received
 * @arg len length of ethernet frame received
 * @arg *iface interface received packet on
 * @return DESSERT_MSG_KEEP if message is valid, DESSERT_MSG_DROP otherwise
 **/
dessert_cb_result dessert_msg_check_cb(dessert_msg_t* msg, uint32_t len, dessert_msg_proc_t* proc, dessert_meshif_t* iface, dessert_frameid_t id) {
    if(dessert_msg_check(msg, len)) {
        dessert_debug("invalid package - discarding");
        return DESSERT_MSG_DROP;
    }

    return DESSERT_MSG_KEEP;
}

/** dump a dessert_msg_t to debug log
 * @arg *msg dessert_msg_t frame received
 * @arg len length of ethernet frame received
 * @arg *iface interface received packet on
 * @return DESSERT_MSG_KEEP always
 **/
dessert_cb_result dessert_msg_dump_cb(dessert_msg_t* msg, uint32_t len, dessert_msg_proc_t* proc, dessert_meshif_t* iface, dessert_frameid_t id) {
    char buf[1024];

    dessert_msg_proc_dump(msg, len, proc, buf, 1024);
    dessert_debug("received frame #%lu on interface %s - dump:\n%s", (unsigned long) id, iface->if_name, buf);

    return DESSERT_MSG_KEEP;
}

/** check if the message carries a trace extension and add the current trace info
 * if iface is NULL, the packet is ignored
 * @arg *msg dessert_msg_t frame received
 * @arg len length of ethernet frame received
 * @arg *iface interface received packet on
 * ®return DESSERT_MSG_KEEP always
 **/
dessert_cb_result dessert_msg_trace_cb(dessert_msg_t* msg, uint32_t len, dessert_msg_proc_t* proc, dessert_meshif_t* iface, dessert_frameid_t id) {
    dessert_ext_t* ext;

    /* abort if message has no trace extension */
    if(dessert_msg_getext(msg, &ext, DESSERT_EXT_TRACE_REQ, 0) == 0) {
        return DESSERT_MSG_KEEP;
    }

    /* abort if iface is NULL */
    if(iface == NULL) {
        return DESSERT_MSG_KEEP;
    }

    /* we cannot add header to sparse messages */
    if(msg->flags & DESSERT_RX_FLAG_SPARSE) {
        return DESSERT_MSG_NEEDNOSPARSE;
    }

    /* get the trace mode (hop vs interface) */
    if(dessert_ext_getdatalen(ext) == DESSERT_MSG_TRACE_HOST) {
        dessert_msg_addext(msg, &ext, DESSERT_EXT_TRACE_REQ, DESSERT_MSG_TRACE_HOST);
        memcpy((ext->data), dessert_l25_defsrc, ETHER_ADDR_LEN);
    }
    else if(dessert_ext_getdatalen(ext) == DESSERT_MSG_TRACE_IFACE) {
        dessert_msg_addext(msg, &ext, DESSERT_EXT_TRACE_REQ, DESSERT_MSG_TRACE_IFACE);
        memcpy((ext->data), dessert_l25_defsrc, ETHER_ADDR_LEN);
        memcpy((ext->data) + ETHER_ADDR_LEN, iface->hwaddr, ETHER_ADDR_LEN);
        memcpy((ext->data) + ETHER_ADDR_LEN * 2, msg->l2h.ether_shost, ETHER_ADDR_LEN);
    }
    else {
        dessert_warn("got packet with trace extension - ignoring");
    }

    return DESSERT_MSG_KEEP;
}

/** callback to set the local processing flags in dessert_msg_proc_t on an arriving dessert_msg_t
 * @arg *msg dessert_msg_t frame received
 * @arg len length of ethernet frame received
 * @arg *iface interface received packet on
 * ®return DESSERT_MSG_KEEP or DESSERT_MSG_NEEDMSGPROC
 **/
dessert_cb_result dessert_msg_ifaceflags_cb(dessert_msg_t* msg, uint32_t len, dessert_msg_proc_t* proc, dessert_meshif_t* riface, dessert_frameid_t id) {
    dessert_meshif_t* iface;
    struct ether_header* l25h;

    /* check if we have an processing header */
    if(proc == NULL) {
        return DESSERT_MSG_NEEDMSGPROC;
    }

    /* get l2.5 header if possible */
    l25h = dessert_msg_getl25ether(msg);

    /* clear flags */
    proc->lflags &= ~(DESSERT_RX_FLAG_L25_DST
        | DESSERT_RX_FLAG_L25_SRC
        | DESSERT_RX_FLAG_L2_DST
        | DESSERT_RX_FLAG_L2_SRC
        | DESSERT_RX_FLAG_L2_BROADCAST
        | DESSERT_RX_FLAG_L25_OVERHEARD
        | DESSERT_RX_FLAG_L2_OVERHEARD);

    /* checks against defaults */
    if(l25h != NULL && memcmp(l25h->ether_dhost, ether_broadcast, ETHER_ADDR_LEN) == 0) {
        proc->lflags |= DESSERT_RX_FLAG_L25_BROADCAST;
    }
    else if(l25h != NULL && l25h->ether_dhost[0] & 0x01) {    /* broadcast also has this bit set */
        proc->lflags |= DESSERT_RX_FLAG_L25_MULTICAST;
    }

    if(l25h != NULL && memcmp(l25h->ether_dhost, dessert_l25_defsrc, ETHER_ADDR_LEN) == 0) {
        proc->lflags |= DESSERT_RX_FLAG_L25_DST;
    }

    if(l25h != NULL && memcmp(l25h->ether_shost, dessert_l25_defsrc, ETHER_ADDR_LEN) == 0) {
        proc->lflags |= DESSERT_RX_FLAG_L25_SRC;
    }

    if(memcmp(msg->l2h.ether_dhost, dessert_l25_defsrc, ETHER_ADDR_LEN) == 0) {
        proc->lflags |= DESSERT_RX_FLAG_L2_DST;
    }

    if(memcmp(msg->l2h.ether_shost, dessert_l25_defsrc, ETHER_ADDR_LEN) == 0) {
        proc->lflags |= DESSERT_RX_FLAG_L2_SRC;
    }

    if(memcmp(msg->l2h.ether_dhost, ether_broadcast, ETHER_ADDR_LEN) == 0) {
        proc->lflags |= DESSERT_RX_FLAG_L2_BROADCAST;
    }

    /* checks against interfaces in list */
    pthread_rwlock_rdlock(&dessert_cfglock);
    DL_FOREACH(dessert_meshiflist_get(), iface) {
        if(l25h != NULL && memcmp(l25h->ether_dhost, iface->hwaddr, ETHER_ADDR_LEN) == 0) {
            proc->lflags |= DESSERT_RX_FLAG_L25_DST;

            if(memcmp(l25h->ether_dhost, riface->hwaddr, ETHER_ADDR_LEN) != 0) {
                proc->lflags |= DESSERT_RX_FLAG_L25_OVERHEARD;
            }
        }

        if(l25h != NULL && memcmp(l25h->ether_shost, iface->hwaddr, ETHER_ADDR_LEN) == 0) {
            proc->lflags |= DESSERT_RX_FLAG_L25_SRC;
        }

        if(memcmp(msg->l2h.ether_dhost, iface->hwaddr, ETHER_ADDR_LEN) == 0) {
            proc->lflags |= DESSERT_RX_FLAG_L2_DST;

            if(memcmp(msg->l2h.ether_dhost, riface->hwaddr, ETHER_ADDR_LEN) != 0) {
                proc->lflags |= DESSERT_RX_FLAG_L2_OVERHEARD;
            }
        }

        if(memcmp(msg->l2h.ether_shost, iface->hwaddr, ETHER_ADDR_LEN) == 0) {
            proc->lflags |= DESSERT_RX_FLAG_L2_SRC;
        }
    }
    pthread_rwlock_unlock(&dessert_cfglock);

    return DESSERT_MSG_KEEP;
}

/** dump packet trace to string
 * @arg *msg dessert_msg_t message used for tracing
 * @arg type DESSERT_EXT_TRACE_REQ or DESSERT_EXT_TRACE_RPL
 * @arg *buf char buffer to place string
 *           use DESSERT_MSG_TRACE_HOST to only record default mac of hosts on the way
 *           use DESSERT_MSG_TRACE_IFACE to also trace input interface and last hop
 * @return length of the string - 0 if msg has no trace header, -1 if wrong type
 **/
int dessert_msg_trace_dump(const dessert_msg_t* msg, uint8_t type, char* buf, int blen) {
    dessert_ext_t* ext;
    int x, i = 0;

    if(type != DESSERT_EXT_TRACE_REQ
       || type != DESSERT_EXT_TRACE_RPL) {
        return -1;
    }

#define _dessert_msg_trace_dump_append(...) snprintf(buf+strlen(buf), blen-strlen(buf), __VA_ARGS__)

    x = dessert_msg_getext(msg, &ext, type, 0);

    if(x < 1) {
        return 0;
    }

    _dessert_msg_trace_dump_append("\tpacket trace:\n" "\t\tfrom " MAC "\n", EXPLODE_ARRAY6(ext->data));

    if(dessert_ext_getdatalen(ext) == DESSERT_MSG_TRACE_IFACE) {
        _dessert_msg_trace_dump_append("\t\t  received on   " MAC "\n", EXPLODE_ARRAY6(ext->data));
        _dessert_msg_trace_dump_append("\t\t  l2.5 src      " MAC "\n", EXPLODE_ARRAY6(ext->data + 12));
    }

    for(i = 1; i < x; i++) {
        dessert_msg_getext(msg, &ext, type, i);
        _dessert_msg_trace_dump_append("\t\t#%3d " MAC "\n", i, EXPLODE_ARRAY6(ext->data));

        if(dessert_ext_getdatalen(ext) == DESSERT_MSG_TRACE_IFACE) {
            _dessert_msg_trace_dump_append("\t\t  received from  " MAC "\n", EXPLODE_ARRAY6(ext->data + 12));
            _dessert_msg_trace_dump_append("\t\t  receiving meshif  " MAC "\n", EXPLODE_ARRAY6(ext->data + 6));
        }
    }

    return strlen(buf);
}


/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * M E S S A G E   H A N D L I N G
 *
 ******************************************************************************/

/* nothing here - yet */

/******************************************************************************
 *
 * LOCAL
 *
 * M E S S A G E   H A N D L I N G
 *
 ******************************************************************************/

/* nothing here - yet */
