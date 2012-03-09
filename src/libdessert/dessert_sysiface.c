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
#include <linux/if_tun.h>

uint8_t dessert_sysif_hwaddr[ETHER_ADDR_LEN]; /** \todo unused! to be removed ??!? */

/* global data storage // P U B L I C */
/* nothing here - yet */

/* global data storage // P R I V A T E */
dessert_sysif_t* _dessert_sysif = NULL;

/* local data storage*/
dessert_sysrxcbe_t* _dessert_sysrxcblist = NULL;
int _dessert_sysrxcblistver = 0;

/* internal functions forward declarations*/
static void* _dessert_sysif_init_thread(void* arg);
static dessert_cb_result _dessert_sysif_init_getmachack(dessert_msg_t* msg, uint32_t len, dessert_msg_proc_t* proc, dessert_sysif_t* sysif, dessert_frameid_t id);

/******************************************************************************
 *
 * EXTERNAL / PUBLIC
 *
 * S Y S - I N T E R F A C E S
 *
 ******************************************************************************/

bool _dessert_check_dup_mac(char* mac) {
    struct ifreq ifreqs[10];
    struct ifconf ifconf;
    memset(&ifconf, 0, sizeof(ifconf));
    ifconf.ifc_buf = (char*) (ifreqs);
    ifconf.ifc_len = sizeof(ifreqs);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) {
        dessert_warn("could not create socket");
        return false;
    }

    if(ioctl(sock, SIOCGIFCONF , &ifconf) < 0) {
        dessert_warn("Could not read interfaces");
        goto out;
    }
    close(sock);

    uint16_t i;
    for(i = 0; i < ifconf.ifc_len/sizeof(struct ifreq); i++) {
        char* ifname = ifreqs[i].ifr_name;
        char buf[ETHER_ADDR_LEN];
        if(_dessert_getHWAddr(ifname, buf) == DESSERT_OK) {
            if(memcmp(buf, mac, ETHER_ADDR_LEN) == 0) {
                return false;
            }
        }
        else {
            return false;
        }
    }
    return true;

out:
    close(sock);
    return false;
}


/** Initializes the tun/tap Interface dev for des-sert.
 * @arg *device interface name
 * @arg flags  @see DESSERT_TUN @see DESSERT_TAP @see DESSERT_MAKE_DEFSRC
 * @return 0       -- on success
 * @return EINVAL  -- if message is broken
 * @return EFAULT  -- if interface not specified and not guessed
 **/
int dessert_sysif_init(char* device, uint8_t flags) {
    /* initialize _dessert_sysif */
    _dessert_sysif = malloc(sizeof(dessert_sysif_t));

    if(_dessert_sysif == NULL) {
        return (-errno);
    }

    memset((void*) _dessert_sysif, 0, sizeof(dessert_sysif_t));
    _dessert_sysif->flags = flags;
    strncpy(_dessert_sysif->if_name, device, IF_NAMESIZE);
    _dessert_sysif->if_name[IF_NAMESIZE - 1] = '\0';
    pthread_mutex_init(&(_dessert_sysif->cnt_mutex), NULL);

#ifdef ANDROID
    char* buf = "/dev/tun";
#else
    char* buf = "/dev/net/tun";
#endif
    /* open device */
    _dessert_sysif->fd = open(buf, O_RDWR);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    if(flags & DESSERT_TUN) {
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI; /* we want the service flag and IFF_NO_PI */
    }
    else {
        ifr.ifr_flags = IFF_TAP | IFF_NO_PI; /* we want the service flag and IFF_NO_PI */
    }

    strcpy(ifr.ifr_name, _dessert_sysif->if_name);

    if(ioctl(_dessert_sysif->fd, TUNSETIFF, (void*) &ifr) < 0) {
        dessert_err("ioctl(TUNSETIFF) failed: %s", strerror(errno));
        goto dessert_sysif_init_err;
        return (-errno);
    }

    /**
     * Derive TAP MAC address from eth0 MAC address
     */
    if(if_nametoindex("eth0")) {
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;

        if(_dessert_getHWAddr("eth0", ifr.ifr_hwaddr.sa_data) == DESSERT_OK) {
            ifr.ifr_hwaddr.sa_data[0] = 0xFE;

            // check if the address is already taken
            if(_dessert_check_dup_mac(ifr.ifr_hwaddr.sa_data)) {
                if(ioctl(_dessert_sysif->fd, SIOCSIFHWADDR, &ifr) < 0) {
                    dessert_warn("ioctl(SIOCSIFHWADDR) failed: %s", strerror(errno));
                }
            }
        }
    }

    /****************************************************/
    strcpy(_dessert_sysif->if_name, ifr.ifr_name);

    /* check interface - abusing dessert_meshif methods */
    _dessert_sysif->if_index = if_nametoindex(device);

    if(!_dessert_sysif->if_index) {
        dessert_err("interface %s - no such interface", _dessert_sysif->if_name);
        goto dessert_sysif_init_err;
    }

    /* do "ip link set dev %s up" to set the interface up - strange things happen otherwise */
    char system_call[64];
    snprintf(system_call, sizeof(system_call), "ip link set dev %s up", _dessert_sysif->if_name);
    int status = system(system_call);

    if(status < 0) {
        dessert_warning("\"ip link set dev %s up\" failed!", _dessert_sysif->if_name);
    }

    /* get hardware address in tap mode if possible */
    if(flags & DESSERT_TAP) {
        if(_dessert_meshif_gethwaddr((dessert_meshif_t*) _dessert_sysif) != 0) {
            dessert_err("failed to get hwaddr of interface %s(%d) - hope src of first packet received from is it", _dessert_sysif->if_name, _dessert_sysif->if_index, _dessert_sysif);
            _dessert_sysif->flags |= _DESSERT_TAP_NOMAC;
            dessert_sysrxcb_add(_dessert_sysif_init_getmachack, 0);
        }
        else {
            /* check whether we need to set defsrc */
            if((flags & DESSERT_MAKE_DEFSRC) || memcmp(dessert_l25_defsrc, ether_null, ETHER_ADDR_LEN) == 0) {
                memcpy(dessert_l25_defsrc, _dessert_sysif->hwaddr, ETHER_ADDR_LEN);
                dessert_info("set dessert_l25_defsrc to hwaddr " MAC, EXPLODE_ARRAY6(dessert_l25_defsrc));
            }
        }
    }

    /* info message */
    if(flags & DESSERT_TAP) {
        dessert_info("starting worker thread for tap interface %s(%d) hwaddr " MAC, _dessert_sysif->if_name, _dessert_sysif->if_index, EXPLODE_ARRAY6(_dessert_sysif->hwaddr));
    }
    else {
        dessert_info("starting worker thread for tap interface %s(%d) fd %d", _dessert_sysif->if_name, _dessert_sysif->if_index, _dessert_sysif->fd);
    }

    /* start worker thread */
    if(pthread_create(&(_dessert_sysif->worker), NULL, _dessert_sysif_init_thread, (void*) _dessert_sysif)) {
        dessert_err("creating worker thread failed for interface %s(%d)", _dessert_sysif->if_name, _dessert_sysif->if_index);
        goto dessert_sysif_init_err;
    }

    return DESSERT_OK;

dessert_sysif_init_err:
    close(_dessert_sysif->fd);
    return (-errno);
}

/** adds a callback function to call if a packet should be injected into dessert via a tun/tap interface
 * @arg *c   callback function
 * @arg prio priority of the function - lower first!
 * @return DESSERT_OK   on success
 * @return -errno       on error
 **/
int dessert_sysrxcb_add(dessert_sysrxcb_t* c, int prio) {
    dessert_sysrxcbe_t* cb, *i;

    cb = (struct dessert_sysrxcbe*) malloc(sizeof(struct dessert_sysrxcbe));

    if(cb == NULL) {
        dessert_err("failed to allocate memory for registering sys callback: %s", strerror(errno));
        return (-errno);
    }

    if(c == NULL) {
        dessert_err("tried to add a null pointer as dessert_sysrxcb");
        return (-EINVAL);
    }

    pthread_rwlock_wrlock(&dessert_cfglock);

    cb->c = c;
    cb->prio = prio;
    cb->next = NULL;

    if(_dessert_sysrxcblist == NULL) {
        _dessert_sysrxcblist = cb;
        _dessert_sysrxcblistver++;

        pthread_rwlock_unlock(&dessert_cfglock);
        return DESSERT_OK;
    }

    if(_dessert_sysrxcblist->prio > cb->prio) {
        cb->next = _dessert_sysrxcblist;
        _dessert_sysrxcblist = cb;
        _dessert_sysrxcblistver++;

        pthread_rwlock_unlock(&dessert_cfglock);
        return DESSERT_OK;
    }

    /* find right place for callback */
    for(i = _dessert_sysrxcblist; i->next != NULL && i->next->prio <= cb->prio; i = i->next) {
        ;
    }

    /* insert it */
    cb->next = i->next;
    i->next = cb;
    _dessert_sysrxcblistver++;

    pthread_rwlock_unlock(&dessert_cfglock);
    return DESSERT_OK;
}

/** removes all occurrences of the callback function from the list of callbacks.
 * @arg c callback function
 * @return DESSERT_OK   on success, DESSERT_ERR  on error
 **/
int dessert_sysrxcb_del(dessert_sysrxcb_t* c) {
    int count = 0;
    dessert_sysrxcbe_t* i, *last;

    pthread_rwlock_wrlock(&dessert_cfglock);

    if(_dessert_sysrxcblist == NULL) {
        goto dessert_sysrxcb_del_out;
    }

    while(_dessert_sysrxcblist->c == c) {
        count++;
        i = _dessert_sysrxcblist;
        _dessert_sysrxcblist = _dessert_sysrxcblist->next;
        free(i);

        if(_dessert_sysrxcblist == NULL) {
            goto dessert_sysrxcb_del_out;
        }
    }

    for(i = _dessert_sysrxcblist; i->next != NULL; i = i->next) {
        if(i->c == c) {
            count++;
            last->next = i->next;
            free(i);
            i = last;
        }

        last = i;
    }

dessert_sysrxcb_del_out:
    _dessert_sysrxcblistver++;
    pthread_rwlock_unlock(&dessert_cfglock);
    return ((count > 0) ? DESSERT_OK : DESSERT_ERR);

}

/** Send a DES-SERT Message via TUN/TAP
 * @arg *msg message to send
 * @return DESSERT_OK   on success
 * @return -EIO         if message failed to be sent
 **/
int dessert_syssend_msg(dessert_msg_t* msg) {
    void* pkt;
    int len = dessert_msg_ethdecap(msg, (struct ether_header**) &pkt);

    // lets see if the message contains an Ethernet frame
    if(len == -1) {
        // might only be an ip datagram due to TUN usage
        len = dessert_msg_ipdecap(msg, (uint8_t**) &pkt);

        // if neither a Ethernet header nor ip datagram are available, something must be wrong
        // also make sure to forward ip datagrams only to a TUN interface
        if(len == -1 || !_dessert_sysif || !(_dessert_sysif->flags & DESSERT_TUN)) {
            return (-EIO);
        }
    }

    dessert_syssend(pkt, len);
    free(pkt);

    return DESSERT_OK;
}

/** Send any type of packet via TUN/TAP
 * @arg *eth message to send
 * @arg len length of message to send
 * @return DESSERT_OK   on success
 * @return -EIO         if message failed to be sent
 **/
int dessert_syssend(const void* pkt, uint32_t len) {

    if(_dessert_sysif == NULL) {
        return (-EIO);
    }

    uint32_t res = write(_dessert_sysif->fd, (const void*) pkt, len);

    if(res == len) {
        pthread_mutex_lock(&(_dessert_sysif->cnt_mutex));
        _dessert_sysif->opkts++;
        _dessert_sysif->obytes += res;
        pthread_mutex_unlock(&(_dessert_sysif->cnt_mutex));
        return (DESSERT_OK);
    }
    else {
        return (-EIO);
    }
}

/******************************************************************************
 *
 * INTERNAL / PRIVATE
 *
 * S Y S - I N T E R F A C E S
 *
 ******************************************************************************/

int _dessert_getHWAddr(char* device, char* hwaddr) {
    /* we need some socket to do that */
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    struct ifreq ifr;
    /* set interface options and get hardware address */
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

    if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) >= 0) {
        memcpy(hwaddr, &ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
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
 * S Y S - I N T E R F A C E S
 *
 ******************************************************************************/

/** internal callback which gets registered if we can't find out mac address of tap interface */
static dessert_cb_result _dessert_sysif_init_getmachack(dessert_msg_t* msg, uint32_t len, dessert_msg_proc_t* proc, dessert_sysif_t* sysif, dessert_frameid_t id) {
    struct ether_header* eth;
    dessert_msg_ethdecap(msg, &eth);

    /* hack to get the hardware address */
    if(sysif->flags & _DESSERT_TAP_NOMAC) {
        /* copy from first packet received */
        memcpy(sysif->hwaddr, eth->ether_shost, ETHER_ADDR_LEN);
        dessert_info("guessed hwaddr for %s: " MAC, sysif->if_name, EXPLODE_ARRAY6(sysif->hwaddr));

        /* check whether we need to set defsrc */
        if((sysif->flags & DESSERT_MAKE_DEFSRC)
           || memcmp(dessert_l25_defsrc, ether_null, ETHER_ADDR_LEN) == 0) {
            memcpy(dessert_l25_defsrc, sysif->hwaddr, ETHER_ADDR_LEN);
            dessert_info("set dessert_l25_defsrc to hwaddr " MAC, EXPLODE_ARRAY6(dessert_l25_defsrc));
        }

        sysif->flags &= ~_DESSERT_TAP_NOMAC;
    }

    /* unregister me */
    dessert_sysrxcb_del(_dessert_sysif_init_getmachack);

    return DESSERT_MSG_KEEP;
}

/** internal packet processing thread body */
static void* _dessert_sysif_init_thread(void* arg) {
    dessert_sysif_t* sysif = (dessert_sysif_t*) arg;
    dessert_sysrxcbe_t* cb;
    dessert_sysrxcb_t** cbl = NULL;

    int cblver = -1;
    int cbllen = 0;

    for(;;) {
        char buf[ETHER_MAX_LEN];
        memset(buf, 0, ETHER_MAX_LEN);
        int len;

        if(sysif->flags & DESSERT_TUN) {  // read IP datagram from TUN interface
            len = read((sysif->fd), buf + ETHER_HDR_LEN, ETHER_MAX_LEN - ETHER_HDR_LEN);
        }
        else {   // read Ethernet frame from TAP interface
            len = read((sysif->fd), buf, sizeof(buf));
        }

        /* Right now the packet has been written to the buffer. The packet is aligned so that
         * the first layer 3 byte is always at the same position independent whether a TUN or
         * a TAP interface has been used:
         * buf: [Ethernet Header Space][Layer 3 Header]
         */
        if(len == -1) {
            dessert_debug("got %s while reading on %s (fd %d) - is the sys (tun/tap) interface up?", strerror(errno), sysif->if_name, sysif->fd);
            sleep(1);
            continue;
        }

        /* copy callbacks to internal list to release dessert_cfglock before invoking callbacks*/
        pthread_rwlock_rdlock(&dessert_cfglock);

        if(cblver < _dessert_sysrxcblistver) {
            /* callback list changed - rebuild it */
            for(cb = _dessert_sysrxcblist; cb != NULL; cb = cb->next) {
                cbllen++;
            }

            cbl = realloc(cbl, cbllen * sizeof(dessert_sysrxcb_t*));

            if(cbl == NULL && cbllen > 0) {
                dessert_err("failed to allocate memory for internal callback list");
                pthread_rwlock_unlock(&dessert_cfglock);
                return (NULL);
            }

            int iter = 0;

            for(cb = _dessert_sysrxcblist; cb != NULL; cb = cb->next) {
                cbl[iter++] = cb->c;
            }

            cblver = _dessert_sysrxcblistver;
        }

        pthread_rwlock_unlock(&dessert_cfglock);

        /* generate frame id */
        dessert_frameid_t id = _dessert_newframeid();

        /* count packet */
        pthread_mutex_lock(&(sysif->cnt_mutex));
        sysif->ipkts++;
        sysif->ibytes += len;
        pthread_mutex_unlock(&(sysif->cnt_mutex));

        dessert_msg_proc_t proc;
        memset(&proc, 0, DESSERT_MSGPROCLEN);
        dessert_msg_t* msg = NULL;

        if(sysif->flags & DESSERT_TUN) {
            if(dessert_msg_ipencap((uint8_t*)(buf + ETHER_HDR_LEN), len, &msg) < 0) {
                dessert_err("failed to encapsulate ip datagram on host-to-network-pipeline: %s", errno);
            }
        }
        else {
            if(dessert_msg_ethencap((struct ether_header*) buf, len, &msg) < 0) {
                dessert_err("failed to encapsulate ethernet frame on host-to-network-pipeline: %s", errno);
            }
        }

        int res = 0;
        int iter = 0;

        while(res > DESSERT_MSG_DROP && iter < cbllen) {
            res = cbl[iter++](msg, len, &proc, sysif, id);
        }

        if(msg != NULL) {
            dessert_msg_destroy(msg);
        }
    }

    dessert_info("stopped reading on %s (fd %d): %s", sysif->if_name, sysif->fd, strerror(errno));

    free(cbl);
    close(sysif->fd);
    return (NULL);
}

/** Add TAP interface
 *
 * This callback can be used to create a TAP device as sys interface.
 *
 * COMMAND: interface sys $iface $ipv4-addr $netmask $mtu
 *
 * @param cli the handle of the cli structure. This must be passed to all cli functions, including cli_print().
 * @param command the entire command which was entered. This is after command expansion.
 * @param argv the list of arguments entered
 * @param argc the number of arguments entered
 *
 * @retval CLI_OK if TAP interface added
 * @retval CLI_ERROR on error
 */
int dessert_cli_cmd_addsysif(struct cli_def* cli, char* command, char* argv[], int argc) {
    char buf[255];
    int i;

    if(argc < 3 || argc > 4) {
        cli_print(cli, "usage %s [sys-interface] [ip-address] [netmask] [mtu]\n", command);
        return CLI_ERROR;
    }

    uint16_t mtu = DESSERT_DEFAULT_MTU;

    if(argc == 4) {
        mtu = (uint16_t) atoi(argv[3]);
    }

    dessert_info("initializing sys interface");
    dessert_sysif_init(argv[0], DESSERT_TAP | DESSERT_MAKE_DEFSRC);
    sprintf(buf, "ifconfig %s %s netmask %s mtu %d up", argv[0], argv[1], argv[2], mtu);
    i = system(buf);

    if(i != 0) {
        dessert_crit("running ifconfig on sys interface %s returned %d", argv[0], i);
        return CLI_ERROR;
    }

    return CLI_OK;
}

/** Add TUN interface
 *
 * This callback can be used to create a TUN device as sys interface.
 *
 * COMMAND: interface sys $iface, $ipv4-addr, $netmask
 *
 * @param cli the handle of the cli structure. This must be passed to all cli functions, including cli_print().
 * @param command the entire command which was entered. This is after command expansion.
 * @param argv the list of arguments entered
 * @param argc the number of arguments entered
 *
 * @retval CLI_OK if TUN interface added
 * @retval CLI_ERROR on error
 */
int dessert_cli_cmd_addsysif_tun(struct cli_def* cli, char* command, char* argv[], int argc) {
    char buf[255];
    int i;

    if(argc != 3) {
        cli_print(cli, "usage %s [sys-interface] [ip-address] [netmask]\n", command);
        return CLI_ERROR;
    }

    dessert_info("initializing sys interface");
    dessert_sysif_init(argv[0], DESSERT_TUN | DESSERT_MAKE_DEFSRC);
    sprintf(buf, "ifconfig %s %s netmask %s mtu %d up", argv[0], argv[1], argv[2], DESSERT_DEFAULT_MTU);
    i = system(buf);
    dessert_info("ifconfig on sys interface returned %d", i);
    return (i == 0 ? CLI_OK : CLI_ERROR);
}

/** Drop IPv6 datagrams
 *
 * Drop all DES-SERT messages containing an IPv6 datagram.
 * Usually when an interface if put in the up state and IPv6 is enabled,
 * several packets are sent. In some scenarios you do want to suppress
 * these packets. This sys callback will drop all IPv6 datagrams sent over
 * the sys interface.
 *
 * @param *msg dessert msg received - original ethernet frame is encapsulated within
 * @param len length of ethernet frame received
 * @param *proc local processing buffer passed along the callback pipeline - may be NULL
 * @param *sysif interface received packet on
 * @param id unique internal frame id of the packet
 *
 * @retval DESSERT_MSG_DROP if the message contains an IPv6 datagram
 * @retval DESSERT_MSG_KEEP if message contains an IPv4 datagram
 */
dessert_cb_result dessert_sys_drop_ipv6(dessert_msg_t* msg, uint32_t len, dessert_msg_proc_t* proc, dessert_sysif_t* sysif, dessert_frameid_t id) {
    void* payload;
    struct ether_header* eth = dessert_msg_getl25ether(msg);

    if(eth == NULL) {  // has no Ethernet extension
        void* payload;
        dessert_msg_getpayload(msg, &payload);
        struct ip6_hdr* ip = (struct ip6_hdr*) payload;

        if(ip && ip->ip6_ctlun.ip6_un1.ip6_un1_flow & 0x60000000) {
            dessert_debug("dropped raw IPv6 packet (false positives are possible)");
            return DESSERT_MSG_DROP;
        }

        return DESSERT_MSG_KEEP;
    }
    else { // has Ethernet extension
        if(eth->ether_type == htons(ETHERTYPE_IPV6)) {
            dessert_debug("dropped IPv6 packet in Ethernet frame");
            return DESSERT_MSG_DROP;
        }
    }

    return DESSERT_MSG_KEEP;
}
