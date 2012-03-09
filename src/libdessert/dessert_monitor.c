/******************************************************************************
 Copyright 2011, The DES-SERT Team, Freie Universitaet Berlin (FUB).
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

#ifndef ANDROID
#include "dessert.h"
#include "dessert_internal.h"
#include <pcap/pcap.h>
#include <iwlib.h>
#include <utlist.h>
#ifndef DL_FOREACH_SAFE
#error "your version of utlist.h does not support DL_FOREACH_SAFE, please install the latest version from http://uthash.sourceforge.net/"
#endif

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))

struct ieee80211_radiotap_header {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
} __attribute__((__packed__));

struct radiotap_header_opt_fields {
    uint64_t wr_tsft; //timestamp in microseconds when the first bit of the packet arrived
    uint8_t wr_flags;
    uint8_t wr_rate;
    struct {
        uint16_t frequency;
        uint16_t flags;
    } wr_channel;
    struct {
        uint8_t hop_set;
        uint8_t hop_pattern;
    } wr_fhss;
    int8_t wr_ant_signal;
    int8_t wr_ant_noise;
    uint16_t wr_lockquality;
    uint16_t wr_tx_attenuation;
    uint16_t wr_db_tx_attenuation;
    int8_t wr_dbm_tx_power;
    uint8_t wr_antenna;
    uint8_t wr_db_antsignal;
    uint8_t wr_db_antnoise;
    uint16_t wr_rx_flags;
};

struct wifi_header {
    struct {
        int8_t version_and_type : 8;
        struct {
            int8_t ds : 2;
            int8_t more_fragments : 1;
            int8_t retry : 1;
            int8_t power_management : 1;
            int8_t moredata : 1;
            int8_t protected : 1;
            int8_t order : 1;
        } flags;
    } frame_control;
    uint16_t duration;
    mac_addr destination_address;
    mac_addr source_address;
    mac_addr bssid;
    uint16_t fragment_number;
    uint16_t sequence_number;
} __attribute__((__packed__));

/* maximum age of rssi samples in seconds; may be overwritten
 * when calling dessert_monitoring start. */
int MAX_AGE = 1;
/* maximum number of rssi samples to store per neighbour */
int MAX_RSSI_VALS = 100;
/* interval in seconds to clean outdated neighbour entries */
int MAINTENANCE_INTERVAL = 10;
/* socket for ioctl channel requests */
int skfd = 0;

static int32_t iw_freq2long(const iwfreq* in) {
    int i;
    int64_t res = in->m;

    for(i = 0; i < in->e; i++) {
        res *= 10;
    }

    return res / 1000000; //convert to MHz
}

static int neighbour_cmp(const struct monitor_neighbour* left, const struct monitor_neighbour* right) {
    return memcmp(left->addr, right->addr, sizeof(left->addr));
}

static struct radiotap_header_opt_fields parse(const uint8_t* packet) {
    struct radiotap_header_opt_fields out;
    struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*) packet;

    memset(&out, 0, sizeof(out));
    /* The radio tap header may contain multiple it_present words
    if bit 31 is set. If it is set, then more it_present words follow
    and the radiotap data follows after the it_present word
    that has bit 31 unset. */

    uint32_t* last_present_field;

    for(last_present_field = &radiotap->it_present;
        *last_present_field >> 31;
        ++last_present_field) {
        continue;
    }

    uint8_t* radiotap_data = (uint8_t*) ++last_present_field;

    int i, offset = 0;

    for(i = 0; i < 15; i++) {
        if(((radiotap->it_present >> i) & 1) == 0) {
            continue;
        }

        switch(i) {
#define PARSE_FIELD_NOBREAK(field) \
            offset = ALIGN(offset, sizeof(out.field)); \
            out.field = * (typeof(out.field) *) (radiotap_data + offset); \
            offset += sizeof(out.field);
#define PARSE_FIELD(field) PARSE_FIELD_NOBREAK(field); break
            case  0:
                PARSE_FIELD(wr_tsft);
            case  1:
                PARSE_FIELD(wr_flags);
            case  2:
                PARSE_FIELD(wr_rate);
            case  3:
                PARSE_FIELD_NOBREAK(wr_channel.frequency);
                PARSE_FIELD(wr_channel.flags);
            case  4:
                PARSE_FIELD_NOBREAK(wr_fhss.hop_set);
                PARSE_FIELD(wr_fhss.hop_pattern);
            case  5:
                PARSE_FIELD(wr_ant_signal);
            case  6:
                PARSE_FIELD(wr_ant_noise);
            case  7:
                PARSE_FIELD(wr_lockquality);
            case  8:
                PARSE_FIELD(wr_tx_attenuation);
            case  9:
                PARSE_FIELD(wr_db_tx_attenuation);
            case 10:
                PARSE_FIELD(wr_dbm_tx_power);
            case 11:
                PARSE_FIELD(wr_antenna);
            case 12:
                PARSE_FIELD(wr_db_antsignal);
            case 13:
                PARSE_FIELD(wr_db_antnoise);
            case 14:
                PARSE_FIELD(wr_rx_flags);
#undef PARSE_FIELD
        }
    }

    return out;
}

struct avg_node_result avg_node(struct monitor_neighbour* n) {
    int counter = 0;
    int accu_rssi = 0;
    int accu_noise = 0;
    int accu_rate = 0;
    int accu_retries = 0;
    int j;

    time_t cur_time = time(NULL);

    for(j = 0; j < MAX_RSSI_VALS; ++j) {
        if(cur_time - n->samples[j].time > MAX_AGE) {
            //operate only if value is valid and not older than MAX_AGE
            continue;
        }

        accu_rssi    += n->samples[j].rssi;
        accu_noise   += n->samples[j].noise;
        accu_rate    += n->samples[j].rate;
        accu_retries += n->samples[j].retry ? 1 : 0;
        ++counter;
    }

    struct avg_node_result result;

    if(counter > 0) {
        result.avg_rssi    = accu_rssi / counter;
        result.avg_noise   = accu_noise / counter;
        result.avg_rate    = accu_rate / counter;
        result.sum_retries = accu_retries;
        result.amount      = counter;
    }
    else {
        memset(&result, 0, sizeof(result));
    }

    return result;
}

static int32_t get_dev_freq(dessert_meshif_t* iface) {
    /* skfd socket is a globally defined socket for the ioctl channel requests */
    //FIXME: not thread-safe
    struct iwreq wrq;

    if(iw_get_ext(skfd, iface->if_name, SIOCGIWNAME, &wrq) < 0) {
        /* If no wireless name : no wireless extensions */
        dessert_crit("Could not open device %s", iface->if_name);
        return -2;
    }

    if(iw_get_ext(skfd, iface->if_name, SIOCGIWFREQ, &wrq) < 0) {
        // TODO: may fail for first call
        return -1;
    }

    return iw_freq2long(&wrq.u.freq);
}

static void maintenance(void) {
    dessert_meshif_t* interface;
    struct monitor_neighbour* neighbour, *tmp;

    MESHIFLIST_ITERATOR_START(interface)
    pthread_rwlock_wrlock(&interface->monitor_neighbour_lock);
    DL_FOREACH_SAFE(interface->neighbours, neighbour, tmp) {
        if(avg_node(neighbour).amount == 0) {
            DL_DELETE(interface->neighbours, neighbour);
            free(neighbour->samples);
            free(neighbour);
        }
    }
    pthread_rwlock_unlock(&interface->monitor_neighbour_lock);
    MESHIFLIST_ITERATOR_STOP;
}

void* maintenance_start(void* nothing __attribute__((unused))) {
    while(1) {
        sleep(MAINTENANCE_INTERVAL);
        maintenance();
    }

    return NULL;
}

static int print_neighbour(const mac_addr hwaddr,
                           dessert_meshif_t* interface,
                           struct avg_node_result avg) {

    cli_print(dessert_cli,
              "Neighbour: " MAC " | "
              "Device: %s | "
              "Freq: %04d MHz | "
              "avg. RSSI: %03d dBm | "
              "avg. noise: %03d dBm | "
              "avg. rate: %03d Mbps | "
              "Values: %03d | "
              "Retries: %03d",
              EXPLODE_ARRAY6(hwaddr),
              interface->if_name,
              get_dev_freq(interface),
              avg.avg_rssi,
              avg.avg_noise,
              avg.avg_rate * 500 / 1000,
              avg.amount,
              avg.sum_retries);
    return 0;
}

static int log_neighbour(const mac_addr hwaddr,
                         dessert_meshif_t* interface,
                         struct avg_node_result avg) {

    dessert_info(
        MAC ","
        "%s,"
        "%04d,"
        "%03d,"
        "%03d,"
        "%03d,"
        "%03d,"
        "%03d",
        EXPLODE_ARRAY6(hwaddr),
        interface->if_name,
        get_dev_freq(interface),
        avg.avg_rssi,
        avg.avg_noise,
        avg.avg_rate * 500 / 1000,
        avg.amount,
        avg.sum_retries);
    return 0;
}

int dessert_print_monitored_database() {
    maintenance();

    dessert_meshif_t* interface;
    struct monitor_neighbour* neighbour;

    struct avg_node_result avg;
    MESHIFLIST_ITERATOR_START(interface)
    pthread_rwlock_wrlock(&interface->monitor_neighbour_lock);
    DL_FOREACH(interface->neighbours, neighbour) {
        avg = avg_node(neighbour);
        print_neighbour(neighbour->addr, interface, avg);
    }
    pthread_rwlock_unlock(&interface->monitor_neighbour_lock);
    MESHIFLIST_ITERATOR_STOP;
    return 0;
}

int dessert_log_monitored_neighbour(const mac_addr hwaddr) {
    dessert_meshif_t* interface;
    MESHIFLIST_ITERATOR_START(interface)
    struct avg_node_result avg = dessert_rssi_avg(hwaddr, interface);

    if(avg.amount != 0) {
        log_neighbour(hwaddr, interface, avg);
    }

    MESHIFLIST_ITERATOR_STOP;
    return 0;
}

/*inserts a value in a node - in the first possible position*/
static inline void insert_value_node(struct monitor_neighbour* n,
                                     struct radiotap_header_opt_fields* opts,
                                     time_t delivery_time,
                                     uint8_t is_retry) {

    time_t min_time = time(NULL);
    int min_index = 0;

    int i;

    for(i = 0; i < MAX_RSSI_VALS; ++i) {
        if(n->samples[i].time < min_time) {
            min_time = n->samples[i].time;
            min_index = i;
        }
    }

    n->samples[min_index].rssi = opts->wr_ant_signal;
    n->samples[min_index].noise = opts->wr_ant_noise;
    n->samples[min_index].rate = opts->wr_rate;
    n->samples[min_index].time = delivery_time;
    n->samples[min_index].retry = is_retry;
}

/*inserts a value in the matrix*/
static inline void insert_value(dessert_meshif_t* iface,
                                struct radiotap_header_opt_fields* opts,
                                time_t delivery_time,
                                mac_addr source_address,
                                uint8_t is_retry) {
    struct monitor_neighbour neighbour_needle, *neighbour_result;
    memcpy(neighbour_needle.addr, source_address, sizeof(mac_addr));

    pthread_rwlock_rdlock(&iface->monitor_neighbour_lock);
    DL_SEARCH(iface->neighbours, neighbour_result, &neighbour_needle, neighbour_cmp);

    if(!neighbour_result) {
        neighbour_result = calloc(1, sizeof(struct monitor_neighbour));
        memcpy(neighbour_result->addr, source_address, sizeof(mac_addr));
        neighbour_result->samples = calloc(MAX_RSSI_VALS, sizeof(struct rssi_sample));
        DL_APPEND(iface->neighbours, neighbour_result);
    }

    insert_value_node(neighbour_result, opts, delivery_time, is_retry);

    pthread_rwlock_unlock(&iface->monitor_neighbour_lock);
}

static void got_packet(uint8_t* node,
                       const struct pcap_pkthdr* header,
                       const uint8_t packet[]) {
    dessert_meshif_t* iface = (dessert_meshif_t*) node;
    int32_t real_freq = get_dev_freq(iface);

    if(real_freq < 0) {
        return;
    }

    struct radiotap_header_opt_fields opts = parse(packet);

    if(real_freq != opts.wr_channel.frequency) {
        /* this packet was not on the right frequency */
        return;
    }

    struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*) packet;

    uint input = radiotap->it_len;

    struct wifi_header* wifi = (struct wifi_header*) &packet[input];

    insert_value(iface, &opts, header->ts.tv_sec, wifi->source_address, wifi->frame_control.flags.retry);
}

static int create_mon_iface(dessert_meshif_t* iface) {
    char* mon = "mon.";

    if(strlen(iface->if_name) + strlen(mon) + 1 > IFNAMSIZ) {
        dessert_crit("Device for the monitor-device seems too long: %s > IFNAMSIZ", strlen(iface->if_name) + strlen(mon) + 1);
        return -1;
    }

    char monitorName[IFNAMSIZ];
    sprintf(monitorName, "%s%s", mon, iface->if_name);

    char cmdBuf[100];
    snprintf(cmdBuf, sizeof(cmdBuf), "iw dev %s interface add %s type monitor", iface->if_name, monitorName);

    int status = system(cmdBuf);

    if(status > 0) {
        dessert_crit("iw isn't installed, but it's needed for monitoring....abording monitoring");
        return -1;
    }

    if(status < 0) {
        //The value returned is -1 on error, and the return status of the command otherwise.
        dessert_crit("Couldn't create device: iw dev %s interface add %s type monitor", iface->if_name, monitorName);
        return -1;
    }

    dessert_info("monitor interface %s has been created", monitorName);

    snprintf(cmdBuf, sizeof(cmdBuf), "ip link set dev %s up", monitorName);

    status = system(cmdBuf);

    if(status > 0) {
        dessert_crit("ip isn't installed or used in the wrong way, but it's needed for monitoring....abording monitoring");
        return -1;
    }

    if(status < 0) {
        //The value returned is -1 on error, and the return status of the command otherwise.
        dessert_crit("Couldn't bring device up: ip link set dev %s up", monitorName);
        return -1;
    }

    iface->monitor_active = 1;

    return 0;
}

static void* monitoring(void* node) {
    char dev_name[IFNAMSIZ];
    snprintf(dev_name, sizeof(dev_name), "mon.%s", ((dessert_meshif_t*) node)->if_name);
    dessert_info("starting worker thread for monitor interface %s", dev_name);

    static pthread_mutex_t pcap_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&pcap_mutex);

    /* error buffer */
    char errbuf[PCAP_ERRBUF_SIZE];
    /* packet capture handle */
    pcap_t* handle = pcap_open_live(dev_name, SNAP_LEN, 1, 1000, errbuf);

    if(handle == NULL) {
        dessert_crit("Couldn't open device %s: %s\n", dev_name, errbuf);
        pthread_mutex_unlock(&pcap_mutex);
        return NULL;
    }

    if(pcap_datalink(handle) != DLT_IEEE802_11_RADIO) {
        dessert_crit("%s is not 802.11 device or device is not in monitor mode\n", dev_name);
        pthread_mutex_unlock(&pcap_mutex);
        return NULL;
    }

    struct bpf_program fp; /* compiled filter program (expression) */

    // ignore all ACKS / CTS / RTS allow only management frames and data frames
    char filter_exp[] = "type mgt subtype beacon or type data"; /* filter expression [3] */

    /* compile the filter expression */
    if(pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        dessert_crit("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pthread_mutex_unlock(&pcap_mutex);
        return NULL;
    }

    /* apply the compiled filter */
    if(pcap_setfilter(handle, &fp) == -1) {
        dessert_crit("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pthread_mutex_unlock(&pcap_mutex);
        return NULL;
    }

    pthread_mutex_unlock(&pcap_mutex);

    /* now we can set our callback function */
    int num_packets = 0; /* number of packets to capture */
    pcap_loop(handle, num_packets, got_packet, node);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}

/** This function will return the average RSSI value of the given connection.
 *  If amount is not NULL, it will contain the number of samples used to
 *  calculate the average after calling this function
 */
avg_node_result_t dessert_rssi_avg(const mac_addr hwaddr, dessert_meshif_t* interface) {
    struct monitor_neighbour neighbour_needle, *neighbour_result;
    memcpy(neighbour_needle.addr, hwaddr, sizeof(mac_addr));

    if(interface) {
        DL_SEARCH(interface->neighbours, neighbour_result, &neighbour_needle, neighbour_cmp);

        if(neighbour_result) {
            return avg_node(neighbour_result);
        }
    }

    struct avg_node_result invalid;

    memset(&invalid, 0, sizeof(invalid));

    return invalid;
}

/** This function is called for the startup of the monitoring and rssi reporting
 *  If the monitoring is already running -1 is returned, 0 represents succeed
 */
int dessert_monitoring_start(int max_rssi_vals, int max_age, int maintenance_interval) {
    dessert_info("Monitoring started....");

    if(max_rssi_vals) {
        MAX_RSSI_VALS = max_rssi_vals;
    }

    if(max_age) {
        MAX_AGE = max_age;
    }
    
    if(maintenance_interval) {
        MAINTENANCE_INTERVAL = maintenance_interval;
    }

    /* create the global skfd-socket for ioctl channel requests */
    if(!skfd && (skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dessert_crit("Error while opening socket for frequencefilter");
        return -1;
    }

    pthread_t thread;
    dessert_meshif_t* iface;
    MESHIFLIST_ITERATOR_START(iface)

    if(!iface->monitor_active) {
        create_mon_iface(iface);
        pthread_create(&thread, NULL, monitoring, iface);
        iface->monitor_active = 1;
    }

    MESHIFLIST_ITERATOR_STOP;

    pthread_create(&thread, NULL, maintenance_start, NULL);

    return 0;
}

/** This function deletes all stuff created by dessert_monitor, eg. interfaces,
 * threads and frees all allocated memory
 */
int dessert_monitoring_stop() {
    // cleans up created interfaces:

    char cmdBuf[100];
    dessert_meshif_t* iface;
    MESHIFLIST_ITERATOR_START(iface)

    if(iface->monitor_active) {
        const char* monitorName = iface->if_name;
        snprintf(cmdBuf, sizeof(cmdBuf), "iw dev mon.%s del", monitorName);

        if(system(cmdBuf) < 0) {
            //The value returned is -1 on error, and the return status of the command otherwise.
            dessert_warn("Couldn't remove device: iw dev %s del", monitorName);
        }

        iface->monitor_active = 0;

        pthread_rwlock_wrlock(&iface->monitor_neighbour_lock);
        struct monitor_neighbour* current = iface->neighbours;

        while(current) {
            struct monitor_neighbour* next = current->next;

            free(current->samples);
            free(current);

            current = next;
        }

        iface->neighbours = NULL;
        pthread_rwlock_unlock(&iface->monitor_neighbour_lock);
    }

    MESHIFLIST_ITERATOR_STOP;

    return 0;
}

#endif /* ANDROID */
