/******************************************************************************
 Copyright 2011, The DES-SERT Team, Freie Universitaet Berlin (FUB).
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

#include "dessert.h"

static inline signed char hexchartoi(const char c) {
    switch(c) {
        case '0':
            return 0;
        case '1':
            return 1;
        case '2':
            return 2;
        case '3':
            return 3;
        case '4':
            return 4;
        case '5':
            return 5;
        case '6':
            return 6;
        case '7':
            return 7;
        case '8':
            return 8;
        case '9':
            return 9;
        case 'a':
        case 'A':
            return 10;
        case 'b':
        case 'B':
            return 11;
        case 'c':
        case 'C':
            return 12;
        case 'd':
        case 'D':
            return 13;
        case 'e':
        case 'E':
            return 14;
        case 'f':
        case 'F':
            return 15;
        default:
            return -1;
    }
}

static inline unsigned int hextoi(const char* input, const char** next) {
    unsigned int result = 0;

    for(; *input; input ++) {
        signed char member = hexchartoi(*input);

        if(member < 0) {
            break;
        }

        result *= 16;
        result += member;
    }

    if(next) {
        *next = input;
    }

    return result;
}

int dessert_parse_mac(const char* input_mac, mac_addr* hwaddr) {
    int i;

    for(i = 0; i < ETHER_ADDR_LEN; ++i) {
        const char* end = 0;
        unsigned int val = hextoi(&input_mac[i*3], &end);

        if(end != &input_mac[i*3 + 2] || *end != (i < ETHER_ADDR_LEN - 1 ? ':' : 0)) {
            return -1;
        }

        (*hwaddr)[i] = (uint8_t) val;
    }

    return 0;
}

