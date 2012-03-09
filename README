
          DES-SERT - an Extensible Routing-Framework for Testbeds 


Copyright
   
   Copyright Philipp Schmidt <phils@inf.fu-berlin.de>,
   Computer Systems and Telematics / Distributed, Embedded Systems (DES) group, 
   Freie Universitaet Berlin

   This document has been published under GNU Free Documentation License.   
   All rights reserved.


1.  Introduction

   DES-SERT, the DES Simple and Extensible Routing-Framework for Testbeds,
   is a framework designed to assist researchers implementing routing
   protocols for testbeds.
   
   DES-SERT enables the implementation of routing protocols on top of
   Ethernet via an underlay (Layer 2.5) in user space.
   It introduces an abstraction from OS specific issues and provides
   functionality and data structures to implement proactive, reactive,
   and hybrid routing protocols. 
   
   While generally usable in many application scenarios, it is primarily
   used in DES-Mesh (http://www.des-testbed.net/), the multi-transceiver
   wireless mesh network testbed part of the DES-Testbed. 


2.  DES-SERT Architecture

   DES-SERT introduces some concepts to implement routing protocols.
   When implementing a routing protocol with DES-SERT, you should be
   familiar with these concepts to structure and tailor your implementation.


2.1.  messages

   Every packet you send or receive on the mesh is represented as a
   DES-SERT message. From a programmers point of view, a DES-SERT message
   is just a C-structure:
   
      typedef struct dessert_msg {
          /** the layer2 header on the wire */
          struct     ether_header l2h;
          /** short name of the protocol as passed to dessert_init() */
          char       proto[DESSERT_PROTO_STRLEN];
          /** version of the app as passed to dessert_init() */
          uint8_t    ver;
          /** flags - bits 1-4 reserved for dessert, bits 5-8 for app usage */
          uint8_t    flags;
          /** ttl or hopcount field for app usage - 0xff if not used*/
          uint8_t    ttl;
          /** reserved for app usage - 0x00 if not used */
          uint8_t    u8;
          /** reserved for app usage - 0xbeef if not used */
          uint16_t   u16;
          /** header length incl. extensions */
          uint16_t   hlen;
          /** payload length */
          uint16_t   plen;
      } dessert_msg_t;
   
   Every message sent via the underlay carries this structure as a packet
   header. All data in a "dessert_msg" is stored in network byte order. 
   DES-SERT tries to care as automatically as possible of this structure.
   Nevertheless you will have to care at least about: "l2h.ether_dhost" and
   "ttl".
   
   If you need to send some data along with every packet, e.g. some kind of
   metric or cost your routing protocol uses, you should try to fit this
   data into the "u8", "u16" and the upper 4 bits of the "flags" field.
   These fields will never be touched by DES-SERT except on initialization
   via "dessert_msg_new".
   
   Because just a C-structure is not really usable as a packet, there are some
   utility functions around - please have a look around in "dessert.h" and the  
   doxygen doku. The most important ones are: "dessert_msg_new" and
   "dessert_msg_destroy", which do not simply allocate memory for a DES-SERT
   message, but for a whole packet of maximum size and initialize the 
   structures for further packet construction/processing.
   
      int dessert_msg_new(dessert_msg_t **msgout);
      
      void dessert_msg_destroy(dessert_msg_t* msg);


2.1.2  DES-SERT extensions

   A DES-SERT extension is some structure used to piggyback data on a 
   DES-SERT message. It consists of a 8-bit user supplied type field (with
   some reserved values), an 8-bit length field and user supplied data of
   arbitrary length of 253 bytes at most.
   
   It can be added to a message via "dessert_msg_addext", retrieved via
   "dessert_msg_getext" and removed via "dessert_msg_delext".
   
      int dessert_msg_addext(dessert_msg_t* msg, 
         dessert_ext_t** ext, uint8_t type, size_t len);
      
      int dessert_msg_getext(const dessert_msg_t* msg, 
         dessert_ext_t** ext, uint8_t type, int index);
      
      int dessert_msg_delext(dessert_msg_t *msg, dessert_ext_t *ext);
   
   It is recommended not to put single data fields in extensions, but 
   combine semantically related data in a struct and attach this struct
   as an extension because every extension carried introduces an 16-bit
   overhead to the packet.


2.2.  Processing pipelines

   Routing algorithms are often split up in several parts like packet 
   validation, loop-detection or routing table lookup.
   To implement these as independent and clear as possible, DES-SERT enables
   you to split up your packet processing in as many parts as you like.
   
   There are two separate processing pipelines - one for packets received 
   from the kernel via a TUN or TAP interface and one for packets received
   via an interface used on the mesh network.
   
   You can register callbacks to be added to one of these pipelines with 
   "dessert_sysrxcb_add" or "dessert_meshrxcb_add". Both take an additional
   integer argument ("priority") specifying the order the callbacks should
   be called. Higher "priority" value results in being called later
   within the pipeline.
   
      int dessert_sysrxcb_add(dessert_sysrxcb_t* c, int prio);
      
      int dessert_meshrxcb_add(dessert_meshrxcb_t* c, int prio);

   If a callback returns "DESSERT_MSG_KEEP" the packed will be processed by
   further callbacks, if it returns "DESSERT_MSG_DROP" the message will be
   dropped and no further callbacks will be called.
   
   You do not need to care about the management of the buffers for incoming
   messages - DES-SERT does this for you. Nevertheless if you need to add
   extensions or enlarge the payload of a message, you need to tell DES-SERT
   to enlarge the buffer for you if the flag "DESSERT_FLAG_SPARSE" is set on
   the message. You can do this by returning "DESSERT_MSG_NEEDNOSPARSE" from
   within a callback. The callback will be called again with a larger buffer
   and no "DESSERT_FLAG_SPARSE" flag being set.


2.2.1.  Processing buffer

   If you need to pass information along several callbacks, you can do this
   in the processing buffer passed to the the callbacks. This buffer contains
   some local processing flags ("lflags") set by the builtin callback
   "dessert_msg_ifaceflags_cb" (e.g. telling you about packet origin or if
   the packet is multicast) and 1KB of space for your callbacks to pass 
   along arbitrary data.
   
   This buffer might only be allocated after you explicitly request it - in
   this case the proc argument is NULL and you can return the value
   "DESSERT_MSG_NEEDMSGPROC" from within your callback. The callback will
   be called again with a valid processing buffer.


2.3.  Using interfaces


2.3.1. Using a TUN/TAP interface

   First you have to choose whether to use a TUN or TAP interface. TUN
   interfaces are used to exchange IPv4 / IPv6 datagrams with the kernel 
   network stack. TAP interfaces are used to exchange Ethernet frames
   with the kernel network stack. If you want to route Ethernet frames,
   you should choose a TAP interface. If you intend to implement
   a custom layer 2 to layer 3 mapping, you should use a TUN interface.
   
   Currently, you can only initialize and use a single sys (TUN/TAP) interface.
   This is done by "dessert_sysif_init". You must then set up the interface
   config in the kernel yourself e.g. by calling "ifconfig".
   
      int dessert_sysif_init(char* name, uint8_t flags);
   
   In either case, frames you receive from a TUN/TAP interface will be
   passed along the callbacks added by "dessert_sysrxcb_add" to the 
   processing pipeline. Each of them will be called with a pointer to an
   Ethernet frame. In case of a TUN interface, "ether_shost" and "ether_dhost"
   are set to "00:00:00:00:00:00", and ether_type reflects whether the packet
   received is IPv4 oder IPv6.
   
   Packets are sent to the kernel network stack with "dessert_syssend".
   In case of a TUN Interface "ether_shost" and "ether_dhost" will be
   ignored.
   
       int dessert_syssend(const struct ether_header *eth, size_t len);


2.3.2. Using a mesh interface

   Mesh interfaces are used similar to the TUN/TAP interface with two major
   differences: You can have multiple mesh interfaces and they send and
   receive DES-SERT messages instead of Ethernet frames. 
   
   You add an mesh interface using "dessert_meshif_add" and can send to it
   by calling "dessert_meshsend". If the interface parameter is NULL, the
   packet will be transmitted over every interface (good for flooding).

      int dessert_meshif_add(const char* dev, uint8_t flags);
      
      int dessert_meshsend(const dessert_msg_t* msg, 
         const dessert_meshif_t *iface);


2.4.  Logging

   You can write log messages easily with a bunch of macros provided
   by DES-SERT ("dessert_debug", "dessert_info" ,"dessert_notice",
   "dessert_warn", "dessert_warning", "dessert_err", "dessert_crit", 
   "dessert_alert" and "dessert_emerg"). Each of them can be used like
   "printf" and logs to Syslog, STDERR, file or a ringbuffer depending
   on your configuration.

   DES-SERT also ships with a custom "assert" macro which acts like
   the original macro from the standard C library and uses the logging
   mechanism described above.


2.5.  Periodics

   Periodics help you to perform maintenance or delayed tasks. A task
   consists of a callback, which will be called at the time you requested,
   and a void pointer the callback is passed. You can add these tasks by
   calling "dessert_periodic_add" or "dessert_periodic_add_delayed".


2.6.  CLI

   DES-SERT supports simple configuration and debugging of your routing
   protocol implementation by providing a Cisco like command line interface
   (cli) and a config file parser based upon it.
   This cli is realized through libcli (http://code.google.com/p/libcli/). 
   
   DES-SERT does some of the initialization of libcli. Therefore, it provides
   the main cli anchor "dessert_cli" and some anchors to add commands below
   "dessert_cli_.*". Because DES-SERT only loosely wraps libcli, you should
   make yourself familiar with libcli itself. This may be improved in further
   DES-SERT releases.
   
   You can evaluate a config file by calling "cli_file" and start a thread
   enabling a telnet-interface for DES-SERT by calling "dessert_cli_run".


2.7. Putting all together

   Now you have learned about the most important aspects of DES-SERT.
   To write your own routing protocol implementation, you need to know
   how to put all this together.
   
   You should start with a main() program parsing the command line options
   and then calling "dessert_init()". This is needed to set up DES-SERT 
   correctly. Afterwards you can register callbacks, read the config file
   and do what you like. If everything is set up, you call "dessert_run()"
   and let the event based framework do its job.
   
   If you would like to see a complete protocol implementation sample,
   have a look at the "gossiping" directory.


3. Contact & Feedback

   We love feedback - if you have patches, comments or questions,
   please contact us! Recent contact information is available on
           http://www.des-testbed.net/des-sert/
