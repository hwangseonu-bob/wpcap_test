#ifndef WPCAP_TEST_PACKET_H
#define WPCAP_TEST_PACKET_H

#include "network_addr.h"

struct EtherHeader {
    HwAddr dst;
    HwAddr src;
    uint16_t ether_type;
};

struct IpHeader {
    uint8_t version_ihl;
    uint8_t type_of_service;
    uint16_t packet_length;
    uint16_t identifier;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    IpAddr sip;
    IpAddr dip;

    int length() const {
        return (version_ihl & 0x0F) * 4;
    }
};

struct TcpHeader {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint16_t hl_rb_flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;

    int length() const {
        return ((hl_rb_flags & 0x00F0) >> 4) * 4;
    }
};

#endif //WPCAP_TEST_PACKET_H
