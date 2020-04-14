#ifndef WPCAP_TEST_NETWORK_ADDR_H
#define WPCAP_TEST_NETWORK_ADDR_H

#include <cstdint>
#include <string>

using byte = uint8_t;

struct HwAddr {
    byte addr[6]{};

    std::string to_string() const {
        char buf[20];
        sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
        return std::string(buf);
    }

    friend std::ostream &operator<<(std::ostream &o, const HwAddr& a) {
        return o << a.to_string();
    }
};


struct IpAddr {
    uint8_t addr[4];

    std::string to_string() const {
        char buff[20];
        sprintf(buff, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
        return std::string(buff);
    }

    friend std::ostream &operator<<(std::ostream &o, const IpAddr& a) {
        return o << a.to_string();
    }
};


#endif //WPCAP_TEST_NETWORK_ADDR_H
