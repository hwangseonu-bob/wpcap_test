#include <iostream>
#include <pcap.h>

#include "packet.h"

#define ETHERTYPE_IP 0x0800
#define MAX_PACKET_SIZE 8192

using namespace std;

pcap_if* select_device() {
    int i, num;

    pcap_if *alldevs;
    pcap_if *d;

    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        throw std::runtime_error(errbuf);
    }

    for (d = alldevs, i = 0; d != nullptr; d = d->next) {
        cout << ++i << ". " << d->name << ' ';
        if (d->description) {
            cout << '(' << d->description << ')';
        } else {
            cout << "(No description available)";
        }
        cout << endl;
    }

    cout << "select interface >> ";
    cin >> num;

    for(d=alldevs, i=0; i<num-1; d=d->next, i++);

    return d;
}

void handle_packet(pcap_pkthdr *header, const byte* packet) {
    auto *eth = reinterpret_cast<const EtherHeader*>(packet);

    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        auto *ip = reinterpret_cast<const IpHeader*>(packet + sizeof(EtherHeader));

        if (ip->protocol == IPPROTO_TCP) {
            auto *tcp = reinterpret_cast<const TcpHeader*>(packet + sizeof(EtherHeader) + ip->length());

            cout << ip->sip << ':' << ntohs(tcp->sport);
            cout << " -> ";
            cout << ip->dip << ':' << ntohs(tcp->dport);
            cout << endl;
        }
    }
}

int main() {
    try {
        pcap_if *dev = select_device();

        pcap *handle;
        pcap_pkthdr *header;
        const byte *packet;
        char errbuf[PCAP_ERRBUF_SIZE];

        cout << "Open Device " << dev->name << endl;
        handle = pcap_open_live(dev->name, MAX_PACKET_SIZE, 1, 512, errbuf);

        if (handle == nullptr) {
            throw std::runtime_error(errbuf);
        }

        int res;
        while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
            if (res == 0) continue;
            handle_packet(header, packet);
        }

        pcap_close(handle);
    } catch (std::runtime_error &e) {
        cerr << e.what() << endl;
        return EXIT_FAILURE;
    }
    return 0;
}
