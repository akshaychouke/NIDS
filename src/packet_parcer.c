#include <stdio.h>

#include "../include/packet_parcer.h"
#include "../include/printUtils.h"

int packet_parser(const u_char *packet, struct pcap_pkthdr *header) {
    
    printf("Parsing packet of length %u \n", header->caplen);

    PacketInfo pkt_info;
    pkt_info.pktheader = header;

    const struct ether_header *eth_header = (struct ether_header *) packet;
    pkt_info.eth = eth_header;

    const struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
    pkt_info.ip = ip_header;

    printPacketInfo(&pkt_info);

    return 0;
}