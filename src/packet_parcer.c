#include <stdio.h>

#include "../include/packet_parcer.h"
#include "../include/printUtils.h"

void parseTCPHeader(const u_char *tcp_header, PacketInfo *pkt_info) {
    pkt_info->tcp = (struct tcphdr *) tcp_header;
    pkt_info->udp = NULL;

    int tcp_header_len = pkt_info->tcp->th_off * 4;
    pkt_info->payload = (u_char *) (tcp_header + tcp_header_len);
    pkt_info->payload_len = pkt_info->pktheader->caplen - (sizeof(struct ether_header) + pkt_info->ip->ip_hl * 4 + tcp_header_len);
}

void parseUDPHeader(const u_char *udp_header, PacketInfo *pkt_info) {
    pkt_info->udp = (struct udphdr *) udp_header;
    pkt_info->tcp = NULL;

    pkt_info->payload = (u_char *) (udp_header + sizeof(struct udphdr));
    pkt_info->payload_len = pkt_info->pktheader->caplen - (sizeof(struct ether_header) + pkt_info->ip->ip_hl * 4 + sizeof(struct udphdr));
}

int packet_parser(const u_char *packet, struct pcap_pkthdr *header) {
    
    printf("Parsing packet of length %u \n", header->caplen);

    PacketInfo pkt_info;
    pkt_info.pktheader = header;

    const struct ether_header *eth_header = (struct ether_header *) packet;
    pkt_info.eth = eth_header;

    const struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
    pkt_info.ip = ip_header;

    int ip_header_len = ip_header->ip_hl * 4;
    u_char *transport_layer_header = (u_char *) (packet + sizeof(struct ether_header) + ip_header_len);
    
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            parseTCPHeader(transport_layer_header, &pkt_info);
            printPacketInfo(&pkt_info);
            break;
        case IPPROTO_UDP:
            parseUDPHeader(transport_layer_header, &pkt_info);
            printPacketInfo(&pkt_info);
            break; 
        default:
            printf("Unsupported transport layer protocol: %d \n", ip_header->ip_p);
            break;
    }
    
    return 0;
}