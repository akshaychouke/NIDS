#include <stdio.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include "printUtils.h"

void printMacAddress(const u_char *mac) {
    int i;
    for(i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if(i < 5) {
            printf(":");
        }
    }
    printf("\n");
}

void printIPtype(uint16_t eth_type) {
    switch(eth_type) {
        case ETHERTYPE_IP:
            printf("IPv4\n");
            break;
        case ETHERTYPE_IPV6:
            printf("IPv6\n");
            break;
        case ETHERTYPE_ARP:
            printf("ARP\n");
            break;
        default:
            printf("Unknown (0x%04x)\n", eth_type);
    }
}

/* Layer 2 Details */
void printEthernetHeader(const struct ether_header *eth_header) {
    printf("Ethernet Header:\n");
    printf("Source MAC: ");
    printMacAddress(eth_header->ether_shost);
    printf("Destination MAC: ");
    printMacAddress(eth_header->ether_dhost);
    printf("Ethernet Type: ");
    printIPtype(ntohs(eth_header->ether_type));
}

void printProtocol(uint8_t protocol) {
    printf("Protocol: ");
    switch(protocol) {
        case IPPROTO_TCP:
            printf("TCP\n");
            break;
        case IPPROTO_UDP:
            printf("UDP\n");
            break;
        case IPPROTO_ICMP:
            printf("ICMP\n");
            break;
        default:
            printf("Other (%d)\n", protocol);
    }
}
/* Layer 3 Details */
void printIPHeader(const struct ip *ip_header) {
    printf("IP Header:\n");
    printf("Version: %d\n", ip_header->ip_v);
    printf("Header Length: %d bytes\n", ip_header->ip_hl * 4);
    printf("Type of Service: 0x%02x\n", ip_header->ip_tos);
    printf("Total Length: %d bytes\n", ntohs(ip_header->ip_len));
    printf("Identification: 0x%04x\n", ntohs(ip_header->ip_id));
    printf("Flags: 0x%02x\n", ip_header->ip_off >> 13);
    printf("Fragment Offset: %d\n", ntohs(ip_header->ip_off) & 0x1fff);
    printf("Time to Live: %d\n", ip_header->ip_ttl);
    printProtocol(ip_header->ip_p);
    printf("Checksum: 0x%04x\n", ntohs(ip_header->ip_sum));
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
}

void printPacketInfo(const PacketInfo *pkt_info) {
    printf("Packet information.........\n");
    printEthernetHeader(pkt_info->eth);
    printIPHeader(pkt_info->ip);
    
}