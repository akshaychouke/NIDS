#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include "../include/packet_parcer.h"

/*
int packet_parser(const u_char *packet, struct pcap_pkthdr *header) {
    // Basic packet parsing example: print source and destination IP addresses for TCP packets
    const struct ether_header *eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        const struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
        if (ip_header->ip_p == IPPROTO_TCP) {
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
            printf("TCP Packet: Src IP: %s, Dst IP: %s\n", src_ip, dst_ip);
        }
    }
    return 0;
}
*/

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

int packet_parser(const u_char *packet, struct pcap_pkthdr *header) {
    
    printf("Parsing packet of length %u \n", header->caplen);

    const struct ether_header  *eth_header = (struct ether_header *) packet;

    printf("Layer 2: Ethernet Header \n");
    printf("Source MAC: ");
    printMacAddress(eth_header->ether_shost);
    printf("Destination MAC: ");    
    printMacAddress(eth_header->ether_dhost);
    printf("Ethernet Type: ");
    printIPtype(ntohs(eth_header->ether_type));

    return 0;
}