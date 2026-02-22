#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

typedef struct PacketInfo {
    struct pcap_pkthdr *pktheader;

    struct ether_header *eth;
    struct ip *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;

    u_char *payload;
    int payload_len;

} PacketInfo;

int packet_parser(const u_char *packet, struct pcap_pkthdr *header);

#endif