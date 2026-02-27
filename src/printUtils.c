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

/* Layer 2 Details -> Ethernet Layer*/
void printEthernetHeader(const struct ether_header *eth_header) {
    printf("Ethernet Header:\n");
    printf("Source MAC: ");
    printMacAddress(eth_header->ether_shost);
    printf("Destination MAC: ");
    printMacAddress(eth_header->ether_dhost);
    printf("Ethernet Type: ");
    printIPtype(ntohs(eth_header->ether_type));
}

/* Layer 3 Details -> Network Layer*/
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

/* Layer 4 Details -> Transport Layer*/

void printTCFlags(uint8_t flags) {
    printf("TCP Flags: ");
    if(flags & TH_FIN) printf("FIN, ");
    if(flags & TH_SYN) printf("SYN, ");
    if(flags & TH_RST) printf("RST, ");
    if(flags & TH_PUSH) printf("PSH, ");
    if(flags & TH_ACK) printf("ACK, ");
    if(flags & TH_URG) printf("URG ");
    printf("\n");
}

void printTCPHeader(const struct tcphdr *tcp_header) {
    printf("TCP Header:\n");
    printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
    printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
    printf("Sequence Number: %u\n", ntohl(tcp_header->th_seq));
    printf("Acknowledgment Number: %u\n", ntohl(tcp_header->th_ack));
    printf("Data Offset: %d bytes\n", tcp_header->th_off * 4);
    printf("Flags: 0x%02x\n", tcp_header->th_flags);
    printTCFlags(tcp_header->th_flags);
    printf("Window Size: %d\n", ntohs(tcp_header->th_win));
    printf("Checksum: 0x%04x\n", ntohs(tcp_header->th_sum));
    printf("Urgent Pointer: %d\n", ntohs(tcp_header->th_urp));
}

void printUDPHeader(const struct udphdr *udp_header) {
    printf("UDP Header:\n");
    printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
    printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
    printf("Length: %d bytes\n", ntohs(udp_header->uh_ulen));
    printf("Checksum: 0x%04x\n", ntohs(udp_header->uh_sum));
}

void printPayload(const u_char *payload, int payload_len) {
    printf("Payload (%d bytes):\n", payload_len);
    for(int i = 0; i < payload_len; i++) {
        printf("%02x ", payload[i]);
        if((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

void printPacketInfo(const PacketInfo *pkt_info) {
    printf("Packet information.........\n");
    printEthernetHeader(pkt_info->eth);
    printIPHeader(pkt_info->ip);
    
    if(pkt_info->tcp != NULL) {
        printTCPHeader(pkt_info->tcp);
    } else if(pkt_info->udp != NULL) {
        printUDPHeader(pkt_info->udp);
    } else {
        printf("No TCP or UDP header found \n");
    }

    if(pkt_info->payload_len > 0) {
        printPayload(pkt_info->payload, pkt_info->payload_len);
    } else {
        printf("No payload data \n");
    }
}

/*
 * Dump the packet in a compact, Wireshark-like layout.  Each layer has a
 * one-line summary followed by indented field values; the payload is shown
 * in hex if present.  The intention is to give users a familiar, nicely
 * formatted representation without having to stitch together the lower-level
 * printer functions themselves.
 */
void printFormattedPacket(const PacketInfo *pkt_info) {
    if (!pkt_info || !pkt_info->eth) {
        printf("<no packet information>\n");
        return;
    }

    /* Ethernet layer */
    printf("Ethernet II, Src: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x%s", pkt_info->eth->ether_shost[i], (i < 5) ? ":" : "");
    }
    printf("  Dst: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x%s", pkt_info->eth->ether_dhost[i], (i < 5) ? ":" : "");
    }
    printf("  Type: ");
    printIPtype(ntohs(pkt_info->eth->ether_type));

    /* IP layer details */
    if (pkt_info->ip) {
        struct ip *ip = pkt_info->ip;
        char srcbuf[INET_ADDRSTRLEN], dstbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->ip_src, srcbuf, sizeof(srcbuf));
        inet_ntop(AF_INET, &ip->ip_dst, dstbuf, sizeof(dstbuf));

        printf("Internet Protocol Version %d, Src: %s, Dst: %s\n",
               ip->ip_v, srcbuf, dstbuf);
        printf("    Version: %d, Header Len: %d bytes, TOS: 0x%02x, Total Len: %d, ID: 0x%04x\n",
               ip->ip_v, ip->ip_hl * 4, ip->ip_tos, ntohs(ip->ip_len), ntohs(ip->ip_id));
        uint16_t ipoff = ntohs(ip->ip_off);
        printf("    Flags: 0x%02x", ipoff >> 13);
        if (ipoff & IP_RF) printf(" RF");
        if (ipoff & IP_DF) printf(" DF");
        if (ipoff & IP_MF) printf(" MF");
        printf(", Fragment Offset: %d\n", ipoff & 0x1fff);
        printf("    TTL: %d, Protocol: ", ip->ip_ttl);
        printProtocol(ip->ip_p);
        printf("    Checksum: 0x%04x\n", ntohs(ip->ip_sum));
    }

    /* Transport layer details */
    if (pkt_info->tcp) {
        struct tcphdr *tcp = pkt_info->tcp;
        printf("Transmission Control Protocol, Src Port: %d, Dst Port: %d, Seq: %u, Ack: %u\n",
               ntohs(tcp->th_sport), ntohs(tcp->th_dport), ntohl(tcp->th_seq), ntohl(tcp->th_ack));
        printf("    Data Offset: %d bytes, Flags: 0x%02x ", tcp->th_off * 4,
               tcp->th_flags);
        printTCFlags(tcp->th_flags);
        printf("    Window: %d, Checksum: 0x%04x, Urgent Ptr: %d\n",
               ntohs(tcp->th_win), ntohs(tcp->th_sum), ntohs(tcp->th_urp));
    } else if (pkt_info->udp) {
        struct udphdr *udp = pkt_info->udp;
        printf("User Datagram Protocol, Src Port: %d, Dst Port: %d, Length: %d\n",
               ntohs(udp->uh_sport), ntohs(udp->uh_dport), ntohs(udp->uh_ulen));
        printf("    Checksum: 0x%04x\n", ntohs(udp->uh_sum));
    }

    /* payload */
    if (pkt_info->payload_len > 0 && pkt_info->payload) {
        printPayload(pkt_info->payload, pkt_info->payload_len);
    } else {
        printf("No payload\n");
    }
}