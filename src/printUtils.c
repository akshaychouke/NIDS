#include <stdio.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>

/* Control whether to print verbose (multi-line) or summary (single-line) */
static int print_verbose = 0;

void setPrintVerbose(int enabled) {
    print_verbose = enabled ? 1 : 0;
}

int getPrintVerbose(void) {
    return print_verbose;
}

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

/* Layer 3 Details -> Network Layer*/
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
 * Print a concise, tcpdump-like single-line summary of the packet.
 * Example output:
 * 2026-02-27 12:34:56.123 192.168.0.1.34567 > 10.0.0.1.80: TCP [SYN] length 74
 */
void printVerboseOneLine(const PacketInfo *pkt_info) {
    if (!pkt_info || !pkt_info->pktheader || !pkt_info->ip) return;

    /* Single-line verbose output: include full headers separated by ' | ' */
    /* timestamp */
    time_t sec = pkt_info->pktheader->ts.tv_sec;
    struct tm lt;
    localtime_r(&sec, &lt);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &lt);
    long msec = pkt_info->pktheader->ts.tv_usec / 1000;

    printf("%s.%03ld | ", timestr, msec);

    /* Ethernet */
    printf("eth src=");
    for(int i=0;i<6;i++) printf("%02x%s", pkt_info->eth->ether_shost[i], i<5?":":"");
    printf(" dst=");
    for(int i=0;i<6;i++) printf("%02x%s", pkt_info->eth->ether_dhost[i], i<5?":":"");
    printf(" type=0x%04x | ", ntohs(pkt_info->eth->ether_type));

    /* IP header fields */
    printf("ip v=%d hl=%d tos=0x%02x len=%d id=0x%04x flg=0x%02x off=%d ttl=%d proto=%d sum=0x%04x src=%s dst=%s | ",
           pkt_info->ip->ip_v,
           pkt_info->ip->ip_hl*4,
           pkt_info->ip->ip_tos,
           ntohs(pkt_info->ip->ip_len),
           ntohs(pkt_info->ip->ip_id),
           pkt_info->ip->ip_off>>13,
           ntohs(pkt_info->ip->ip_off)&0x1fff,
           pkt_info->ip->ip_ttl,
           pkt_info->ip->ip_p,
           ntohs(pkt_info->ip->ip_sum),
           inet_ntoa(pkt_info->ip->ip_src),
           inet_ntoa(pkt_info->ip->ip_dst));

    /* Transport */
    if (pkt_info->tcp) {
        printf("tcp sport=%u dport=%u seq=%u ack=%u off=%d flags=0x%02x ",
               ntohs(pkt_info->tcp->th_sport),
               ntohs(pkt_info->tcp->th_dport),
               ntohl(pkt_info->tcp->th_seq),
               ntohl(pkt_info->tcp->th_ack),
               pkt_info->tcp->th_off*4,
               pkt_info->tcp->th_flags);
        printf("win=%u sum=0x%04x urg=%u | ",
               ntohs(pkt_info->tcp->th_win),
               ntohs(pkt_info->tcp->th_sum),
               ntohs(pkt_info->tcp->th_urp));
    } else if (pkt_info->udp) {
        printf("udp sport=%u dport=%u len=%u sum=0x%04x | ",
               ntohs(pkt_info->udp->uh_sport),
               ntohs(pkt_info->udp->uh_dport),
               ntohs(pkt_info->udp->uh_ulen),
               ntohs(pkt_info->udp->uh_sum));
    }

    printf("payload_len=%d", pkt_info->payload_len);
    printf("\n");
}

/*
 * Print a concise, tcpdump-like single-line summary of the packet.
 * Example output:
 * 2026-02-27 12:34:56.123 192.168.0.1.34567 > 10.0.0.1.80: TCP [SYN] length 74
 */
void printFormattedPacket(const PacketInfo *pkt_info) {
    if (!pkt_info || !pkt_info->pktheader || !pkt_info->ip) return;
    
    /* Timestamp */
    time_t sec = pkt_info->pktheader->ts.tv_sec;
    struct tm lt;
    localtime_r(&sec, &lt);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &lt);
    long msec = pkt_info->pktheader->ts.tv_usec / 1000;

    /* IP addresses */
    char src[INET_ADDRSTRLEN] = "";
    char dst[INET_ADDRSTRLEN] = "";
    inet_ntop(AF_INET, &pkt_info->ip->ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &pkt_info->ip->ip_dst, dst, sizeof(dst));

    /* Start printing summary */
    printf("%s.%03ld ", timestr, msec);

    if (pkt_info->tcp) {
        printf("%s.%u > %s.%u: TCP ", src, ntohs(pkt_info->tcp->th_sport), dst, ntohs(pkt_info->tcp->th_dport));

        /* Flags */
        char flags[64] = "";
        int pos = 0;
        if (pkt_info->tcp->th_flags & TH_FIN) pos += snprintf(flags + pos, sizeof(flags) - pos, "FIN,");
        if (pkt_info->tcp->th_flags & TH_SYN) pos += snprintf(flags + pos, sizeof(flags) - pos, "SYN,");
        if (pkt_info->tcp->th_flags & TH_RST) pos += snprintf(flags + pos, sizeof(flags) - pos, "RST,");
        if (pkt_info->tcp->th_flags & TH_PUSH) pos += snprintf(flags + pos, sizeof(flags) - pos, "PSH,");
        if (pkt_info->tcp->th_flags & TH_ACK) pos += snprintf(flags + pos, sizeof(flags) - pos, "ACK,");
        if (pkt_info->tcp->th_flags & TH_URG) pos += snprintf(flags + pos, sizeof(flags) - pos, "URG,");
        if (pos > 0) {
            /* trim trailing comma */
            if (flags[pos - 1] == ',') flags[pos - 1] = '\0';
            printf("[%s] ", flags);
        }

        printf("length %u", pkt_info->pktheader->caplen);
    } else if (pkt_info->udp) {
        printf("%s.%u > %s.%u: UDP length %u", src, ntohs(pkt_info->udp->uh_sport), dst, ntohs(pkt_info->udp->uh_dport), pkt_info->pktheader->caplen);
    } else {
        /* Non-TCP/UDP: show protocol and length */
        printf("%s > %s: Proto %d length %u", src, dst, pkt_info->ip->ip_p, pkt_info->pktheader->caplen);
    }

    printf("\n");
}