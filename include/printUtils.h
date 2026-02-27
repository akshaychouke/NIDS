#ifndef PRINTUTILS_H
#define PRINTUTILS_H

#include <stdint.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include "packet_parcer.h"

/* Layer 2 Details -> Ethernet Layer*/
void printMacAddress(const u_char *mac);
void printIPtype(uint16_t eth_type);
void printEthernetHeader(const struct ether_header *eth_header);

/* Layer 3 Details -> Network Layer*/
void printProtocol(uint8_t protocol);
void printIPHeader(const struct ip *ip_header);

/* Layer 4 Details -> Transport Layer*/
void printTCFlags(uint8_t flags);
void printTCPHeader(const struct tcphdr *tcp_header);
void printUDPHeader(const struct udphdr *udp_header);
void printPayload(const u_char *payload, int payload_len);
void printPacketInfo(const PacketInfo *pkt_info);

/*
 * A more detailed, Wireshark‑style dump of a packet.  This prints a single
 * line summary for each layer (Ethernet, IP, TCP/UDP) followed by indented
 * field values and a hex/ASCII payload dump if one exists.  The goal is to
 * resemble the network traffic capture format used by tools like Wireshark.
 */
void printFormattedPacket(const PacketInfo *pkt_info);

#endif