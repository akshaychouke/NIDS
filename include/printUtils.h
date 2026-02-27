#ifndef PRINTUTILS_H
#define PRINTUTILS_H

#include <stdint.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include "packet_parcer.h"

void printMacAddress(const u_char *mac);
void printIPtype(uint16_t eth_type);
void printEthernetHeader(const struct ether_header *eth_header);
void printIPHeader(const struct ip *ip_header);
void printPacketInfo(const PacketInfo *pkt_info);

/*
 * A more detailed, Wireshark‑style dump of a packet.  This prints a single
 * line summary for each layer (Ethernet, IP, TCP/UDP) followed by indented
 * field values and a hex/ASCII payload dump if one exists.  The goal is to
 * resemble the network traffic capture format used by tools like Wireshark.
 */
void printFormattedPacket(const PacketInfo *pkt_info);

#endif