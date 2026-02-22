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

#endif