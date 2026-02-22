#include<pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include "../include/packet_parcer.h"


void printMacAddress(const u_char *mac);
void printIPtype(uint16_t eth_type);
void printEthernetHeader(const struct ether_header *eth_header);
void printIPHeader(const struct ip *ip_header);
void printPacketInfo(const PacketInfo *pkt_info);