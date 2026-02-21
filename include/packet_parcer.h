#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>


int packet_parser(const u_char *packet, struct pcap_pkthdr *header);