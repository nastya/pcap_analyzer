#ifndef __PCAP_READER_H
#define __PCAP_READER_H

#include "connection.h"

#include <string>
#include <map>
#include <pcap.h>

using namespace std;

class Reader
{
public:
	void readInterface(const char * interface);
	void readPcap(const char * name);
	~Reader();
private:
	void processEthernetPkt(pcap_pkthdr header, const u_char * packet);
	void processIPv4Pkt(const u_char * packet, int remaining_len);
	void processIPv6Pkt(const u_char * packet, int remaining_len);
	void processTcpPkt(const u_char * packet, const char * src_ip, const char * dst_ip, int tcp_tot_len);
	void processUdpPkt(const u_char * packet, const char * src_ip, const char * dst_ip, int udp_tot_len);
	void addToConnections(string name, unsigned char * data, int length);
	void analyzeConnection(string name);
	map<string, Connection> connections;
}; 

#endif //__PCAP_READER_H
