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
	Reader();
private:
	void processEthernetPkt(pcap_pkthdr header, const u_char * packet);
	void processIPv4Pkt(const u_char * packet, unsigned int remaining_len);
	void processIPv6Pkt(const u_char * packet, unsigned int remaining_len);
	void processTcpPkt(const u_char * packet, const char * src_ip, const char * dst_ip, uint tcp_tot_len);
	void processUdpPkt(const u_char * packet, const char * src_ip, const char * dst_ip, uint udp_tot_len);
	void addToConnections(string name, unsigned char * data, uint length);
	void analyzeConnection(string name);
	void writePcap(string name);
	map<string, Connection> connections;
	Packet _packet;
	pcap_t *pd;
	pcap_dumper_t *pdumper;
	FILE * logfile;
}; 

#endif //__PCAP_READER_H
