#ifndef __PACKET_H
#define __PACKET_H

#include <pcap.h>

struct Packet
{
	Packet(const u_char *, struct pcap_pkthdr);
	Packet();
	Packet(const Packet &);
	const u_char * packet; //does not allocate memory for it, just stores the pointer
	struct pcap_pkthdr header;
};

#endif //__PACKET_H
