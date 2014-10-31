#include "packet.h"

Packet::Packet(const u_char * p, struct pcap_pkthdr h)
{
	packet = p;
	header = h;
}

Packet::Packet()
{
	packet = NULL;
}

Packet::Packet(const Packet & p)
{
	packet = p.packet;
	header = p.header;
}
