#include "pcap_reader.h"
#include "analyzer.h"

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define SIZE_ETHERNET 14
#define TCP_NUMBER (0x06)
#define UDP_NUMBER (0x11)

void Reader::readInterface(const char * interface)
{
	pcap_t *handle; 
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL )
	{
		fprintf(stderr, "Couldn't open interface %s\n", interface); 
		return;
	}
	while (true)
	{
		pcap_pkthdr header;
		const u_char * packet = pcap_next(handle, &header);
		if (!packet)
			continue;
		if (pcap_datalink(handle) == DLT_EN10MB)
		{
			//fprintf(stdout, "Ethernet package received!\n");
			processEthernetPkt(header, packet);
		}
		/*if (pcap_datalink(handle) == DLT_IEEE802_11)
			fprintf(stdout, "Wifi package received!\n");*/
	}
}

void Reader::readPcap(const char * name)
{
	connections.clear();
	pcap_t *handle; 
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	const u_char *packet;
	handle = pcap_open_offline(name, errbuf);   //call pcap library function 
	
	if (handle == NULL)
	{ 
		fprintf(stderr,"Couldn't open pcap file %s: %s\n", name, errbuf); 
		return; 
	}
	while ((packet = pcap_next(handle, &header)) != NULL)
	{ 
		// header contains information about the packet (e.g. timestamp)
		if( pcap_datalink(handle) == DLT_EN10MB )
			processEthernetPkt(header, packet);
	}
	pcap_close(handle);
	//fprintf(stdout, "Opened connections: %d\n", connections.size());
	for (map<string, Connection>::iterator it = connections.begin(); it != connections.end(); ++it)
	{
		//fprintf(stdout, "%s\n",it->first.c_str());
		analyzeConnection(it->first);
	}
}

Reader::~Reader()
{
	connections.clear();
}

void Reader::processEthernetPkt(pcap_pkthdr header, const u_char * packet)
{
	int caplen = header.caplen; /* length of portion present from bpf */
	int length = header.len; /* length of this packet off the wire */
	if (caplen < length)
		return;
	if (caplen < SIZE_ETHERNET)
	{
		fprintf(stderr, "Caplen %d is less than header size, total packet size %d\n", caplen, length);
		return;
	}
	struct ether_header * hdr_ethernet = (struct ether_header*)( packet );
	u_int16_t type = ntohs(hdr_ethernet->ether_type);
	if (type == ETHERTYPE_IP)
		processIPv4Pkt(packet + sizeof(struct ether_header), caplen - sizeof(struct ether_header));
	if (type == ETHERTYPE_IPV6)
		processIPv6Pkt(packet + sizeof(struct ether_header), caplen - sizeof(struct ether_header));
}

void Reader::processIPv4Pkt(const u_char * packet, int remaining_len)
{
	struct ip * hdr_ip = (struct ip *)(packet);
	int size_ip = hdr_ip->ip_hl * 4;
	if (size_ip < 20 || size_ip > remaining_len)
	{
		fprintf(stderr, "Invalid IP header length: %d bytes, less than 20 bytes\n",size_ip);
		return;
	}
	//tcp packet has been received
	if (hdr_ip->ip_p == TCP_NUMBER)
		processTcpPkt(packet + size_ip, inet_ntoa(hdr_ip->ip_src), inet_ntoa(hdr_ip->ip_dst),
				ntohs(hdr_ip->ip_len) - size_ip);
	//udp packet
	if(hdr_ip->ip_p == UDP_NUMBER)
		processUdpPkt(packet + size_ip, inet_ntoa(hdr_ip->ip_src), inet_ntoa(hdr_ip->ip_dst),
				ntohs(hdr_ip->ip_len) - size_ip);
}

void Reader::processIPv6Pkt(const u_char * packet, int remaining_len)
{
	if ((int)(sizeof(struct ip6_hdr)) > remaining_len)
		fprintf(stderr, "Invalid IPv6 packet\n");
	struct ip6_hdr * hdr_ip6 = (struct ip6_hdr *)(packet);
	int size_ip6 = sizeof(struct ip6_hdr);
	char source_addr[INET6_ADDRSTRLEN], dest_addr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &(hdr_ip6->ip6_src), source_addr, sizeof(source_addr));
	inet_ntop(AF_INET6, &(hdr_ip6->ip6_dst), dest_addr, sizeof(dest_addr));
	if (hdr_ip6->ip6_nxt == TCP_NUMBER)
		processTcpPkt(packet + size_ip6, source_addr, dest_addr, ntohs(hdr_ip6->ip6_plen));
	if (hdr_ip6->ip6_nxt == UDP_NUMBER)
		processUdpPkt(packet + size_ip6, source_addr, dest_addr, ntohs(hdr_ip6->ip6_plen));
}

void Reader::processTcpPkt(const u_char * packet, const char * src_ip, const char * dst_ip, int tcp_tot_len)
{
	if (tcp_tot_len < (int)(sizeof(struct tcphdr )))
	{
		fprintf(stderr, "Invalid TCP packet\n");
		return;
	}
	struct tcphdr * hdr_tcp = (struct tcphdr *)(packet);
	int size_tcp = hdr_tcp->th_off * 4;
	if (size_tcp < 20 )
	{
		fprintf(stderr, "Invalid TCP header length\n");
		return;
	}

	int tcp_source_p = ntohs(hdr_tcp->source);
	int tcp_dest_p = ntohs(hdr_tcp->dest);
			char s_port_buf[10], d_port_buf[10];
	snprintf(s_port_buf, 10, "%d", tcp_source_p);
	snprintf(d_port_buf, 10, "%d", tcp_dest_p);
	string name = string(src_ip) + ":" + string(s_port_buf) + "->" +
			string(dst_ip) + ":" + string(d_port_buf);

	int size_payload = tcp_tot_len - size_tcp;
	unsigned char * payload = (unsigned char *)(packet + size_tcp);

	if (hdr_tcp->fin)
	{
		//fprintf(stderr, "Received fin of connection %s\n", name.c_str());
		if (connections.count(name) != 0)
		{
			analyzeConnection(name);
			connections.erase(name);
		}
	}
	else
	{
		//fprintf(stderr, "Adding to connections tcp connection %s of size %d\n", name.c_str(), size_payload);
		addToConnections(name, payload, size_payload);
	}
}

void Reader::processUdpPkt(const u_char * packet, const char * src_ip, const char * dst_ip, int udp_tot_len)
{
	if (udp_tot_len < (int)(sizeof(struct udphdr)))
	{
		fprintf(stderr, "Invalid UDP packet\n");
		return;
	}
	struct udphdr * hdr_udp = (struct udphdr *)(packet);
	int size_udp = sizeof(udphdr);
	int size_payload = udp_tot_len - size_udp;
	unsigned char * payload = (unsigned char *)(packet + size_udp);

	int udp_source_p = ntohs(hdr_udp->source);
	int udp_dest_p = ntohs(hdr_udp->dest);
	char s_port_buf[10], d_port_buf[10];
	snprintf(s_port_buf, 10, "%d", udp_source_p);
	snprintf(d_port_buf, 10, "%d", udp_dest_p);
	string name = string(src_ip) + ":" + string(s_port_buf) + "->" +
			string(dst_ip) + ":" + string(d_port_buf);
	//fprintf(stderr, "Adding to connections udp connection %s of size %d\n", name.c_str(), size_payload);
	addToConnections(name, payload, size_payload);
}

void Reader::addToConnections(string name, unsigned char * data, int length)
{
	if (connections.count(name) == 0)
		connections.insert(pair<string, Connection>(name, Connection(name)));
	connections[name].addData(data, length);
	if (connections[name].getBufferSize() >= BUFFER_ANALYZE)
		analyzeConnection(name);
}

void Reader::analyzeConnection(string name)
{
	//fprintf(stderr, "In analyzing connection %s, size %d\n", name.c_str(), connections[name].getBufferSize());
	int buffer_size = BUFFER_ANALYZE;
	if (connections[name].getBufferSize() < buffer_size)
		buffer_size = connections[name].getBufferSize();
	if (buffer_size == 0)
		return;
	unsigned char * buffer = connections[name].extractData();
	//... analyze buffer of size buffer_size
	Analyzer::analyze(buffer, buffer_size);
	//fprintf(stdout, "Analyzing Connection %s...\n", name.c_str());
	delete [] buffer;
} 
