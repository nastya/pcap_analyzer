#ifndef __CONNECTION_H
#define __CONNECTION_H

#include "packet.h"
#include "config.h"

#include <string>
#include <map>
#include <vector>

#define BUFFER_ANALYZE (Config::buffer_analyze)
#define BUFFER_ALLOCATE (BUFFER_ANALYZE*2)

using namespace std;

class Connection
{
public:
	Connection();
	Connection(string session_id);
	Connection(const Connection & c);
	~Connection();
	void addData(unsigned char * payload, unsigned int size_payload, Packet packet);
	unsigned int getBufferSize();
	unsigned char * getBuffer();
	vector<Packet> getPackets();
	void extractData(unsigned int size);
private:
	string session_id;
	unsigned char * buffer;
	unsigned int buffer_size;
	map<uint, Packet> packet_map; //map from the position (only the first bytes of each payload) in buffer
					// to the corresponding packet
}; 

#endif //__CONNECTION_H
