#ifndef __CONNECTION_H
#define __CONNECTION_H

#include "packet.h"

#include <string>
#include <map>
#include <vector>

#define BUFFER_ANALYZE 3000
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
	void extractData(unsigned int size = BUFFER_ANALYZE);
private:
	string session_id;
	unsigned char * buffer;
	unsigned int buffer_size;
	map<uint, Packet> packet_map; //map from the position (only the first bytes of each payload) in buffer
					// to the corresponding packet
}; 

#endif //__CONNECTION_H
