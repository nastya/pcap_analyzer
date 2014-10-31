#include "connection.h"

#include <stdio.h>
#include <string.h>
#include <iterator>

Connection::Connection()
{
	buffer = NULL;
	buffer_size = 0;
}

Connection::Connection(string session_id)
{
	this->session_id = session_id;
	buffer = new unsigned char [BUFFER_ALLOCATE];
	buffer_size = 0;
}

Connection::Connection(const Connection & c)
{
	buffer = new unsigned char [BUFFER_ALLOCATE];
	session_id = c.session_id;
	memcpy(buffer, c.buffer, c.buffer_size);
	buffer_size = c.buffer_size;
}

Connection::~Connection()
{
	if (buffer != NULL)
		delete [] buffer;
	map <uint, Packet>::iterator it1;
	for (it1 = packet_map.begin(); it1 != packet_map.end(); it1++)
	{
		delete [] (it1->second.packet);
	}
}

void Connection::addData(unsigned char * payload, uint size_payload, Packet packet)
{
	if (BUFFER_ALLOCATE - buffer_size < size_payload)
	{
		fprintf(stderr, "Something went wrong, unable to add payload to Connection buffer.\n");
		return;
	}
	memcpy(buffer + buffer_size, payload, size_payload);
	uint start_pos = buffer_size;
	buffer_size += size_payload;

	uint packet_size = packet.header.caplen;
	unsigned char * copy_packet = new unsigned char [packet_size];
	memcpy(copy_packet, packet.packet, packet_size);
	Packet copy_p(copy_packet, packet.header);
	packet_map[start_pos] = copy_p;
}

uint Connection::getBufferSize()
{
	return buffer_size;
}

unsigned char * Connection::getBuffer()
{
	return buffer;
}

vector<Packet> Connection::getPackets()
{
	vector<Packet> v;
	for (auto it1 = packet_map.begin(); it1 != packet_map.end(); it1++)
	{
		v.push_back(it1->second);
	}
	return v;
}

void Connection::extractData(uint size)
{
	if (size == 0)
		return;
	if (size > buffer_size)
		size = buffer_size;
	if (size == BUFFER_ANALYZE)
	{
		memmove(buffer, buffer + (size*2/3), buffer_size - (size*2/3));
		buffer_size -= size*2/3;
		size = size *2/3; //the actual number of bytes we removed from the buffer
	}
	else
	{
		buffer_size = 0;
	}
	map <uint, Packet> new_packet_map;
	map <uint, Packet>::iterator it1, it2;
	for (it1 = packet_map.begin(); it1 != packet_map.end(); it1++)
	{
		if (it1->first < size) //we extracted at least part of this packet
		{
			if (next(it1) != packet_map.end())
			{
				if ((next(it1)->first) <= size)
				{
					//remove package
					delete [] (it1->second.packet);
				}
				else
				{
					new_packet_map[0] = it1->second;
					for (it2 = next(it1); it2 != packet_map.end(); it2++)
						new_packet_map[it2->first-size] = it2->second;
					break;
				}
			}
			if (next(it1) == packet_map.end())
			{
				if (buffer_size != 0)
					new_packet_map[0] = it1->second;
				else
					delete [] (it1->second.packet);
			}
		}
		else if (it1->first == size)
		{
			new_packet_map[0] = it1->second;
			for (it2 = next(it1); it2 != packet_map.end(); it2++)
				new_packet_map[it2->first-size] = it2->second;
			break;
		}
		else
		{
			fprintf(stderr, "Connection::extractData: Something is wrong, shouldn't get there\n");
			break;
		}
	}
	packet_map = new_packet_map;
}
