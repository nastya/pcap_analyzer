#include "connection.h"

#include <stdio.h>
#include <string.h>

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
}

void Connection::addData(unsigned char * payload, int size_payload)
{
	if (BUFFER_ALLOCATE - buffer_size < size_payload)
	{
		fprintf(stderr, "Something went wrong, unable to add payload to Connection buffer.\n");
		return;
	}
	memcpy(buffer + buffer_size, payload, size_payload);
	buffer_size += size_payload;
}

int Connection::getBufferSize()
{
	return buffer_size;
}

unsigned char * Connection::extractData(int size)
{
	if (size == 0)
		return NULL;
	if (size > buffer_size)
		size = buffer_size;
	unsigned char * extracted_data = new unsigned char [size];
	memcpy(extracted_data, buffer, size);
	if (size == BUFFER_ANALYZE)
	{
		memmove(buffer, buffer + (size*2/3), buffer_size - (size*2/3));
		buffer_size -= size*2/3;
	}
	else
	{
		buffer_size = 0;
	}
	return extracted_data;
} 
