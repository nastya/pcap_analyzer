#ifndef __CONNECTION_H
#define __CONNECTION_H

#include <string>

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
	void addData(unsigned char * payload, int size_payload);
	int getBufferSize();
	unsigned char * extractData(int size = BUFFER_ANALYZE);
private:
	string session_id;
	unsigned char * buffer;
	int buffer_size;
}; 

#endif //__CONNECTION_H
