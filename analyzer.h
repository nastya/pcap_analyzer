#ifndef __ANALYZER_H
#define __ANALYZER_H

#include <finddecryptor.h>
#include <stdio.h>

class Analyzer
{
public:
	static FindDecryptor analyzer;
	static void analyze(unsigned char * buffer, int size);
};

#endif //__ANALYZER_H