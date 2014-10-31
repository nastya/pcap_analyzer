#ifndef __ANALYZER_H
#define __ANALYZER_H

#include <finddecryptor.h>
#include <stdio.h>
#include <string>

class Analyzer
{
public:
	static FindDecryptor analyzer;
	static bool analyze(unsigned char * buffer, int size);
	static string getMessage();
	static string message;
};

#endif //__ANALYZER_H