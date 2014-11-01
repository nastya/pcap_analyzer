#ifndef __ANALYZER_H
#define __ANALYZER_H

#include <finddecryptor.h>
#include <detectSimilar.h>
#include <stdio.h>
#include <string>

#include "config.h"

class Analyzer
{
public:
	static FindDecryptor decryptor_analyzer;
	static DetectSimilar * similarity_analyzer;
	static bool analyze(unsigned char * buffer, int size);
	static string getMessage();
	static string message;
	static void initAnalyzer();
	static void freeAnalyzer();
};

#endif //__ANALYZER_H