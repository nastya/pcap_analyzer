#ifndef __CONFIG_H
#define __CONFIG_H

#include <string>

using namespace std;

class Config
{
public:
	static unsigned int buffer_analyze; //the size of buffer used for analysis
	static string analyzer_name;
	static string logfile;
	static string shellcode_pcap_file;
};

#endif //__CONFIG_H
