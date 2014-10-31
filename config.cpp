#include "config.h"

unsigned int Config::buffer_analyze = 3000; //the size of buffer used for analysis
string Config::analyzer_name = "FindDecryptor"; //Analyzer name: FindDecryptor or DetectSimilar
string Config::logfile = "log.txt"; //file to store messages about found shellcodes
string Config::shellcode_pcap_file = "shellcode_capture.pcap"; //file to store packages containing found shellcodes
