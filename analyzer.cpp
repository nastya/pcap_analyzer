#include "analyzer.h"
#include <stdio.h>
#include <list>
#include <string>

FindDecryptor Analyzer::analyzer = FindDecryptor();
string Analyzer::message = "";

bool Analyzer::analyze(unsigned char * buffer, int size)
{
	/*fprintf(stdout, "Analyzing buffer of size %d...\n", size);
	for (int i = 0; i < size; i++)
		fprintf(stdout, "%c", buffer[i]);
	fprintf(stdout, "\n");*/
	analyzer.link(buffer, size);
	int found = analyzer.find();
	if (found)
	{
		message = "Decryptor found!\n";
		list <int> start_pos = analyzer.get_start_list();
		for (list<int>::iterator it = start_pos.begin(); it != start_pos.end(); it++)
		{
			message += "Decryption routine:\n";
			message += analyzer.get_decryptor(*it);
			message += "--------------------------------------------------------------\n";
		}
		return true;
	}
	message = "";
	return false;
}

string Analyzer::getMessage()
{
	return message;
}

 
