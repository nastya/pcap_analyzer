#include "analyzer.h"
#include <stdio.h>
#include <list>
#include <string>

FindDecryptor Analyzer::analyzer = FindDecryptor(); 

void Analyzer::analyze(unsigned char * buffer, int size)
{
	/*fprintf(stdout, "Analyzing buffer of size %d...\n", size);
	for (int i = 0; i < size; i++)
		fprintf(stdout, "%c", buffer[i]);
	fprintf(stdout, "\n");*/
	analyzer.link(buffer, size);
	int found = analyzer.find();
	if (found)
	{
		fprintf(stdout, "Shellcode found!\n");
		list <int> start_pos = analyzer.get_start_list();
		for (list<int>::iterator it = start_pos.begin(); it != start_pos.end(); it++)
		{
			fprintf(stdout, "Decryption routine:\n");
			fprintf(stdout, "%s\n", analyzer.get_decryptor(*it).c_str());
			fprintf(stdout, "--------------------------------------------------------------\n");
		}
	}
}

 
