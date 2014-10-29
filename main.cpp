#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <dirent.h>
#include <string>
#include <string.h>

#include "pcap_reader.h"

static struct option long_options[] =
{
	{"directory", required_argument, 0, 'd'},
	{"interface", required_argument, 0, 'i'},
	{"pcap", required_argument, 0, 'p'},
	{"help", no_argument, 0, 'h'}
};

void printHelp(const char * program_name)
{
	fprintf(stderr, "Usage: %s [ --pcap pcap_file | --directory directory_with_pcap_files | --interface interface_name]\n",
		program_name);
}

//------------------------------------------------------------------- 
int main(int argc, char **argv) 
{
	Reader r;
	
	string dev, file, directory;
	int opt;
	bool analysis_done = false;
	while (1) {
		int option_index = 0;
		opt = getopt_long(argc, argv, "d:i:p:h", long_options, &option_index);
		if(opt == -1) break;
		switch (opt)
		{
			case 'i':
				dev = optarg;
				fprintf(stdout, "Analyzing traffic on interface %s...\n", dev.c_str());
				r.readInterface(dev.c_str());
				analysis_done = true;
				break;
			case 'p':
				file = optarg;
				fprintf(stdout, "Analyzing pcap file %s...\n", file.c_str());
				r.readPcap(file.c_str());
				analysis_done = true;
				break;
			case 'd':
				directory = optarg;
				DIR *dir;
				struct dirent *ent;
				if ((dir = opendir (directory.c_str())) != NULL)
				{
					while ((ent = readdir(dir)) != NULL)
					{
						if (strcmp(ent->d_name, ".") == 0)
							continue;
						if (strcmp(ent->d_name, "..") == 0)
							continue;
						fprintf(stdout, "Analyzing pcap file %s/%s...\n", directory.c_str(), ent->d_name);
						r.readPcap((directory + "/" + string(ent->d_name)).c_str());
					}
					closedir(dir);
				}
				else 
				{
					fprintf(stderr, "Could not open provided directory %s\n", directory.c_str());
					exit(0);
				}
				analysis_done = true;
				break;
			case 'h':
				printHelp(argv[0]);
				exit(0);
			default:
				printHelp(argv[0]);
				exit(0);
		}
	}
	if (!analysis_done)
		printHelp(argv[0]);  
}
