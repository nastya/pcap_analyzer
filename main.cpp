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
	{"help", no_argument, 0, 'h'},
	{"logfile", required_argument, 0, 'l'},
	{"shellcodedump", required_argument, 0, 's'}
};

void printHelp(const char * program_name)
{
	fprintf(stderr, "Usage: %s [ --pcap pcap_file | --directory directory_with_pcap_files | --interface interface_name]\n"
				"\t\t[--logfile logfile] [--shellcodedump dumpfile]\n",
		program_name);
}

//------------------------------------------------------------------- 
int main(int argc, char **argv) 
{
	string type = "", name;
	int opt;
	while (1) {
		int option_index = 0;
		opt = getopt_long(argc, argv, "d:i:p:hl:s:", long_options, &option_index);
		if(opt == -1) break;
		switch (opt)
		{
			case 'i':
				type = "interface";
				name = optarg;
				break;
			case 'p':
				type = "file";
				name = optarg;
				break;
			case 'd':
				type = "directory";
				name = optarg;
				break;
			case 'h':
				printHelp(argv[0]);
				exit(0);
			case 'l':
				Config::logfile = optarg;
				break;
			case 's':
				Config::shellcode_pcap_file = optarg;
				break;
			default:
				printHelp(argv[0]);
				exit(0);
		}
	}

	Reader r;
	if (type == "interface")
	{
		fprintf(stdout, "Analyzing traffic on interface %s...\n", name.c_str());
		r.readInterface(name.c_str());
	}
	if (type == "file")
	{
		fprintf(stdout, "Analyzing pcap file %s...\n", name.c_str());
		r.readPcap(name.c_str());
	}
	if (type == "directory")
	{
		DIR *dir;
		struct dirent *ent;
		if ((dir = opendir (name.c_str())) != NULL)
		{
			while ((ent = readdir(dir)) != NULL)
			{
				if (strcmp(ent->d_name, ".") == 0)
					continue;
				if (strcmp(ent->d_name, "..") == 0)
					continue;
				fprintf(stdout, "Analyzing pcap file %s/%s...\n", name.c_str(), ent->d_name);
				r.readPcap((name + "/" + string(ent->d_name)).c_str());
			}
			closedir(dir);
		}
		else
		{
			fprintf(stderr, "Could not open provided directory %s\n", name.c_str());
			exit(0);
		}
	}
	if (type == "")
		printHelp(argv[0]);
	return 0;
}
