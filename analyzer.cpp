#include "analyzer.h"
#include <stdio.h>
#include <list>
#include <string>

FindDecryptor Analyzer::decryptor_analyzer = FindDecryptor();
string Analyzer::message = "";
DetectSimilar * Analyzer::similarity_analyzer = NULL;

void Analyzer::initAnalyzer()
{
	if (Config::analyzer_name == "DetectSimilar")
	{
		if (Config::analyzer_type == "Diff")
			similarity_analyzer = new DetectSimilar(DetectSimilar::AnalyzerTypeDiff);
		else if (Config::analyzer_type == "Ngram")
			similarity_analyzer = new DetectSimilar(DetectSimilar::AnalyzerTypeNgram);
		else if (Config::analyzer_type == "CFG")
			similarity_analyzer = new DetectSimilar(DetectSimilar::AnalyzerTypeCFG);
		else if (Config::analyzer_type == "Trace")
			similarity_analyzer = new DetectSimilar(DetectSimilar::AnalyzerTypeTrace);
		else
			similarity_analyzer = new DetectSimilar;
		similarity_analyzer->loadShellcodes(Config::shellcodes_dir);
	} else if (Config::analyzer_name != "FindDecryptor")
		fprintf(stderr, "Incorrect analyzer name specified. Use FindDecryptor or DetectSimilar.\n");
}

void Analyzer::freeAnalyzer()
{
	if (similarity_analyzer != NULL)
		delete similarity_analyzer;
}

bool Analyzer::analyze(unsigned char * buffer, int size)
{
	/*fprintf(stdout, "Analyzing buffer of size %d...\n", size);
	for (int i = 0; i < size; i++)
		fprintf(stdout, "%c", buffer[i]);
	fprintf(stdout, "\n");*/
	if (Config::analyzer_name == "FindDecryptor")
	{
		decryptor_analyzer.link(buffer, size);
		int found = decryptor_analyzer.find();
		if (found)
		{
			message = "Decryptor found!\n";
			list <int> start_pos = decryptor_analyzer.get_start_list();
			for (list<int>::iterator it = start_pos.begin(); it != start_pos.end(); it++)
			{
				message += "Decryption routine:\n";
				message += decryptor_analyzer.get_decryptor(*it);
				message += "--------------------------------------------------------------\n";
			}
			return true;
		}
		message = "";
		return false;
	}
	if (Config::analyzer_name == "DetectSimilar")
	{
		similarity_analyzer->link(buffer, size);
		message = "";
		string answer = similarity_analyzer->analyze();
		if (answer == "")
			return false;
		else
		{
			message = "Shellcode found: " + answer + "\n";
			return true;
		}
	}
	return false;
}

string Analyzer::getMessage()
{
	return message;
}

 
