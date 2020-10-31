#ifndef H_SSHRAM
#define H_SSHRAM

#include <stdio.h>
#include <stdbool.h>

// structs
enum action
{
	SSHRAM_ACTION_EXIT,
	SSHRAM_ACTION_DECODE,
	SSHRAM_ACTION_ENCODE,
};

struct config
{
	enum action action;
	FILE* file_encoded;
	FILE* file_decoded;
	char* key_name;
	bool keep_pipe;
	bool verbose;
};

// functions
void sshram_encode(struct config* config);
void sshram_decode(struct config* config);

#endif
