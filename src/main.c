#define _XOPEN_SOURCE 700

#include "argoat.h"
#include "dragonfail.h"
#include "sshram.h"

#include <libgen.h>

#define ARG_COUNT 11

// arguments handling
void arg_unflagged(void* data, char** pars, const int pars_count)
{
	struct config* config = (struct config*) data;

	if (pars_count != 1)
	{
		config->action = SSHRAM_ACTION_EXIT;
		return;
	}

	if (config->key_name == NULL)
	{
		config->key_name = basename(pars[0]);
	}

	if (config->action == SSHRAM_ACTION_ENCODE)
	{
		config->file_encoded = fopen(pars[0], "w+");
	}
	else
	{
		config->file_encoded = fopen(pars[0], "r");
	}

	if (config->file_encoded == NULL)
	{
		dgn_throw(SSHRAM_ERR_UNKNOWN);
		return;
	}
}

void arg_help(void* data, char** pars, const int pars_count)
{
	printf(
		"usage:\n"
		"    sshram [arguments] [encoded file]\n"
		"\n"
		"arguments:\n"
		"    -e [decoded file]\n"
		"    --encode [decoded file]\n"
		"        specify a plaintext SSH private key [decoded file] to encode in [encoded file]\n"
		"\n"
		"    -h\n"
		"    --help\n"
		"        print this help message\n"
		"\n"
		"    -k\n"
		"    --keep\n"
		"        do not remove the pipe after execution\n"
		"\n"
		"    -n [pipe name]\n"
		"    --name [pipe name]\n"
		"        override the pipe name (the file name of [encoded file] is used by default)\n"
		"\n"
		"    -v\n"
		"    --verbose\n"
		"        print debugging information, including plaintext private key and password hash\n"
		);
}

void arg_encode(void* data, char** pars, const int pars_count)
{
	if (pars_count != 1)
	{
		dgn_throw(SSHRAM_ERR_UNKNOWN);
		return;
	}

	struct config* config = (struct config*) data;

	config->file_decoded = fopen(pars[0], "r");

	if (config->file_decoded == NULL)
	{
		dgn_throw(SSHRAM_ERR_UNKNOWN);
		return;
	}

	config->action = SSHRAM_ACTION_ENCODE;
}

void arg_keep(void* data, char** pars, const int pars_count)
{
	struct config* config = (struct config*) data;

	config->keep_pipe = true;
}

void arg_name(void* data, char** pars, const int pars_count)
{
	if (pars_count != 1)
	{
		dgn_throw(SSHRAM_ERR_UNKNOWN);
		return;
	}

	struct config* config = (struct config*) data;

	config->key_name = pars[0];
}

void arg_verbose(void* data, char** pars, const int pars_count)
{
	struct config* config = (struct config*) data;

	config->verbose = true;
}

// errors initialization
void log_init(char** log)
{
	log[DGN_OK] =
		"out-of-bounds log message";
	log[SSHRAM_ERR_UNKNOWN] =
		"unknown error";
}

// sshram startup
int main(int argc, char** argv)
{
	// init sshram config
	struct config config =
	{
		.action = SSHRAM_ACTION_DECODE,
		.file_encoded = NULL,
		.file_decoded = NULL,
		.key_name = NULL,
		.keep_pipe = false,
		.verbose = false,
	};

	// init error handling
	log_init(dgn_init());

	// handle args
	char* unflagged;

	struct argoat_sprig sprigs[ARG_COUNT] =
	{
		{NULL,     1, &config, arg_unflagged},
		{"encode", 1, &config, arg_encode},
		{"e",      1, &config, arg_encode},
		{"help",   0, NULL,    arg_help},
		{"h",      0, NULL,    arg_help},
		{"keep",   0, &config, arg_keep},
		{"k",      0, &config, arg_keep},
		{"name",   1, &config, arg_name},
		{"n",      1, &config, arg_name},
		{"verbose",0, &config, arg_verbose},
		{"v",      0, &config, arg_verbose},
	};

	struct argoat args =
	{
		sprigs,
		ARG_COUNT,
		&unflagged,
		0,
		1,
	};

	argoat_graze(&args, argc, argv);

	if (dgn_catch())
	{
		return 1;
	}

	// run core program
	switch (config.action)
	{
		case SSHRAM_ACTION_ENCODE:
		{
			sshram_encode(&config);
			fclose(config.file_decoded);
			fclose(config.file_encoded);
			break;
		}
		case SSHRAM_ACTION_DECODE:
		{
			sshram_decode(&config);
			fclose(config.file_encoded);
			break;
		}
		case SSHRAM_ACTION_EXIT:
		default:
		{
			break;
		}
	}

	if (dgn_catch())
	{
		return 1;
	}

	return 0;
}
