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

	if (pars_count < 1)
	{
		config->action = SSHRAM_ACTION_EXIT;
		return;
	}

	if (pars_count > 1)
	{
		dgn_throw(SSHRAM_ERR_ARG_ENCODED);
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
		dgn_throw(SSHRAM_ERR_ARG_ENCODED_OPEN);
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
		"        (progams using SSH will freeze until EOF is sent!)\n"
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
		dgn_throw(SSHRAM_ERR_ARG_DECODED);
		return;
	}

	struct config* config = (struct config*) data;

	config->file_decoded = fopen(pars[0], "r");

	if (config->file_decoded == NULL)
	{
		dgn_throw(SSHRAM_ERR_ARG_DECODED_OPEN);
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
		dgn_throw(SSHRAM_ERR_ARG_NAME);
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
	log[SSHRAM_ERR_ARG_NAME] =
		"couldn't set the pipe name (please give exactly one)";
	log[SSHRAM_ERR_ARG_DECODED] =
		"couldn't get a decoded file name (please give exactly one)";
	log[SSHRAM_ERR_ARG_DECODED_OPEN] =
		"couldn't open a decoded file";
	log[SSHRAM_ERR_ARG_ENCODED] =
		"couldn't get an encoded file name (please give exactly one)";
	log[SSHRAM_ERR_ARG_ENCODED_OPEN] =
		"couldn't open an encoded file";

	log[SSHRAM_ERR_RNG] =
		"End-Of-File was received as input";
	log[SSHRAM_ERR_ARGON2] =
		"couldn't hash password (Argon2 returned an error)";

	log[SSHRAM_ERR_MALLOC] =
		"couldn't allocate memmory";
	log[SSHRAM_ERR_MLOCK] =
		"couldn't lock memory";

	log[SSHRAM_ERR_ENV] =
		"couldn't get environment";
	log[SSHRAM_ERR_FGETS] =
		"couldn't get user input";
	log[SSHRAM_ERR_FSEEK] =
		"couldn't move file cursor";
	log[SSHRAM_ERR_FTELL] =
		"couldn't get file cursor position";
	log[SSHRAM_ERR_FREAD] =
		"couldn't read file";
	log[SSHRAM_ERR_FWRITE] =
		"couldn't write file";

	log[SSHRAM_ERR_ENC_PASS_LEN] =
		"password is not long enough (please use 16 bytes or more)";
	log[SSHRAM_ERR_ENC_PASS_MATCH] =
		"passwords did not match";

	log[SSHRAM_ERR_DEC_CHACHAPOLY] =
		"couldn't decode file";
	log[SSHRAM_ERR_DEC_PATH_LEN] =
		"constructed file path did not have the expected length";
	log[SSHRAM_ERR_DEC_PASUNEPIPE] =
		"the pipe path points to a file that is not a pipe";
	log[SSHRAM_ERR_DEC_MKFIFO] =
		"couldn't create a new pipe";
	log[SSHRAM_ERR_DEC_PIPE_FOPEN] =
		"couldn't open the pipe";
	log[SSHRAM_ERR_DEC_PIPE_FWRITE] =
		"couldn't write to the pipe";
	log[SSHRAM_ERR_DEC_PIPE_FCLOSE] =
		"couldn't close the pipe";
	log[SSHRAM_ERR_DEC_PIPE_UNLINK] =
		"couldn't remove the pipe";
	log[SSHRAM_ERR_DEC_INOTIFY_INIT] =
		"couldn't initialize inotify";
	log[SSHRAM_ERR_DEC_INOTIFY_ADD_WATCH] =
		"couldn't add an inotify watch";
	log[SSHRAM_ERR_DEC_INOTIFY_READ] =
		"couldn't read inotify events or received SIGINT";
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
