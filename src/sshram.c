#define _XOPEN_SOURCE 700

#include "argon2.h"
#include "chacha20poly1305.h"
#include "chrono.h"
#include "dragonfail.h"
#include "handy.h"
#include "sshram.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

void sshram_rng(uint8_t* out, size_t len)
{
	int fd = open("/dev/random", O_RDONLY);

	if (fd == -1)
	{
		dgn_throw(SSHRAM_ERR_RNG);
		return;
	}

	ssize_t ok = read(fd, out, len);

	if (ok == -1)
	{
		dgn_throw(SSHRAM_ERR_RNG);
		return;
	}

	ok = close(fd);

	if (ok == -1)
	{
		dgn_throw(SSHRAM_ERR_RNG);
		return;
	}
}

char* getpassword(char* s, int size, FILE* stream)
{
	struct termios ctx_a;
	struct termios ctx_b;
	char* err_pass;
	int ok;

	ok = tcgetattr(fileno(stream), &ctx_a);

	if (ok != 0)
	{
		return NULL;
	}

	ctx_b = ctx_a;
	ctx_b.c_lflag &= ~ECHO;

	ok = tcsetattr(fileno(stream), TCSAFLUSH, &ctx_b);

	if (ok != 0)
	{
		return NULL;
	}

	err_pass = fgets(s, size, stream);

	if (err_pass == NULL)
	{
		return NULL;
	}

	ok = tcsetattr(fileno(stream), TCSAFLUSH, &ctx_a);

	if (ok != 0)
	{
		return NULL;
	}

	printf("\n");

	return err_pass;
}

void sshram_encode(struct config* config)
{
	// init timers
	uint64_t times[16];

	chrono_init(times);

	for (int i = 0; i < 16; ++i)
	{
		chrono_start(i);
	}

	int err_mlock;
	char* err_pass;

	// get password
	char pass[257] = {0};

	err_mlock = mlock(pass, 257);

	if (err_mlock != 0)
	{
		dgn_throw(SSHRAM_ERR_MLOCK);
		return;
	}

	printf("Please enter a password (16-256 bytes, not that of your SSH private key!): ");

	err_pass = getpassword(pass, 257, stdin);

	if (err_pass != pass)
	{
		mem_clean(pass, 257);
		munlock(pass, 257);

		dgn_throw(SSHRAM_ERR_FGETS);
		return;
	}

	if (strlen(pass) < 16)
	{
		mem_clean(pass, 257);
		munlock(pass, 257);

		dgn_throw(SSHRAM_ERR_ENC_PASS_LEN);
		return;
	}

	// confirm password
	char confirm[257] = {0};

	err_mlock = mlock(confirm, 257);

	if (err_mlock != 0)
	{
		mem_clean(pass, 257);
		munlock(pass, 257);

		dgn_throw(SSHRAM_ERR_MLOCK);
		return;
	}

	printf("Please confirm this password by typing it one more time: ");

	err_pass = getpassword(confirm, 257, stdin);

	if (err_pass != confirm)
	{
		mem_clean(pass, 257);
		mem_clean(confirm, 257);
		munlock(pass, 257);
		munlock(confirm, 257);

		dgn_throw(SSHRAM_ERR_FGETS);
		return;
	}

	if (strcmp(pass, confirm) != 0)
	{
		mem_clean(pass, 257);
		mem_clean(confirm, 257);
		munlock(pass, 257);
		munlock(confirm, 257);

		dgn_throw(SSHRAM_ERR_ENC_PASS_MATCH);
		return;
	}

	// generate salt
	uint8_t salt[16];

	printf("Generating the random salt (blocking while gathering entropy)\n");

	sshram_rng(salt, 16);

	if (dgn_catch())
	{
		mem_clean(pass, 257);
		mem_clean(confirm, 257);
		munlock(pass, 257);
		munlock(confirm, 257);

		return;
	}

	// derive password
	uint8_t hash[32];

	err_mlock = mlock(hash, 32);

	if (err_mlock != 0)
	{
		mem_clean(pass, 257);
		mem_clean(confirm, 257);
		munlock(pass, 257);
		munlock(confirm, 257);

		dgn_throw(SSHRAM_ERR_MLOCK);
		return;
	}

	printf("Deriving password with Argon2...\n");

	int err_hash = argon2i_hash_raw(
		100,
		(1 << 16),
		1,
		pass,
		strlen(pass),
		salt,
		16,
		hash,
		32);

	if (err_hash != ARGON2_OK)
	{
		mem_clean(pass, 257);
		mem_clean(confirm, 257);
		mem_clean(hash, 32);
		munlock(pass, 257);
		munlock(confirm, 257);
		munlock(hash, 32);

		dgn_throw(SSHRAM_ERR_ARGON2);
		return;
	}

	if (config->verbose == true)
	{
		for (int i = 0; i < 32; ++i)
		{
			printf("%02x ", hash[i]);
		}

		printf("\n");
	}

	mem_clean(pass, 257);
	mem_clean(confirm, 257);
	munlock(pass, 257);
	munlock(confirm, 257);

	// generate nonce
	uint8_t nonce[12];

	printf("Generating the random nonce (blocking while gathering entropy)\n");

	sshram_rng(nonce, 12);

	if (dgn_catch())
	{
		mem_clean(hash, 32);
		munlock(hash, 32);

		return;
	}

	int err_file;

	// allocate buffers
	printf("Encoding private key with ChaCha20-Poly1305...\n");

	err_file = fseek(config->file_decoded, 0, SEEK_END);

	if (err_file != 0)
	{
		mem_clean(hash, 32);
		munlock(hash, 32);

		dgn_throw(SSHRAM_ERR_FSEEK);
		return;
	}

	long buf_len = ftell(config->file_decoded);
	long header_len = 16 + 12 + 16;

	if (buf_len < 0)
	{
		mem_clean(hash, 32);
		munlock(hash, 32);

		dgn_throw(SSHRAM_ERR_FTELL);
		return;
	}

	uint8_t* buf_decoded = malloc(buf_len);

	if (buf_decoded == NULL)
	{
		mem_clean(hash, 32);
		munlock(hash, 32);

		dgn_throw(SSHRAM_ERR_MALLOC);
		return;
	}

	uint8_t* buf_encoded = malloc(buf_len + header_len);

	if (buf_encoded == NULL)
	{
		mem_clean(hash, 32);
		munlock(hash, 32);

		free(buf_decoded);

		dgn_throw(SSHRAM_ERR_MALLOC);
		return;
	}

	// lock memory
	err_mlock = mlock(buf_decoded, buf_len);

	if (err_mlock != 0)
	{
		mem_clean(hash, 32);
		munlock(hash, 32);

		free(buf_decoded);
		free(buf_encoded);

		dgn_throw(SSHRAM_ERR_MLOCK);
		return;
	}

	err_mlock = mlock(buf_encoded, buf_len + header_len);

	if (err_mlock != 0)
	{
		mem_clean(hash, 32);
		munlock(hash, 32);
		munlock(buf_decoded, buf_len);

		free(buf_decoded);
		free(buf_encoded);

		dgn_throw(SSHRAM_ERR_MLOCK);
		return;
	}

	// encode SSH private key
	err_file = fseek(config->file_decoded, 0, SEEK_SET);

	if (err_file != 0)
	{
		mem_clean(hash, 32);
		munlock(hash, 32);
		munlock(buf_decoded, buf_len);
		munlock(buf_encoded, buf_len + header_len);

		free(buf_decoded);
		free(buf_encoded);

		dgn_throw(SSHRAM_ERR_FSEEK);
		return;
	}

	err_file = fread(buf_decoded, 1, buf_len, config->file_decoded);

	if (err_file < 0)
	{
		mem_clean(hash, 32);
		mem_clean(buf_decoded, buf_len);
		munlock(hash, 32);
		munlock(buf_decoded, buf_len);
		munlock(buf_encoded, buf_len + header_len);

		free(buf_decoded);
		free(buf_encoded);

		dgn_throw(SSHRAM_ERR_FREAD);
		return;
	}

	uint8_t tag[16];

	cf_chacha20poly1305_encrypt(
		hash,
		nonce,
		NULL,
		0,
		buf_decoded,
		buf_len,
		buf_encoded,
		tag);

	err_file  = fwrite(salt,        1, 16,      config->file_encoded);
	err_file += fwrite(nonce,       1, 12,      config->file_encoded);
	err_file += fwrite(tag,         1, 16,      config->file_encoded);
	err_file += fwrite(buf_encoded, 1, buf_len, config->file_encoded);

	if (err_file != (buf_len + header_len))
	{
		dgn_throw(SSHRAM_ERR_FWRITE);
	}

	// unlock remaining resources
	mem_clean(hash, 32);
	mem_clean(buf_decoded, buf_len);
	mem_clean(buf_encoded, buf_len);
	munlock(hash, 32);
	munlock(buf_decoded, buf_len);
	munlock(buf_encoded, buf_len + header_len);

	free(buf_decoded);
	free(buf_encoded);
}

void sshram_decode(struct config* config)
{
	int err_file;

	// get SSH private key length
	err_file = fseek(config->file_encoded, 0, SEEK_END);

	if (err_file != 0)
	{
		dgn_throw(SSHRAM_ERR_FSEEK);
		return;
	}

	long header_len = 16 + 12 + 16;
	long buf_len = ftell(config->file_encoded) - header_len;

	if (buf_len < 0)
	{
		dgn_throw(SSHRAM_ERR_FTELL);
		return;
	}

	// read salt, nonce, tag
	err_file = fseek(config->file_encoded, 0, SEEK_SET);

	if (err_file != 0)
	{
		dgn_throw(SSHRAM_ERR_FSEEK);
		return;
	}

	uint8_t salt[16];
	err_file = fread(salt, 1, 16, config->file_encoded);

	if (err_file < 0)
	{
		dgn_throw(SSHRAM_ERR_FREAD);
		return;
	}

	uint8_t nonce[12];
	err_file = fread(nonce, 1, 12, config->file_encoded);

	if (err_file < 0)
	{
		dgn_throw(SSHRAM_ERR_FREAD);
		return;
	}

	uint8_t tag[16];
	err_file = fread(tag, 1, 16, config->file_encoded);

	if (err_file < 0)
	{
		dgn_throw(SSHRAM_ERR_FREAD);
		return;
	}

	if (config->verbose == true)
	{
		printf("salt: ");
		for (int i = 0; i < 16; ++i)
		{
			printf("%02x ", salt[i]);
		}
		printf("\n");

		printf("nonce: ");
		for (int i = 0; i < 12; ++i)
		{
			printf("%02x ", nonce[i]);
		}
		printf("\n");

		printf("tag: ");
		for (int i = 0; i < 16; ++i)
		{
			printf("%02x ", tag[i]);
		}
		printf("\n");
	}

	// get password
	char pass[257] = {0};

	int err_mlock = mlock(pass, 257);

	if (err_mlock != 0)
	{
		dgn_throw(SSHRAM_ERR_MLOCK);
		return;
	}

	printf("Please enter your password: ");
	fflush(stdin);

	char* err_pass = getpassword(pass, 257, stdin);

	if (err_pass != pass)
	{
		mem_clean(pass, 257);
		munlock(pass, 257);

		dgn_throw(SSHRAM_ERR_FGETS);
		return;
	}

	// derive password
	uint8_t hash[32];

	err_mlock = mlock(hash, 32);

	if (err_mlock != 0)
	{
		mem_clean(pass, 257);
		munlock(pass, 257);

		dgn_throw(SSHRAM_ERR_MLOCK);
		return;
	}

	printf("Deriving password with Argon2...\n");

	int err_hash = argon2i_hash_raw(
		100,
		(1 << 16),
		1,
		pass,
		strlen(pass),
		salt,
		16,
		hash,
		32);

	if (err_hash != ARGON2_OK)
	{
		mem_clean(pass, 257);
		mem_clean(hash, 32);
		munlock(pass, 257);
		munlock(hash, 32);

		dgn_throw(SSHRAM_ERR_ARGON2);
		return;
	}

	if (config->verbose == true)
	{
		for (int i = 0; i < 32; ++i)
		{
			printf("%02x ", hash[i]);
		}

		printf("\n");
	}

	mem_clean(pass, 257);
	munlock(pass, 257);

	// allocate buffers
	uint8_t* buf_decoded = malloc(buf_len + 1);

	if (buf_decoded == NULL)
	{
		mem_clean(hash, 32);
		munlock(hash, 32);

		dgn_throw(SSHRAM_ERR_MALLOC);
		return;
	}

	uint8_t* buf_encoded = malloc(buf_len);

	if (buf_encoded == NULL)
	{
		mem_clean(hash, 32);
		munlock(hash, 32);

		free(buf_decoded);

		dgn_throw(SSHRAM_ERR_MALLOC);
		return;
	}

	// lock memory
	err_mlock = mlock(buf_decoded, buf_len + 1);

	if (err_mlock != 0)
	{
		mem_clean(hash, 32);
		munlock(hash, 32);

		free(buf_decoded);
		free(buf_encoded);

		dgn_throw(SSHRAM_ERR_MLOCK);
		return;
	}

	err_mlock = mlock(buf_encoded, buf_len);

	if (err_mlock != 0)
	{
		mem_clean(hash, 32);
		munlock(hash, 32);
		munlock(buf_decoded, buf_len + 1);

		free(buf_decoded);
		free(buf_encoded);

		dgn_throw(SSHRAM_ERR_MLOCK);
		return;
	}

	// decode SSH private key
	err_file = fread(buf_encoded, 1, buf_len, config->file_encoded);

	if (err_file < 0)
	{
		mem_clean(hash, 32);
		mem_clean(buf_encoded, buf_len);
		munlock(hash, 32);
		munlock(buf_decoded, buf_len + 1);
		munlock(buf_encoded, buf_len);

		free(buf_decoded);
		free(buf_encoded);

		dgn_throw(SSHRAM_ERR_FREAD);
		return;
	}

	printf("Decoding private key with ChaCha20-Poly1305...\n");

	int err_decode = cf_chacha20poly1305_decrypt(
		hash,
		nonce,
		NULL,
		0,
		buf_encoded,
		buf_len,
		tag,
		buf_decoded);

	mem_clean(hash, 32);
	mem_clean(buf_encoded, buf_len);
	munlock(hash, 32);
	munlock(buf_encoded, buf_len);
	free(buf_encoded);

	if (err_decode != 0)
	{
		mem_clean(buf_decoded, buf_len + 1);
		munlock(buf_decoded, buf_len + 1);
		free(buf_decoded);

		dgn_throw(SSHRAM_ERR_DEC_CHACHAPOLY);
		return;
	}

	if (config->verbose == true)
	{
		buf_decoded[buf_len] = '\0';
		printf("%s\n", buf_decoded);
	}

	// build key file path
	char* home = getenv("HOME");

	if (home == NULL)
	{
		mem_clean(buf_decoded, buf_len + 1);
		munlock(buf_decoded, buf_len + 1);
		free(buf_decoded);

		dgn_throw(SSHRAM_ERR_ENV);
		return;
	}

	int path_len = strlen(home) + strlen("/.ssh/") + strlen(config->key_name);
	char* path = malloc(path_len + 1);

	if (path == NULL)
	{
		mem_clean(buf_decoded, buf_len + 1);
		munlock(buf_decoded, buf_len + 1);
		free(buf_decoded);

		dgn_throw(SSHRAM_ERR_MALLOC);
		return;
	}

	int err_path = snprintf(path, path_len + 1, "%s/.ssh/%s", home, config->key_name);

	if (err_path != path_len)
	{
		mem_clean(buf_decoded, buf_len + 1);
		munlock(buf_decoded, buf_len + 1);
		free(buf_decoded);
		free(path);

		dgn_throw(SSHRAM_ERR_DEC_PATH_LEN);
		return;
	}

	// check if the pipe already exists, create it if needed
	struct stat file_info = {0};

	err_file = stat(path, &file_info);

	// file exists
	if (err_file != -1)
	{
		// can't continue because it's not a pipe
		if (!S_ISFIFO(file_info.st_mode))
		{
			mem_clean(buf_decoded, buf_len + 1);
			munlock(buf_decoded, buf_len + 1);
			free(buf_decoded);
			free(path);

			dgn_throw(SSHRAM_ERR_DEC_PASUNEPIPE);
			return;
		}
	}
	// file does not exist
	else
	{
		// create named pipe
		int err_pipe = mkfifo(path, S_IRUSR | S_IWUSR);

		if (err_pipe != 0)
		{
			mem_clean(buf_decoded, buf_len + 1);
			munlock(buf_decoded, buf_len + 1);
			free(buf_decoded);
			free(path);

			dgn_throw(SSHRAM_ERR_DEC_MKFIFO);
			return;
		}
	}

	size_t err_write;
	char answer[257] = "n";

	printf(
		"\n"
		"Entering transmission loop. Here you will be able to send the key read by read.\n"
		"The OpenSSH agent reads your SSH private key 4 times when first unlocking it,\n"
		"so you will have to allow 3 reads at startup and 1 read after the password.\n"
		"\n");

	do
	{
		do
		{
			printf("Send private key over the pipe ? [Y/n]: ");
			fflush(stdout);
			fflush(stdin);
			fgets(answer, 257, stdin);
		}
		while ((*answer != '\n')
			&& (*answer != 'y')
			&& (*answer != 'Y')
			&& (*answer != 'n')
			&& (*answer != 'N'));

		if ((*answer == 'n') || (*answer == 'N'))
		{
			break;
		}

		FILE* pipe = fopen(path, "w");

		if (pipe == NULL)
		{
			dgn_throw(SSHRAM_ERR_DEC_PIPE_FOPEN);
			break;
		}

		err_write = fwrite(buf_decoded, 1, buf_len, pipe);

		if (err_write != ((size_t) buf_len))
		{
			dgn_throw(SSHRAM_ERR_DEC_PIPE_FWRITE);
			break;
		}

		err_file = fclose(pipe);

		if (err_file == -1)
		{
			dgn_throw(SSHRAM_ERR_DEC_PIPE_FCLOSE);
			break;
		}

		printf("Private key transmitted\n");
	}
	while ((*answer != 'n') && (*answer != 'N'));

	if (config->keep_pipe == false)
	{
		err_file = unlink(path);

		if (err_file == -1)
		{
			dgn_throw(SSHRAM_ERR_DEC_PIPE_UNLINK);
		}
	}

	// cleanup
	mem_clean(buf_decoded, buf_len + 1);
	munlock(buf_decoded, buf_len + 1);
	free(buf_decoded);
	free(path);
}
