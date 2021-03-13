#define _XOPEN_SOURCE 700

#include "argon2.h"
#include "chacha20poly1305.h"
#include "chrono.h"
#include "dragonfail.h"
#include "handy.h"
#include "sshram.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

static volatile sig_atomic_t decode_run = 1;

static void sigint_handler(int sig)
{
	decode_run = 0;
}

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

	if (buf_len < 2)
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
	// set SIGINT handler
	const struct sigaction sig_struct =
	{
		.sa_handler = sigint_handler,
		.sa_flags = 0, // interrupt read
	};

	int err_sig = sigaction(SIGINT, &sig_struct, NULL);

	if (err_sig == -1)
	{
		dgn_throw(SSHRAM_ERR_DEC_SIGACTION);
		return;
	}

	// get SSH private key length
	int err_file = fseek(config->file_encoded, 0, SEEK_END);

	if (err_file != 0)
	{
		dgn_throw(SSHRAM_ERR_FSEEK);
		return;
	}

	long header_len = 16 + 12 + 16;
	long buf_len = ftell(config->file_encoded) - header_len;

	if (buf_len < (header_len + 2))
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

	int inotify_fd = inotify_init();

	if (inotify_fd == -1)
	{
		mem_clean(buf_decoded, buf_len + 1);
		munlock(buf_decoded, buf_len + 1);
		free(buf_decoded);
		free(path);

		dgn_throw(SSHRAM_ERR_DEC_INOTIFY_INIT);
		return;
	}

	int inotify_watch_fd = inotify_add_watch(inotify_fd, path, IN_ACCESS);

	if (inotify_watch_fd == -1)
	{
		close(inotify_fd);
		mem_clean(buf_decoded, buf_len + 1);
		munlock(buf_decoded, buf_len + 1);
		free(buf_decoded);
		free(path);

		dgn_throw(SSHRAM_ERR_DEC_INOTIFY_ADD_WATCH);
		return;
	}

	// allocate a large enough inotify event buffer
	size_t inotify_event_buf_size = (buf_len - 1) * (sizeof (struct inotify_event));
	struct inotify_event* inotify_event_buf = malloc(inotify_event_buf_size);

	if (inotify_event_buf == NULL)
	{
		decode_run = 0;
		dgn_throw(SSHRAM_ERR_MALLOC);
		return;
	}

	// blocking, no-confirmation key transmission using inotify
	int pipe;
	ssize_t err_loop;

	if (decode_run == 1)
	{
		printf("Entering transmission loop\n");
	}

	while (decode_run == 1)
	{
		// we *must* open in read-write mode to get a non-blocking descriptor
		// because unix pipes must be opened in read or read/write mode first
		// or we will not be able to open without non-blocking
		pipe = open(path, O_RDWR | O_NONBLOCK);

		if (pipe == -1)
		{
			dgn_throw(SSHRAM_ERR_DEC_PIPE_FOPEN);
			break;
		}

		// send the first character of the private key to be able to detect reads
		err_loop = write(pipe, buf_decoded, 1);

		if (err_loop != 1)
		{
			dgn_throw(SSHRAM_ERR_DEC_PIPE_FWRITE);
			break;
		}

		// wait for read
		err_loop = read(inotify_fd, inotify_event_buf, sizeof (struct inotify_event));

		if (err_loop == -1)
		{
			if (errno == EINTR)
			{
				dgn_throw(SSHRAM_ERR_DEC_INOTIFY_READ_INT);
			}
			else
			{
				dgn_throw(SSHRAM_ERR_DEC_INOTIFY_READ);
			}

			break;
		}

		if (decode_run == 0)
		{
			break;
		}

		// write the rest of the private key
		err_loop = write(pipe, buf_decoded + 1, buf_len - 1);

		if (err_loop != ((ssize_t) buf_len - 1))
		{
			dgn_throw(SSHRAM_ERR_DEC_PIPE_FWRITE);
			break;
		}

		// close pipe to simulate end-of-file
		err_file = close(pipe);

		if (err_file == -1)
		{
			dgn_throw(SSHRAM_ERR_DEC_PIPE_FCLOSE);
			break;
		}

		// wait for read
		err_loop = read(inotify_fd, inotify_event_buf, inotify_event_buf_size);

		if (err_loop == -1)
		{
			if (errno == EINTR)
			{
				dgn_throw(SSHRAM_ERR_DEC_INOTIFY_READ_INT);
			}
			else
			{
				dgn_throw(SSHRAM_ERR_DEC_INOTIFY_READ);
			}

			break;
		}

		// success!
		printf("Private key transmitted\n");
	}

	if (config->keep_pipe == false)
	{
		err_file = unlink(path);

		if (err_file == -1)
		{
			dgn_throw(SSHRAM_ERR_DEC_PIPE_UNLINK);
		}
	}

	// cleanup
	inotify_rm_watch(inotify_fd, inotify_watch_fd);
	close(inotify_fd);
	mem_clean(buf_decoded, buf_len + 1);
	munlock(buf_decoded, buf_len + 1);
	free(inotify_event_buf);
	free(buf_decoded);
	free(path);

	printf("Exiting normally\n");
}
