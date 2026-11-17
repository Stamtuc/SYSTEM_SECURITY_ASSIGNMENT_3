#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <openssl/evp.h> //install the required package

#define LOG_PATH "access_audit.log"
#define HASH_LEN 65










void hash_file(const char *path, char *out)
{
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	unsigned char buf[4096];
	EVP_MD_CTX *ctx;
	ssize_t n;
	int fd, i;

	// default: 64 zeros if the file cannot be read
	for (i = 0; i < 64; i++)
		out[i] = '0';
	out[64] = '\0';

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		close(fd);
		return;
	}

	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
		goto done;

	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		if (EVP_DigestUpdate(ctx, buf, n) != 1)
			goto done;
	}
	if (n < 0)
		goto done;

	if (EVP_DigestFinal_ex(ctx, md, &md_len) != 1)
		goto done;

	// 32 bytes -> 64 hex chars
	for (i = 0; i < (int)md_len; i++)
		sprintf(out + 2 * i, "%02x", md[i]);

done:
	EVP_MD_CTX_free(ctx);
	close(fd);
}




void data_log(const char *filename, int operation, int denied)
{
	char line[PATH_MAX + 256];
	char hash[HASH_LEN];
	time_t now;
	struct tm tm;
	char date[11];         //YYYY-MM-DD + '\0'
	char tbuf[9];          //HH:MM:SS + '\0'
	int fd;                //file descriptor
	int len;               //byte length
    
	hash_file(filename, hash);
	//current time in seconds
	now = time(NULL);

	//convert time to UTC
	gmtime_r(&now, &tm);
	strftime(date, sizeof(date), "%Y-%m-%d", &tm);
	strftime(tbuf, sizeof(tbuf), "%H:%M:%S", &tm);

	//Header Composition
		len = snprintf(line, sizeof(line),
	    "%d\t%d\t%s\t%s\t%s\t%d\t%d\t%s\n",
	    (int)getuid(), (int)getpid(),                  //UNIQUE USER ID Proccess ID
	    filename,                                      //Absolute path of the accessed file
	    date,                                          //Year Month Day
	    tbuf,                                          //Hours Minutes Seconds
	    operation,                                     // Operation 0=created, 1=opened, 2=written, 3=closed
	    denied,                                        // Denied 0=success, 1=denied
	    hash);                                         //File hash

	if (len < 0)
		return;
	if (len >= (int)sizeof(line))      //cut line
		len = sizeof(line) - 1;

	fd = open(LOG_PATH, O_WRONLY | O_APPEND | O_CREAT, 0666); //4+2 accessible to all users
	if (fd < 0)
		return;

	//write to fd
	write(fd, line, len);
	close(fd);
}


int get_path_from_stream(FILE *stream, char *out)
{
	char link[64];
	int fd;

	if (stream == NULL)
		return -1;

	fd = fileno(stream);
	if (fd < 0)
		return -1;

	snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);

	if (realpath(link, out) == NULL)
		return -1;

	return 0;
}


FILE *
fopen(const char *path, const char *mode)
{
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);
	char abs_path[PATH_MAX];
	struct stat st;
	int existed;
	int saved_errno;
	int operation;
	int denied;

	existed = (stat(path, &st) == 0);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);
	saved_errno = errno;

	if (realpath(path, abs_path) == NULL)
		snprintf(abs_path, sizeof(abs_path), "%s", path);

	if (!existed && (mode[0] == 'w' || mode[0] == 'a'))
		operation = 0;
	else
		operation = 1;

	if (original_fopen_ret == NULL && saved_errno == EACCES)
		denied = 1;
	else
		denied = 0;

	data_log(abs_path, operation, denied);

	errno = saved_errno;
	return original_fopen_ret;
}


size_t
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);
	char abs_path[PATH_MAX];
	int saved_errno;
	int denied;

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	errno = 0;
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
	saved_errno = errno;

	if (get_path_from_stream(stream, abs_path) == 0) {
		if (original_fwrite_ret < nmemb && (saved_errno == EACCES || saved_errno == EBADF))
			denied = 1;
		else
			denied = 0;

		if (!denied)
			fflush(stream);

		data_log(abs_path, 2, denied);
	}

	errno = saved_errno;
	return original_fwrite_ret;
}


int
fclose(FILE *stream)
{
	int original_fclose_ret;
	int (*original_fclose)(FILE*);
	char abs_path[PATH_MAX];
	int have_path;
	int saved_errno;

	have_path = (get_path_from_stream(stream, abs_path) == 0);

	/* call the original fclose function */
	original_fclose = dlsym(RTLD_NEXT, "fclose");
	original_fclose_ret = (*original_fclose)(stream);
	saved_errno = errno;

	if (have_path)
		data_log(abs_path, 3, 0);

	errno = saved_errno;
	return original_fclose_ret;
}