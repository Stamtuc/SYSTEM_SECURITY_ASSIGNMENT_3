
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>


// open name with mode, write text (if not NULL), close 
void
write_file(const char *name, const char *mode, const char *text)
{
	FILE *file = fopen(name, mode);

	if (!file) {
		perror(name);
		return;
	}
	if (text)
		fwrite(text, strlen(text), 1, file);
	fclose(file);
}


int
main()
{
	int i;
	char name[16];
	const char *modes[6] = {"r", "r", "w", "w", "r", "w"};

	// 1. Create several files.
	for (i = 0; i < 8; i++) {
		snprintf(name, sizeof(name), "file_%d", i);
		write_file(name, "w+", name);
	}

	// 2. Open and modify them under various conditions.
	write_file("example.txt", "w",  "version one\n");
	write_file("example.txt", "w",  "version two\n");
	write_file("example.txt", "a",  "added line A\n");
	write_file("example.txt", "a",  "added line B\n");
	write_file("example.txt", "r+", "VERSION");
	write_file("example.txt", "r+", "VERSION");
	write_file("example.txt", "r",  NULL);

	// 3. Attempt to open files without permissions to generate denied actions.
	for (i = 0; i < 6; i++) {
		snprintf(name, sizeof(name), "locked_%d", i);
		chmod(name, 0600);
		write_file(name, "w", "secret\n");
		chmod(name, 0000);
	}

	for (i = 0; i < 6; i++) {
		snprintf(name, sizeof(name), "locked_%d", i);
		write_file(name, modes[i], NULL);
	}

	return 0;
}