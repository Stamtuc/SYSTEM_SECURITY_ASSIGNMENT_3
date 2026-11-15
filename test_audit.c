#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int main()
{
	int i;
	FILE *file;
	char name[16];
	char filenames[8][7] = {"file_0", "file_1",
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7"};

	/* create 8 files and write their name inside */
	for (i = 0; i < 8; i++) {
		file = fopen(filenames[i], "w+");
		if (file == NULL)
			printf("fopen error\n");
		else {
			fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
	}

	/* create example.txt from scratch and write */
	file = fopen("example.txt", "w");
	if (file) {
		fwrite("version one\n", 12, 1, file);
		fclose(file);
	}

	/* recreate example.txt from scratch, old content is erased */
	file = fopen("example.txt", "w");
	if (file) {
		fwrite("version two\n", 12, 1, file);
		fclose(file);
	}

	/* add a line at the end, keeping the old content */
	file = fopen("example.txt", "a");
	if (file) {
		fwrite("added line A\n", 13, 1, file);
		fclose(file);
	}

	/* add another line at the end */
	file = fopen("example.txt", "a");
	if (file) {
		fwrite("added line B\n", 13, 1, file);
		fclose(file);
	}

	/* overwrite the first characters, keep the rest */
	file = fopen("example.txt", "r+");
	if (file) {
		fwrite("VERSION", 7, 1, file);
		fclose(file);
	}

	/* write the same bytes again: write happens, content does not change */
	file = fopen("example.txt", "r+");
	if (file) {
		fwrite("VERSION", 7, 1, file);
		fclose(file);
	}

	/* open for reading only, no write */
	file = fopen("example.txt", "r");
	if (file)
		fclose(file);

	/* prepare 6 locked files: create them, then remove all permissions */
	for (i = 0; i < 6; i++) {
		snprintf(name, sizeof(name), "locked_%d", i);
		chmod(name, 0600);              /* unlock leftovers from a previous run */
		file = fopen(name, "w");
		if (file) {
			fwrite("secret\n", 7, 1, file);
			fclose(file);
		}
		chmod(name, 0000);              /* nobody can read or write it now */
	}

	/* locked_0, locked_1: attempt to read */
	for (i = 0; i < 2; i++) {
		snprintf(name, sizeof(name), "locked_%d", i);
		file = fopen(name, "r");
		if (file == NULL)
			printf("%s: read denied (expected)\n", name);
		else
			fclose(file);
	}

	/* locked_2, locked_3: attempt to write */
	for (i = 2; i < 4; i++) {
		snprintf(name, sizeof(name), "locked_%d", i);
		file = fopen(name, "w");
		if (file == NULL)
			printf("%s: write denied (expected)\n", name);
		else
			fclose(file);
	}

	/* locked_4, locked_5: alternate read and write */
	for (i = 4; i < 6; i++) {
		snprintf(name, sizeof(name), "locked_%d", i);
		file = fopen(name, (i % 2 == 0) ? "r" : "w");
		if (file == NULL)
			printf("%s: %s denied (expected)\n", name, (i % 2 == 0) ? "read" : "write");
		else
			fclose(file);
	}

	return 0;
}