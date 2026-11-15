#include <stdio.h>

int main(void)
{
	FILE *f;

	remove("new.txt");
	f = fopen("new.txt", "w");
	if (f) {
		fwrite("hello\n", 6, 1, f);
		fclose(f);
	}

	f = fopen("new.txt", "r");
	if (f) fclose(f);

	f = fopen("secret.txt", "r");
	if (f == NULL) printf("secret.txt: denied (expected)\n");

	return 0;
}