#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#define DENIED_THRESHOLD 5
#define NULL_HASH "0000000000000000000000000000000000000000000000000000000000000000"

struct log_entry {

	int uid; /* user id (positive integer) */
	pid_t pid; /* process id (positive integer) */

	char *file; /* filename (string) */

	char date[11]; /* file access date - utc, YYYY-MM-DD */
	char time[9]; /* file access time - utc, HH:MM:SS */

	int operation; /* access type values [0-3] */
	int action_denied; /* is action denied values [0-1] */

	char filehash[65]; /* file hash - sha256 - evp */

};

/* all entries of the log, in memory */
struct log_entry *entries = NULL;
int n_entries = 0;


void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./audit_monitor \n"
		   "Options:\n"
		   "-s, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


/* split one tab-separated line into a log_entry; returns 0 on success */
int
parse_line(char *line, struct log_entry *e)
{
	char *fields[8];
	char *tok;
	int i = 0;

	line[strcspn(line, "\n")] = '\0';

	tok = strtok(line, "\t");
	while (tok != NULL && i < 8) {
		fields[i++] = tok;
		tok = strtok(NULL, "\t");
	}
	if (i != 8)
		return -1;

	e->uid = atoi(fields[0]);
	e->pid = atoi(fields[1]);
	e->file = strdup(fields[2]);
	snprintf(e->date, sizeof(e->date), "%s", fields[3]);
	snprintf(e->time, sizeof(e->time), "%s", fields[4]);
	e->operation = atoi(fields[5]);
	e->action_denied = atoi(fields[6]);
	snprintf(e->filehash, sizeof(e->filehash), "%s", fields[7]);
	return 0;
}


/* read the whole log file into the entries array */
void
load_log(FILE *log)
{
	char line[PATH_MAX + 256];
	struct log_entry e;

	while (fgets(line, sizeof(line), log) != NULL) {
		if (parse_line(line, &e) != 0)
			continue;

		entries = realloc(entries, (n_entries + 1) * sizeof(struct log_entry));
		if (entries == NULL) {
			perror("realloc");
			exit(1);
		}
		entries[n_entries] = e;
		n_entries++;
	}
}


void
list_unauthorized_accesses(FILE *log)
{
	int i, j, k;
	int found = 0;

	if (n_entries == 0)
		load_log(log);

	printf("UID\tDENIED FILES\n");

	for (i = 0; i < n_entries; i++) {
		int uid = entries[i].uid;

		/* process each uid only once */
		int seen = 0;
		for (j = 0; j < i; j++)
			if (entries[j].uid == uid)
				seen = 1;
		if (seen)
			continue;

		/* collect distinct denied files for this uid */
		char *denied_files[n_entries];
		int n_denied = 0;

		for (j = 0; j < n_entries; j++) {
			if (entries[j].uid != uid || !entries[j].action_denied)
				continue;

			int dup = 0;
			for (k = 0; k < n_denied; k++)
				if (strcmp(denied_files[k], entries[j].file) == 0)
					dup = 1;
			if (!dup)
				denied_files[n_denied++] = entries[j].file;
		}

		if (n_denied > DENIED_THRESHOLD) {
			printf("%d\t%d\n", uid, n_denied);
			found = 1;
		}
	}

	if (!found)
		printf("(no suspicious users)\n");

	return;
}


void
list_file_modifications(FILE *log, char *file_to_scan)
{
	char target[PATH_MAX];
	int i, j, u;

	if (n_entries == 0)
		load_log(log);

	int uids[n_entries + 1], fwrites[n_entries + 1], changes[n_entries + 1];
	int n_uids = 0;
	char *hashes[n_entries + 1];
	int n_hashes = 0;
	const char *prev_hash = NULL;

	if (realpath(file_to_scan, target) == NULL)
		snprintf(target, sizeof(target), "%s", file_to_scan);

	for (i = 0; i < n_entries; i++) {
		struct log_entry *e = &entries[i];

		if (strcmp(e->file, target) != 0)
			continue;

		/* find or add this uid */
		for (u = 0; u < n_uids; u++)
			if (uids[u] == e->uid)
				break;
		if (u == n_uids) {
			uids[u] = e->uid;
			fwrites[u] = 0;
			changes[u] = 0;
			n_uids++;
		}

		if (e->action_denied)
			continue;

		if (e->operation == 2)
			fwrites[u]++;

		if (strcmp(e->filehash, NULL_HASH) == 0)
			continue;

		/* content changed since the previous event on this file? */
		if (prev_hash != NULL && strcmp(prev_hash, e->filehash) != 0) {
			changes[u]++;

			int dup = 0;
			for (j = 0; j < n_hashes; j++)
				if (strcmp(hashes[j], e->filehash) == 0)
					dup = 1;
			if (!dup)
				hashes[n_hashes++] = e->filehash;
		}
		prev_hash = e->filehash;
	}

	if (n_uids == 0) {
		printf("No entries for \"%s\"\n", target);
		return;
	}

	printf("File: %s\n", target);
	printf("UID\tFWRITES\tHASH CHANGES\n");
	for (u = 0; u < n_uids; u++)
		printf("%d\t%d\t%d\n", uids[u], fwrites[u], changes[u]);
	printf("Unique modifications: %d\n", n_hashes);

	return;
}


int
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./access_audit.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./access_audit.log");
		return 1;
	}

	opterr = 0;                                        /* ΝΕΟ */
	while ((ch = getopt(argc, argv, "hi:s")) != -1) {
		switch (ch) {
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 's':
			list_unauthorized_accesses(log);
			break;
		case '?':                                      /* ΝΕΟ */
			if (optopt == 'i')
				printf("error: -i requires a filename\n");
			else
				printf("error: unknown option -%c\n", optopt);
			usage();
			break;
		default:
			usage();
		}

	}

	fclose(log);
	argc -= optind;
	argv += optind;

	return 0;
}