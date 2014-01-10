#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#ifdef DEBUG
#define dbg(fmt, args...)	printf(fmt, __VA_ARGS__);
#else
#define dbg(fmt, args...)
#endif

/*
 * f2fs status
 */
#define F2FS_STATUS	"/sys/kernel/debug/f2fs/status"

unsigned long util;
unsigned long used_node_blks;
unsigned long used_data_blks;
//unsigned long inline_inode;

unsigned long free_segs;
unsigned long valid_segs;
unsigned long dirty_segs;
unsigned long prefree_segs;

unsigned long gc;
unsigned long bg_gc;
unsigned long gc_data_blks;
unsigned long gc_node_blks;

//unsigned long extent_hit_ratio;

unsigned long dirty_node;
unsigned long dirty_dents;
unsigned long dirty_meta;
unsigned long nat_caches;
unsigned long dirty_sit;

unsigned long free_nids;

unsigned long ssr_blks;
unsigned long lfs_blks;


struct options {
	int delay;
	int interval;
};

struct mm_table {
	const char *name;
	unsigned long *val;
};

static int compare_mm_table(const void *a, const void *b)
{
	dbg("[COMPARE] %s, %s\n", ((struct mm_table *)a)->name, ((struct mm_table *)b)->name);
	return strcmp(((struct mm_table *)a)->name, ((struct mm_table *)b)->name);
}

static inline void remove_newline(char **head)
{
again:
	if (**head == '\n') {
		*head = *head + 1;
		goto again;
	}
}

void f2fstat(void)
{
	int fd;
	int ret;
	char keyname[32];
	char buf[4096];
	struct mm_table key = { keyname, NULL };
	struct mm_table *found;
	int f2fstat_table_cnt;
	char *head, *tail;

	static struct mm_table f2fstat_table[] = {
		{ "  - Data",		&used_data_blks },
		{ "  - Dirty",		&dirty_segs },
		{ "  - Free",		&free_segs },
		{ "  - NATs",		&nat_caches },
		{ "  - Node",		&used_node_blks },
		{ "  - Prefree",	&prefree_segs },
		{ "  - SITs",		&dirty_sit },
		{ "  - Valid",		&valid_segs },
		{ "  - dents",		&dirty_dents },
		{ "  - meta",		&dirty_meta },
		{ "  - nodes",		&dirty_node },
		{ "GC calls",		&gc },
		{ "LFS",		&lfs_blks },
		{ "SSR",		&ssr_blks },
		{ "Utilization",	&util },
	};

	f2fstat_table_cnt = sizeof(f2fstat_table)/sizeof(struct mm_table);

	fd = open(F2FS_STATUS, O_RDONLY);
	if (fd < 0) {
		perror("open " F2FS_STATUS);
		exit(EXIT_FAILURE);
	}

	ret = read(fd, buf, 4096);
	if (ret < 0) {
		perror("read " F2FS_STATUS);
		exit(EXIT_FAILURE);
	}
	buf[ret] = '\0';

	head = buf;
	for (;;) {
		remove_newline(&head);
		tail = strchr(head, ':');
		if (!tail)
			break;
		*tail = '\0';
		if (strlen(head) >= sizeof(keyname)) {
			dbg("[OVER] %s\n", head);
			*tail = ':';
			tail = strchr(head, '\n');
			head = tail + 1;
			continue;
		}

		strcpy(keyname, head);

		found = bsearch(&key, f2fstat_table, f2fstat_table_cnt, sizeof(struct mm_table), compare_mm_table);
		dbg("[RESULT] %s (%s)\n", head, (found) ? "O" : "X");
		head = tail + 1;
		if (!found)
			goto nextline;

		*(found->val) = strtoul(head, &tail, 10);
nextline:
		tail = strchr(head, '\n');
		if (!tail)
			break;
		head =  tail + 1;
	}

	close(fd);
}

void usage(void)
{
	printf("Usage: f2fstat [option]\n"
			"    -d    delay (secs)\n"
			"    -i    interval of head info\n");
	exit(EXIT_FAILURE);
}

void parse_option(int argc, char *argv[], struct options *opt)
{
	char option;
	const char *option_string = "d:i:h";

	while ((option = getopt(argc, argv, option_string)) != EOF) {
		switch (option) {
		case 'd':
			opt->delay = atoi(optarg);
			break;
		case 'i':
			opt->interval = atoi(optarg);
			break;
		default:
			usage();
			break;
		}
	}
}

void print_head(void)
{
	printf("---utilization--- -----------main area-------- ---balancing async-- -gc- ---alloc---\n");
	printf("util  node   data   free  valid  dirty prefree node  dent meta sit   gc    ssr    lfs\n");
}

int main(int argc, char *argv[])
{
	char format[] = "%3ld %6ld %6ld %6ld %6ld %6ld %6ld %5ld %5ld %3ld %3ld %5ld %6ld %6ld\n";
	int head_interval;
	struct options opt = {
		.delay = 1,
		.interval = 20,
	};

	parse_option(argc, argv, &opt);
	head_interval = opt.interval;

	print_head();
	while (1) {
		if (head_interval-- == 0) {
			print_head();
			head_interval = opt.interval;
		}

		f2fstat();

		printf(format, util, used_node_blks, used_data_blks,
				free_segs, valid_segs, dirty_segs, prefree_segs,
				dirty_node, dirty_dents, dirty_meta, dirty_sit,
				gc, ssr_blks, lfs_blks);

		sleep(opt.delay);
	}

	return 0;
}
