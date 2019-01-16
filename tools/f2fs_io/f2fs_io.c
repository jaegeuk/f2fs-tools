/*
 * f2fs_io.c - f2fs ioctl utility
 *
 * Author: Jaegeuk Kim <jaegeuk@kernel.org>
 *
 * Copied portion of the code from ../f2fscrypt.c
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "f2fs_io.h"

struct cmd_desc {
	const char *cmd_name;
	void (*cmd_func)(int, char **, const struct cmd_desc *);
	const char *cmd_desc;
	const char *cmd_help;
	int cmd_flags;
};

#define shutdown_desc "shutdown filesystem"
#define shutdown_help					\
"f2fs_io shutdown [level] [dir]\n\n"			\
"Freeze and stop all IOs given mount point\n"		\
"level can be\n"					\
"  0 : going down with full sync\n"			\
"  1 : going down with checkpoint only\n"		\
"  2 : going down with no sync\n"			\
"  3 : going down with metadata flush\n"		\
"  4 : going down with fsck mark\n"

static void do_shutdown(int argc, char **argv, const struct cmd_desc *cmd)
{
	u32 flag;
	int ret, fd;

	if (argc != 3) {
		fputs("Excess arguments\n\n", stderr);
		fputs(cmd->cmd_help, stderr);
		exit(1);
	}

	flag = atoi(argv[1]);
	if (flag >= F2FS_GOING_DOWN_MAX) {
		fputs("Wrong level\n\n", stderr);
		fputs(cmd->cmd_help, stderr);
		exit(1);
	}
	fd = open(argv[2], O_RDONLY);
	if (fd == -1) {
		fputs("Open failed\n\n", stderr);
		fputs(cmd->cmd_help, stderr);
		exit(1);
	}

	ret = ioctl(fd, F2FS_IOC_SHUTDOWN, &flag);
	if (ret < 0) {
		perror("F2FS_IOC_SHUTDOWN");
		exit(1);
	}
	printf("Shutdown %s with level=%d\n", argv[2], flag);
	exit(0);
}

#define pinfile_desc "pin file control"
#define pinfile_help						\
"f2fs_io pinfile [get|set] [file]\n\n"			\
"get/set pinning given the file\n"				\

static void do_pinfile(int argc, char **argv, const struct cmd_desc *cmd)
{
	u32 pin;
	int ret, fd;

	if (argc != 3) {
		fputs("Excess arguments\n\n", stderr);
		fputs(cmd->cmd_help, stderr);
		exit(1);
	}

	fd = open(argv[2], O_RDWR);
	if (fd == -1) {
		fputs("Open failed\n\n", stderr);
		fputs(cmd->cmd_help, stderr);
		exit(1);
	}

	ret = -1;
	if (!strcmp(argv[1], "set")) {
		pin = 1;
		ret = ioctl(fd, F2FS_IOC_SET_PIN_FILE, &pin);
		if (ret != 0) {
			perror("set_pin_file failed");
			exit(1);
		}
		printf("set_pin_file: %u blocks moved in %s\n", ret, argv[2]);
	} else if (!strcmp(argv[1], "get")) {
		unsigned int flags;

		ret = ioctl(fd, F2FS_IOC_GET_PIN_FILE, &pin);
		if (ret < 0) {
			perror("pin_file failed");
			exit(1);
		}
		ret = ioctl(fd, F2FS_IOC_GETFLAGS, &flags);
		if (ret < 0) {
			perror("get flags failed");
			exit(1);
		}
		printf("get_pin_file: %s with %u blocks moved in %s\n",
				(flags & F2FS_NOCOW_FL) ? "pinned" : "un-pinned",
				pin, argv[2]);
	}
	exit(0);
}

#define write_desc "write data into file"
#define write_help					\
"f2fs_io write [chunk_size in 4kb] [offset in chunk_size] [count] [pattern] [IO] [file_path]\n\n"	\
"Write given patten data in file_path\n"		\
"pattern can be\n"					\
"  zero     : zeros\n"					\
"  inc_num  : incrementing numbers\n"			\
"  rand     : random numbers\n"				\
"IO can be\n"						\
"  buffered : buffered IO\n"				\
"  dio      : direct IO\n"				\

static void do_write(int argc, char **argv, const struct cmd_desc *cmd)
{
	u64 buf_size = 0, inc_num = 0, ret = 0, written = 0;
	loff_t offset;
	char *buf = NULL;
	unsigned bs, count, i;
	int flags = 0;
	int fd;

	srand(time(0));

	if (argc != 7) {
		fputs("Excess arguments\n\n", stderr);
		fputs(cmd->cmd_help, stderr);
		exit(1);
	}

	bs = atoi(argv[1]);
	if (bs > 1024) {
		fputs("Too big chunk size - limit: 4MB\n\n", stderr);
		exit(1);
	}
	buf_size = bs * 4096;

	offset = atoi(argv[2]) * buf_size;

	buf = aligned_alloc(4096, buf_size);
	if (!buf) {
		fputs("Memory alloc failed\n\n", stderr);
		exit(1);
	}
	count = atoi(argv[3]);

	if (!strcmp(argv[4], "zero")) {
		memset(buf, 0, buf_size);
	} else if (strcmp(argv[4], "inc_num") &&
			strcmp(argv[4], "rand")) {
		fputs("Wrong pattern type\n\n", stderr);
		exit(1);
	}

	if (!strcmp(argv[5], "buffered")) {
		flags |= O_DIRECT;
	} else if (strcmp(argv[5], "dio")) {
		fputs("Wrong IO type\n\n", stderr);
		exit(1);
	}

	fd = open(argv[6], O_CREAT | O_WRONLY | flags, 0755);
	if (fd == -1) {
		fputs("Open failed\n\n", stderr);
		exit(1);
	}

	for (i = 0; i < count; i++) {
		if (!strcmp(argv[4], "inc_num"))
			*(int *)buf = inc_num++;
		else if (!strcmp(argv[4], "rand"))
			*(int *)buf = rand();

		/* write data */
		ret = pwrite(fd, buf, buf_size, offset + buf_size * i);
		if (ret != buf_size)
			break;
		written += ret;
	}

	printf("Written %lu bytes with pattern=%s\n", written, argv[4]);
	exit(0);
}

#define CMD_HIDDEN 	0x0001
#define CMD(name) { #name, do_##name, name##_desc, name##_help, 0 }
#define _CMD(name) { #name, do_##name, NULL, NULL, CMD_HIDDEN }

static void do_help(int argc, char **argv, const struct cmd_desc *cmd);
const struct cmd_desc cmd_list[] = {
	_CMD(help),
	CMD(shutdown),
	CMD(pinfile),
	CMD(write),
	{ NULL, NULL, NULL, NULL, 0 }
};

static void do_help(int argc, char **argv, const struct cmd_desc *UNUSED(cmd))
{
	const struct cmd_desc *p;

	if (argc > 1) {
		for (p = cmd_list; p->cmd_name; p++) {
			if (p->cmd_flags & CMD_HIDDEN)
				continue;
			if (strcmp(p->cmd_name, argv[1]) == 0) {
				putc('\n', stdout);
				fputs("USAGE:\n  ", stdout);
				fputs(p->cmd_help, stdout);
				exit(0);
			}
		}
		printf("Unknown command: %s\n\n", argv[1]);
	}

	fputs("Available commands:\n", stdout);
	for (p = cmd_list; p->cmd_name; p++) {
		if (p->cmd_flags & CMD_HIDDEN)
			continue;
		printf("  %-20s %s\n", p->cmd_name, p->cmd_desc);
	}
	printf("\nTo get more information on a command, "
	       "type 'f2fs_io help cmd'\n");
	exit(0);
}

static void die_signal_handler(int UNUSED(signum), siginfo_t *UNUSED(siginfo),
				void *UNUSED(context))
{
	exit(-1);
}

static void sigcatcher_setup(void)
{
	struct sigaction	sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_sigaction = die_signal_handler;
	sa.sa_flags = SA_SIGINFO;

	sigaction(SIGHUP, &sa, 0);
	sigaction(SIGINT, &sa, 0);
	sigaction(SIGQUIT, &sa, 0);
	sigaction(SIGFPE, &sa, 0);
	sigaction(SIGILL, &sa, 0);
	sigaction(SIGBUS, &sa, 0);
	sigaction(SIGSEGV, &sa, 0);
	sigaction(SIGABRT, &sa, 0);
	sigaction(SIGPIPE, &sa, 0);
	sigaction(SIGALRM, &sa, 0);
	sigaction(SIGTERM, &sa, 0);
	sigaction(SIGUSR1, &sa, 0);
	sigaction(SIGUSR2, &sa, 0);
	sigaction(SIGPOLL, &sa, 0);
	sigaction(SIGPROF, &sa, 0);
	sigaction(SIGSYS, &sa, 0);
	sigaction(SIGTRAP, &sa, 0);
	sigaction(SIGVTALRM, &sa, 0);
	sigaction(SIGXCPU, &sa, 0);
	sigaction(SIGXFSZ, &sa, 0);
}

int main(int argc, char **argv)
{
	const struct cmd_desc *cmd;

	if (argc < 2)
		do_help(argc, argv, cmd_list);

	sigcatcher_setup();
	for (cmd = cmd_list; cmd->cmd_name; cmd++) {
		if (strcmp(cmd->cmd_name, argv[1]) == 0) {
			cmd->cmd_func(argc - 1, argv + 1, cmd);
			exit(0);
		}
	}
	printf("Unknown command: %s\n\n", argv[1]);
	do_help(1, argv, cmd_list);
	return 0;
}
