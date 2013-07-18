#define _LARGEFILE64_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <linux/fs.h>

struct file_ext {
	__u32 f_pos;
	__u32 start_blk;
	__u32 end_blk;
	__u32 blk_count;
};

void print_ext(struct file_ext *ext)
{
	if (ext->end_blk == 0)
		printf("%8d    %8d    %8d    %8d\n", ext->f_pos, 0, 0, ext->blk_count);
	else
		printf("%8d    %8d    %8d    %8d\n", ext->f_pos, ext->start_blk,
					ext->end_blk, ext->blk_count);
}

int main(int argc, char *argv[])
{
	int fd;
	int ret = 0;
	char *filename;
	struct stat64 st;
	int total_blks;
	unsigned int i;
	struct file_ext ext;
	__u32 blknum;

	if (argc != 2) {
		fprintf(stderr, "No filename\n");
		exit(-1);
	}
	filename = argv[1];

	fd = open(filename, O_RDONLY|O_LARGEFILE);
	if (fd < 0) {
		ret = errno;
		perror(filename);
		exit(-1);
	}

	fsync(fd);

	if (fstat64(fd, &st) < 0) {
		ret = errno;
		perror(filename);
		goto out;
	}

	total_blks = (st.st_size + st.st_blksize - 1) / st.st_blksize;

	printf("\n%s :\n", filename);
	printf("file_pos   start_blk     end_blk        blks\n");

	blknum = 0;
	if (ioctl(fd, FIBMAP, &blknum) < 0) {
		ret = errno;
		perror("ioctl(FIBMAP)");
		goto out;
	}
	ext.f_pos = 0;
	ext.start_blk = blknum;
	ext.end_blk = blknum;
	ext.blk_count = 1;

	for (i = 1; i < total_blks; i++) {
		blknum = i;

		if (ioctl(fd, FIBMAP, &blknum) < 0) {
			ret = errno;
			perror("ioctl(FIBMAP)");
			goto out;
		}

		if ((blknum == 0 && blknum == ext.end_blk) || (ext.end_blk + 1) == blknum) {
			ext.end_blk = blknum;
			ext.blk_count++;
		} else {
			ext.blk_count++;
			print_ext(&ext);
			ext.f_pos = i * st.st_blksize;
			ext.start_blk = blknum;
			ext.end_blk = blknum;
			ext.blk_count = 0;
		}
	}

	print_ext(&ext);
out:
	close(fd);
	return ret;
}
