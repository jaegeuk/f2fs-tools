/**
 * libf2fs.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * Dual licensed under the GPL or LGPL version 2 licenses.
 */
#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <mntent.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <linux/hdreg.h>

#include <f2fs_fs.h>

struct f2fs_configuration c;

#ifdef WITH_ANDROID
#include <sparse/sparse.h>
struct sparse_file *f2fs_sparse_file;

struct buf_item {
	void *buf;
	size_t len;
	struct buf_item *next;
};

struct buf_item *buf_list;
#endif

static int __get_device_fd(__u64 *offset)
{
	__u64 blk_addr = *offset >> F2FS_BLKSIZE_BITS;
	int i;

	for (i = 0; i < c.ndevs; i++) {
		if (c.devices[i].start_blkaddr <= blk_addr &&
				c.devices[i].end_blkaddr >= blk_addr) {
			*offset -=
				c.devices[i].start_blkaddr << F2FS_BLKSIZE_BITS;
			return c.devices[i].fd;
		}
	}
	return -1;
}

/*
 * IO interfaces
 */
int dev_read_version(void *buf, __u64 offset, size_t len)
{
	if (c.sparse_mode)
		return 0;
	if (lseek64(c.kd, (off64_t)offset, SEEK_SET) < 0)
		return -1;
	if (read(c.kd, buf, len) < 0)
		return -1;
	return 0;
}

int dev_read(void *buf, __u64 offset, size_t len)
{
	int fd;

	if (c.sparse_mode)
		return 0;

	fd = __get_device_fd(&offset);
	if (fd < 0)
		return fd;

	if (lseek64(fd, (off64_t)offset, SEEK_SET) < 0)
		return -1;
	if (read(fd, buf, len) < 0)
		return -1;
	return 0;
}

int dev_readahead(__u64 offset, size_t len)
{
	int fd = __get_device_fd(&offset);

	if (fd < 0)
		return fd;
#ifdef POSIX_FADV_WILLNEED
	return posix_fadvise(fd, offset, len, POSIX_FADV_WILLNEED);
#else
	return 0;
#endif
}

#ifdef WITH_ANDROID
static int dev_write_sparse(void *buf, __u64 byte_offset, size_t byte_len)
{
	struct buf_item *bi = calloc(1, sizeof(struct buf_item));

	if (bi == NULL) {
		return -1;
	}
	bi->buf = malloc(byte_len);
	if (bi->buf == NULL) {
		free(bi);
		return -1;
	}

	bi->len = byte_len;
	memcpy(bi->buf, buf, byte_len);
	bi->next = buf_list;
	buf_list = bi;

	sparse_file_add_data(f2fs_sparse_file, bi->buf, byte_len, byte_offset/F2FS_BLKSIZE);
	return 0;
}
#else
static int dev_write_sparse(void *buf, __u64 byte_offset, size_t byte_len) { return 0; }
#endif

int dev_write(void *buf, __u64 offset, size_t len)
{
	int fd;

	if (c.sparse_mode)
		return dev_write_sparse(buf, offset, len);

	fd = __get_device_fd(&offset);
	if (fd < 0)
		return fd;

	if (lseek64(fd, (off64_t)offset, SEEK_SET) < 0)
		return -1;
	if (write(fd, buf, len) < 0)
		return -1;
	return 0;
}

int dev_write_block(void *buf, __u64 blk_addr)
{
	return dev_write(buf, blk_addr << F2FS_BLKSIZE_BITS, F2FS_BLKSIZE);
}

int dev_write_dump(void *buf, __u64 offset, size_t len)
{
	if (lseek64(c.dump_fd, (off64_t)offset, SEEK_SET) < 0)
		return -1;
	if (write(c.dump_fd, buf, len) < 0)
		return -1;
	return 0;
}

int dev_fill(void *buf, __u64 offset, size_t len)
{
	int fd;

	if (c.sparse_mode)
		return 0;

	fd = __get_device_fd(&offset);
	if (fd < 0)
		return fd;

	/* Only allow fill to zero */
	if (*((__u8*)buf))
		return -1;
	if (lseek64(fd, (off64_t)offset, SEEK_SET) < 0)
		return -1;
	if (write(fd, buf, len) < 0)
		return -1;
	return 0;
}

int dev_fill_block(void *buf, __u64 blk_addr)
{
	return dev_fill(buf, blk_addr << F2FS_BLKSIZE_BITS, F2FS_BLKSIZE);
}

int dev_read_block(void *buf, __u64 blk_addr)
{
	return dev_read(buf, blk_addr << F2FS_BLKSIZE_BITS, F2FS_BLKSIZE);
}

int dev_reada_block(__u64 blk_addr)
{
	return dev_readahead(blk_addr << F2FS_BLKSIZE_BITS, F2FS_BLKSIZE);
}

void f2fs_finalize_device(void)
{
	int i;

#ifdef WITH_ANDROID
	if (c.sparse_mode) {
		sparse_file_write(f2fs_sparse_file, c.devices[0].fd, /*gzip*/0, /*sparse*/1, /*crc*/0);
		sparse_file_destroy(f2fs_sparse_file);
		while (buf_list) {
			struct buf_item *bi = buf_list;
			buf_list = buf_list->next;
			free(bi->buf);
			free(bi);
		}
		f2fs_sparse_file = NULL;
	}
#endif

	/*
	 * We should call fsync() to flush out all the dirty pages
	 * in the block device page cache.
	 */
	for (i = 0; i < c.ndevs; i++) {
		if (fsync(c.devices[i].fd) < 0)
			MSG(0, "\tError: Could not conduct fsync!!!\n");

		if (close(c.devices[i].fd) < 0)
			MSG(0, "\tError: Failed to close device file!!!\n");
	}
	close(c.kd);
}
