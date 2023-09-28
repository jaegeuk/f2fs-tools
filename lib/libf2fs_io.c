/**
 * libf2fs.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 * Copyright (c) 2020 Google Inc.
 *   Robin Hsu <robinhsu@google.com>
 *  : add quick-buffer for sload compression support
 *
 * Dual licensed under the GPL or LGPL version 2 licenses.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#ifdef HAVE_MNTENT_H
#include <mntent.h>
#endif
#include <time.h>
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_LINUX_HDREG_H
#include <linux/hdreg.h>
#endif

#include "f2fs_fs.h"

struct f2fs_configuration c;

#ifdef HAVE_SPARSE_SPARSE_H
#include <sparse/sparse.h>
struct sparse_file *f2fs_sparse_file;
static char **blocks;
uint64_t blocks_count;
static char *zeroed_block;
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
	if (lseek(c.kd, (off_t)offset, SEEK_SET) < 0)
		return -1;
	if (read(c.kd, buf, len) < 0)
		return -1;
	return 0;
}

#ifdef HAVE_SPARSE_SPARSE_H
static int sparse_read_blk(__u64 block, int count, void *buf)
{
	int i;
	char *out = buf;
	__u64 cur_block;

	for (i = 0; i < count; ++i) {
		cur_block = block + i;
		if (blocks[cur_block])
			memcpy(out + (i * F2FS_BLKSIZE),
					blocks[cur_block], F2FS_BLKSIZE);
		else if (blocks)
			memset(out + (i * F2FS_BLKSIZE), 0, F2FS_BLKSIZE);
	}
	return 0;
}

static int sparse_write_blk(__u64 block, int count, const void *buf)
{
	int i;
	__u64 cur_block;
	const char *in = buf;

	for (i = 0; i < count; ++i) {
		cur_block = block + i;
		if (blocks[cur_block] == zeroed_block)
			blocks[cur_block] = NULL;
		if (!blocks[cur_block]) {
			blocks[cur_block] = calloc(1, F2FS_BLKSIZE);
			if (!blocks[cur_block])
				return -ENOMEM;
		}
		memcpy(blocks[cur_block], in + (i * F2FS_BLKSIZE),
				F2FS_BLKSIZE);
	}
	return 0;
}

static int sparse_write_zeroed_blk(__u64 block, int count)
{
	int i;
	__u64 cur_block;

	for (i = 0; i < count; ++i) {
		cur_block = block + i;
		if (blocks[cur_block])
			continue;
		blocks[cur_block] = zeroed_block;
	}
	return 0;
}

#ifdef SPARSE_CALLBACK_USES_SIZE_T
static int sparse_import_segment(void *UNUSED(priv), const void *data,
		size_t len, unsigned int block, unsigned int nr_blocks)
#else
static int sparse_import_segment(void *UNUSED(priv), const void *data, int len,
		unsigned int block, unsigned int nr_blocks)
#endif
{
	/* Ignore chunk headers, only write the data */
	if (!nr_blocks || len % F2FS_BLKSIZE)
		return 0;

	return sparse_write_blk(block, nr_blocks, data);
}

static int sparse_merge_blocks(uint64_t start, uint64_t num, int zero)
{
	char *buf;
	uint64_t i;

	if (zero) {
		blocks[start] = NULL;
		return sparse_file_add_fill(f2fs_sparse_file, 0x0,
					F2FS_BLKSIZE * num, start);
	}

	buf = calloc(num, F2FS_BLKSIZE);
	if (!buf) {
		fprintf(stderr, "failed to alloc %llu\n",
			(unsigned long long)num * F2FS_BLKSIZE);
		return -ENOMEM;
	}

	for (i = 0; i < num; i++) {
		memcpy(buf + i * F2FS_BLKSIZE, blocks[start + i], F2FS_BLKSIZE);
		free(blocks[start + i]);
		blocks[start + i] = NULL;
	}

	/* free_sparse_blocks will release this buf. */
	blocks[start] = buf;

	return sparse_file_add_data(f2fs_sparse_file, blocks[start],
					F2FS_BLKSIZE * num, start);
}
#else
static int sparse_read_blk(__u64 UNUSED(block),
				int UNUSED(count), void *UNUSED(buf))
{
	return 0;
}

static int sparse_write_blk(__u64 UNUSED(block),
				int UNUSED(count), const void *UNUSED(buf))
{
	return 0;
}

static int sparse_write_zeroed_blk(__u64 UNUSED(block), int UNUSED(count))
{
	return 0;
}
#endif

int dev_read(void *buf, __u64 offset, size_t len)
{
	int fd;

	if (c.sparse_mode)
		return sparse_read_blk(offset / F2FS_BLKSIZE,
					len / F2FS_BLKSIZE, buf);

	fd = __get_device_fd(&offset);
	if (fd < 0)
		return fd;

	if (lseek(fd, (off_t)offset, SEEK_SET) < 0)
		return -1;
	if (read(fd, buf, len) < 0)
		return -1;
	return 0;
}

#ifdef POSIX_FADV_WILLNEED
int dev_readahead(__u64 offset, size_t len)
#else
int dev_readahead(__u64 offset, size_t UNUSED(len))
#endif
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

int dev_write(void *buf, __u64 offset, size_t len)
{
	int fd;

	if (c.dry_run)
		return 0;

	if (c.sparse_mode)
		return sparse_write_blk(offset / F2FS_BLKSIZE,
					len / F2FS_BLKSIZE, buf);

	fd = __get_device_fd(&offset);
	if (fd < 0)
		return fd;

	if (lseek(fd, (off_t)offset, SEEK_SET) < 0)
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
	if (lseek(c.dump_fd, (off_t)offset, SEEK_SET) < 0)
		return -1;
	if (write(c.dump_fd, buf, len) < 0)
		return -1;
	return 0;
}

int dev_fill(void *buf, __u64 offset, size_t len)
{
	int fd;

	if (c.sparse_mode)
		return sparse_write_zeroed_blk(offset / F2FS_BLKSIZE,
						len / F2FS_BLKSIZE);

	fd = __get_device_fd(&offset);
	if (fd < 0)
		return fd;

	/* Only allow fill to zero */
	if (*((__u8*)buf))
		return -1;
	if (lseek(fd, (off_t)offset, SEEK_SET) < 0)
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

int f2fs_fsync_device(void)
{
#ifdef HAVE_FSYNC
	int i;

	for (i = 0; i < c.ndevs; i++) {
		if (fsync(c.devices[i].fd) < 0) {
			MSG(0, "\tError: Could not conduct fsync!!!\n");
			return -1;
		}
	}
#endif
	return 0;
}

int f2fs_init_sparse_file(void)
{
#ifdef HAVE_SPARSE_SPARSE_H
	if (c.func == MKFS) {
		f2fs_sparse_file = sparse_file_new(F2FS_BLKSIZE, c.device_size);
		if (!f2fs_sparse_file)
			return -1;
	} else {
		f2fs_sparse_file = sparse_file_import(c.devices[0].fd,
							true, false);
		if (!f2fs_sparse_file)
			return -1;

		c.device_size = sparse_file_len(f2fs_sparse_file, 0, 0);
		c.device_size &= (~((uint64_t)(F2FS_BLKSIZE - 1)));
	}

	if (sparse_file_block_size(f2fs_sparse_file) != F2FS_BLKSIZE) {
		MSG(0, "\tError: Corrupted sparse file\n");
		return -1;
	}
	blocks_count = c.device_size / F2FS_BLKSIZE;
	blocks = calloc(blocks_count, sizeof(char *));
	if (!blocks) {
		MSG(0, "\tError: Calloc Failed for blocks!!!\n");
		return -1;
	}

	zeroed_block = calloc(1, F2FS_BLKSIZE);
	if (!zeroed_block) {
		MSG(0, "\tError: Calloc Failed for zeroed block!!!\n");
		return -1;
	}

	return sparse_file_foreach_chunk(f2fs_sparse_file, true, false,
				sparse_import_segment, NULL);
#else
	MSG(0, "\tError: Sparse mode is only supported for android\n");
	return -1;
#endif
}

void f2fs_release_sparse_resource(void)
{
#ifdef HAVE_SPARSE_SPARSE_H
	int j;

	if (c.sparse_mode) {
		if (f2fs_sparse_file != NULL) {
			sparse_file_destroy(f2fs_sparse_file);
			f2fs_sparse_file = NULL;
		}
		for (j = 0; j < blocks_count; j++)
			free(blocks[j]);
		free(blocks);
		blocks = NULL;
		free(zeroed_block);
		zeroed_block = NULL;
	}
#endif
}

#define MAX_CHUNK_SIZE		(1 * 1024 * 1024 * 1024ULL)
#define MAX_CHUNK_COUNT		(MAX_CHUNK_SIZE / F2FS_BLKSIZE)
int f2fs_finalize_device(void)
{
	int i;
	int ret = 0;

#ifdef HAVE_SPARSE_SPARSE_H
	if (c.sparse_mode) {
		int64_t chunk_start = (blocks[0] == NULL) ? -1 : 0;
		uint64_t j;

		if (c.func != MKFS) {
			sparse_file_destroy(f2fs_sparse_file);
			ret = ftruncate(c.devices[0].fd, 0);
			ASSERT(!ret);
			lseek(c.devices[0].fd, 0, SEEK_SET);
			f2fs_sparse_file = sparse_file_new(F2FS_BLKSIZE,
							c.device_size);
		}

		for (j = 0; j < blocks_count; ++j) {
			if (chunk_start != -1) {
				if (j - chunk_start >= MAX_CHUNK_COUNT) {
					ret = sparse_merge_blocks(chunk_start,
							j - chunk_start, 0);
					ASSERT(!ret);
					chunk_start = -1;
				}
			}

			if (chunk_start == -1) {
				if (!blocks[j])
					continue;

				if (blocks[j] == zeroed_block) {
					ret = sparse_merge_blocks(j, 1, 1);
					ASSERT(!ret);
				} else {
					chunk_start = j;
				}
			} else {
				if (blocks[j] && blocks[j] != zeroed_block)
					continue;

				ret = sparse_merge_blocks(chunk_start,
						j - chunk_start, 0);
				ASSERT(!ret);

				if (blocks[j] == zeroed_block) {
					ret = sparse_merge_blocks(j, 1, 1);
					ASSERT(!ret);
				}

				chunk_start = -1;
			}
		}
		if (chunk_start != -1) {
			ret = sparse_merge_blocks(chunk_start,
						blocks_count - chunk_start, 0);
			ASSERT(!ret);
		}

		sparse_file_write(f2fs_sparse_file, c.devices[0].fd,
				/*gzip*/0, /*sparse*/1, /*crc*/0);

		f2fs_release_sparse_resource();
	}
#endif
	/*
	 * We should call fsync() to flush out all the dirty pages
	 * in the block device page cache.
	 */
	for (i = 0; i < c.ndevs; i++) {
#ifdef HAVE_FSYNC
		ret = fsync(c.devices[i].fd);
		if (ret < 0) {
			MSG(0, "\tError: Could not conduct fsync!!!\n");
			break;
		}
#endif
		ret = close(c.devices[i].fd);
		if (ret < 0) {
			MSG(0, "\tError: Failed to close device file!!!\n");
			break;
		}
		free(c.devices[i].path);
		free(c.devices[i].zone_cap_blocks);
	}
	close(c.kd);

	return ret;
}
