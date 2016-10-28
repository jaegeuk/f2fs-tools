/**
 * f2fs_format_utils.c
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * Dual licensed under the GPL or LGPL version 2 licenses.
 */
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "f2fs_fs.h"

#ifdef HAVE_LINUX_FS_H
#include <linux/fs.h>
#endif
#ifdef HAVE_LINUX_FALLOC_H
#include <linux/falloc.h>
#endif

#ifndef BLKDISCARD
#define BLKDISCARD	_IO(0x12,119)
#endif
#ifndef BLKSECDISCARD
#define BLKSECDISCARD	_IO(0x12,125)
#endif

int f2fs_trim_device(int fd, u_int64_t bytes)
{
	unsigned long long range[2];
	struct stat stat_buf;

	if (fstat(fd, &stat_buf) < 0 ) {
		MSG(1, "\tError: Failed to get the device stat!!!\n");
		return -1;
	}

	range[0] = 0;
	range[1] = bytes;

#if defined(WITH_BLKDISCARD) && defined(BLKDISCARD)
	MSG(0, "Info: Discarding device\n");
	if (S_ISREG(stat_buf.st_mode)) {
#if defined(HAVE_FALLOCATE) && defined(FALLOC_FL_PUNCH_HOLE)
		if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
				range[0], range[1]) < 0) {
			MSG(0, "Info: fallocate(PUNCH_HOLE|KEEP_SIZE) is failed\n");
		}
#endif
		return 0;
	} else if (S_ISBLK(stat_buf.st_mode)) {
		if (c.zoned_mode)
			return f2fs_reset_zones();
#ifdef BLKSECDISCARD
		if (ioctl(fd, BLKSECDISCARD, &range) < 0) {
			MSG(0, "Info: This device doesn't support BLKSECDISCARD\n");
		} else {
			MSG(0, "Info: Secure Discarded %lu MB\n",
						stat_buf.st_size >> 20);
			return 0;
		}
#endif
		if (ioctl(fd, BLKDISCARD, &range) < 0) {
			MSG(0, "Info: This device doesn't support BLKDISCARD\n");
		} else {
			MSG(0, "Info: Discarded %llu MB\n", range[1] >> 20);
		}
	} else
		return -1;
#endif
	return 0;
}
