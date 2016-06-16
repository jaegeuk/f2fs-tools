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

int f2fs_trim_device()
{
	unsigned long long range[2];
	struct stat stat_buf;

	if (!config.trim)
		return 0;

	range[0] = 0;
	range[1] = config.total_sectors * config.sector_size;

	if (fstat(config.fd, &stat_buf) < 0 ) {
		MSG(1, "\tError: Failed to get the device stat!!!\n");
		return -1;
	}

#if defined(WITH_BLKDISCARD) && defined(BLKDISCARD)
	MSG(0, "Info: Discarding device\n");
	if (S_ISREG(stat_buf.st_mode)) {
#if defined(HAVE_FALLOCATE) && defined(FALLOC_FL_PUNCH_HOLE)
		if (fallocate(config.fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
				range[0], range[1]) < 0) {
			MSG(0, "Info: fallocate(PUNCH_HOLE|KEEP_SIZE) is failed\n");
		}
#endif
		return 0;
	} else if (S_ISBLK(stat_buf.st_mode)) {
#ifdef BLKSECDISCARD
		if (ioctl(config.fd, BLKSECDISCARD, &range) < 0) {
			MSG(0, "Info: This device doesn't support BLKSECDISCARD\n");
		} else {
			MSG(0, "Info: Secure Discarded %lu sectors\n",
						config.total_sectors);
			return 0;
		}
#endif
		if (ioctl(config.fd, BLKDISCARD, &range) < 0) {
			MSG(0, "Info: This device doesn't support BLKDISCARD\n");
		} else {
			MSG(0, "Info: Discarded %lu sectors\n",
						config.total_sectors);
		}
	} else
		return -1;
#endif
	return 0;
}

