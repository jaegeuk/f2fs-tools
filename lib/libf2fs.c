/**
 * libf2fs.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <mntent.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <linux/hdreg.h>
#include <linux/fs.h>

#include "f2fs_fs.h"

struct f2fs_configuration config;

void ASCIIToUNICODE(u_int16_t *out_buf, u_int8_t *in_buf)
{
	u_int8_t *pchTempPtr = in_buf;
	u_int16_t *pwTempPtr = out_buf;

	while (*pchTempPtr != '\0') {
		*pwTempPtr = (u_int16_t)*pchTempPtr;
		pchTempPtr++;
		pwTempPtr++;
	}
	*pwTempPtr = '\0';
	return;
}

int log_base_2(u_int32_t num)
{
	int ret = 0;
	if (num <= 0 || (num & (num - 1)) != 0)
		return -1;

	while (num >>= 1)
		ret++;
	return ret;
}

/*
 * f2fs bit operations
 */
int f2fs_test_bit(unsigned int nr, const char *p)
{
	int mask;
	char *addr = (char *)p;

	addr += (nr >> 3);
	mask = 1 << (7 - (nr & 0x07));
	return (mask & *addr) != 0;
}

int f2fs_set_bit(unsigned int nr, unsigned char *addr)
{
	int mask;
	int ret;

	addr += (nr >> 3);
	mask = 1 << (7 - (nr & 0x07));
	ret = mask & *addr;
	*addr |= mask;
	return ret;
}

int f2fs_clear_bit(unsigned int nr, char *addr)
{
	int mask;
	int ret;

	addr += (nr >> 3);
	mask = 1 << (7 - (nr & 0x07));
	ret = mask & *addr;
	*addr &= ~mask;
	return ret;
}

/*
 * CRC32
 */
#define CRCPOLY_LE 0xedb88320

u_int32_t f2fs_cal_crc32(u_int32_t crc, void *buf, int len)
{
	int i;
	unsigned char *p = (unsigned char *)buf;
	while (len--) {
		crc ^= *p++;
		for (i = 0; i < 8; i++)
			crc = (crc >> 1) ^ ((crc & 1) ? CRCPOLY_LE : 0);
	}
	return crc;
}

int f2fs_crc_valid(u_int32_t blk_crc, void *buf, int len)
{
	u_int32_t cal_crc = 0;

	cal_crc = f2fs_cal_crc32(F2FS_SUPER_MAGIC, buf, len);

	if (cal_crc != blk_crc)	{
		DBG(0,"CRC validation failed: cal_crc = %u \
			blk_crc = %u buff_size = 0x%x",
			cal_crc, blk_crc, len);
		return -1;
	}
	return 0;
}

/*
 * device information
 */
void f2fs_init_configuration(struct f2fs_configuration *c)
{
	c->sector_size = DEFAULT_SECTOR_SIZE;
	c->sectors_per_blk = DEFAULT_SECTORS_PER_BLOCK;
	c->blks_per_seg = DEFAULT_BLOCKS_PER_SEGMENT;

	/* calculated by overprovision ratio */
	c->reserved_segments = 48;
	c->overprovision = 5;
	c->segs_per_sec = 1;
	c->secs_per_zone = 1;
	c->heap = 1;
	memset(c->vol_label, 0, sizeof(c->vol_label));

	c->vol_label[0] = 'F';
	c->vol_label[1] = '2';
	c->vol_label[2] = 'F';
	c->vol_label[3] = 'S';
	c->vol_label[4] = '\0';
	c->device_name = NULL;
}

int f2fs_dev_is_mounted(struct f2fs_configuration *c)
{
	FILE *file = NULL;
	struct mntent *mnt = NULL;

	file = setmntent(MOUNTED, "r");
	if (file == NULL)
		return 0;

	while (1) {
		mnt = getmntent(file);
		if (mnt == NULL)
			break;
		if (!strcmp(c->device_name, mnt->mnt_fsname)) {
			endmntent(file);
			return -1;
		}
	}
	endmntent(file);
	return 0;
}

int f2fs_get_device_info(struct f2fs_configuration *c)
{
	int32_t fd = 0;
	int32_t sector_size;
	struct stat stat_buf;
	struct hd_geometry geom;

	fd = open(c->device_name, O_RDWR);
	if (fd < 0) {
		MSG(0, "\tError: Failed to open the device!\n");
		return -1;
	}
	c->fd = fd;

	if (fstat(fd, &stat_buf) < 0 ) {
		MSG(0, "\tError: Failed to get the device stat!\n");
		return -1;
	}

	if (S_ISREG(stat_buf.st_mode)) {
		c->total_sectors = stat_buf.st_size / c->sector_size;
	} else if (S_ISBLK(stat_buf.st_mode)) {
		if (ioctl(fd, BLKSSZGET, &sector_size) < 0) {
			MSG(0, "\tError: Using the default sector size\n");
		} else {
			if (c->sector_size < sector_size) {
				MSG(0, "\tError: Cannot set the sector size to:"
					" %d as the device does not support"
					"\nSetting the sector size to : %d\n",
					c->sector_size, sector_size);
				c->sector_size = sector_size;
				c->sectors_per_blk = PAGE_SIZE / sector_size;
			}
		}

		if (ioctl(fd, BLKGETSIZE, &c->total_sectors) < 0) {
			MSG(0, "\tError: Cannot get the device size\n");
			return -1;
		}

		if (ioctl(fd, HDIO_GETGEO, &geom) < 0)
			c->start_sector = 0;
		else
			c->start_sector = geom.start;
	} else {
		MSG(0, "\tError: Volume type is not supported!!!\n");
		return -1;
	}

	MSG(0, "Info: sector size = %u\n", c->sector_size);
	MSG(0, "Info: total sectors = %"PRIu64" (in 512bytes)\n",
					c->total_sectors);
	if (c->total_sectors <
			(F2FS_MIN_VOLUME_SIZE / DEFAULT_SECTOR_SIZE)) {
		MSG(0, "Error: Min volume size supported is %d\n",
				F2FS_MIN_VOLUME_SIZE);
		return -1;
	}

	return 0;
}

/*
 * IO interfaces
 */
int dev_read(void *buf, __u64 offset, size_t len)
{
	if (lseek64(config.fd, (off64_t)offset, SEEK_SET) < 0)
		return -1;
	if (read(config.fd, buf, len) < 0)
		return -1;
	return 0;
}

int dev_write(void *buf, __u64 offset, size_t len)
{
	if (lseek64(config.fd, (off64_t)offset, SEEK_SET) < 0)
		return -1;
	if (write(config.fd, buf, len) < 0)
		return -1;
	return 0;
}

int dev_read_block(void *buf, __u64 blk_addr)
{
	return dev_read(buf, blk_addr * F2FS_BLKSIZE, F2FS_BLKSIZE);
}

int dev_read_blocks(void *buf, __u64 addr, __u32 nr_blks)
{
	return dev_read(buf, addr * F2FS_BLKSIZE, nr_blks * F2FS_BLKSIZE);
}
