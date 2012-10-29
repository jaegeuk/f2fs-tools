/**
 * f2fs_format.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <mntent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <linux/hdreg.h>
#include <time.h>
#include <linux/fs.h>
#include <uuid/uuid.h>

#include "f2fs_format.h"

struct f2fs_global_parameters f2fs_params;
struct f2fs_super_block super_block;

/**
 * @brief     	This function will change a given string from ASCII to UNICODE
 * @param	out_buf Output UNICODE string
 * @param	in_buf Input ASCII string
 * @return	None
 */
void ASCIIToUNICODE(u_int16_t *out_buf, u_int8_t *in_buf)
{
	u_int8_t *pchTempPtr = in_buf;
	u_int16_t *pwTempPtr = out_buf;

	while (*pchTempPtr != '\0') {
		/* Copy the string elements character by character
		 * to the output string with typecasting the source.
		 */
		*pwTempPtr = (u_int16_t)*pchTempPtr;
		pchTempPtr++;
		pwTempPtr++;
	}
	*pwTempPtr = '\0';
	return;
}

/**
 * @brief     	This function will ntitlize f2fs global paramenters
 * @param	None
 * @return	None
 */
static void f2fs_init_global_parameters(void)
{
	f2fs_params.sector_size = DEFAULT_SECTOR_SIZE;
	f2fs_params.sectors_per_blk = DEFAULT_SECTORS_PER_BLOCK;
	f2fs_params.blks_per_seg = DEFAULT_BLOCKS_PER_SEGMENT;
	f2fs_params.reserved_segments = 20; /* calculated by overprovision ratio */
	f2fs_params.overprovision = 5;
	f2fs_params.segs_per_sec = 1;
	f2fs_params.secs_per_zone = 1;
	f2fs_params.heap = 1;
	memset(f2fs_params.vol_label, 0, sizeof(f2fs_params.vol_label));

	f2fs_params.vol_label[0] = 'F';
	f2fs_params.vol_label[1] = '2';
	f2fs_params.vol_label[2] = 'F';
	f2fs_params.vol_label[3] = 'S';
	f2fs_params.vol_label[4] = '\0';
	f2fs_params.device_name = NULL;
}

static inline int f2fs_set_bit(unsigned int nr, unsigned char *addr)
{
	int mask;
	int ret;

	addr += (nr >> 3);
	mask = 1 << (7 - (nr & 0x07));
	ret = mask & *addr;
	*addr |= mask;
	return ret;
}

/**
 * @brief     	This function calculates log base 2 of given number
 * @param	num an integer number
 * @return	an int log base 2 of given number
 */
static int8_t log_base_2(u_int32_t num)
{
	int8_t ret = 0;

	if (num <= 0 || (num & (num - 1)) != 0) {
		return -1;
	}

	while (num >>= 1) {
		ret++;
	}

	return ret;
}

/**
 * @brief     	This function shows error if user gives wrong parameters
 * @param	None
 * @return	None
 */
static void f2fs_usage(void)
{
	fprintf(stderr, "Usage: f2fs_format [options] device\n");
	fprintf(stderr, "[options]\n");
	fprintf(stderr, "-l label\n");
	fprintf(stderr, "-a heap-based allocation [default:1]\n");
	fprintf(stderr, "-o overprovision ratio [default:5]\n");
	fprintf(stderr, "-s # of segments per section [default:1]\n");
	fprintf(stderr, "-z # of sections per zone [default:1]\n");
	fprintf(stderr, "-e [extension list] e.g. \"mp3,gif,mov\"\n");
	exit(1);
}

/**
 * @brief     	This function calculates log base 2 of given number
 * @param	argc number of arguments
 * @param	argv an array of arguments
 * @return	None
 */
static void f2fs_parse_options(int argc, char *argv[])
{
	static const char *option_string = "l:o:z:a:s:e:";
	int32_t option=0;

	while ((option = getopt(argc,argv,option_string)) != EOF) {
		switch (option) {
		case 'l':		/*v: volume label */
			if (strlen(optarg) > 512) {
				printf("Error: Volume Label should be less than \
						512 characters\n");
				f2fs_usage();
			}
			sprintf((char *)f2fs_params.vol_label, "%s", optarg);
			break;
		case 'o':
			f2fs_params.overprovision = atoi(optarg);
			printf("Info: Overprovision ratio = %u%%\n", atoi(optarg));
			break;
		case 's':
			f2fs_params.segs_per_sec = atoi(optarg);
			printf("Info: segments per section = %d\n", atoi(optarg));
			break;
		case 'a':
			f2fs_params.heap = atoi(optarg);
			if (f2fs_params.heap == 0)
				printf("Info: Allocate without heap-based policy\n");
			break;
		case 'z':
			f2fs_params.secs_per_zone = atoi(optarg);
			printf("Info: sections per zone = %d\n", atoi(optarg));
			break;
		case 'e':
			f2fs_params.extension_list = strdup(optarg);
			break;
		default:
			printf("Error: Unknown option %c\n",option);
			f2fs_usage();
			break;
		}
	}

	if ((optind + 1) != argc) {
		printf("Error: Device not specified\n");
		f2fs_usage();
	}

	f2fs_params.reserved_segments  =
			(100 / f2fs_params.overprovision + 5)
			* f2fs_params.segs_per_sec;
	f2fs_params.device_name = argv[optind];
}

/**
 * @brief     	Routine to  check if the device is already mounted
 * @param	None
 * @return	0 if device is not mounted
 * 		-1 if already mounted
 */
static int8_t f2fs_is_device_mounted()
{
	FILE *file;
	struct mntent *mnt; /* mntent structure to retrieve mount info */

	if ((file = setmntent(MOUNTED, "r")) == NULL)
		return 0;

	while ((mnt = getmntent(file)) != NULL) {
		if (!strcmp(f2fs_params.device_name, mnt->mnt_fsname)) {
			printf("Error: %s is already mounted\n",
					f2fs_params.device_name);
			return -1;
		}
	}
	endmntent(file);
	return 0;
}

/**
 * @brief     	Get device info - sector size, number of sectors etc
 * @param	None
 * @return	0 if successfully got device info
 */
static int8_t f2fs_get_device_info()
{
	int32_t fd = 0;
	int32_t sector_size;
	struct stat stat_buf;
	struct hd_geometry geom;

	fd = open(f2fs_params.device_name, O_RDWR);
	if (fd < 0) {
		printf("\n\tError: Failed to open the device!!!\n");
		return -1;
	}
	f2fs_params.fd = fd;

	if (fstat(fd, &stat_buf) < 0 ) {
		printf("\n\tError: Failed to get the device stat!!!\n");
		return -1;
	}

	if (S_ISREG(stat_buf.st_mode)) {
		f2fs_params.total_sectors = stat_buf.st_size /
			f2fs_params.sector_size;
	}
	else if (S_ISBLK(stat_buf.st_mode)) {
		if (ioctl(fd, BLKSSZGET, &sector_size) < 0 )
			printf("\n\tError: Cannot get the sector size!!! \
					Using the default Sector Size\n");
		else {
			if (f2fs_params.sector_size < sector_size) {
				printf("\n\tError: Cannot set the sector size to: %d"
					" as the device does not support"
					"\nSetting the sector size to : %d\n",
					f2fs_params.sector_size, sector_size);
				f2fs_params.sector_size = sector_size;
				f2fs_params.sectors_per_blk = PAGE_SIZE / sector_size;
			}
		}

		if (ioctl(fd, BLKGETSIZE, &f2fs_params.total_sectors) < 0) {
			printf("\n\tError: Cannot get the device size\n");
			return -1;
		}

		if (ioctl(fd, HDIO_GETGEO, &geom) < 0) {
			printf("\n\tError: Cannot get the device geometry\n");
			return -1;
		}
		f2fs_params.start_sector = geom.start;
	}
	else {
		printf("\n\n\tError: Volume type is not supported!!!\n");
		return -1;
	}

	printf("Info: sector size = %u\n", f2fs_params.sector_size);
	printf("Info: total sectors = %llu (in 512bytes)\n", f2fs_params.total_sectors);
	if (f2fs_params.total_sectors <
			(F2FS_MIN_VOLUME_SIZE / DEFAULT_SECTOR_SIZE)) {
		printf("Error: Min volume size supported is %d\n",
				F2FS_MIN_VOLUME_SIZE);
		return -1;
	}

	return 0;
}

const char *media_ext_lists[] = {
	"jpg",
	"gif",
	"png",
	"avi",
	"divx",
	"mp4",
	"mp3",
	"3gp",
	"wmv",
	"wma",
	"mpeg",
	"mkv",
	"mov",
	"asx",
	"asf",
	"wmx",
	"svi",
	"wvx",
	"wm",
	"mpg",
	"mpe",
	"rm",
	"ogg",
	NULL
};

static void configure_extension_list(void)
{
	const char **extlist = media_ext_lists;
	char *ext_str = f2fs_params.extension_list;
	char *ue;
	int name_len;
	int i = 0;

	super_block.extension_count = 0;
	memset(super_block.extension_list, 0,
			sizeof(super_block.extension_list));

	while (*extlist) {
		name_len = strlen(*extlist);
		memcpy(super_block.extension_list[i++], *extlist, name_len);
		extlist++;
	}
	super_block.extension_count = i - 1;

	if (!ext_str)
		return;

	/* add user ext list */
	ue = strtok(ext_str, ",");
	while (ue != NULL) {
		name_len = strlen(ue);
		memcpy(super_block.extension_list[i++], ue, name_len);
		ue = strtok(NULL, ",");
		if (i > F2FS_MAX_EXTENSION)
			break;
	}

	super_block.extension_count = i - 1;

	free(f2fs_params.extension_list);
}


/**
 * @brief     	It writes buffer to disk or storage meant to be formatted
 *		with F2FS.
 * @param	fd File descriptor for device
 * @param	buf buffer to be written
 * @param	offset where to bw written on the device
 * @param	length length of the device
 * @return	0 if success
 */
static int writetodisk(int32_t fd, void *buf, u_int64_t offset, size_t length)
{
	if (lseek64(fd, offset, SEEK_SET) < 0) {
		printf("\n\tError: While lseek to the derised location!!!\n");
		return -1;
	}

	if (write(fd, buf, length) < 0) {
		printf("\n\tError: While writing data to the disk!!! Error Num : \
				%d\n", errno);
		return -1;
	}

	return 0;
}

/**
 * @brief     	It initialize F2FS super block
 * @param	None
 * @return	None
 */
static int f2fs_prepare_super_block(void)
{
	u_int32_t blk_size_bytes;
	u_int32_t log_sectorsize, log_sectors_per_block;
	u_int32_t log_blocksize, log_blks_per_seg;
	u_int32_t segment_size_bytes, zone_size_bytes;
	u_int32_t sit_segments;
	u_int32_t blocks_for_sit, blocks_for_nat, blocks_for_ssa;
	u_int32_t total_valid_blks_available;
	u_int64_t zone_align_start_offset, diff, total_meta_segments;
	u_int32_t sit_bitmap_size, max_nat_bitmap_size, max_nat_segments;
	u_int32_t total_zones;

	super_block.magic = cpu_to_le32(F2FS_SUPER_MAGIC);
	super_block.major_ver = cpu_to_le16(F2FS_MAJOR_VERSION);
	super_block.minor_ver = cpu_to_le16(F2FS_MINOR_VERSION);

	log_sectorsize = log_base_2(f2fs_params.sector_size);
	log_sectors_per_block = log_base_2(f2fs_params.sectors_per_blk);
	log_blocksize = log_sectorsize + log_sectors_per_block;
	log_blks_per_seg = log_base_2(f2fs_params.blks_per_seg);

	super_block.log_sectorsize = cpu_to_le32(log_sectorsize);

	if (log_sectorsize < 0) {
		printf("\n\tError: Failed to get the sector size: %u!\n",
				f2fs_params.sector_size);
		return -1;
	}

	super_block.log_sectors_per_block = cpu_to_le32(log_sectors_per_block);

	if (log_sectors_per_block < 0) {
		printf("\n\tError: Failed to get sectors per block: %u!\n",
				f2fs_params.sectors_per_blk);
		return -1;
	}

	super_block.log_blocksize = cpu_to_le32(log_blocksize);
	super_block.log_blocks_per_seg = cpu_to_le32(log_blks_per_seg);

	if (log_blks_per_seg < 0) {
		printf("\n\tError: Failed to get block per segment: %u!\n",
				f2fs_params.blks_per_seg);
		return -1;
	}

	super_block.segs_per_sec = cpu_to_le32(f2fs_params.segs_per_sec);
	super_block.secs_per_zone = cpu_to_le32(f2fs_params.secs_per_zone);
	blk_size_bytes = 1 << log_blocksize;
	segment_size_bytes = blk_size_bytes * f2fs_params.blks_per_seg;
	zone_size_bytes =
		blk_size_bytes * f2fs_params.secs_per_zone *
		f2fs_params.segs_per_sec * f2fs_params.blks_per_seg;

	super_block.checksum_offset = 0;

	super_block.block_count = cpu_to_le64(
		(f2fs_params.total_sectors * DEFAULT_SECTOR_SIZE) /
			blk_size_bytes);

	zone_align_start_offset =
		(f2fs_params.start_sector * DEFAULT_SECTOR_SIZE +
		F2FS_SUPER_OFFSET * F2FS_BLKSIZE +
		sizeof(struct f2fs_super_block) * 2 +
		zone_size_bytes - 1) / zone_size_bytes * zone_size_bytes -
		f2fs_params.start_sector * DEFAULT_SECTOR_SIZE;

	if (f2fs_params.start_sector % DEFAULT_SECTORS_PER_BLOCK) {
		printf("WARN: Align start sector number in a unit of pages\n");
		printf("\ti.e., start sector: %d, ofs:%d (sectors per page: %d)\n",
				f2fs_params.start_sector,
				f2fs_params.start_sector % DEFAULT_SECTORS_PER_BLOCK,
				DEFAULT_SECTORS_PER_BLOCK);
	}

	super_block.segment_count = cpu_to_le32(
		((f2fs_params.total_sectors * DEFAULT_SECTOR_SIZE) -
		zone_align_start_offset) / segment_size_bytes);

	super_block.segment0_blkaddr =
		cpu_to_le32(zone_align_start_offset / blk_size_bytes);

	printf("Info: zone aligned segment0 blkaddr: %u\n",
				le32_to_cpu(super_block.segment0_blkaddr));

	super_block.start_segment_checkpoint = super_block.segment0_blkaddr;
	super_block.segment_count_ckpt =
				cpu_to_le32(F2FS_NUMBER_OF_CHECKPOINT_PACK);

	super_block.sit_blkaddr = cpu_to_le32(
		le32_to_cpu(super_block.start_segment_checkpoint) +
		(le32_to_cpu(super_block.segment_count_ckpt) *
		(1 << log_blks_per_seg)));

	blocks_for_sit = (le32_to_cpu(super_block.segment_count) +
			SIT_ENTRY_PER_BLOCK - 1) / SIT_ENTRY_PER_BLOCK;

	sit_segments = (blocks_for_sit + f2fs_params.blks_per_seg - 1)
			/ f2fs_params.blks_per_seg;

	super_block.segment_count_sit = cpu_to_le32(sit_segments * 2);

	super_block.nat_blkaddr = cpu_to_le32(
			le32_to_cpu(super_block.sit_blkaddr) +
			(le32_to_cpu(super_block.segment_count_sit) *
			 f2fs_params.blks_per_seg));

	total_valid_blks_available = (le32_to_cpu(super_block.segment_count) -
			(le32_to_cpu(super_block.segment_count_ckpt) +
			 le32_to_cpu(super_block.segment_count_sit))) *
			f2fs_params.blks_per_seg;

	blocks_for_nat = (total_valid_blks_available + NAT_ENTRY_PER_BLOCK - 1)
				/ NAT_ENTRY_PER_BLOCK;

	super_block.segment_count_nat = cpu_to_le32(
				(blocks_for_nat + f2fs_params.blks_per_seg - 1) /
				f2fs_params.blks_per_seg);
	/*
	 * The number of node segments should not be exceeded a "Threshold".
	 * This number resizes NAT bitmap area in a CP page.
	 * So the threshold is determined not to overflow one CP page
	 */
	sit_bitmap_size = ((le32_to_cpu(super_block.segment_count_sit) / 2) <<
				log_blks_per_seg) / 8;
	max_nat_bitmap_size = 4096 - sizeof(struct f2fs_checkpoint) + 1 -
			sit_bitmap_size;
	max_nat_segments = (max_nat_bitmap_size * 8) >> log_blks_per_seg;

	if (le32_to_cpu(super_block.segment_count_nat) > max_nat_segments)
		super_block.segment_count_nat = cpu_to_le32(max_nat_segments);

	super_block.segment_count_nat = cpu_to_le32(
			le32_to_cpu(super_block.segment_count_nat) * 2);

	super_block.ssa_blkaddr = cpu_to_le32(
			le32_to_cpu(super_block.nat_blkaddr) +
			le32_to_cpu(super_block.segment_count_nat) *
			f2fs_params.blks_per_seg);

	total_valid_blks_available = (le32_to_cpu(super_block.segment_count) -
			(le32_to_cpu(super_block.segment_count_ckpt) +
			le32_to_cpu(super_block.segment_count_sit) +
			le32_to_cpu(super_block.segment_count_nat))) *
			f2fs_params.blks_per_seg;

	blocks_for_ssa = total_valid_blks_available /
				f2fs_params.blks_per_seg + 1;

	super_block.segment_count_ssa = cpu_to_le32(
			(blocks_for_ssa + f2fs_params.blks_per_seg - 1) /
			f2fs_params.blks_per_seg);

	total_meta_segments = le32_to_cpu(super_block.segment_count_ckpt) +
		le32_to_cpu(super_block.segment_count_sit) +
		le32_to_cpu(super_block.segment_count_nat) +
		le32_to_cpu(super_block.segment_count_ssa);
	diff = total_meta_segments % (f2fs_params.segs_per_sec *
						f2fs_params.secs_per_zone);
	if (diff)
		super_block.segment_count_ssa = cpu_to_le32(
			le32_to_cpu(super_block.segment_count_ssa) +
			(f2fs_params.segs_per_sec * f2fs_params.secs_per_zone -
			 diff));

	super_block.main_blkaddr = cpu_to_le32(
			le32_to_cpu(super_block.ssa_blkaddr) +
			(le32_to_cpu(super_block.segment_count_ssa) *
			 f2fs_params.blks_per_seg));

	super_block.segment_count_main = cpu_to_le32(
			le32_to_cpu(super_block.segment_count) -
			(le32_to_cpu(super_block.segment_count_ckpt)
			 + le32_to_cpu(super_block.segment_count_sit) +
			 le32_to_cpu(super_block.segment_count_nat) +
			 le32_to_cpu(super_block.segment_count_ssa)));

	super_block.section_count = cpu_to_le32(
			le32_to_cpu(super_block.segment_count_main)
			/ f2fs_params.segs_per_sec);

	super_block.segment_count_main = cpu_to_le32(
			le32_to_cpu(super_block.section_count) *
			f2fs_params.segs_per_sec);

	if ((le32_to_cpu(super_block.segment_count_main) - 2) <
					f2fs_params.reserved_segments) {
		printf("Error: Device size is not sufficient for F2FS volume, \
			more segment needed =%u",
			f2fs_params.reserved_segments -
			(le32_to_cpu(super_block.segment_count_main) - 2));
		return -1;
	}

	super_block.failure_safe_block_distance = 0;
	uuid_generate(super_block.uuid);

	ASCIIToUNICODE(super_block.volume_name, f2fs_params.vol_label);

	super_block.node_ino = cpu_to_le32(1);
	super_block.meta_ino = cpu_to_le32(2);
	super_block.root_ino = cpu_to_le32(3);

	total_zones = ((le32_to_cpu(super_block.segment_count_main) - 1) /
			f2fs_params.segs_per_sec) /
			f2fs_params.secs_per_zone;
	if (total_zones <= 6) {
		printf("\n\tError: %d zones: Need more zones \
			by shrinking zone size\n", total_zones);
		return -1;
	}

	if (f2fs_params.heap) {
		f2fs_params.cur_seg[CURSEG_HOT_NODE] = (total_zones - 1) *
					f2fs_params.segs_per_sec *
					f2fs_params.secs_per_zone +
					((f2fs_params.secs_per_zone - 1) *
					f2fs_params.segs_per_sec);
		f2fs_params.cur_seg[CURSEG_WARM_NODE] =
					f2fs_params.cur_seg[CURSEG_HOT_NODE] -
					f2fs_params.segs_per_sec *
					f2fs_params.secs_per_zone;
		f2fs_params.cur_seg[CURSEG_COLD_NODE] =
					f2fs_params.cur_seg[CURSEG_WARM_NODE] -
					f2fs_params.segs_per_sec *
					f2fs_params.secs_per_zone;
		f2fs_params.cur_seg[CURSEG_HOT_DATA] =
					f2fs_params.cur_seg[CURSEG_COLD_NODE] -
					f2fs_params.segs_per_sec *
					f2fs_params.secs_per_zone;
		f2fs_params.cur_seg[CURSEG_COLD_DATA] = 0;
		f2fs_params.cur_seg[CURSEG_WARM_DATA] =
					f2fs_params.cur_seg[CURSEG_COLD_DATA] +
					f2fs_params.segs_per_sec *
					f2fs_params.secs_per_zone;
	} else {
		f2fs_params.cur_seg[CURSEG_HOT_NODE] = 0;
		f2fs_params.cur_seg[CURSEG_WARM_NODE] =
					f2fs_params.cur_seg[CURSEG_HOT_NODE] +
					f2fs_params.segs_per_sec *
					f2fs_params.secs_per_zone;
		f2fs_params.cur_seg[CURSEG_COLD_NODE] =
					f2fs_params.cur_seg[CURSEG_WARM_NODE] +
					f2fs_params.segs_per_sec *
					f2fs_params.secs_per_zone;
		f2fs_params.cur_seg[CURSEG_HOT_DATA] =
					f2fs_params.cur_seg[CURSEG_COLD_NODE] +
					f2fs_params.segs_per_sec *
					f2fs_params.secs_per_zone;
		f2fs_params.cur_seg[CURSEG_COLD_DATA] =
					f2fs_params.cur_seg[CURSEG_HOT_DATA] +
					f2fs_params.segs_per_sec *
					f2fs_params.secs_per_zone;
		f2fs_params.cur_seg[CURSEG_WARM_DATA] =
					f2fs_params.cur_seg[CURSEG_COLD_DATA] +
					f2fs_params.segs_per_sec *
					f2fs_params.secs_per_zone;
	}

	configure_extension_list();

	return 0;
}

/**
 * @brief     	It initialize SIT Data structure
 * @param	None
 * @return	0 if success
 */
static int8_t f2fs_init_sit_area(void)
{
	u_int32_t blk_size_bytes;
	u_int32_t seg_size_bytes;
	u_int32_t index = 0;
	u_int64_t sit_seg_blk_offset = 0;
	u_int8_t *zero_buf = NULL;

	blk_size_bytes = 1 << le32_to_cpu(super_block.log_blocksize);
	seg_size_bytes = (1 << le32_to_cpu(super_block.log_blocks_per_seg)) *
				blk_size_bytes;

	zero_buf = calloc(sizeof(u_int8_t), seg_size_bytes);
	if(zero_buf == NULL) {
		printf("\n\tError: Calloc Failed for sit_zero_buf!!!\n");
		return -1;
	}

	sit_seg_blk_offset = le32_to_cpu(super_block.sit_blkaddr) *
						blk_size_bytes;

	for (index = 0;
		index < (le32_to_cpu(super_block.segment_count_sit) / 2);
								index++) {
		if (writetodisk(f2fs_params.fd, zero_buf, sit_seg_blk_offset,
					seg_size_bytes) < 0) {
			printf("\n\tError: While zeroing out the sit area \
					on disk!!!\n");
			return -1;
		}
		sit_seg_blk_offset = sit_seg_blk_offset + seg_size_bytes;
	}

	free(zero_buf);
	return 0 ;
}

/**
 * @brief     	It initialize NAT Area
 * @param	None
 * @return	0 if success
 */
static int8_t f2fs_init_nat_area(void)
{
	u_int32_t blk_size_bytes;
	u_int32_t seg_size_bytes;
	u_int32_t index = 0;
	u_int64_t nat_seg_blk_offset = 0;
	u_int8_t *nat_buf = NULL;

	blk_size_bytes = 1 << le32_to_cpu(super_block.log_blocksize);
	seg_size_bytes = (1 << le32_to_cpu(super_block.log_blocks_per_seg)) *
					blk_size_bytes;

	nat_buf = calloc(sizeof(u_int8_t), seg_size_bytes);
	if (nat_buf == NULL) {
		printf("\n\tError: Calloc Failed for nat_zero_blk!!!\n");
		return -1;
	}

	nat_seg_blk_offset = le32_to_cpu(super_block.nat_blkaddr) *
							blk_size_bytes;

	for (index = 0;
		index < (le32_to_cpu(super_block.segment_count_nat) / 2);
								index++) {
		if (writetodisk(f2fs_params.fd, nat_buf, nat_seg_blk_offset,
					seg_size_bytes) < 0) {
			printf("\n\tError: While zeroing out the nat area \
					on disk!!!\n");
			return -1;
		}
		nat_seg_blk_offset = nat_seg_blk_offset + (2 * seg_size_bytes);
	}

	free(nat_buf);
	return 0 ;
}

#define CRCPOLY_LE 0xedb88320

unsigned int f2fs_cal_crc32(unsigned int crc, void *buff, unsigned int len)
{
	int i;
	unsigned char *p = (unsigned char *)buff;
	while (len--) {
		crc ^= *p++;
		for (i = 0; i < 8; i++)
			crc = (crc >> 1) ^ ((crc & 1) ? CRCPOLY_LE : 0);
	}
	return crc;
}

/**
 * @brief     	It writes check poiint pack on Check point Area
 * @param	None
 * @return	0 if succes
 */
static int8_t f2fs_write_check_point_pack(void)
{
	struct f2fs_checkpoint *ckp = NULL;
	struct f2fs_summary_block *sum = NULL;
	u_int32_t blk_size_bytes;
	u_int64_t cp_seg_blk_offset = 0;
	u_int32_t crc = 0;
	int i;

	ckp = calloc(F2FS_CP_BLOCK_SIZE, 1);
	if (ckp == NULL) {
		printf("\n\tError: Calloc Failed for f2fs_checkpoint!!!\n");
		return -1;
	}

	sum = calloc(sizeof(struct f2fs_summary_block), 1);
	if (sum == NULL) {
		printf("\n\tError: Calloc Failed for summay_node!!!\n");
		return -1;
	}

	/* 1. cp page 1 of checkpoint pack 1 */
	ckp->checkpoint_ver = 1;
	ckp->cur_node_segno[0] =
		cpu_to_le32(f2fs_params.cur_seg[CURSEG_HOT_NODE]);
	ckp->cur_node_segno[1] =
		cpu_to_le32(f2fs_params.cur_seg[CURSEG_WARM_NODE]);
	ckp->cur_node_segno[2] =
		cpu_to_le32(f2fs_params.cur_seg[CURSEG_COLD_NODE]);
	ckp->cur_data_segno[0] =
		cpu_to_le32(f2fs_params.cur_seg[CURSEG_HOT_DATA]);
	ckp->cur_data_segno[1] =
		cpu_to_le32(f2fs_params.cur_seg[CURSEG_WARM_DATA]);
	ckp->cur_data_segno[2] =
		cpu_to_le32(f2fs_params.cur_seg[CURSEG_COLD_DATA]);
	for (i = 3; i < MAX_ACTIVE_NODE_LOGS; i++) {
		ckp->cur_node_segno[i] = 0xffffffff;
		ckp->cur_data_segno[i] = 0xffffffff;
	}

	ckp->cur_node_blkoff[0] = cpu_to_le16(1);
	ckp->nat_upd_blkoff[0] = cpu_to_le16(1);
	ckp->cur_data_blkoff[0] = cpu_to_le16(1);
	ckp->valid_block_count = cpu_to_le64(2);
	ckp->rsvd_segment_count = cpu_to_le32(f2fs_params.reserved_segments);
	ckp->overprov_segment_count = cpu_to_le32(
			(le32_to_cpu(super_block.segment_count_main) -
			le32_to_cpu(ckp->rsvd_segment_count)) *
			f2fs_params.overprovision / 100);
	ckp->overprov_segment_count = cpu_to_le32(
			le32_to_cpu(ckp->overprov_segment_count) +
			le32_to_cpu(ckp->rsvd_segment_count));

	/* main segments - reserved segments - (node + data segments) */
	ckp->free_segment_count = cpu_to_le32(
			le32_to_cpu(super_block.segment_count_main) - 6);
	ckp->user_block_count = cpu_to_le64(
			((le32_to_cpu(ckp->free_segment_count) + 6 -
			le32_to_cpu(ckp->overprov_segment_count)) *
			 f2fs_params.blks_per_seg));
	ckp->cp_pack_total_block_count = cpu_to_le32(5);
	ckp->cp_pack_start_sum = cpu_to_le32(1);
	ckp->valid_node_count = cpu_to_le32(1);
	ckp->valid_inode_count = cpu_to_le32(1);
	ckp->next_free_nid = cpu_to_le32(
			le32_to_cpu(super_block.root_ino) + 1);

	ckp->sit_ver_bitmap_bytesize = cpu_to_le32(
			((le32_to_cpu(super_block.segment_count_sit) / 2) <<
			 le32_to_cpu(super_block.log_blocks_per_seg)) / 8);

	ckp->nat_ver_bitmap_bytesize = cpu_to_le32(
			((le32_to_cpu(super_block.segment_count_nat) / 2) <<
			 le32_to_cpu(super_block.log_blocks_per_seg)) / 8);

	ckp->checksum_offset = cpu_to_le32(4092);

	crc = f2fs_cal_crc32(F2FS_SUPER_MAGIC, ckp,
					le32_to_cpu(ckp->checksum_offset));
	*((u_int32_t *)((unsigned char *)ckp +
				le32_to_cpu(ckp->checksum_offset))) = crc;

	blk_size_bytes = 1 << le32_to_cpu(super_block.log_blocksize);
	cp_seg_blk_offset =
		le32_to_cpu(super_block.start_segment_checkpoint) * blk_size_bytes;

	if (writetodisk(f2fs_params.fd, ckp, cp_seg_blk_offset,
				F2FS_CP_BLOCK_SIZE) < 0) {
		printf("\n\tError: While writing the ckp to disk!!!\n");
		return -1;
	}

	/* 2. Prepare and write Segment summary for data blocks */
	SET_SUM_TYPE((&sum->footer), SUM_TYPE_DATA);

	sum->entries[0].nid = super_block.root_ino;
	sum->entries[0].ofs_in_node = 0;

	cp_seg_blk_offset += blk_size_bytes;
	if (writetodisk(f2fs_params.fd, sum, cp_seg_blk_offset,
				sizeof(struct f2fs_summary_block)) < 0) {
		printf("\n\tError: While writing the sum_blk to disk!!!\n");
		return -1;
	}

	/* 3. Fill segment summary for data block to zero. */
	memset(sum, 0, sizeof(struct f2fs_summary_block));

	cp_seg_blk_offset += blk_size_bytes;
	if (writetodisk(f2fs_params.fd, sum, cp_seg_blk_offset,
				sizeof(struct f2fs_summary_block)) < 0) {
		printf("\n\tError: While writing the sum_blk to disk!!!\n");
		return -1;
	}

	/* 4. Fill segment summary for data block to zero. */
	memset(sum, 0, sizeof(struct f2fs_summary_block));

	/* inode sit for root */
	sum->n_sits = cpu_to_le16(6);
	sum->sit_j.entries[0].segno = ckp->cur_node_segno[0];
	sum->sit_j.entries[0].se.vblocks = cpu_to_le16((CURSEG_HOT_NODE << 10) | 1);
	f2fs_set_bit(0, sum->sit_j.entries[0].se.valid_map);
	sum->sit_j.entries[1].segno = ckp->cur_node_segno[1];
	sum->sit_j.entries[1].se.vblocks = cpu_to_le16((CURSEG_WARM_NODE << 10));
	sum->sit_j.entries[2].segno = ckp->cur_node_segno[2];
	sum->sit_j.entries[2].se.vblocks = cpu_to_le16((CURSEG_COLD_NODE << 10));

	/* data sit for root */
	sum->sit_j.entries[3].segno = ckp->cur_data_segno[0];
	sum->sit_j.entries[3].se.vblocks = cpu_to_le16((CURSEG_HOT_DATA << 10) | 1);
	f2fs_set_bit(0, sum->sit_j.entries[3].se.valid_map);
	sum->sit_j.entries[4].segno = ckp->cur_data_segno[1];
	sum->sit_j.entries[4].se.vblocks = cpu_to_le16((CURSEG_WARM_DATA << 10));
	sum->sit_j.entries[5].segno = ckp->cur_data_segno[2];
	sum->sit_j.entries[5].se.vblocks = cpu_to_le16((CURSEG_COLD_DATA << 10));

	cp_seg_blk_offset += blk_size_bytes;
	if (writetodisk(f2fs_params.fd, sum, cp_seg_blk_offset,
				sizeof(struct f2fs_summary_block)) < 0) {
		printf("\n\tError: While writing the sum_blk to disk!!!\n");
		return -1;
	}

	/* 5. cp page2 */
	cp_seg_blk_offset += blk_size_bytes;
	if (writetodisk(f2fs_params.fd, ckp, cp_seg_blk_offset,
				F2FS_CP_BLOCK_SIZE) < 0) {
		printf("\n\tError: While writing the ckp to disk!!!\n");
		return -1;
	}

	/* 6. cp page 1 of check point pack 2
	 * Initiatialize other checkpoint pack with version zero
	 */
	ckp->checkpoint_ver = 0;

	crc = f2fs_cal_crc32(F2FS_SUPER_MAGIC, ckp,
					le32_to_cpu(ckp->checksum_offset));
	*((u_int32_t *)((unsigned char *)ckp +
				le32_to_cpu(ckp->checksum_offset))) = crc;

	cp_seg_blk_offset = (le32_to_cpu(super_block.start_segment_checkpoint) +
				f2fs_params.blks_per_seg) *
				blk_size_bytes;
	if (writetodisk(f2fs_params.fd, ckp,
				cp_seg_blk_offset, F2FS_CP_BLOCK_SIZE) < 0) {
		printf("\n\tError: While writing the ckp to disk!!!\n");
		return -1;
	}

	/* 7. */
	memset(sum, 0, sizeof(struct f2fs_summary_block));
	SET_SUM_TYPE((&sum->footer), SUM_TYPE_DATA);
	cp_seg_blk_offset += blk_size_bytes;
	if (writetodisk(f2fs_params.fd, sum, cp_seg_blk_offset,
				sizeof(struct f2fs_summary_block)) < 0) {
		printf("\n\tError: While writing the sum_blk to disk!!!\n");
		return -1;
	}

	/* 8. */
	memset(sum, 0, sizeof(struct f2fs_summary_block));
	cp_seg_blk_offset += blk_size_bytes;
	if (writetodisk(f2fs_params.fd, sum, cp_seg_blk_offset,
				sizeof(struct f2fs_summary_block)) < 0) {
		printf("\n\tError: While writing the sum_blk to disk!!!\n");
		return -1;
	}

	/* 9. */
	memset(sum, 0, sizeof(struct f2fs_summary_block));
	cp_seg_blk_offset += blk_size_bytes;
	if (writetodisk(f2fs_params.fd, sum, cp_seg_blk_offset,
				sizeof(struct f2fs_summary_block)) < 0) {
		printf("\n\tError: While writing the sum_blk to disk!!!\n");
		return -1;
	}

	/* 10. cp page 2 of check point pack 2 */
	cp_seg_blk_offset += blk_size_bytes;
	if (writetodisk(f2fs_params.fd, ckp, cp_seg_blk_offset,
				F2FS_CP_BLOCK_SIZE) < 0) {
		printf("\n\tError: While writing the ckp to disk!!!\n");
		return -1;
	}

	free(sum) ;
	free(ckp) ;
	return	0;
}

/**
 * @brief     	It writes super block on device
 * @param	None
 * @return	0 if success
 */
static int8_t f2fs_write_super_block(void)
{
	u_int32_t index = 0;
	u_int64_t super_blk_offset;
	u_int8_t *zero_buff;

	zero_buff = calloc(f2fs_params.sector_size, 1);
	super_blk_offset = F2FS_SUPER_OFFSET * F2FS_BLKSIZE;

	for (index = 0; index < 2; index++) {
		if (writetodisk(f2fs_params.fd, &super_block, super_blk_offset,
					sizeof(struct f2fs_super_block)) < 0) {
			printf("\n\tError: While while writing supe_blk \
					on disk!!! index : %d\n", index);
			return -1;
		}
		super_blk_offset += F2FS_BLKSIZE;
	}

	free(zero_buff);
	return 0;
}

/**
 * @brief     	It initializes and writes root inode on device.
 * @param	None
 * @return	0 if success
 */
static int8_t f2fs_write_root_inode(void)
{
	struct f2fs_node *raw_node = NULL;
	u_int32_t blk_size_bytes;
	u_int64_t data_blk_nor;
	u_int64_t main_area_node_seg_blk_offset = 0;

	raw_node = calloc(sizeof(struct f2fs_node), 1);
	if (raw_node == NULL) {
		printf("\n\tError: Calloc Failed for raw_node!!!\n");
		return -1;
	}

	raw_node->footer.nid = super_block.root_ino;
	raw_node->footer.ino = super_block.root_ino;
	raw_node->footer.cp_ver = cpu_to_le64(1);
	raw_node->footer.next_blkaddr = cpu_to_le32(
			le32_to_cpu(super_block.main_blkaddr) +
			f2fs_params.cur_seg[CURSEG_HOT_NODE] *
			f2fs_params.blks_per_seg + 1);

	raw_node->i.i_mode = cpu_to_le16(0x41ed);
	raw_node->i.i_links = cpu_to_le32(2);
	raw_node->i.i_uid = cpu_to_le32(getuid());
	raw_node->i.i_gid = cpu_to_le32(getgid());

	blk_size_bytes = 1 << le32_to_cpu(super_block.log_blocksize);
	raw_node->i.i_size = cpu_to_le64(1 * blk_size_bytes); /* dentry */
	raw_node->i.i_blocks = cpu_to_le64(2);

	raw_node->i.i_atime = cpu_to_le32(time(NULL));
	raw_node->i.i_atime_nsec = 0;
	raw_node->i.i_ctime = cpu_to_le32(time(NULL));
	raw_node->i.i_ctime_nsec = 0;
	raw_node->i.i_mtime = cpu_to_le32(time(NULL));
	raw_node->i.i_mtime_nsec = 0;
	raw_node->i.i_generation = 0;
	raw_node->i.i_xattr_nid = 0;
	raw_node->i.i_flags = 0;
	raw_node->i.i_current_depth = cpu_to_le32(1);

	data_blk_nor = le32_to_cpu(super_block.main_blkaddr) +
		f2fs_params.cur_seg[CURSEG_HOT_DATA] * f2fs_params.blks_per_seg;
	raw_node->i.i_addr[0] = cpu_to_le32(data_blk_nor);

	raw_node->i.i_ext.fofs = 0;
	raw_node->i.i_ext.blk_addr = cpu_to_le32(data_blk_nor);
	raw_node->i.i_ext.len = cpu_to_le32(1);

	main_area_node_seg_blk_offset = le32_to_cpu(super_block.main_blkaddr);
	main_area_node_seg_blk_offset += f2fs_params.cur_seg[CURSEG_HOT_NODE] *
					f2fs_params.blks_per_seg;
        main_area_node_seg_blk_offset *= blk_size_bytes;

	if (writetodisk(f2fs_params.fd, raw_node, main_area_node_seg_blk_offset,
				sizeof(struct f2fs_node)) < 0) {
		printf("\n\tError: While writing the raw_node to disk!!!\n");
		return -1;
	}

	memset(raw_node, 0xff, sizeof(struct f2fs_node));

	if (writetodisk(f2fs_params.fd, raw_node,
				main_area_node_seg_blk_offset + 4096,
				sizeof(struct f2fs_node)) < 0) {
		printf("\n\tError: While writing the raw_node to disk!!!\n");
		return -1;
	}
	free(raw_node);
	return 0;
}

/**
 * @brief     	It updates NAT for root Inode
 * @param	None
 * @return	0 if success
 */
static int8_t f2fs_update_nat_root(void)
{
	struct f2fs_nat_block *nat_blk = NULL;
	u_int32_t blk_size_bytes;
	u_int64_t nat_seg_blk_offset = 0;

	nat_blk = calloc(sizeof(struct f2fs_nat_block), 1);
	if(nat_blk == NULL) {
		printf("\n\tError: Calloc Failed for nat_blk!!!\n");
		return -1;
	}

	/* update root */
	nat_blk->entries[super_block.root_ino].block_addr = cpu_to_le32(
		le32_to_cpu(super_block.main_blkaddr) +
		f2fs_params.cur_seg[CURSEG_HOT_NODE] * f2fs_params.blks_per_seg);
	nat_blk->entries[super_block.root_ino].ino = super_block.root_ino;

	/* update node nat */
	nat_blk->entries[super_block.node_ino].block_addr = cpu_to_le32(1);
	nat_blk->entries[super_block.node_ino].ino = super_block.node_ino;

	/* update meta nat */
	nat_blk->entries[super_block.meta_ino].block_addr = cpu_to_le32(1);
	nat_blk->entries[super_block.meta_ino].ino = super_block.meta_ino;

	blk_size_bytes = 1 << le32_to_cpu(super_block.log_blocksize);

	nat_seg_blk_offset = le32_to_cpu(super_block.nat_blkaddr) *
							blk_size_bytes;

	if (writetodisk(f2fs_params.fd, nat_blk, nat_seg_blk_offset,
				sizeof(struct f2fs_nat_block)) < 0) {
		printf("\n\tError: While writing the nat_blk set0 to disk!!!\n");
		return -1;
	}

	free(nat_blk);
	return 0;
}

/**
 * @brief     	It updates default dentries in Root Inode
 * @param	None
 * @return	0 if success
 */
static int8_t f2fs_add_default_dentry_root(void)
{
	struct f2fs_dentry_block *dent_blk = NULL;
	u_int32_t blk_size_bytes;
	u_int64_t data_blk_offset = 0;

	dent_blk = calloc(sizeof(struct f2fs_dentry_block), 1);
	if(dent_blk == NULL) {
		printf("\n\tError: Calloc Failed for dent_blk!!!\n");
		return -1;
	}

	dent_blk->dentry[0].hash_code = 0;
	dent_blk->dentry[0].ino = super_block.root_ino;
	dent_blk->dentry[0].name_len = cpu_to_le16(1);
	dent_blk->dentry[0].file_type = F2FS_FT_DIR;
	memcpy(dent_blk->filename[0], ".", 1);

	dent_blk->dentry[1].hash_code = 0;
	dent_blk->dentry[1].ino = super_block.root_ino;
	dent_blk->dentry[1].name_len = cpu_to_le16(2);
	dent_blk->dentry[1].file_type = F2FS_FT_DIR;
	memcpy(dent_blk->filename[1], "..", 2);

	/* bitmap for . and .. */
	dent_blk->dentry_bitmap[0] = (1 << 1) | (1 << 0);
	blk_size_bytes = 1 << le32_to_cpu(super_block.log_blocksize);
	data_blk_offset = (le32_to_cpu(super_block.main_blkaddr) +
			f2fs_params.cur_seg[CURSEG_HOT_DATA] *
			f2fs_params.blks_per_seg) * blk_size_bytes;

	if (writetodisk(f2fs_params.fd, dent_blk, data_blk_offset,
				sizeof(struct f2fs_dentry_block)) < 0) {
		printf("\n\tError: While writing the dentry_blk to disk!!!\n");
		return -1;
	}

	free(dent_blk);
	return 0;
}

/**
 * @brief     	It creates root directory on device.
 * @param	None
 * @return	0 if success
 */
static int8_t f2fs_create_root_dir(void)
{
	int8_t err = 0;

	err = f2fs_write_root_inode();
	if (err < 0) {
		printf("\n\tError: Failed to write root inode!!!\n");
		goto exit;
	}

	err = f2fs_update_nat_root();
	if (err < 0) {
		printf("\n\tError: Failed to update NAT for root!!!\n");
		goto exit;
	}

	err = f2fs_add_default_dentry_root();
	if (err < 0) {
		printf("\n\tError: Failed to add default dentries for root!!!\n");
		goto exit;
	}
exit:
	if (err)
		printf("\n\tError: Could not create the root directory!!!\n");

	return err;
}

int f2fs_trim_device()
{
	unsigned long long range[2];
	struct stat stat_buf;

	range[0] = 0;
	range[1] = f2fs_params.total_sectors * DEFAULT_SECTOR_SIZE;

	if (fstat(f2fs_params.fd, &stat_buf) < 0 ) {
		printf("\n\tError: Failed to get the device stat!!!\n");
		return -1;
	}

	if (S_ISREG(stat_buf.st_mode))
		return 0;
	else if (S_ISBLK(stat_buf.st_mode)) {
		if (ioctl(f2fs_params.fd, BLKDISCARD, &range) < 0)
			printf("Info: This device doesn't support TRIM\n");
	} else
		return -1;
	return 0;
}

/**
 * @brief     	It s a routine to fromat device with F2FS on-disk layout
 * @param	None
 * @return	0 if success
 */
static int8_t f2fs_format_device(void)
{
	int8_t err = 0;

	err= f2fs_prepare_super_block();
	if (err < 0)
		goto exit;

	err = f2fs_trim_device();
	if (err < 0) {
		printf("\n\tError: Failed to trim whole device!!!\n");
		goto exit;
	}

	err = f2fs_init_sit_area();
	if (err < 0) {
		printf("\n\tError: Failed to Initialise the SIT AREA!!!\n");
		goto exit;
	}

	err = f2fs_init_nat_area();
	if (err < 0) {
		printf("\n\tError: Failed to Initialise the NAT AREA!!!\n");
		goto exit;
	}

	err = f2fs_create_root_dir();
	if (err < 0) {
		printf("\n\tError: Failed to create the root directory!!!\n");
		goto exit;
	}

	err = f2fs_write_check_point_pack();
	if (err < 0) {
		printf("\n\tError: Failed to write the check point pack!!!\n");
		goto exit;
	}

	err = f2fs_write_super_block();
	if (err < 0) {
		printf("\n\tError: Failed to write the Super Block!!!\n");
		goto exit;
	}
exit:
	if (err)
		printf("\n\tError: Could not format the device!!!\n");

	/*
	 * We should call fsync() to flush out all the dirty pages
	 * in the block device page cache.
	 */
	if (fsync(f2fs_params.fd) < 0)
		printf("\n\tError: Could not conduct fsync!!!\n");

	if (close(f2fs_params.fd) < 0)
		printf("\n\tError: Failed to close device file!!!\n");

	return err;
}

/**
 * @brief     	main function of F2Fs utility
 * @param	argc count of argument
 * @param	argv array of arguments
 * @return	0 if success
 */
int main(int argc, char *argv[])
{
	f2fs_init_global_parameters();

	f2fs_parse_options(argc, argv);

	if (f2fs_is_device_mounted() < 0)
		return -1;

	if (f2fs_get_device_info() < 0)
		return -1;

	if (f2fs_format_device() < 0)
		return -1;

	printf("Info: format successful\n");

	return 0;
}
