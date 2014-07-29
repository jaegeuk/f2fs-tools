/**
 * f2fs_format.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * Dual licensed under the GPL or LGPL version 2 licenses.
 */
#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <time.h>
#include <uuid/uuid.h>

#include "f2fs_fs.h"
#include "f2fs_format_utils.h"

extern struct f2fs_configuration config;
struct f2fs_super_block super_block;

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
	"jpeg",
	"video",
	"apk",	/* for android system */
	NULL
};

static void configure_extension_list(void)
{
	const char **extlist = media_ext_lists;
	char *ext_str = config.extension_list;
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
	super_block.extension_count = i;

	if (!ext_str)
		return;

	/* add user ext list */
	ue = strtok(ext_str, ",");
	while (ue != NULL) {
		name_len = strlen(ue);
		memcpy(super_block.extension_list[i++], ue, name_len);
		ue = strtok(NULL, ",");
		if (i >= F2FS_MAX_EXTENSION)
			break;
	}

	super_block.extension_count = i;

	free(config.extension_list);
}

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
	u_int32_t sit_bitmap_size, max_sit_bitmap_size;
	u_int32_t max_nat_bitmap_size, max_nat_segments;
	u_int32_t total_zones;

	super_block.magic = cpu_to_le32(F2FS_SUPER_MAGIC);
	super_block.major_ver = cpu_to_le16(F2FS_MAJOR_VERSION);
	super_block.minor_ver = cpu_to_le16(F2FS_MINOR_VERSION);

	log_sectorsize = log_base_2(config.sector_size);
	log_sectors_per_block = log_base_2(config.sectors_per_blk);
	log_blocksize = log_sectorsize + log_sectors_per_block;
	log_blks_per_seg = log_base_2(config.blks_per_seg);

	super_block.log_sectorsize = cpu_to_le32(log_sectorsize);
	super_block.log_sectors_per_block = cpu_to_le32(log_sectors_per_block);

	super_block.log_blocksize = cpu_to_le32(log_blocksize);
	super_block.log_blocks_per_seg = cpu_to_le32(log_blks_per_seg);

	super_block.segs_per_sec = cpu_to_le32(config.segs_per_sec);
	super_block.secs_per_zone = cpu_to_le32(config.secs_per_zone);
	blk_size_bytes = 1 << log_blocksize;
	segment_size_bytes = blk_size_bytes * config.blks_per_seg;
	zone_size_bytes =
		blk_size_bytes * config.secs_per_zone *
		config.segs_per_sec * config.blks_per_seg;

	super_block.checksum_offset = 0;

	super_block.block_count = cpu_to_le64(
		(config.total_sectors * DEFAULT_SECTOR_SIZE) /
			blk_size_bytes);

	zone_align_start_offset =
		(config.start_sector * DEFAULT_SECTOR_SIZE +
		2 * F2FS_BLKSIZE + zone_size_bytes - 1) /
		zone_size_bytes * zone_size_bytes -
		config.start_sector * DEFAULT_SECTOR_SIZE;

	if (config.start_sector % DEFAULT_SECTORS_PER_BLOCK) {
		MSG(1, "\tWARN: Align start sector number to the page unit\n");
		MSG(1, "\ti.e., start sector: %d, ofs:%d (sects/page: %d)\n",
				config.start_sector,
				config.start_sector % DEFAULT_SECTORS_PER_BLOCK,
				DEFAULT_SECTORS_PER_BLOCK);
	}

	super_block.segment_count = cpu_to_le32(
		((config.total_sectors * DEFAULT_SECTOR_SIZE) -
		zone_align_start_offset) / segment_size_bytes);

	super_block.segment0_blkaddr =
		cpu_to_le32(zone_align_start_offset / blk_size_bytes);
	super_block.cp_blkaddr = super_block.segment0_blkaddr;

	MSG(0, "Info: zone aligned segment0 blkaddr: %u\n",
				le32_to_cpu(super_block.segment0_blkaddr));

	super_block.segment_count_ckpt =
				cpu_to_le32(F2FS_NUMBER_OF_CHECKPOINT_PACK);

	super_block.sit_blkaddr = cpu_to_le32(
		le32_to_cpu(super_block.segment0_blkaddr) +
		(le32_to_cpu(super_block.segment_count_ckpt) *
		(1 << log_blks_per_seg)));

	blocks_for_sit = (le32_to_cpu(super_block.segment_count) +
			SIT_ENTRY_PER_BLOCK - 1) / SIT_ENTRY_PER_BLOCK;

	sit_segments = (blocks_for_sit + config.blks_per_seg - 1)
			/ config.blks_per_seg;

	super_block.segment_count_sit = cpu_to_le32(sit_segments * 2);

	super_block.nat_blkaddr = cpu_to_le32(
			le32_to_cpu(super_block.sit_blkaddr) +
			(le32_to_cpu(super_block.segment_count_sit) *
			 config.blks_per_seg));

	total_valid_blks_available = (le32_to_cpu(super_block.segment_count) -
			(le32_to_cpu(super_block.segment_count_ckpt) +
			 le32_to_cpu(super_block.segment_count_sit))) *
			config.blks_per_seg;

	blocks_for_nat = (total_valid_blks_available + NAT_ENTRY_PER_BLOCK - 1)
				/ NAT_ENTRY_PER_BLOCK;

	super_block.segment_count_nat = cpu_to_le32(
				(blocks_for_nat + config.blks_per_seg - 1) /
				config.blks_per_seg);
	/*
	 * The number of node segments should not be exceeded a "Threshold".
	 * This number resizes NAT bitmap area in a CP page.
	 * So the threshold is determined not to overflow one CP page
	 */
	sit_bitmap_size = ((le32_to_cpu(super_block.segment_count_sit) / 2) <<
				log_blks_per_seg) / 8;

	if (sit_bitmap_size > MAX_SIT_BITMAP_SIZE)
		max_sit_bitmap_size = MAX_SIT_BITMAP_SIZE;
	else
		max_sit_bitmap_size = sit_bitmap_size;

	/*
	 * It should be reserved minimum 1 segment for nat.
	 * When sit is too large, we should expand cp area. It requires more pages for cp.
	 */
	if (max_sit_bitmap_size >
			(CHECKSUM_OFFSET - sizeof(struct f2fs_checkpoint) + 65)) {
		max_nat_bitmap_size = CHECKSUM_OFFSET - sizeof(struct f2fs_checkpoint) + 1;
		super_block.cp_payload = F2FS_BLK_ALIGN(max_sit_bitmap_size);
	} else {
		max_nat_bitmap_size = CHECKSUM_OFFSET - sizeof(struct f2fs_checkpoint) + 1
			- max_sit_bitmap_size;
		super_block.cp_payload = 0;
	}

	max_nat_segments = (max_nat_bitmap_size * 8) >> log_blks_per_seg;

	if (le32_to_cpu(super_block.segment_count_nat) > max_nat_segments)
		super_block.segment_count_nat = cpu_to_le32(max_nat_segments);

	super_block.segment_count_nat = cpu_to_le32(
			le32_to_cpu(super_block.segment_count_nat) * 2);

	super_block.ssa_blkaddr = cpu_to_le32(
			le32_to_cpu(super_block.nat_blkaddr) +
			le32_to_cpu(super_block.segment_count_nat) *
			config.blks_per_seg);

	total_valid_blks_available = (le32_to_cpu(super_block.segment_count) -
			(le32_to_cpu(super_block.segment_count_ckpt) +
			le32_to_cpu(super_block.segment_count_sit) +
			le32_to_cpu(super_block.segment_count_nat))) *
			config.blks_per_seg;

	blocks_for_ssa = total_valid_blks_available /
				config.blks_per_seg + 1;

	super_block.segment_count_ssa = cpu_to_le32(
			(blocks_for_ssa + config.blks_per_seg - 1) /
			config.blks_per_seg);

	total_meta_segments = le32_to_cpu(super_block.segment_count_ckpt) +
		le32_to_cpu(super_block.segment_count_sit) +
		le32_to_cpu(super_block.segment_count_nat) +
		le32_to_cpu(super_block.segment_count_ssa);
	diff = total_meta_segments % (config.segs_per_sec *
						config.secs_per_zone);
	if (diff)
		super_block.segment_count_ssa = cpu_to_le32(
			le32_to_cpu(super_block.segment_count_ssa) +
			(config.segs_per_sec * config.secs_per_zone -
			 diff));

	super_block.main_blkaddr = cpu_to_le32(
			le32_to_cpu(super_block.ssa_blkaddr) +
			(le32_to_cpu(super_block.segment_count_ssa) *
			 config.blks_per_seg));

	super_block.segment_count_main = cpu_to_le32(
			le32_to_cpu(super_block.segment_count) -
			(le32_to_cpu(super_block.segment_count_ckpt)
			 + le32_to_cpu(super_block.segment_count_sit) +
			 le32_to_cpu(super_block.segment_count_nat) +
			 le32_to_cpu(super_block.segment_count_ssa)));

	super_block.section_count = cpu_to_le32(
			le32_to_cpu(super_block.segment_count_main)
			/ config.segs_per_sec);

	super_block.segment_count_main = cpu_to_le32(
			le32_to_cpu(super_block.section_count) *
			config.segs_per_sec);

	if ((le32_to_cpu(super_block.segment_count_main) - 2) <
					config.reserved_segments) {
		MSG(1, "\tError: Device size is not sufficient for F2FS volume,\
			more segment needed =%u",
			config.reserved_segments -
			(le32_to_cpu(super_block.segment_count_main) - 2));
		return -1;
	}

	uuid_generate(super_block.uuid);

	ASCIIToUNICODE(super_block.volume_name, (u_int8_t *)config.vol_label);

	super_block.node_ino = cpu_to_le32(1);
	super_block.meta_ino = cpu_to_le32(2);
	super_block.root_ino = cpu_to_le32(3);

	total_zones = le32_to_cpu(super_block.segment_count_main) /
			(config.segs_per_sec * config.secs_per_zone);
	if (total_zones <= 6) {
		MSG(1, "\tError: %d zones: Need more zones \
			by shrinking zone size\n", total_zones);
		return -1;
	}

	if (config.heap) {
		config.cur_seg[CURSEG_HOT_NODE] = (total_zones - 1) *
					config.segs_per_sec *
					config.secs_per_zone +
					((config.secs_per_zone - 1) *
					config.segs_per_sec);
		config.cur_seg[CURSEG_WARM_NODE] =
					config.cur_seg[CURSEG_HOT_NODE] -
					config.segs_per_sec *
					config.secs_per_zone;
		config.cur_seg[CURSEG_COLD_NODE] =
					config.cur_seg[CURSEG_WARM_NODE] -
					config.segs_per_sec *
					config.secs_per_zone;
		config.cur_seg[CURSEG_HOT_DATA] =
					config.cur_seg[CURSEG_COLD_NODE] -
					config.segs_per_sec *
					config.secs_per_zone;
		config.cur_seg[CURSEG_COLD_DATA] = 0;
		config.cur_seg[CURSEG_WARM_DATA] =
					config.cur_seg[CURSEG_COLD_DATA] +
					config.segs_per_sec *
					config.secs_per_zone;
	} else {
		config.cur_seg[CURSEG_HOT_NODE] = 0;
		config.cur_seg[CURSEG_WARM_NODE] =
					config.cur_seg[CURSEG_HOT_NODE] +
					config.segs_per_sec *
					config.secs_per_zone;
		config.cur_seg[CURSEG_COLD_NODE] =
					config.cur_seg[CURSEG_WARM_NODE] +
					config.segs_per_sec *
					config.secs_per_zone;
		config.cur_seg[CURSEG_HOT_DATA] =
					config.cur_seg[CURSEG_COLD_NODE] +
					config.segs_per_sec *
					config.secs_per_zone;
		config.cur_seg[CURSEG_COLD_DATA] =
					config.cur_seg[CURSEG_HOT_DATA] +
					config.segs_per_sec *
					config.secs_per_zone;
		config.cur_seg[CURSEG_WARM_DATA] =
					config.cur_seg[CURSEG_COLD_DATA] +
					config.segs_per_sec *
					config.secs_per_zone;
	}

	configure_extension_list();

	return 0;
}

static int f2fs_init_sit_area(void)
{
	u_int32_t blk_size, seg_size;
	u_int32_t index = 0;
	u_int64_t sit_seg_addr = 0;
	u_int8_t *zero_buf = NULL;

	blk_size = 1 << le32_to_cpu(super_block.log_blocksize);
	seg_size = (1 << le32_to_cpu(super_block.log_blocks_per_seg)) *
							blk_size;

	zero_buf = calloc(sizeof(u_int8_t), seg_size);
	if(zero_buf == NULL) {
		MSG(1, "\tError: Calloc Failed for sit_zero_buf!!!\n");
		return -1;
	}

	sit_seg_addr = le32_to_cpu(super_block.sit_blkaddr);
	sit_seg_addr *= blk_size;

	DBG(1, "\tFilling sit area at offset 0x%08"PRIx64"\n", sit_seg_addr);
	for (index = 0;
		index < (le32_to_cpu(super_block.segment_count_sit) / 2);
								index++) {
		if (dev_fill(zero_buf, sit_seg_addr, seg_size)) {
			MSG(1, "\tError: While zeroing out the sit area \
					on disk!!!\n");
			return -1;
		}
		sit_seg_addr += seg_size;
	}

	free(zero_buf);
	return 0 ;
}

static int f2fs_init_nat_area(void)
{
	u_int32_t blk_size, seg_size;
	u_int32_t index = 0;
	u_int64_t nat_seg_addr = 0;
	u_int8_t *nat_buf = NULL;

	blk_size = 1 << le32_to_cpu(super_block.log_blocksize);
	seg_size = (1 << le32_to_cpu(super_block.log_blocks_per_seg)) *
							blk_size;

	nat_buf = calloc(sizeof(u_int8_t), seg_size);
	if (nat_buf == NULL) {
		MSG(1, "\tError: Calloc Failed for nat_zero_blk!!!\n");
		return -1;
	}

	nat_seg_addr = le32_to_cpu(super_block.nat_blkaddr);
	nat_seg_addr *= blk_size;

	DBG(1, "\tFilling nat area at offset 0x%08"PRIx64"\n", nat_seg_addr);
	for (index = 0;
		index < (le32_to_cpu(super_block.segment_count_nat) / 2);
								index++) {
		if (dev_fill(nat_buf, nat_seg_addr, seg_size)) {
			MSG(1, "\tError: While zeroing out the nat area \
					on disk!!!\n");
			return -1;
		}
		nat_seg_addr = nat_seg_addr + (2 * seg_size);
	}

	free(nat_buf);
	return 0 ;
}

static int f2fs_write_check_point_pack(void)
{
	struct f2fs_checkpoint *ckp = NULL;
	struct f2fs_summary_block *sum = NULL;
	u_int32_t blk_size_bytes;
	u_int64_t cp_seg_blk_offset = 0;
	u_int32_t crc = 0;
	unsigned int i;
	char *cp_payload = NULL;

	ckp = calloc(F2FS_BLKSIZE, 1);
	if (ckp == NULL) {
		MSG(1, "\tError: Calloc Failed for f2fs_checkpoint!!!\n");
		return -1;
	}

	sum = calloc(F2FS_BLKSIZE, 1);
	if (sum == NULL) {
		MSG(1, "\tError: Calloc Failed for summay_node!!!\n");
		return -1;
	}

	cp_payload = calloc(F2FS_BLKSIZE, 1);
	if (cp_payload == NULL) {
		MSG(1, "\tError: Calloc Failed for cp_payload!!!\n");
		return -1;
	}

	/* 1. cp page 1 of checkpoint pack 1 */
	ckp->checkpoint_ver = cpu_to_le64(1);
	ckp->cur_node_segno[0] =
		cpu_to_le32(config.cur_seg[CURSEG_HOT_NODE]);
	ckp->cur_node_segno[1] =
		cpu_to_le32(config.cur_seg[CURSEG_WARM_NODE]);
	ckp->cur_node_segno[2] =
		cpu_to_le32(config.cur_seg[CURSEG_COLD_NODE]);
	ckp->cur_data_segno[0] =
		cpu_to_le32(config.cur_seg[CURSEG_HOT_DATA]);
	ckp->cur_data_segno[1] =
		cpu_to_le32(config.cur_seg[CURSEG_WARM_DATA]);
	ckp->cur_data_segno[2] =
		cpu_to_le32(config.cur_seg[CURSEG_COLD_DATA]);
	for (i = 3; i < MAX_ACTIVE_NODE_LOGS; i++) {
		ckp->cur_node_segno[i] = 0xffffffff;
		ckp->cur_data_segno[i] = 0xffffffff;
	}

	ckp->cur_node_blkoff[0] = cpu_to_le16(1);
	ckp->cur_data_blkoff[0] = cpu_to_le16(1);
	ckp->valid_block_count = cpu_to_le64(2);
	ckp->rsvd_segment_count = cpu_to_le32(config.reserved_segments);
	ckp->overprov_segment_count = cpu_to_le32(
			(le32_to_cpu(super_block.segment_count_main) -
			le32_to_cpu(ckp->rsvd_segment_count)) *
			config.overprovision / 100);
	ckp->overprov_segment_count = cpu_to_le32(
			le32_to_cpu(ckp->overprov_segment_count) +
			le32_to_cpu(ckp->rsvd_segment_count));

	/* main segments - reserved segments - (node + data segments) */
	ckp->free_segment_count = cpu_to_le32(
			le32_to_cpu(super_block.segment_count_main) - 6);
	ckp->user_block_count = cpu_to_le64(
			((le32_to_cpu(ckp->free_segment_count) + 6 -
			le32_to_cpu(ckp->overprov_segment_count)) *
			 config.blks_per_seg));
	ckp->cp_pack_total_block_count =
		cpu_to_le32(8 + le32_to_cpu(super_block.cp_payload));
	ckp->ckpt_flags = cpu_to_le32(CP_UMOUNT_FLAG);
	ckp->cp_pack_start_sum = cpu_to_le32(1 + le32_to_cpu(super_block.cp_payload));
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

	ckp->checksum_offset = cpu_to_le32(CHECKSUM_OFFSET);

	crc = f2fs_cal_crc32(F2FS_SUPER_MAGIC, ckp, CHECKSUM_OFFSET);
	*((__le32 *)((unsigned char *)ckp + CHECKSUM_OFFSET)) =
							cpu_to_le32(crc);

	blk_size_bytes = 1 << le32_to_cpu(super_block.log_blocksize);
	cp_seg_blk_offset = le32_to_cpu(super_block.segment0_blkaddr);
	cp_seg_blk_offset *= blk_size_bytes;

	DBG(1, "\tWriting main segments, ckp at offset 0x%08"PRIx64"\n", cp_seg_blk_offset);
	if (dev_write(ckp, cp_seg_blk_offset, blk_size_bytes)) {
		MSG(1, "\tError: While writing the ckp to disk!!!\n");
		return -1;
	}

	for (i = 0; i < le32_to_cpu(super_block.cp_payload); i++) {
		cp_seg_blk_offset += blk_size_bytes;
		if (dev_fill(cp_payload, cp_seg_blk_offset, blk_size_bytes)) {
			MSG(1, "\tError: While zeroing out the sit bitmap area \
					on disk!!!\n");
			return -1;
		}
	}

	/* 2. Prepare and write Segment summary for data blocks */
	memset(sum, 0, sizeof(struct f2fs_summary_block));
	SET_SUM_TYPE((&sum->footer), SUM_TYPE_DATA);

	sum->entries[0].nid = super_block.root_ino;
	sum->entries[0].ofs_in_node = 0;

	cp_seg_blk_offset += blk_size_bytes;
	DBG(1, "\tWriting segment summary for data, ckp at offset 0x%08"PRIx64"\n", cp_seg_blk_offset);
	if (dev_write(sum, cp_seg_blk_offset, blk_size_bytes)) {
		MSG(1, "\tError: While writing the sum_blk to disk!!!\n");
		return -1;
	}

	/* 3. Fill segment summary for data block to zero. */
	memset(sum, 0, sizeof(struct f2fs_summary_block));
	SET_SUM_TYPE((&sum->footer), SUM_TYPE_DATA);

	cp_seg_blk_offset += blk_size_bytes;
	DBG(1, "\tWriting segment summary, ckp at offset 0x%08"PRIx64"\n", cp_seg_blk_offset);
	if (dev_write(sum, cp_seg_blk_offset, blk_size_bytes)) {
		MSG(1, "\tError: While writing the sum_blk to disk!!!\n");
		return -1;
	}

	/* 4. Fill segment summary for data block to zero. */
	memset(sum, 0, sizeof(struct f2fs_summary_block));
	SET_SUM_TYPE((&sum->footer), SUM_TYPE_DATA);

	/* inode sit for root */
	sum->n_sits = cpu_to_le16(6);
	sum->sit_j.entries[0].segno = ckp->cur_node_segno[0];
	sum->sit_j.entries[0].se.vblocks = cpu_to_le16((CURSEG_HOT_NODE << 10) | 1);
	f2fs_set_bit(0, (char *)sum->sit_j.entries[0].se.valid_map);
	sum->sit_j.entries[1].segno = ckp->cur_node_segno[1];
	sum->sit_j.entries[1].se.vblocks = cpu_to_le16((CURSEG_WARM_NODE << 10));
	sum->sit_j.entries[2].segno = ckp->cur_node_segno[2];
	sum->sit_j.entries[2].se.vblocks = cpu_to_le16((CURSEG_COLD_NODE << 10));

	/* data sit for root */
	sum->sit_j.entries[3].segno = ckp->cur_data_segno[0];
	sum->sit_j.entries[3].se.vblocks = cpu_to_le16((CURSEG_HOT_DATA << 10) | 1);
	f2fs_set_bit(0, (char *)sum->sit_j.entries[3].se.valid_map);
	sum->sit_j.entries[4].segno = ckp->cur_data_segno[1];
	sum->sit_j.entries[4].se.vblocks = cpu_to_le16((CURSEG_WARM_DATA << 10));
	sum->sit_j.entries[5].segno = ckp->cur_data_segno[2];
	sum->sit_j.entries[5].se.vblocks = cpu_to_le16((CURSEG_COLD_DATA << 10));

	cp_seg_blk_offset += blk_size_bytes;
	DBG(1, "\tWriting data sit for root, at offset 0x%08"PRIx64"\n", cp_seg_blk_offset);
	if (dev_write(sum, cp_seg_blk_offset, blk_size_bytes)) {
		MSG(1, "\tError: While writing the sum_blk to disk!!!\n");
		return -1;
	}

	/* 5. Prepare and write Segment summary for node blocks */
	memset(sum, 0, sizeof(struct f2fs_summary_block));
	SET_SUM_TYPE((&sum->footer), SUM_TYPE_NODE);

	sum->entries[0].nid = super_block.root_ino;
	sum->entries[0].ofs_in_node = 0;

	cp_seg_blk_offset += blk_size_bytes;
	DBG(1, "\tWriting Segment summary for node blocks, at offset 0x%08"PRIx64"\n", cp_seg_blk_offset);
	if (dev_write(sum, cp_seg_blk_offset, blk_size_bytes)) {
		MSG(1, "\tError: While writing the sum_blk to disk!!!\n");
		return -1;
	}

	/* 6. Fill segment summary for data block to zero. */
	memset(sum, 0, sizeof(struct f2fs_summary_block));
	SET_SUM_TYPE((&sum->footer), SUM_TYPE_NODE);

	cp_seg_blk_offset += blk_size_bytes;
	DBG(1, "\tWriting Segment summary for data block (1/2), at offset 0x%08"PRIx64"\n", cp_seg_blk_offset);
	if (dev_write(sum, cp_seg_blk_offset, blk_size_bytes)) {
		MSG(1, "\tError: While writing the sum_blk to disk!!!\n");
		return -1;
	}

	/* 7. Fill segment summary for data block to zero. */
	memset(sum, 0, sizeof(struct f2fs_summary_block));
	SET_SUM_TYPE((&sum->footer), SUM_TYPE_NODE);
	cp_seg_blk_offset += blk_size_bytes;
	DBG(1, "\tWriting Segment summary for data block (2/2), at offset 0x%08"PRIx64"\n", cp_seg_blk_offset);
	if (dev_write(sum, cp_seg_blk_offset, blk_size_bytes)) {
		MSG(1, "\tError: While writing the sum_blk to disk!!!\n");
		return -1;
	}

	/* 8. cp page2 */
	cp_seg_blk_offset += blk_size_bytes;
	DBG(1, "\tWriting cp page2, at offset 0x%08"PRIx64"\n", cp_seg_blk_offset);
	if (dev_write(ckp, cp_seg_blk_offset, blk_size_bytes)) {
		MSG(1, "\tError: While writing the ckp to disk!!!\n");
		return -1;
	}

	/* 9. cp page 1 of check point pack 2
	 * Initiatialize other checkpoint pack with version zero
	 */
	ckp->checkpoint_ver = 0;

	crc = f2fs_cal_crc32(F2FS_SUPER_MAGIC, ckp, CHECKSUM_OFFSET);
	*((__le32 *)((unsigned char *)ckp + CHECKSUM_OFFSET)) =
							cpu_to_le32(crc);
	cp_seg_blk_offset = (le32_to_cpu(super_block.segment0_blkaddr) +
				config.blks_per_seg) *
				blk_size_bytes;
	DBG(1, "\tWriting cp page 1 of checkpoint pack 2, at offset 0x%08"PRIx64"\n", cp_seg_blk_offset);
	if (dev_write(ckp, cp_seg_blk_offset, blk_size_bytes)) {
		MSG(1, "\tError: While writing the ckp to disk!!!\n");
		return -1;
	}

	for (i = 0; i < le32_to_cpu(super_block.cp_payload); i++) {
		cp_seg_blk_offset += blk_size_bytes;
		if (dev_fill(cp_payload, cp_seg_blk_offset, blk_size_bytes)) {
			MSG(1, "\tError: While zeroing out the sit bitmap area \
					on disk!!!\n");
			return -1;
		}
	}

	/* 10. cp page 2 of check point pack 2 */
	cp_seg_blk_offset += blk_size_bytes * (le32_to_cpu(ckp->cp_pack_total_block_count)
			- le32_to_cpu(super_block.cp_payload) - 1);
	DBG(1, "\tWriting cp page 2 of checkpoint pack 2, at offset 0x%08"PRIx64"\n", cp_seg_blk_offset);
	if (dev_write(ckp, cp_seg_blk_offset, blk_size_bytes)) {
		MSG(1, "\tError: While writing the ckp to disk!!!\n");
		return -1;
	}

	free(sum) ;
	free(ckp) ;
	free(cp_payload);
	return	0;
}

static int f2fs_write_super_block(void)
{
	int index;
	u_int8_t *zero_buff;

	zero_buff = calloc(F2FS_BLKSIZE, 1);

	memcpy(zero_buff + F2FS_SUPER_OFFSET, &super_block,
						sizeof(super_block));
	DBG(1, "\tWriting super block, at offset 0x%08x\n", 0);
	for (index = 0; index < 2; index++) {
		if (dev_write(zero_buff, index * F2FS_BLKSIZE, F2FS_BLKSIZE)) {
			MSG(1, "\tError: While while writing supe_blk \
					on disk!!! index : %d\n", index);
			return -1;
		}
	}

	free(zero_buff);
	return 0;
}

static int f2fs_write_root_inode(void)
{
	struct f2fs_node *raw_node = NULL;
	u_int64_t blk_size_bytes, data_blk_nor;
	u_int64_t main_area_node_seg_blk_offset = 0;

	raw_node = calloc(F2FS_BLKSIZE, 1);
	if (raw_node == NULL) {
		MSG(1, "\tError: Calloc Failed for raw_node!!!\n");
		return -1;
	}

	raw_node->footer.nid = super_block.root_ino;
	raw_node->footer.ino = super_block.root_ino;
	raw_node->footer.cp_ver = cpu_to_le64(1);
	raw_node->footer.next_blkaddr = cpu_to_le32(
			le32_to_cpu(super_block.main_blkaddr) +
			config.cur_seg[CURSEG_HOT_NODE] *
			config.blks_per_seg + 1);

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
	raw_node->i.i_dir_level = DEF_DIR_LEVEL;

	data_blk_nor = le32_to_cpu(super_block.main_blkaddr) +
		config.cur_seg[CURSEG_HOT_DATA] * config.blks_per_seg;
	raw_node->i.i_addr[0] = cpu_to_le32(data_blk_nor);

	raw_node->i.i_ext.fofs = 0;
	raw_node->i.i_ext.blk_addr = cpu_to_le32(data_blk_nor);
	raw_node->i.i_ext.len = cpu_to_le32(1);

	main_area_node_seg_blk_offset = le32_to_cpu(super_block.main_blkaddr);
	main_area_node_seg_blk_offset += config.cur_seg[CURSEG_HOT_NODE] *
					config.blks_per_seg;
        main_area_node_seg_blk_offset *= blk_size_bytes;

	DBG(1, "\tWriting root inode (hot node), at offset 0x%08"PRIx64"\n", main_area_node_seg_blk_offset);
	if (dev_write(raw_node, main_area_node_seg_blk_offset, F2FS_BLKSIZE)) {
		MSG(1, "\tError: While writing the raw_node to disk!!!\n");
		return -1;
	}

	memset(raw_node, 0xff, sizeof(struct f2fs_node));

	/* avoid power-off-recovery based on roll-forward policy */
	main_area_node_seg_blk_offset = le32_to_cpu(super_block.main_blkaddr);
	main_area_node_seg_blk_offset += config.cur_seg[CURSEG_WARM_NODE] *
					config.blks_per_seg;
        main_area_node_seg_blk_offset *= blk_size_bytes;

	DBG(1, "\tWriting root inode (warm node), at offset 0x%08"PRIx64"\n", main_area_node_seg_blk_offset);
	if (dev_write(raw_node, main_area_node_seg_blk_offset, F2FS_BLKSIZE)) {
		MSG(1, "\tError: While writing the raw_node to disk!!!\n");
		return -1;
	}
	free(raw_node);
	return 0;
}

static int f2fs_update_nat_root(void)
{
	struct f2fs_nat_block *nat_blk = NULL;
	u_int64_t blk_size_bytes, nat_seg_blk_offset = 0;

	nat_blk = calloc(F2FS_BLKSIZE, 1);
	if(nat_blk == NULL) {
		MSG(1, "\tError: Calloc Failed for nat_blk!!!\n");
		return -1;
	}

	/* update root */
	nat_blk->entries[le32_to_cpu(super_block.root_ino)].block_addr = cpu_to_le32(
		le32_to_cpu(super_block.main_blkaddr) +
		config.cur_seg[CURSEG_HOT_NODE] * config.blks_per_seg);
	nat_blk->entries[le32_to_cpu(super_block.root_ino)].ino = super_block.root_ino;

	/* update node nat */
	nat_blk->entries[le32_to_cpu(super_block.node_ino)].block_addr = cpu_to_le32(1);
	nat_blk->entries[le32_to_cpu(super_block.node_ino)].ino = super_block.node_ino;

	/* update meta nat */
	nat_blk->entries[le32_to_cpu(super_block.meta_ino)].block_addr = cpu_to_le32(1);
	nat_blk->entries[le32_to_cpu(super_block.meta_ino)].ino = super_block.meta_ino;

	blk_size_bytes = 1 << le32_to_cpu(super_block.log_blocksize);
	nat_seg_blk_offset = le32_to_cpu(super_block.nat_blkaddr);
	nat_seg_blk_offset *= blk_size_bytes;

	DBG(1, "\tWriting nat root, at offset 0x%08"PRIx64"\n", nat_seg_blk_offset);
	if (dev_write(nat_blk, nat_seg_blk_offset, F2FS_BLKSIZE)) {
		MSG(1, "\tError: While writing the nat_blk set0 to disk!\n");
		return -1;
	}

	free(nat_blk);
	return 0;
}

static int f2fs_add_default_dentry_root(void)
{
	struct f2fs_dentry_block *dent_blk = NULL;
	u_int64_t blk_size_bytes, data_blk_offset = 0;

	dent_blk = calloc(F2FS_BLKSIZE, 1);
	if(dent_blk == NULL) {
		MSG(1, "\tError: Calloc Failed for dent_blk!!!\n");
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
	data_blk_offset = le32_to_cpu(super_block.main_blkaddr);
	data_blk_offset += config.cur_seg[CURSEG_HOT_DATA] *
				config.blks_per_seg;
	data_blk_offset *= blk_size_bytes;

	DBG(1, "\tWriting default dentry root, at offset 0x%08"PRIx64"\n", data_blk_offset);
	if (dev_write(dent_blk, data_blk_offset, F2FS_BLKSIZE)) {
		MSG(1, "\tError: While writing the dentry_blk to disk!!!\n");
		return -1;
	}

	free(dent_blk);
	return 0;
}

static int f2fs_create_root_dir(void)
{
	int err = 0;

	err = f2fs_write_root_inode();
	if (err < 0) {
		MSG(1, "\tError: Failed to write root inode!!!\n");
		goto exit;
	}

	err = f2fs_update_nat_root();
	if (err < 0) {
		MSG(1, "\tError: Failed to update NAT for root!!!\n");
		goto exit;
	}

	err = f2fs_add_default_dentry_root();
	if (err < 0) {
		MSG(1, "\tError: Failed to add default dentries for root!!!\n");
		goto exit;
	}
exit:
	if (err)
		MSG(1, "\tError: Could not create the root directory!!!\n");

	return err;
}

int f2fs_format_device(void)
{
	int err = 0;

	err= f2fs_prepare_super_block();
	if (err < 0) {
		MSG(0, "\tError: Failed to prepare a super block!!!\n");
		goto exit;
	}

	err = f2fs_trim_device();
	if (err < 0) {
		MSG(0, "\tError: Failed to trim whole device!!!\n");
		goto exit;
	}

	err = f2fs_init_sit_area();
	if (err < 0) {
		MSG(0, "\tError: Failed to Initialise the SIT AREA!!!\n");
		goto exit;
	}

	err = f2fs_init_nat_area();
	if (err < 0) {
		MSG(0, "\tError: Failed to Initialise the NAT AREA!!!\n");
		goto exit;
	}

	err = f2fs_create_root_dir();
	if (err < 0) {
		MSG(0, "\tError: Failed to create the root directory!!!\n");
		goto exit;
	}

	err = f2fs_write_check_point_pack();
	if (err < 0) {
		MSG(0, "\tError: Failed to write the check point pack!!!\n");
		goto exit;
	}

	err = f2fs_write_super_block();
	if (err < 0) {
		MSG(0, "\tError: Failed to write the Super Block!!!\n");
		goto exit;
	}
exit:
	if (err)
		MSG(0, "\tError: Could not format the device!!!\n");

	return err;
}
