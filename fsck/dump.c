/**
 * dump.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include "fsck.h"

#define BUF_SZ	80

const char *seg_type_name[SEG_TYPE_MAX] = {
	"SEG_TYPE_DATA",
	"SEG_TYPE_CUR_DATA",
	"SEG_TYPE_NODE",
	"SEG_TYPE_CUR_NODE",
};

void sit_dump(struct f2fs_sb_info *sbi, int start_sit, int end_sit)
{
	struct seg_entry *se;
	int segno;
	char buf[BUF_SZ];
	u32 free_segs = 0;;
	u64 valid_blocks = 0;
	int ret;
	int fd;

	fd = open("dump_sit", O_CREAT|O_WRONLY|O_TRUNC, 0666);
	ASSERT(fd >= 0);

	for (segno = start_sit; segno < end_sit; segno++) {
		se = get_seg_entry(sbi, segno);

		memset(buf, 0, BUF_SZ);
		snprintf(buf, BUF_SZ, "%5d %8d\n", segno, se->valid_blocks);

		ret = write(fd, buf, strlen(buf));
		ASSERT(ret >= 0);

		DBG(4, "SIT[0x%3x] : 0x%x\n", segno, se->valid_blocks);
		if (se->valid_blocks == 0x0) {
			free_segs++;
		} else {
			ASSERT(se->valid_blocks <= 512);
			valid_blocks += se->valid_blocks;
		}
	}

	memset(buf, 0, BUF_SZ);
	snprintf(buf, BUF_SZ, "valid_segs:%d\t free_segs:%d\n",
			SM_I(sbi)->main_segments - free_segs, free_segs);
	ret = write(fd, buf, strlen(buf));
	ASSERT(ret >= 0);

	close(fd);
	DBG(1, "Blocks [0x%lx] Free Segs [0x%x]\n", valid_blocks, free_segs);
}

void ssa_dump(struct f2fs_sb_info *sbi, int start_ssa, int end_ssa)
{
	struct f2fs_summary_block sum_blk;
	char buf[BUF_SZ];
	int segno, i, ret;
	int fd;

	fd = open("dump_ssa", O_CREAT|O_WRONLY|O_TRUNC, 0666);
	ASSERT(fd >= 0);

	snprintf(buf, BUF_SZ, "Note: dump.f2fs -b blkaddr = 0x%x + segno * "
				" 0x200 + offset\n",
				sbi->sm_info->main_blkaddr);
	ret = write(fd, buf, strlen(buf));
	ASSERT(ret >= 0);

	for (segno = start_ssa; segno < end_ssa; segno++) {
		ret = get_sum_block(sbi, segno, &sum_blk);

		memset(buf, 0, BUF_SZ);
		switch (ret) {
		case SEG_TYPE_CUR_NODE:
			snprintf(buf, BUF_SZ, "\n\nsegno: %x, Current Node\n", segno);
			break;
		case SEG_TYPE_CUR_DATA:
			snprintf(buf, BUF_SZ, "\n\nsegno: %x, Current Data\n", segno);
			break;
		case SEG_TYPE_NODE:
			snprintf(buf, BUF_SZ, "\n\nsegno: %x, Node\n", segno);
			break;
		case SEG_TYPE_DATA:
			snprintf(buf, BUF_SZ, "\n\nsegno: %x, Data\n", segno);
			break;
		}
		ret = write(fd, buf, strlen(buf));
		ASSERT(ret >= 0);

		for (i = 0; i < ENTRIES_IN_SUM; i++) {
			memset(buf, 0, BUF_SZ);
			if (i % 10 == 0) {
				buf[0] = '\n';
				ret = write(fd, buf, strlen(buf));
				ASSERT(ret >= 0);
			}
			snprintf(buf, BUF_SZ, "[%3d: %6x]", i,
					le32_to_cpu(sum_blk.entries[i].nid));
			ret = write(fd, buf, strlen(buf));
			ASSERT(ret >= 0);
		}
	}
	close(fd);
}

int dump_node(struct f2fs_sb_info *sbi, nid_t nid)
{
	struct node_info ni;
	struct f2fs_node *node_blk;
	int ret;

	ret = get_node_info(sbi, nid, &ni);
	ASSERT(ret >= 0);

	node_blk = calloc(BLOCK_SZ, 1);
	dev_read_block(node_blk, ni.blk_addr);

	DBG(1, "Node ID               [0x%x]\n", nid);
	DBG(1, "nat_entry.block_addr  [0x%x]\n", ni.blk_addr);
	DBG(1, "nat_entry.version     [0x%x]\n", ni.version);
	DBG(1, "nat_entry.ino         [0x%x]\n", ni.ino);

	if (ni.blk_addr == 0x0) {
		MSG(0, "Invalid nat entry\n\n");
	}

	DBG(1, "node_blk.footer.ino [0x%x]\n", le32_to_cpu(node_blk->footer.ino));
	DBG(1, "node_blk.footer.nid [0x%x]\n", le32_to_cpu(node_blk->footer.nid));

	if (le32_to_cpu(node_blk->footer.ino) == ni.ino &&
			le32_to_cpu(node_blk->footer.nid) == ni.nid) {
		print_node_info(node_blk);
	} else {
		MSG(0, "Invalid node block\n\n");
	}

	free(node_blk);
	return 0;
}

int dump_inode_from_blkaddr(struct f2fs_sb_info *sbi, u32 blk_addr)
{
	nid_t ino, nid;
	int type, ret;
	struct f2fs_summary sum_entry;
	struct node_info ni;
	struct f2fs_node *node_blk;

	type = get_sum_entry(sbi, blk_addr, &sum_entry);
	nid = le32_to_cpu(sum_entry.nid);

	ret = get_node_info(sbi, nid, &ni);
	ASSERT(ret >= 0);

	DBG(1, "Note: blkaddr = main_blkaddr + segno * 512 + offset\n");
	DBG(1, "Block_addr            [0x%x]\n", blk_addr);
	DBG(1, " - Segno              [0x%x]\n", GET_SEGNO(sbi, blk_addr));
	DBG(1, " - Offset             [0x%x]\n", OFFSET_IN_SEG(sbi, blk_addr));
	DBG(1, "SUM.nid               [0x%x]\n", nid);
	DBG(1, "SUM.type              [%s]\n", seg_type_name[type]);
	DBG(1, "SUM.version           [%d]\n", sum_entry.version);
	DBG(1, "SUM.ofs_in_node       [%d]\n", sum_entry.ofs_in_node);
	DBG(1, "NAT.blkaddr           [0x%x]\n", ni.blk_addr);
	DBG(1, "NAT.ino               [0x%x]\n", ni.ino);

	node_blk = calloc(BLOCK_SZ, 1);

read_node_blk:
	dev_read_block(node_blk, blk_addr);

	ino = le32_to_cpu(node_blk->footer.ino);
	nid = le32_to_cpu(node_blk->footer.nid);

	if (ino == nid) {
		print_node_info(node_blk);
	} else {
		ret = get_node_info(sbi, ino, &ni);
		goto read_node_blk;
	}

	free(node_blk);
	return ino;
}
