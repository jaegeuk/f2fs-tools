/**
 * fsck.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include "fsck.h"

char *tree_mark;
uint32_t tree_mark_size = 256;

static inline int f2fs_set_main_bitmap(struct f2fs_sb_info *sbi, u32 blk,
								int type)
{
	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
	struct seg_entry *se;

	se = get_seg_entry(sbi, GET_SEGNO(sbi, blk));
	if (se->type != type) {
		if (type == CURSEG_WARM_DATA) {
			if (se->type != CURSEG_COLD_DATA) {
				DBG(1, "Wrong segment type [0x%x] %x -> %x",
						GET_SEGNO(sbi, blk), se->type,
						CURSEG_WARM_DATA);
				se->type = CURSEG_WARM_DATA;
			}
		} else {
			DBG(1, "Wrong segment type [0x%x] %x -> %x",
				GET_SEGNO(sbi, blk), se->type, type);
			se->type = type;
		}
	}
	return f2fs_set_bit(BLKOFF_FROM_MAIN(sbi, blk), fsck->main_area_bitmap);
}

static inline int f2fs_test_main_bitmap(struct f2fs_sb_info *sbi, u32 blk)
{
	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);

	return f2fs_test_bit(BLKOFF_FROM_MAIN(sbi, blk),
						fsck->main_area_bitmap);
}

static inline int f2fs_test_sit_bitmap(struct f2fs_sb_info *sbi, u32 blk)
{
	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);

	return f2fs_test_bit(BLKOFF_FROM_MAIN(sbi, blk), fsck->sit_area_bitmap);
}

static int add_into_hard_link_list(struct f2fs_sb_info *sbi,
						u32 nid, u32 link_cnt)
{
	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
	struct hard_link_node *node = NULL, *tmp = NULL, *prev = NULL;

	node = calloc(sizeof(struct hard_link_node), 1);
	ASSERT(node != NULL);

	node->nid = nid;
	node->links = link_cnt;
	node->next = NULL;

	if (fsck->hard_link_list_head == NULL) {
		fsck->hard_link_list_head = node;
		goto out;
	}

	tmp = fsck->hard_link_list_head;

	/* Find insertion position */
	while (tmp && (nid < tmp->nid)) {
		ASSERT(tmp->nid != nid);
		prev = tmp;
		tmp = tmp->next;
	}

	if (tmp == fsck->hard_link_list_head) {
		node->next = tmp;
		fsck->hard_link_list_head = node;
	} else {
		prev->next = node;
		node->next = tmp;
	}

out:
	DBG(2, "ino[0x%x] has hard links [0x%x]\n", nid, link_cnt);
	return 0;
}

static int find_and_dec_hard_link_list(struct f2fs_sb_info *sbi, u32 nid)
{
	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
	struct hard_link_node *node = NULL, *prev = NULL;

	if (fsck->hard_link_list_head == NULL)
		return -EINVAL;

	node = fsck->hard_link_list_head;

	while (node && (nid < node->nid)) {
		prev = node;
		node = node->next;
	}

	if (node == NULL || (nid != node->nid))
		return -EINVAL;

	/* Decrease link count */
	node->links = node->links - 1;

	/* if link count becomes one, remove the node */
	if (node->links == 1) {
		if (fsck->hard_link_list_head == node)
			fsck->hard_link_list_head = node->next;
		else
			prev->next = node->next;
		free(node);
	}
	return 0;
}

static int is_valid_ssa_node_blk(struct f2fs_sb_info *sbi, u32 nid,
							u32 blk_addr)
{
	int ret = 0;
	struct f2fs_summary sum_entry;

	ret = get_sum_entry(sbi, blk_addr, &sum_entry);

	if (ret != SEG_TYPE_NODE && ret != SEG_TYPE_CUR_NODE) {
		ASSERT_MSG("Summary footer is not for node segment");
		return -EINVAL;
	}

	if (le32_to_cpu(sum_entry.nid) != nid) {
		DBG(0, "nid                       [0x%x]\n", nid);
		DBG(0, "target blk_addr           [0x%x]\n", blk_addr);
		DBG(0, "summary blk_addr          [0x%x]\n",
					GET_SUM_BLKADDR(sbi,
					GET_SEGNO(sbi, blk_addr)));
		DBG(0, "seg no / offset           [0x%x / 0x%x]\n",
					GET_SEGNO(sbi, blk_addr),
					OFFSET_IN_SEG(sbi, blk_addr));
		DBG(0, "summary_entry.nid         [0x%x]\n",
					le32_to_cpu(sum_entry.nid));
		DBG(0, "--> node block's nid      [0x%x]\n", nid);
		ASSERT_MSG("Invalid node seg summary\n");
		return -EINVAL;
	}
	return 0;
}

static int is_valid_ssa_data_blk(struct f2fs_sb_info *sbi, u32 blk_addr,
		u32 parent_nid, u16 idx_in_node, u8 version)
{
	int ret = 0;
	struct f2fs_summary sum_entry;

	ret = get_sum_entry(sbi, blk_addr, &sum_entry);

	if (ret != SEG_TYPE_DATA && ret != SEG_TYPE_CUR_DATA) {
		ASSERT_MSG("Summary footer is not for data segment");
		return -EINVAL;
	}

	if (le32_to_cpu(sum_entry.nid) != parent_nid ||
			sum_entry.version != version ||
			le16_to_cpu(sum_entry.ofs_in_node) != idx_in_node) {

		DBG(0, "summary_entry.nid         [0x%x]\n",
					le32_to_cpu(sum_entry.nid));
		DBG(0, "summary_entry.version     [0x%x]\n",
					sum_entry.version);
		DBG(0, "summary_entry.ofs_in_node [0x%x]\n",
					le16_to_cpu(sum_entry.ofs_in_node));
		DBG(0, "parent nid                [0x%x]\n", parent_nid);
		DBG(0, "version from nat          [0x%x]\n", version);
		DBG(0, "idx in parent node        [0x%x]\n", idx_in_node);

		DBG(0, "Target data block addr    [0x%x]\n", blk_addr);
		ASSERT_MSG("Invalid data seg summary\n");
		return -EINVAL;
	}
	return 0;
}

static int sanity_check_nid(struct f2fs_sb_info *sbi, u32 nid,
			struct f2fs_node *node_blk,
			enum FILE_TYPE ftype, enum NODE_TYPE ntype,
			struct node_info *ni)
{
	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
	int ret;

	if (!IS_VALID_NID(sbi, nid)) {
		ASSERT_MSG("nid is not valid. [0x%x]", nid);
		return -EINVAL;
	}

	get_node_info(sbi, nid, ni);
	if (ni->blk_addr == NEW_ADDR) {
		ASSERT_MSG("nid is NEW_ADDR. [0x%x]", nid);
		return -EINVAL;
	}

	if (!IS_VALID_BLK_ADDR(sbi, ni->blk_addr)) {
		ASSERT_MSG("blkaddres is not valid. [0x%x]", ni->blk_addr);
		return -EINVAL;
	}

	if (is_valid_ssa_node_blk(sbi, nid, ni->blk_addr)) {
		ASSERT_MSG("summary node block is not valid. [0x%x]", nid);
		return -EINVAL;
	}

	ret = dev_read_block(node_blk, ni->blk_addr);
	ASSERT(ret >= 0);

	if (ntype == TYPE_INODE &&
			node_blk->footer.nid != node_blk->footer.ino) {
		ASSERT_MSG("nid[0x%x] footer.nid[0x%x] footer.ino[0x%x]",
				nid, le32_to_cpu(node_blk->footer.nid),
				le32_to_cpu(node_blk->footer.ino));
		return -EINVAL;
	}
	if (ntype != TYPE_INODE &&
			node_blk->footer.nid == node_blk->footer.ino) {
		ASSERT_MSG("nid[0x%x] footer.nid[0x%x] footer.ino[0x%x]",
				nid, le32_to_cpu(node_blk->footer.nid),
				le32_to_cpu(node_blk->footer.ino));
		return -EINVAL;
	}

	if (le32_to_cpu(node_blk->footer.nid) != nid) {
		ASSERT_MSG("nid[0x%x] blk_addr[0x%x] footer.nid[0x%x]",
				nid, ni->blk_addr,
				le32_to_cpu(node_blk->footer.nid));
		return -EINVAL;
	}

	if (ntype == TYPE_XATTR) {
		u32 flag = le32_to_cpu(node_blk->footer.flag);

		if ((flag >> OFFSET_BIT_SHIFT) != XATTR_NODE_OFFSET) {
			ASSERT_MSG("xnid[0x%x] has wrong ofs:[0x%x]",
					nid, flag);
			return -EINVAL;
		}
	}

	if ((ntype == TYPE_INODE && ftype == F2FS_FT_DIR) ||
			(ntype == TYPE_XATTR && ftype == F2FS_FT_XATTR)) {
		/* not included '.' & '..' */
		if (f2fs_test_main_bitmap(sbi, ni->blk_addr) != 0) {
			ASSERT_MSG("Duplicated node blk. nid[0x%x][0x%x]\n",
					nid, ni->blk_addr);
			return -EINVAL;
		}
	}

	/* workaround to fix later */
	if (ftype != F2FS_FT_ORPHAN ||
			f2fs_test_bit(nid, fsck->nat_area_bitmap) != 0)
		f2fs_clear_bit(nid, fsck->nat_area_bitmap);
	else
		ASSERT_MSG("orphan or xattr nid is duplicated [0x%x]\n",
				nid);

	if (f2fs_test_sit_bitmap(sbi, ni->blk_addr) == 0)
		ASSERT_MSG("SIT bitmap is 0x0. blk_addr[0x%x]",
				ni->blk_addr);

	if (f2fs_test_main_bitmap(sbi, ni->blk_addr) == 0) {
		fsck->chk.valid_blk_cnt++;
		fsck->chk.valid_node_cnt++;
	}
	return 0;
}

static int fsck_chk_xattr_blk(struct f2fs_sb_info *sbi, u32 ino,
					u32 x_nid, u32 *blk_cnt)
{
	struct f2fs_node *node_blk = NULL;
	struct node_info ni;
	int ret = 0;

	if (x_nid == 0x0)
		return 0;

	node_blk = (struct f2fs_node *)calloc(BLOCK_SZ, 1);
	ASSERT(node_blk != NULL);

	/* Sanity check */
	if (sanity_check_nid(sbi, x_nid, node_blk,
				F2FS_FT_XATTR, TYPE_XATTR, &ni)) {
		ret = -EINVAL;
		goto out;
	}

	*blk_cnt = *blk_cnt + 1;
	f2fs_set_main_bitmap(sbi, ni.blk_addr, CURSEG_COLD_NODE);
	DBG(2, "ino[0x%x] x_nid[0x%x]\n", ino, x_nid);
out:
	free(node_blk);
	return ret;
}

int fsck_chk_node_blk(struct f2fs_sb_info *sbi, struct f2fs_inode *inode,
		u32 nid, enum FILE_TYPE ftype, enum NODE_TYPE ntype,
		u32 *blk_cnt)
{
	struct node_info ni;
	struct f2fs_node *node_blk = NULL;

	node_blk = (struct f2fs_node *)calloc(BLOCK_SZ, 1);
	ASSERT(node_blk != NULL);

	if (sanity_check_nid(sbi, nid, node_blk, ftype, ntype, &ni))
		goto err;

	if (ntype == TYPE_INODE) {
		fsck_chk_inode_blk(sbi, nid, ftype, node_blk, blk_cnt, &ni);
	} else {
		switch (ntype) {
		case TYPE_DIRECT_NODE:
			f2fs_set_main_bitmap(sbi, ni.blk_addr,
							CURSEG_WARM_NODE);
			fsck_chk_dnode_blk(sbi, inode, nid, ftype, node_blk,
					blk_cnt, &ni);
			break;
		case TYPE_INDIRECT_NODE:
			f2fs_set_main_bitmap(sbi, ni.blk_addr,
							CURSEG_COLD_NODE);
			fsck_chk_idnode_blk(sbi, inode, ftype, node_blk,
					blk_cnt);
			break;
		case TYPE_DOUBLE_INDIRECT_NODE:
			f2fs_set_main_bitmap(sbi, ni.blk_addr,
							CURSEG_COLD_NODE);
			fsck_chk_didnode_blk(sbi, inode, ftype, node_blk,
					blk_cnt);
			break;
		default:
			ASSERT(0);
		}
	}
	free(node_blk);
	return 0;
err:
	free(node_blk);
	return -EINVAL;
}

/* start with valid nid and blkaddr */
void fsck_chk_inode_blk(struct f2fs_sb_info *sbi, u32 nid,
		enum FILE_TYPE ftype, struct f2fs_node *node_blk,
		u32 *blk_cnt, struct node_info *ni)
{
	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
	u32 child_cnt = 0, child_files = 0;
	enum NODE_TYPE ntype;
	u32 i_links = le32_to_cpu(node_blk->i.i_links);
	u64 i_blocks = le64_to_cpu(node_blk->i.i_blocks);
	unsigned int idx = 0;
	int need_fix = 0;
	int ret;

	if (f2fs_test_main_bitmap(sbi, ni->blk_addr) == 0)
		fsck->chk.valid_inode_cnt++;

	if (ftype == F2FS_FT_DIR) {
		f2fs_set_main_bitmap(sbi, ni->blk_addr, CURSEG_HOT_NODE);
	} else {
		if (f2fs_test_main_bitmap(sbi, ni->blk_addr) == 0) {
			f2fs_set_main_bitmap(sbi, ni->blk_addr,
							CURSEG_WARM_NODE);
			if (i_links > 1) {
				/* First time. Create new hard link node */
				add_into_hard_link_list(sbi, nid, i_links);
				fsck->chk.multi_hard_link_files++;
			}
		} else {
			DBG(3, "[0x%x] has hard links [0x%x]\n", nid, i_links);
			if (find_and_dec_hard_link_list(sbi, nid)) {
				ASSERT_MSG("[0x%x] needs more i_links=0x%x",
						nid, i_links);
				if (config.fix_on) {
					node_blk->i.i_links =
						cpu_to_le32(i_links + 1);
					need_fix = 1;
					FIX_MSG("File: 0x%x "
						"i_links= 0x%x -> 0x%x",
						nid, i_links, i_links + 1);
				}
				goto check;
			}
			/* No need to go deep into the node */
			return;
		}
	}

	if (fsck_chk_xattr_blk(sbi, nid,
			le32_to_cpu(node_blk->i.i_xattr_nid), blk_cnt) &&
			config.fix_on) {
		node_blk->i.i_xattr_nid = 0;
		need_fix = 1;
		FIX_MSG("Remove xattr block: 0x%x, x_nid = 0x%x",
				nid, le32_to_cpu(node_blk->i.i_xattr_nid));
	}

	if (ftype == F2FS_FT_CHRDEV || ftype == F2FS_FT_BLKDEV ||
			ftype == F2FS_FT_FIFO || ftype == F2FS_FT_SOCK)
		goto check;

	if((node_blk->i.i_inline & F2FS_INLINE_DATA)) {
		if (le32_to_cpu(node_blk->i.i_addr[0]) != 0) {
			/* should fix this bug all the time */
			FIX_MSG("inline_data has wrong 0'th block = %x",
					le32_to_cpu(node_blk->i.i_addr[0]));
			node_blk->i.i_addr[0] = 0;
			node_blk->i.i_blocks = cpu_to_le64(*blk_cnt);
			need_fix = 1;
		}
		if (!(node_blk->i.i_inline & F2FS_DATA_EXIST)) {
			char buf[MAX_INLINE_DATA];
			memset(buf, 0, MAX_INLINE_DATA);

			if (memcmp(buf, &node_blk->i.i_addr[1],
							MAX_INLINE_DATA)) {
				FIX_MSG("inline_data has DATA_EXIST");
				node_blk->i.i_inline |= F2FS_DATA_EXIST;
				need_fix = 1;
			}
		}
		DBG(3, "ino[0x%x] has inline data!\n", nid);
		goto check;
	}
	if((node_blk->i.i_inline & F2FS_INLINE_DENTRY)) {
		DBG(3, "ino[0x%x] has inline dentry!\n", nid);
		ret = fsck_chk_inline_dentries(sbi, node_blk,
					&child_cnt, &child_files);
		if (ret < 0) {
			/* should fix this bug all the time */
			need_fix = 1;
		}
		goto check;
	}

	/* readahead node blocks */
	for (idx = 0; idx < 5; idx++) {
		u32 nid = le32_to_cpu(node_blk->i.i_nid[idx]);

		if (nid != 0) {
			struct node_info ni;

			get_node_info(sbi, nid, &ni);
			if (IS_VALID_BLK_ADDR(sbi, ni.blk_addr))
				dev_reada_block(ni.blk_addr);
		}
	}

	/* check data blocks in inode */
	for (idx = 0; idx < ADDRS_PER_INODE(&node_blk->i); idx++) {
		if (le32_to_cpu(node_blk->i.i_addr[idx]) != 0) {
			ret = fsck_chk_data_blk(sbi,
					le32_to_cpu(node_blk->i.i_addr[idx]),
					&child_cnt, &child_files,
					(i_blocks == *blk_cnt),
					ftype, nid, idx, ni->version);
			if (!ret) {
				*blk_cnt = *blk_cnt + 1;
			} else if (config.fix_on) {
				node_blk->i.i_addr[idx] = 0;
				need_fix = 1;
				FIX_MSG("[0x%x] i_addr[%d] = 0", nid, idx);
			}
		}
	}

	/* check node blocks in inode */
	for (idx = 0; idx < 5; idx++) {
		if (idx == 0 || idx == 1)
			ntype = TYPE_DIRECT_NODE;
		else if (idx == 2 || idx == 3)
			ntype = TYPE_INDIRECT_NODE;
		else if (idx == 4)
			ntype = TYPE_DOUBLE_INDIRECT_NODE;
		else
			ASSERT(0);

		if (le32_to_cpu(node_blk->i.i_nid[idx]) != 0) {
			ret = fsck_chk_node_blk(sbi, &node_blk->i,
					le32_to_cpu(node_blk->i.i_nid[idx]),
					ftype, ntype, blk_cnt);
			if (!ret) {
				*blk_cnt = *blk_cnt + 1;
			} else if (config.fix_on) {
				node_blk->i.i_nid[idx] = 0;
				need_fix = 1;
				FIX_MSG("[0x%x] i_nid[%d] = 0", nid, idx);
			}
		}
	}
check:
	if (ftype == F2FS_FT_DIR)
		DBG(1, "Directory Inode: 0x%x [%s] depth: %d has %d files\n\n",
				le32_to_cpu(node_blk->footer.ino),
				node_blk->i.i_name,
				le32_to_cpu(node_blk->i.i_current_depth),
				child_files);
	if (ftype == F2FS_FT_ORPHAN)
		DBG(1, "Orphan Inode: 0x%x [%s] i_blocks: %u\n\n",
				le32_to_cpu(node_blk->footer.ino),
				node_blk->i.i_name,
				(u32)i_blocks);

	if (i_blocks != *blk_cnt) {
		ASSERT_MSG("ino: 0x%x has i_blocks: %08"PRIx64", "
				"but has %u blocks",
				nid, i_blocks, *blk_cnt);
		if (config.fix_on) {
			node_blk->i.i_blocks = cpu_to_le64(*blk_cnt);
			need_fix = 1;
			FIX_MSG("[0x%x] i_blocks=0x%08"PRIx64" -> 0x%x",
					nid, i_blocks, *blk_cnt);
		}
	}
	if (ftype == F2FS_FT_DIR && i_links != child_cnt) {
		ASSERT_MSG("ino: 0x%x has i_links: %u but real links: %u",
				nid, i_links, child_cnt);
		if (config.fix_on) {
			node_blk->i.i_links = cpu_to_le32(child_cnt);
			need_fix = 1;
			FIX_MSG("Dir: 0x%x i_links= 0x%x -> 0x%x",
						nid, i_links, child_cnt);
		}
	}

	if (ftype == F2FS_FT_ORPHAN && i_links)
		ASSERT_MSG("ino: 0x%x is orphan inode, but has i_links: %u",
				nid, i_links);
	if (need_fix) {
		ret = dev_write_block(node_blk, ni->blk_addr);
		ASSERT(ret >= 0);
	}
}

int fsck_chk_dnode_blk(struct f2fs_sb_info *sbi, struct f2fs_inode *inode,
		u32 nid, enum FILE_TYPE ftype, struct f2fs_node *node_blk,
		u32 *blk_cnt, struct node_info *ni)
{
	int idx, ret;
	u32 child_cnt = 0, child_files = 0;
	int need_fix = 0;

	for (idx = 0; idx < ADDRS_PER_BLOCK; idx++) {
		if (le32_to_cpu(node_blk->dn.addr[idx]) == 0x0)
			continue;
		ret = fsck_chk_data_blk(sbi,
			le32_to_cpu(node_blk->dn.addr[idx]),
			&child_cnt, &child_files,
			le64_to_cpu(inode->i_blocks) == *blk_cnt, ftype,
			nid, idx, ni->version);
		if (!ret) {
			*blk_cnt = *blk_cnt + 1;
		} else if (config.fix_on) {
			node_blk->dn.addr[idx] = 0;
			need_fix = 1;
			FIX_MSG("[0x%x] dn.addr[%d] = 0", nid, idx);
		}
	}
	if (need_fix) {
		ret = dev_write_block(node_blk, ni->blk_addr);
		ASSERT(ret >= 0);
	}
	return 0;
}

int fsck_chk_idnode_blk(struct f2fs_sb_info *sbi, struct f2fs_inode *inode,
		enum FILE_TYPE ftype, struct f2fs_node *node_blk, u32 *blk_cnt)
{
	int ret;
	int i = 0;

	for (i = 0 ; i < NIDS_PER_BLOCK; i++) {
		if (le32_to_cpu(node_blk->in.nid[i]) == 0x0)
			continue;
		ret = fsck_chk_node_blk(sbi, inode,
				le32_to_cpu(node_blk->in.nid[i]),
				ftype, TYPE_DIRECT_NODE, blk_cnt);
		if (!ret)
			*blk_cnt = *blk_cnt + 1;
		else if (ret == -EINVAL)
			printf("delete in.nid[i] = 0;\n");
	}
	return 0;
}

int fsck_chk_didnode_blk(struct f2fs_sb_info *sbi, struct f2fs_inode *inode,
		enum FILE_TYPE ftype, struct f2fs_node *node_blk, u32 *blk_cnt)
{
	int i = 0;
	int ret = 0;

	for (i = 0; i < NIDS_PER_BLOCK; i++) {
		if (le32_to_cpu(node_blk->in.nid[i]) == 0x0)
			continue;
		ret = fsck_chk_node_blk(sbi, inode,
				le32_to_cpu(node_blk->in.nid[i]),
				ftype, TYPE_INDIRECT_NODE, blk_cnt);
		if (!ret)
			*blk_cnt = *blk_cnt + 1;
		else if (ret == -EINVAL)
			printf("delete in.nid[i] = 0;\n");
	}
	return 0;
}

static void print_dentry(__u32 depth, __u8 *name,
		unsigned long *bitmap,
		struct f2fs_dir_entry *dentry,
		int max, int idx, int last_blk)
{
	int last_de = 0;
	int next_idx = 0;
	int name_len;
	unsigned int i;
	int bit_offset;

	if (config.dbg_lv != -1)
		return;

	name_len = le16_to_cpu(dentry[idx].name_len);
	next_idx = idx + (name_len + F2FS_SLOT_LEN - 1) / F2FS_SLOT_LEN;

	bit_offset = find_next_bit(bitmap, max, next_idx);
	if (bit_offset >= max && last_blk)
		last_de = 1;

	if (tree_mark_size <= depth) {
		tree_mark_size *= 2;
		tree_mark = realloc(tree_mark, tree_mark_size);
	}

	if (last_de)
		tree_mark[depth] = '`';
	else
		tree_mark[depth] = '|';

	if (tree_mark[depth - 1] == '`')
		tree_mark[depth - 1] = ' ';


	for (i = 1; i < depth; i++)
		printf("%c   ", tree_mark[i]);
	printf("%c-- %s 0x%x\n", last_de ? '`' : '|',
				name, le32_to_cpu(dentry[idx].ino));
}

static int __chk_dentries(struct f2fs_sb_info *sbi, u32 *child_cnt,
			u32* child_files,
			unsigned long *bitmap,
			struct f2fs_dir_entry *dentry,
			__u8 (*filenames)[F2FS_SLOT_LEN],
			int max, int last_blk)
{
	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
	enum FILE_TYPE ftype;
	int dentries = 0;
	u32 blk_cnt;
	u8 *name;
	u32 hash_code, ino;
	u16 name_len;;
	int ret = 0;
	int fixed = 0;
	int i;

	/* readahead inode blocks */
	for (i = 0; i < max;) {
		if (test_bit(i, bitmap) == 0) {
			i++;
			continue;
		}
		ino = le32_to_cpu(dentry[i].ino);

		if (IS_VALID_NID(sbi, ino)) {
			struct node_info ni;

			get_node_info(sbi, ino, &ni);
			if (IS_VALID_BLK_ADDR(sbi, ni.blk_addr))
				dev_reada_block(ni.blk_addr);
		}
		name_len = le16_to_cpu(dentry[i].name_len);
		i += (name_len + F2FS_SLOT_LEN - 1) / F2FS_SLOT_LEN;
	}

	for (i = 0; i < max;) {
		if (test_bit(i, bitmap) == 0) {
			i++;
			continue;
		}
		if (!IS_VALID_NID(sbi, le32_to_cpu(dentry[i].ino))) {
			DBG(1, "Bad dentry 0x%x with invalid NID/ino 0x%x",
			    i, le32_to_cpu(dentry[i].ino));
			if (config.fix_on) {
				FIX_MSG("Clear bad dentry 0x%x with bad ino 0x%x",
					i, le32_to_cpu(dentry[i].ino));
				clear_bit(i, bitmap);
				i++;
				fixed = 1;
				continue;
			}
		}
		ftype = dentry[i].file_type;
		if ((ftype <= F2FS_FT_UNKNOWN || ftype > F2FS_FT_LAST_FILE_TYPE) && config.fix_on) {
			DBG(1, "Bad dentry 0x%x with unexpected ftype 0x%x",
			    i, ftype);
			if (config.fix_on) {
				FIX_MSG("Clear bad dentry 0x%x with bad ftype 0x%x",
					i, ftype);
				clear_bit(i, bitmap);
				i++;
				fixed = 1;
				continue;
			}
		}
		name_len = le16_to_cpu(dentry[i].name_len);
		name = calloc(name_len + 1, 1);
		memcpy(name, filenames[i], name_len);
		hash_code = f2fs_dentry_hash((const unsigned char *)name,
								name_len);

		/* fix hash_code made by old buggy code */
		if (le32_to_cpu(dentry[i].hash_code) != hash_code) {
			dentry[i].hash_code = hash_code;
			fixed = 1;
			FIX_MSG("hash_code[%d] of %s", i, name);
		}

		/* Becareful. 'dentry.file_type' is not imode. */
		if (ftype == F2FS_FT_DIR) {
			*child_cnt = *child_cnt + 1;
			if ((name[0] == '.' && name_len == 1) ||
				(name[0] == '.' && name[1] == '.' &&
							name_len == 2)) {
				i++;
				free(name);
				continue;
			}
		}

		DBG(1, "[%3u]-[0x%x] name[%s] len[0x%x] ino[0x%x] type[0x%x]\n",
				fsck->dentry_depth, i, name, name_len,
				le32_to_cpu(dentry[i].ino),
				dentry[i].file_type);

		print_dentry(fsck->dentry_depth, name, bitmap,
						dentry, max, i, last_blk);

		blk_cnt = 1;
		ret = fsck_chk_node_blk(sbi,
				NULL, le32_to_cpu(dentry[i].ino),
				ftype, TYPE_INODE, &blk_cnt);

		if (ret && config.fix_on) {
			int j;
			int slots = (name_len + F2FS_SLOT_LEN - 1) /
				F2FS_SLOT_LEN;
			for (j = 0; j < slots; j++)
				clear_bit(i + j, bitmap);
			FIX_MSG("Unlink [0x%x] - %s len[0x%x], type[0x%x]",
					le32_to_cpu(dentry[i].ino),
					name, name_len,
					dentry[i].file_type);
			i += slots;
			free(name);
			fixed = 1;
			continue;
		}

		i += (name_len + F2FS_SLOT_LEN - 1) / F2FS_SLOT_LEN;
		dentries++;
		*child_files = *child_files + 1;
		free(name);
	}
	return fixed ? -1 : dentries;
}

int fsck_chk_inline_dentries(struct f2fs_sb_info *sbi,
		struct f2fs_node *node_blk, u32 *child_cnt, u32 *child_files)
{
	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
	struct f2fs_inline_dentry *de_blk;
	int dentries;

	de_blk = inline_data_addr(node_blk);
	ASSERT(de_blk != NULL);

	fsck->dentry_depth++;
	dentries = __chk_dentries(sbi, child_cnt, child_files,
			(unsigned long *)de_blk->dentry_bitmap,
			de_blk->dentry, de_blk->filename,
			NR_INLINE_DENTRY, 1);
	if (dentries < 0) {
		DBG(1, "[%3d] Inline Dentry Block Fixed hash_codes\n\n",
			fsck->dentry_depth);
	} else {
		DBG(1, "[%3d] Inline Dentry Block Done : "
				"dentries:%d in %d slots (len:%d)\n\n",
			fsck->dentry_depth, dentries,
			(int)NR_INLINE_DENTRY, F2FS_NAME_LEN);
	}
	fsck->dentry_depth--;
	return dentries;
}

int fsck_chk_dentry_blk(struct f2fs_sb_info *sbi, u32 blk_addr,
		u32 *child_cnt, u32 *child_files, int last_blk)
{
	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
	struct f2fs_dentry_block *de_blk;
	int dentries, ret;

	de_blk = (struct f2fs_dentry_block *)calloc(BLOCK_SZ, 1);
	ASSERT(de_blk != NULL);

	ret = dev_read_block(de_blk, blk_addr);
	ASSERT(ret >= 0);

	fsck->dentry_depth++;
	dentries = __chk_dentries(sbi, child_cnt, child_files,
			(unsigned long *)de_blk->dentry_bitmap,
			de_blk->dentry, de_blk->filename,
			NR_DENTRY_IN_BLOCK, last_blk);

	if (dentries < 0) {
		ret = dev_write_block(de_blk, blk_addr);
		ASSERT(ret >= 0);
		DBG(1, "[%3d] Dentry Block [0x%x] Fixed hash_codes\n\n",
			fsck->dentry_depth, blk_addr);
	} else {
		DBG(1, "[%3d] Dentry Block [0x%x] Done : "
				"dentries:%d in %d slots (len:%d)\n\n",
			fsck->dentry_depth, blk_addr, dentries,
			NR_DENTRY_IN_BLOCK, F2FS_NAME_LEN);
	}
	fsck->dentry_depth--;
	free(de_blk);
	return 0;
}

int fsck_chk_data_blk(struct f2fs_sb_info *sbi, u32 blk_addr,
		u32 *child_cnt, u32 *child_files, int last_blk,
		enum FILE_TYPE ftype, u32 parent_nid, u16 idx_in_node, u8 ver)
{
	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);

	/* Is it reserved block? */
	if (blk_addr == NEW_ADDR) {
		fsck->chk.valid_blk_cnt++;
		return 0;
	}

	if (!IS_VALID_BLK_ADDR(sbi, blk_addr)) {
		ASSERT_MSG("blkaddres is not valid. [0x%x]", blk_addr);
		return -EINVAL;
	}

	if (is_valid_ssa_data_blk(sbi, blk_addr, parent_nid,
						idx_in_node, ver)) {
		ASSERT_MSG("summary data block is not valid. [0x%x]",
						parent_nid);
		return -EINVAL;
	}

	if (f2fs_test_sit_bitmap(sbi, blk_addr) == 0)
		ASSERT_MSG("SIT bitmap is 0x0. blk_addr[0x%x]", blk_addr);

	if (f2fs_test_main_bitmap(sbi, blk_addr) != 0)
		ASSERT_MSG("Duplicated data [0x%x]. pnid[0x%x] idx[0x%x]",
				blk_addr, parent_nid, idx_in_node);


	fsck->chk.valid_blk_cnt++;

	if (ftype == F2FS_FT_DIR) {
		f2fs_set_main_bitmap(sbi, blk_addr, CURSEG_HOT_DATA);
		return fsck_chk_dentry_blk(sbi, blk_addr, child_cnt,
				child_files, last_blk);
	} else {
		f2fs_set_main_bitmap(sbi, blk_addr, CURSEG_WARM_DATA);
	}
	return 0;
}

void fsck_chk_orphan_node(struct f2fs_sb_info *sbi)
{
	u32 blk_cnt = 0;
	block_t start_blk, orphan_blkaddr, i, j;
	struct f2fs_orphan_block *orphan_blk;
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);

	if (!is_set_ckpt_flags(ckpt, CP_ORPHAN_PRESENT_FLAG))
		return;

	start_blk = __start_cp_addr(sbi) + 1 +
		le32_to_cpu(F2FS_RAW_SUPER(sbi)->cp_payload);
	orphan_blkaddr = __start_sum_addr(sbi) - 1;
	orphan_blk = calloc(BLOCK_SZ, 1);

	for (i = 0; i < orphan_blkaddr; i++) {
		int ret = dev_read_block(orphan_blk, start_blk + i);

		ASSERT(ret >= 0);

		for (j = 0; j < le32_to_cpu(orphan_blk->entry_count); j++) {
			nid_t ino = le32_to_cpu(orphan_blk->ino[j]);
			DBG(1, "[%3d] ino [0x%x]\n", i, ino);
			if (config.fix_on) {
				FIX_MSG("Discard orphan inodes: ino [0x%x]",
									ino);
				continue;
			}
			blk_cnt = 1;
			fsck_chk_node_blk(sbi, NULL, ino,
					F2FS_FT_ORPHAN, TYPE_INODE, &blk_cnt);
		}
		memset(orphan_blk, 0, BLOCK_SZ);
	}
	free(orphan_blk);
}

void fsck_init(struct f2fs_sb_info *sbi)
{
	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
	struct f2fs_sm_info *sm_i = SM_I(sbi);

	/*
	 * We build three bitmap for main/sit/nat so that may check consistency
	 * of filesystem.
	 * 1. main_area_bitmap will be used to check whether all blocks of main
	 *    area is used or not.
	 * 2. nat_area_bitmap has bitmap information of used nid in NAT.
	 * 3. sit_area_bitmap has bitmap information of used main block.
	 * At Last sequence, we compare main_area_bitmap with sit_area_bitmap.
	 */
	fsck->nr_main_blks = sm_i->main_segments << sbi->log_blocks_per_seg;
	fsck->main_area_bitmap_sz = (fsck->nr_main_blks + 7) / 8;
	fsck->main_area_bitmap = calloc(fsck->main_area_bitmap_sz, 1);
	ASSERT(fsck->main_area_bitmap != NULL);

	build_nat_area_bitmap(sbi);

	build_sit_area_bitmap(sbi);

	tree_mark = calloc(tree_mark_size, 1);
	ASSERT(tree_mark != NULL);
}

static void fix_nat_entries(struct f2fs_sb_info *sbi)
{
	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
	u32 i;

	for (i = 0; i < fsck->nr_nat_entries; i++)
		if (f2fs_test_bit(i, fsck->nat_area_bitmap) != 0)
			nullify_nat_entry(sbi, i);
}

static void fix_checkpoint(struct f2fs_sb_info *sbi)
{
	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
	struct f2fs_super_block *raw_sb = sbi->raw_super;
	struct f2fs_checkpoint *ckp = F2FS_CKPT(sbi);
	unsigned long long cp_blk_no;
	u32 i;
	int ret;
	u_int32_t crc = 0;

	ckp->ckpt_flags = cpu_to_le32(CP_UMOUNT_FLAG);
	ckp->cp_pack_total_block_count =
		cpu_to_le32(8 + le32_to_cpu(raw_sb->cp_payload));
	ckp->cp_pack_start_sum = cpu_to_le32(1 +
				le32_to_cpu(raw_sb->cp_payload));

	ckp->free_segment_count = cpu_to_le32(fsck->chk.free_segs);
	ckp->valid_block_count = cpu_to_le32(fsck->chk.valid_blk_cnt);
	ckp->valid_node_count = cpu_to_le32(fsck->chk.valid_node_cnt);
	ckp->valid_inode_count = cpu_to_le32(fsck->chk.valid_inode_cnt);

	crc = f2fs_cal_crc32(F2FS_SUPER_MAGIC, ckp, CHECKSUM_OFFSET);
	*((__le32 *)((unsigned char *)ckp + CHECKSUM_OFFSET)) =
							cpu_to_le32(crc);

	cp_blk_no = le32_to_cpu(raw_sb->cp_blkaddr);
	if (sbi->cur_cp == 2)
		cp_blk_no += 1 << le32_to_cpu(raw_sb->log_blocks_per_seg);

	ret = dev_write_block(ckp, cp_blk_no++);
	ASSERT(ret >= 0);

	for (i = 0; i < le32_to_cpu(raw_sb->cp_payload); i++) {
		ret = dev_write_block(((unsigned char *)ckp) + i * F2FS_BLKSIZE,
								cp_blk_no++);
		ASSERT(ret >= 0);
	}

	for (i = 0; i < NO_CHECK_TYPE; i++) {
		struct curseg_info *curseg = CURSEG_I(sbi, i);

		ret = dev_write_block(curseg->sum_blk, cp_blk_no++);
		ASSERT(ret >= 0);
	}

	ret = dev_write_block(ckp, cp_blk_no++);
	ASSERT(ret >= 0);
}

int check_curseg_offset(struct f2fs_sb_info *sbi)
{
	int i;

	for (i = 0; i < NO_CHECK_TYPE; i++) {
		struct curseg_info *curseg = CURSEG_I(sbi, i);
		struct seg_entry *se;

		se = get_seg_entry(sbi, curseg->segno);
		if (f2fs_test_bit(curseg->next_blkoff,
				(const char *)se->cur_valid_map) == 1) {
			ASSERT_MSG("Next block offset is not free, type:%d", i);
			return -EINVAL;
		}
	}
	return 0;
}

int check_sit_types(struct f2fs_sb_info *sbi)
{
	unsigned int i;
	int err = 0;

	for (i = 0; i < TOTAL_SEGS(sbi); i++) {
		struct seg_entry *se;

		se = get_seg_entry(sbi, i);
		if (se->orig_type != se->type) {
			if (se->orig_type == CURSEG_COLD_DATA) {
				se->type = se->orig_type;
			} else {
				FIX_MSG("Wrong segment type [0x%x] %x -> %x",
						i, se->orig_type, se->type);
				err = -EINVAL;
			}
		}
	}
	return err;
}

int fsck_verify(struct f2fs_sb_info *sbi)
{
	unsigned int i = 0;
	int ret = 0;
	int force = 0;
	u32 nr_unref_nid = 0;
	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
	struct hard_link_node *node = NULL;

	printf("\n");

	for (i = 0; i < fsck->nr_nat_entries; i++) {
		if (f2fs_test_bit(i, fsck->nat_area_bitmap) != 0) {
			printf("NID[0x%x] is unreachable\n", i);
			nr_unref_nid++;
		}
	}

	if (fsck->hard_link_list_head != NULL) {
		node = fsck->hard_link_list_head;
		while (node) {
			printf("NID[0x%x] has [0x%x] more unreachable links\n",
					node->nid, node->links);
			node = node->next;
		}
		config.bug_on = 1;
	}

	printf("[FSCK] Unreachable nat entries                       ");
	if (nr_unref_nid == 0x0) {
		printf(" [Ok..] [0x%x]\n", nr_unref_nid);
	} else {
		printf(" [Fail] [0x%x]\n", nr_unref_nid);
		ret = EXIT_ERR_CODE;
		config.bug_on = 1;
	}

	printf("[FSCK] SIT valid block bitmap checking                ");
	if (memcmp(fsck->sit_area_bitmap, fsck->main_area_bitmap,
					fsck->sit_area_bitmap_sz) == 0x0) {
		printf("[Ok..]\n");
	} else {
		printf("[Fail]\n");
		ret = EXIT_ERR_CODE;
		config.bug_on = 1;
	}

	printf("[FSCK] Hard link checking for regular file           ");
	if (fsck->hard_link_list_head == NULL) {
		printf(" [Ok..] [0x%x]\n", fsck->chk.multi_hard_link_files);
	} else {
		printf(" [Fail] [0x%x]\n", fsck->chk.multi_hard_link_files);
		ret = EXIT_ERR_CODE;
		config.bug_on = 1;
	}

	printf("[FSCK] valid_block_count matching with CP            ");
	if (sbi->total_valid_block_count == fsck->chk.valid_blk_cnt) {
		printf(" [Ok..] [0x%x]\n", (u32)fsck->chk.valid_blk_cnt);
	} else {
		printf(" [Fail] [0x%x]\n", (u32)fsck->chk.valid_blk_cnt);
		ret = EXIT_ERR_CODE;
		config.bug_on = 1;
	}

	printf("[FSCK] valid_node_count matcing with CP (de lookup)  ");
	if (sbi->total_valid_node_count == fsck->chk.valid_node_cnt) {
		printf(" [Ok..] [0x%x]\n", fsck->chk.valid_node_cnt);
	} else {
		printf(" [Fail] [0x%x]\n", fsck->chk.valid_node_cnt);
		ret = EXIT_ERR_CODE;
		config.bug_on = 1;
	}

	printf("[FSCK] valid_node_count matcing with CP (nat lookup) ");
	if (sbi->total_valid_node_count == fsck->chk.valid_nat_entry_cnt) {
		printf(" [Ok..] [0x%x]\n", fsck->chk.valid_nat_entry_cnt);
	} else {
		printf(" [Fail] [0x%x]\n", fsck->chk.valid_nat_entry_cnt);
		ret = EXIT_ERR_CODE;
		config.bug_on = 1;
	}

	printf("[FSCK] valid_inode_count matched with CP             ");
	if (sbi->total_valid_inode_count == fsck->chk.valid_inode_cnt) {
		printf(" [Ok..] [0x%x]\n", fsck->chk.valid_inode_cnt);
	} else {
		printf(" [Fail] [0x%x]\n", fsck->chk.valid_inode_cnt);
		ret = EXIT_ERR_CODE;
		config.bug_on = 1;
	}

	printf("[FSCK] free segment_count matched with CP            ");
	if (le32_to_cpu(F2FS_CKPT(sbi)->free_segment_count) ==
						fsck->chk.sit_free_segs) {
		printf(" [Ok..] [0x%x]\n", fsck->chk.sit_free_segs);
	} else {
		printf(" [Fail] [0x%x]\n", fsck->chk.sit_free_segs);
		ret = EXIT_ERR_CODE;
		config.bug_on = 1;
	}

	printf("[FSCK] next block offset is free                     ");
	if (check_curseg_offset(sbi) == 0) {
		printf(" [Ok..]\n");
	} else {
		printf(" [Fail]\n");
		ret = EXIT_ERR_CODE;
		config.bug_on = 1;
	}

	printf("[FSCK] fixing SIT types\n");
	if (check_sit_types(sbi) != 0)
		force = 1;

	printf("[FSCK] other corrupted bugs                          ");
	if (config.bug_on == 0) {
		printf(" [Ok..]\n");
	} else {
		printf(" [Fail]\n");
		ret = EXIT_ERR_CODE;
	}

	/* fix global metadata */
	if (force || (config.bug_on && config.fix_on)) {
		fix_nat_entries(sbi);
		rewrite_sit_area_bitmap(sbi);
		fix_checkpoint(sbi);
	}
	return ret;
}

void fsck_free(struct f2fs_sb_info *sbi)
{
	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
	if (fsck->main_area_bitmap)
		free(fsck->main_area_bitmap);

	if (fsck->nat_area_bitmap)
		free(fsck->nat_area_bitmap);

	if (fsck->sit_area_bitmap)
		free(fsck->sit_area_bitmap);

	if (tree_mark)
		free(tree_mark);
}
