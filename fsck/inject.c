/**
 * inject.c
 *
 * Copyright (c) 2024 OPPO Mobile Comm Corp., Ltd.
 *             http://www.oppo.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <getopt.h>
#include "inject.h"

static void print_raw_nat_entry_info(struct f2fs_nat_entry *ne)
{
	if (!c.dbg_lv)
		return;

	DISP_u8(ne, version);
	DISP_u32(ne, ino);
	DISP_u32(ne, block_addr);
}

void inject_usage(void)
{
	MSG(0, "\nUsage: inject.f2fs [options] device\n");
	MSG(0, "[options]:\n");
	MSG(0, "  -d debug level [default:0]\n");
	MSG(0, "  -V print the version number and exit\n");
	MSG(0, "  --mb <member name> which member is injected in a struct\n");
	MSG(0, "  --val <new value> new value to set\n");
	MSG(0, "  --str <new string> new string to set\n");
	MSG(0, "  --idx <slot index> which slot is injected in an array\n");
	MSG(0, "  --nid <nid> which nid is injected\n");
	MSG(0, "  --sb <0|1|2> --mb <name> [--idx <index>] --val/str <value/string> inject superblock\n");
	MSG(0, "  --cp <0|1|2> --mb <name> [--idx <index>] --val <value> inject checkpoint\n");
	MSG(0, "  --nat <0|1|2> --mb <name> --nid <nid> --val <value> inject nat entry\n");
	MSG(0, "  --dry-run do not really inject\n");

	exit(1);
}

static void inject_sb_usage(void)
{
	MSG(0, "inject.f2fs --sb <0|1|2> --mb <name> [--idx <index>] --val/str <value/string>\n");
	MSG(0, "[sb]:\n");
	MSG(0, "  0: auto select the first super block\n");
	MSG(0, "  1: select the first super block\n");
	MSG(0, "  2: select the second super block\n");
	MSG(0, "[mb]:\n");
	MSG(0, "  magic: inject magic number\n");
	MSG(0, "  s_stop_reason: inject s_stop_reason array selected by --idx <index>\n");
	MSG(0, "  s_errors: inject s_errors array selected by --idx <index>\n");
	MSG(0, "  devs.path: inject path in devs array selected by --idx <index> specified by --str <string>\n");
}

static void inject_cp_usage(void)
{
	MSG(0, "inject.f2fs --cp <0|1|2> --mb <name> [--idx <index>] --val <value> inject checkpoint\n");
	MSG(0, "[cp]:\n");
	MSG(0, "  0: auto select the current cp pack\n");
	MSG(0, "  1: select the first cp pack\n");
	MSG(0, "  2: select the second cp pack\n");
	MSG(0, "[mb]:\n");
	MSG(0, "  checkpoint_ver: inject checkpoint_ver\n");
	MSG(0, "  ckpt_flags: inject ckpt_flags\n");
	MSG(0, "  cur_node_segno: inject cur_node_segno array selected by --idx <index>\n");
	MSG(0, "  cur_node_blkoff: inject cur_node_blkoff array selected by --idx <index>\n");
	MSG(0, "  cur_data_segno: inject cur_data_segno array selected by --idx <index>\n");
	MSG(0, "  cur_data_blkoff: inject cur_data_blkoff array selected by --idx <index>\n");
}

static void inject_nat_usage(void)
{
	MSG(0, "inject.f2fs --nat <0|1|2> --mb <name> --nid <nid> --val <value> inject nat entry\n");
	MSG(0, "[nat]:\n");
	MSG(0, "  0: auto select the current nat pack\n");
	MSG(0, "  1: select the first nat pack\n");
	MSG(0, "  2: select the second nat pack\n");
	MSG(0, "[mb]:\n");
	MSG(0, "  version: inject nat entry version\n");
	MSG(0, "  ino: inject nat entry ino\n");
	MSG(0, "  block_addr: inject nat entry block_addr\n");
}

int inject_parse_options(int argc, char *argv[], struct inject_option *opt)
{
	int o = 0;
	const char *pack[] = {"auto", "1", "2"};
	const char *option_string = "d:Vh";
	char *endptr;
	struct option long_opt[] = {
		{"dry-run", no_argument, 0, 1},
		{"mb", required_argument, 0, 2},
		{"idx", required_argument, 0, 3},
		{"val", required_argument, 0, 4},
		{"str", required_argument, 0, 5},
		{"sb", required_argument, 0, 6},
		{"cp", required_argument, 0, 7},
		{"nat", required_argument, 0, 8},
		{"nid", required_argument, 0, 9},
		{0, 0, 0, 0}
	};

	while ((o = getopt_long(argc, argv, option_string,
				long_opt, NULL)) != EOF) {
		switch (o) {
		case 1:
			c.dry_run = 1;
			MSG(0, "Info: Dry run\n");
			break;
		case 2:
			opt->mb = optarg;
			MSG(0, "Info: inject member %s\n", optarg);
			break;
		case 3:
			if (!is_digits(optarg))
				return EWRONG_OPT;
			opt->idx = atoi(optarg);
			MSG(0, "Info: inject slot index %d\n", opt->idx);
			break;
		case 4:
			opt->val = strtoll(optarg, &endptr, 0);
			if (opt->val == LLONG_MAX || opt->val == LLONG_MIN ||
			    *endptr != '\0')
				return -ERANGE;
			MSG(0, "Info: inject value %lld : 0x%llx\n", opt->val,
			    (unsigned long long)opt->val);
			break;
		case 5:
			opt->str = strdup(optarg);
			if (!opt->str)
				return -ENOMEM;
			MSG(0, "Info: inject string %s\n", opt->str);
			break;
		case 6:
			if (!is_digits(optarg))
				return EWRONG_OPT;
			opt->sb = atoi(optarg);
			if (opt->sb < 0 || opt->sb > 2)
				return -ERANGE;
			MSG(0, "Info: inject sb %s\n", pack[opt->sb]);
			break;
		case 7:
			if (!is_digits(optarg))
				return EWRONG_OPT;
			opt->cp = atoi(optarg);
			if (opt->cp < 0 || opt->cp > 2)
				return -ERANGE;
			MSG(0, "Info: inject cp pack %s\n", pack[opt->cp]);
			break;
		case 8:
			if (!is_digits(optarg))
				return EWRONG_OPT;
			opt->nat = atoi(optarg);
			if (opt->nat < 0 || opt->nat > 2)
				return -ERANGE;
			MSG(0, "Info: inject nat pack %s\n", pack[opt->nat]);
			break;
		case 9:
			opt->nid = strtol(optarg, &endptr, 0);
			if (opt->nid == LONG_MAX || opt->nid == LONG_MIN ||
			    *endptr != '\0')
				return -ERANGE;
			MSG(0, "Info: inject nid %u : 0x%x\n", opt->nid, opt->nid);
			break;
		case 'd':
			if (optarg[0] == '-' || !is_digits(optarg))
				return EWRONG_OPT;
			c.dbg_lv = atoi(optarg);
			MSG(0, "Info: Debug level = %d\n", c.dbg_lv);
			break;
		case 'V':
			show_version("inject.f2fs");
			exit(0);
		case 'h':
		default:
			if (opt->sb >= 0) {
				inject_sb_usage();
				exit(0);
			} else if (opt->cp >= 0) {
				inject_cp_usage();
				exit(0);
			} else if (opt->nat >= 0) {
				inject_nat_usage();
				exit(0);
			}
			return EUNKNOWN_OPT;
		}
	}

	return 0;
}

static int inject_sb(struct f2fs_sb_info *sbi, struct inject_option *opt)
{
	struct f2fs_super_block *sb;
	char *buf;
	int ret;

	buf = calloc(1, F2FS_BLKSIZE);
	ASSERT(buf != NULL);

	if (opt->sb == 0)
		opt->sb = 1;

	ret = dev_read_block(buf, opt->sb == 1 ? SB0_ADDR : SB1_ADDR);
	ASSERT(ret >= 0);

	sb = (struct f2fs_super_block *)(buf + F2FS_SUPER_OFFSET);

	if (!strcmp(opt->mb, "magic")) {
		MSG(0, "Info: inject magic of sb %d: 0x%x -> 0x%x\n",
		    opt->sb, get_sb(magic), (u32)opt->val);
		set_sb(magic, (u32)opt->val);
	} else if (!strcmp(opt->mb, "s_stop_reason")) {
		if (opt->idx >= MAX_STOP_REASON) {
			ERR_MSG("invalid index %u of sb->s_stop_reason[]\n",
				opt->idx);
			ret = -EINVAL;
			goto out;
		}
		MSG(0, "Info: inject s_stop_reason[%d] of sb %d: %d -> %d\n",
		    opt->idx, opt->sb, sb->s_stop_reason[opt->idx],
		    (u8)opt->val);
		sb->s_stop_reason[opt->idx] = (u8)opt->val;
	} else if (!strcmp(opt->mb, "s_errors")) {
		if (opt->idx >= MAX_F2FS_ERRORS) {
			ERR_MSG("invalid index %u of sb->s_errors[]\n",
				opt->idx);
			ret = -EINVAL;
			goto out;
		}
		MSG(0, "Info: inject s_errors[%d] of sb %d: %x -> %x\n",
		    opt->idx, opt->sb, sb->s_errors[opt->idx], (u8)opt->val);
		sb->s_errors[opt->idx] = (u8)opt->val;
	} else if (!strcmp(opt->mb, "devs.path")) {
		if (opt->idx >= MAX_DEVICES) {
			ERR_MSG("invalid index %u of sb->devs[]\n", opt->idx);
			ret = -EINVAL;
			goto out;
		}
		if (strlen(opt->str) >= MAX_PATH_LEN) {
			ERR_MSG("invalid length of option str\n");
			ret = -EINVAL;
			goto out;
		}
		MSG(0, "Info: inject devs[%d].path of sb %d: %s -> %s\n",
		    opt->idx, opt->sb, (char *)sb->devs[opt->idx].path, opt->str);
		strcpy((char *)sb->devs[opt->idx].path, opt->str);
	} else {
		ERR_MSG("unknown or unsupported member \"%s\"\n", opt->mb);
		ret = -EINVAL;
		goto out;
	}

	print_raw_sb_info(sb);
	update_superblock(sb, SB_MASK((u32)opt->sb - 1));

out:
	free(buf);
	free(opt->str);
	return ret;
}

static int inject_cp(struct f2fs_sb_info *sbi, struct inject_option *opt)
{
	struct f2fs_checkpoint *cp, *cur_cp = F2FS_CKPT(sbi);
	char *buf = NULL;
	int ret = 0;

	if (opt->cp == 0)
		opt->cp = sbi->cur_cp;

	if (opt->cp != sbi->cur_cp) {
		struct f2fs_super_block *sb = sbi->raw_super;
		block_t cp_addr;

		buf = calloc(1, F2FS_BLKSIZE);
		ASSERT(buf != NULL);

		cp_addr = get_sb(cp_blkaddr);
		if (opt->cp == 2)
			cp_addr += 1 << get_sb(log_blocks_per_seg);
		ret = dev_read_block(buf, cp_addr);
		ASSERT(ret >= 0);

		cp = (struct f2fs_checkpoint *)buf;
		sbi->ckpt = cp;
		sbi->cur_cp = opt->cp;
	} else {
		cp = cur_cp;
	}

	if (!strcmp(opt->mb, "checkpoint_ver")) {
		MSG(0, "Info: inject checkpoint_ver of cp %d: 0x%llx -> 0x%lx\n",
		    opt->cp, get_cp(checkpoint_ver), (u64)opt->val);
		set_cp(checkpoint_ver, (u64)opt->val);
	} else if (!strcmp(opt->mb, "ckpt_flags")) {
		MSG(0, "Info: inject ckpt_flags of cp %d: 0x%x -> 0x%x\n",
		    opt->cp, get_cp(ckpt_flags), (u32)opt->val);
		set_cp(ckpt_flags, (u32)opt->val);
	} else if (!strcmp(opt->mb, "cur_node_segno")) {
		if (opt->idx >= MAX_ACTIVE_NODE_LOGS) {
			ERR_MSG("invalid index %u of cp->cur_node_segno[]\n",
				opt->idx);
			ret = -EINVAL;
			goto out;
		}
		MSG(0, "Info: inject cur_node_segno[%d] of cp %d: 0x%x -> 0x%x\n",
		    opt->idx, opt->cp, get_cp(cur_node_segno[opt->idx]),
		    (u32)opt->val);
		set_cp(cur_node_segno[opt->idx], (u32)opt->val);
	} else if (!strcmp(opt->mb, "cur_node_blkoff")) {
		if (opt->idx >= MAX_ACTIVE_NODE_LOGS) {
			ERR_MSG("invalid index %u of cp->cur_node_blkoff[]\n",
				opt->idx);
			ret = -EINVAL;
			goto out;
		}
		MSG(0, "Info: inject cur_node_blkoff[%d] of cp %d: 0x%x -> 0x%x\n",
		    opt->idx, opt->cp, get_cp(cur_node_blkoff[opt->idx]),
		    (u16)opt->val);
		set_cp(cur_node_blkoff[opt->idx], (u16)opt->val);
	} else if (!strcmp(opt->mb, "cur_data_segno")) {
		if (opt->idx >= MAX_ACTIVE_DATA_LOGS) {
			ERR_MSG("invalid index %u of cp->cur_data_segno[]\n",
				opt->idx);
			ret = -EINVAL;
			goto out;
		}
		MSG(0, "Info: inject cur_data_segno[%d] of cp %d: 0x%x -> 0x%x\n",
		    opt->idx, opt->cp, get_cp(cur_data_segno[opt->idx]),
		    (u32)opt->val);
		set_cp(cur_data_segno[opt->idx], (u32)opt->val);
	} else if (!strcmp(opt->mb, "cur_data_blkoff")) {
		if (opt->idx >= MAX_ACTIVE_DATA_LOGS) {
			ERR_MSG("invalid index %u of cp->cur_data_blkoff[]\n",
				opt->idx);
			ret = -EINVAL;
			goto out;
		}
		MSG(0, "Info: inject cur_data_blkoff[%d] of cp %d: 0x%x -> 0x%x\n",
		    opt->idx, opt->cp, get_cp(cur_data_blkoff[opt->idx]),
		    (u16)opt->val);
		set_cp(cur_data_blkoff[opt->idx], (u16)opt->val);
	} else {
		ERR_MSG("unknown or unsupported member \"%s\"\n", opt->mb);
		ret = -EINVAL;
		goto out;
	}

	print_ckpt_info(sbi);
	write_raw_cp_blocks(sbi, cp, opt->cp);

out:
	free(buf);
	sbi->ckpt = cur_cp;
	return ret;
}

static int inject_nat(struct f2fs_sb_info *sbi, struct inject_option *opt)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
	struct f2fs_nat_block *nat_blk;
	struct f2fs_nat_entry *ne;
	block_t blk_addr;
	unsigned int offs;
	bool is_set;
	int ret;

	if (!IS_VALID_NID(sbi, opt->nid)) {
		ERR_MSG("Invalid nid %u range [%u:%lu]\n", opt->nid, 0,
			NAT_ENTRY_PER_BLOCK *
			((get_sb(segment_count_nat) << 1) <<
			 sbi->log_blocks_per_seg));
		return -EINVAL;
	}

	nat_blk = calloc(F2FS_BLKSIZE, 1);
	ASSERT(nat_blk);

	/* change NAT version bitmap temporarily to select specified pack */
	is_set = f2fs_test_bit(opt->nid, nm_i->nat_bitmap);
	if (opt->nat == 0) {
		opt->nat = is_set ? 2 : 1;
	} else {
		if (opt->nat == 1)
			f2fs_clear_bit(opt->nid, nm_i->nat_bitmap);
		else
			f2fs_set_bit(opt->nid, nm_i->nat_bitmap);
	}

	blk_addr = current_nat_addr(sbi, opt->nid, NULL);

	ret = dev_read_block(nat_blk, blk_addr);
	ASSERT(ret >= 0);

	offs = opt->nid % NAT_ENTRY_PER_BLOCK;
	ne = &nat_blk->entries[offs];

	if (!strcmp(opt->mb, "version")) {
		MSG(0, "Info: inject nat entry version of nid %u "
		    "in pack %d: %d -> %d\n", opt->nid, opt->nat,
		    ne->version, (u8)opt->val);
		ne->version = (u8)opt->val;
	} else if (!strcmp(opt->mb, "ino")) {
		MSG(0, "Info: inject nat entry ino of nid %u "
		    "in pack %d: %d -> %d\n", opt->nid, opt->nat,
		    le32_to_cpu(ne->ino), (nid_t)opt->val);
		ne->ino = cpu_to_le32((nid_t)opt->val);
	} else if (!strcmp(opt->mb, "block_addr")) {
		MSG(0, "Info: inject nat entry block_addr of nid %u "
		    "in pack %d: 0x%x -> 0x%x\n", opt->nid, opt->nat,
		    le32_to_cpu(ne->block_addr), (block_t)opt->val);
		ne->block_addr = cpu_to_le32((block_t)opt->val);
	} else {
		ERR_MSG("unknown or unsupported member \"%s\"\n", opt->mb);
		free(nat_blk);
		return -EINVAL;
	}
	print_raw_nat_entry_info(ne);

	ret = dev_write_block(nat_blk, blk_addr);
	ASSERT(ret >= 0);
	/* restore NAT version bitmap */
	if (is_set)
		f2fs_set_bit(opt->nid, nm_i->nat_bitmap);
	else
		f2fs_clear_bit(opt->nid, nm_i->nat_bitmap);

	free(nat_blk);
	return ret;
}

int do_inject(struct f2fs_sb_info *sbi)
{
	struct inject_option *opt = (struct inject_option *)c.private;
	int ret = -EINVAL;

	if (opt->sb >= 0)
		ret = inject_sb(sbi, opt);
	else if (opt->cp >= 0)
		ret = inject_cp(sbi, opt);
	else if (opt->nat >= 0)
		ret = inject_nat(sbi, opt);

	return ret;
}
