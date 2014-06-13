/**
 * main.c
 *
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include "fsck.h"
#include <libgen.h>

struct f2fs_fsck gfsck = {
	.sbi = { .fsck = &gfsck, },
};

void fsck_usage()
{
	MSG(0, "\nUsage: fsck.f2fs [options] device\n");
	MSG(0, "[options]:\n");
	MSG(0, "  -d debug level [default:0]\n");
	exit(1);
}

void dump_usage()
{
	MSG(0, "\nUsage: dump.f2fs [options] device\n");
	MSG(0, "[options]:\n");
	MSG(0, "  -d debug level [default:0]\n");
	MSG(0, "  -i inode no (hex)\n");
	MSG(0, "  -s [SIT dump segno from #1~#2 (decimal), for all 0~-1]\n");
	MSG(0, "  -a [SSA dump segno from #1~#2 (decimal), for all 0~-1]\n");
	MSG(0, "  -b blk_addr (in 4KB)\n");

	exit(1);
}

void f2fs_parse_options(int argc, char *argv[])
{
	int option = 0;
	char *prog = basename(argv[0]);

	if (!strcmp("fsck.f2fs", prog)) {
		const char *option_string = "d:t";

		config.func = FSCK;
		while ((option = getopt(argc, argv, option_string)) != EOF) {
			switch (option) {
				case 'd':
					config.dbg_lv = atoi(optarg);
					MSG(0, "Info: Debug level = %d\n", config.dbg_lv);
					break;
				case 't':
					config.dbg_lv = -1;
					break;
				default:
					MSG(0, "\tError: Unknown option %c\n",option);
					fsck_usage();
					break;
			}
		}
	} else if (!strcmp("dump.f2fs", prog)) {
		const char *option_string = "d:i:s:a:b:";
		static struct dump_option dump_opt = {
			.nid = 3,	/* default root ino */
			.start_sit = -1,
			.end_sit = -1,
			.start_ssa = -1,
			.end_ssa = -1,
			.blk_addr = -1,
		};

		config.func = DUMP;
		while ((option = getopt(argc, argv, option_string)) != EOF) {
			switch (option) {
				case 'd':
					config.dbg_lv = atoi(optarg);
					MSG(0, "Info: Debug level = %d\n", config.dbg_lv);
					break;
				case 'i':
					if (strncmp(optarg, "0x", 2))
						sscanf(optarg, "%d", &dump_opt.nid);
					else
						sscanf(optarg, "%x", &dump_opt.nid);
					break;
				case 's':
					sscanf(optarg, "%d~%d", &dump_opt.start_sit, &dump_opt.end_sit);
					break;
				case 'a':
					sscanf(optarg, "%d~%d", &dump_opt.start_ssa, &dump_opt.end_ssa);
					break;
				case 'b':
					if (strncmp(optarg, "0x", 2))
						sscanf(optarg, "%d", &dump_opt.blk_addr);
					else
						sscanf(optarg, "%x", &dump_opt.blk_addr);
					break;
				default:
					MSG(0, "\tError: Unknown option %c\n", option);
					dump_usage();
					break;
			}
		}

		config.private = &dump_opt;
	}

	if ((optind + 1) != argc) {
		MSG(0, "\tError: Device not specified\n");
		if (config.func == FSCK)
			fsck_usage();
		else if (config.func == DUMP)
			dump_usage();
	}
	config.device_name = argv[optind];
}

int do_fsck(struct f2fs_sb_info *sbi)
{
	u32 blk_cnt;
	int ret;

	ret = fsck_init(sbi);
	if (ret < 0)
		return ret;

	fsck_chk_orphan_node(sbi);

	/* Travses all block recursively from root inode  */
	blk_cnt = 1;
	ret = fsck_chk_node_blk(sbi,
			NULL,
			sbi->root_ino_num,
			F2FS_FT_DIR,
			TYPE_INODE,
			&blk_cnt);
	if (ret < 0)
		goto out1;

	ret = fsck_verify(sbi);

out1:
	fsck_free(sbi);
	return ret;
}

int do_dump(struct f2fs_sb_info *sbi)
{
	struct dump_option *opt = (struct dump_option *)config.private;
	int ret;

	ret = fsck_init(sbi);
	if (ret < 0)
		return ret;

	if (opt->end_sit == -1)
		opt->end_sit = SM_I(sbi)->main_segments;
	if (opt->end_ssa == -1)
		opt->end_ssa = SM_I(sbi)->main_segments;
	if (opt->start_sit != -1)
		sit_dump(sbi, opt->start_sit, opt->end_sit);
	if (opt->start_ssa != -1)
		ssa_dump(sbi, opt->start_ssa, opt->end_ssa);
	if (opt->blk_addr != -1) {
		dump_inode_from_blkaddr(sbi, opt->blk_addr);
		goto cleanup;
	}

	dump_node(sbi, opt->nid);

cleanup:
	fsck_free(sbi);
	return 0;
}

int main (int argc, char **argv)
{
	struct f2fs_sb_info *sbi = &gfsck.sbi;
	int ret = 0;

	f2fs_init_configuration(&config);

	f2fs_parse_options(argc, argv);

	if (f2fs_dev_is_umounted(&config) < 0)
		return -1;

	/* Get device */
	if (f2fs_get_device_info(&config) < 0)
		return -1;

	if (f2fs_do_mount(sbi) < 0)
		return -1;

	switch (config.func) {
		case FSCK:
			ret = do_fsck(sbi);
			break;
		case DUMP:
			ret = do_dump(sbi);
			break;
	}

	f2fs_do_umount(sbi);

	f2fs_finalize_device(&config);

	printf("\nDone.\n");
	return ret;
}
