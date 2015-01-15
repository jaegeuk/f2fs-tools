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

struct f2fs_fsck gfsck;

void fsck_usage()
{
	MSG(0, "\nUsage: fsck.f2fs [options] device\n");
	MSG(0, "[options]:\n");
	MSG(0, "  -a check/fix potential corruption, reported by f2fs\n");
	MSG(0, "  -d debug level [default:0]\n");
	MSG(0, "  -f check/fix entire partition\n");
	MSG(0, "  -t show directory tree [-d -1]\n");
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
		const char *option_string = "ad:ft";

		config.func = FSCK;
		while ((option = getopt(argc, argv, option_string)) != EOF) {
			switch (option) {
			case 'a':
				config.auto_fix = 1;
				MSG(0, "Info: Fix the reported corruption.\n");
				break;
			case 'd':
				config.dbg_lv = atoi(optarg);
				MSG(0, "Info: Debug level = %d\n",
							config.dbg_lv);
				break;
			case 'f':
				config.fix_on = 1;
				MSG(0, "Info: Force to fix corruption\n");
				break;
			case 't':
				config.dbg_lv = -1;
				break;
			default:
				MSG(0, "\tError: Unknown option %c\n", option);
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
			int ret = 0;

			switch (option) {
			case 'd':
				config.dbg_lv = atoi(optarg);
				MSG(0, "Info: Debug level = %d\n",
							config.dbg_lv);
				break;
			case 'i':
				if (strncmp(optarg, "0x", 2))
					ret = sscanf(optarg, "%d",
							&dump_opt.nid);
				else
					ret = sscanf(optarg, "%x",
							&dump_opt.nid);
				break;
			case 's':
				ret = sscanf(optarg, "%d~%d",
							&dump_opt.start_sit,
							&dump_opt.end_sit);
				break;
			case 'a':
				ret = sscanf(optarg, "%d~%d",
							&dump_opt.start_ssa,
							&dump_opt.end_ssa);
				break;
			case 'b':
				if (strncmp(optarg, "0x", 2))
					ret = sscanf(optarg, "%d",
							&dump_opt.blk_addr);
				else
					ret = sscanf(optarg, "%x",
							&dump_opt.blk_addr);
				break;
			default:
				MSG(0, "\tError: Unknown option %c\n", option);
				dump_usage();
				break;
			}
			ASSERT(ret >= 0);
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

static void do_fsck(struct f2fs_sb_info *sbi)
{
	u32 blk_cnt;

	fsck_init(sbi);

	fsck_chk_orphan_node(sbi);

	/* Traverse all block recursively from root inode */
	blk_cnt = 1;
	fsck_chk_node_blk(sbi, NULL, sbi->root_ino_num,
			F2FS_FT_DIR, TYPE_INODE, &blk_cnt);
	fsck_verify(sbi);
	fsck_free(sbi);
}

static void do_dump(struct f2fs_sb_info *sbi)
{
	struct dump_option *opt = (struct dump_option *)config.private;
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	u32 flag = le32_to_cpu(ckpt->ckpt_flags);

	fsck_init(sbi);

	if (opt->end_sit == -1)
		opt->end_sit = SM_I(sbi)->main_segments;
	if (opt->end_ssa == -1)
		opt->end_ssa = SM_I(sbi)->main_segments;
	if (opt->start_sit != -1)
		sit_dump(sbi, opt->start_sit, opt->end_sit);
	if (opt->start_ssa != -1)
		ssa_dump(sbi, opt->start_ssa, opt->end_ssa);
	if (opt->blk_addr != -1) {
		dump_info_from_blkaddr(sbi, opt->blk_addr);
		goto cleanup;
	}

	MSG(0, "Info: checkpoint state = %x : ", flag);
	if (flag & CP_FSCK_FLAG)
		MSG(0, "%s", " fsck");
	if (flag & CP_ERROR_FLAG)
		MSG(0, "%s", " error");
	if (flag & CP_COMPACT_SUM_FLAG)
		MSG(0, "%s", " compacted_summary");
	if (flag & CP_ORPHAN_PRESENT_FLAG)
		MSG(0, "%s", " orphan_inodes");
	if (flag & CP_FASTBOOT_FLAG)
		MSG(0, "%s", " fastboot");
	if (flag & CP_UMOUNT_FLAG)
		MSG(0, "%s", " unmount");
	else
		MSG(0, "%s", " sudden-power-off");
	MSG(0, "\n");

	dump_node(sbi, opt->nid);
cleanup:
	fsck_free(sbi);
}

int main(int argc, char **argv)
{
	struct f2fs_sb_info *sbi;
	int ret = 0;

	f2fs_init_configuration(&config);

	f2fs_parse_options(argc, argv);

	if (f2fs_dev_is_umounted(&config) < 0)
		return -1;

	/* Get device */
	if (f2fs_get_device_info(&config) < 0)
		return -1;
fsck_again:
	memset(&gfsck, 0, sizeof(gfsck));
	gfsck.sbi.fsck = &gfsck;
	sbi = &gfsck.sbi;

	ret = f2fs_do_mount(sbi);
	if (ret == 1) {
		free(sbi->ckpt);
		free(sbi->raw_super);
		goto out;
	} else if (ret < 0)
		return -1;

	switch (config.func) {
	case FSCK:
		do_fsck(sbi);
		break;
	case DUMP:
		do_dump(sbi);
		break;
	}

	f2fs_do_umount(sbi);
out:
	if (config.func == FSCK && config.bug_on) {
		if (config.fix_on == 0 && config.auto_fix == 0) {
			char ans[255] = {0};
retry:
			printf("Do you want to fix this partition? [Y/N] ");
			ret = scanf("%s", ans);
			ASSERT(ret >= 0);
			if (!strcasecmp(ans, "y"))
				config.fix_on = 1;
			else if (!strcasecmp(ans, "n"))
				config.fix_on = 0;
			else
				goto retry;

			if (config.fix_on)
				goto fsck_again;
		}
	}
	f2fs_finalize_device(&config);

	printf("\nDone.\n");
	return 0;
}
