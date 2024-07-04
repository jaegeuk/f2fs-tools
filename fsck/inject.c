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
	MSG(0, "  --sb <0|1|2> --mb <name> [--idx <index>] --val/str <value/string> inject superblock\n");
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

int do_inject(struct f2fs_sb_info *sbi)
{
	struct inject_option *opt = (struct inject_option *)c.private;
	int ret = -EINVAL;

	if (opt->sb >= 0)
		ret = inject_sb(sbi, opt);

	return ret;
}
