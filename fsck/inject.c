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
	MSG(0, "  --dry-run do not really inject\n");

	exit(1);
}

int inject_parse_options(int argc, char *argv[], struct inject_option *opt)
{
	int o = 0;
	const char *option_string = "d:V";
	struct option long_opt[] = {
		{"dry-run", no_argument, 0, 1},
		{0, 0, 0, 0}
	};

	while ((o = getopt_long(argc, argv, option_string,
				long_opt, NULL)) != EOF) {
		switch (o) {
		case 1:
			c.dry_run = 1;
			MSG(0, "Info: Dry run\n");
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
		default:
			return EUNKNOWN_OPT;
		}
	}

	return 0;
}

int do_inject(struct f2fs_sb_info *sbi)
{
	int ret = -EINVAL;

	return ret;
}
