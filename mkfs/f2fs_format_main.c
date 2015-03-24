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
//#include <linux/fs.h>
#include <uuid/uuid.h>

#include "f2fs_fs.h"
#include "f2fs_format_utils.h"

extern struct f2fs_configuration config;

static void mkfs_usage()
{
	MSG(0, "\nUsage: mkfs.f2fs [options] device [sectors]\n");
	MSG(0, "[options]:\n");
	MSG(0, "  -a heap-based allocation [default:1]\n");
	MSG(0, "  -d debug level [default:0]\n");
	MSG(0, "  -e [extension list] e.g. \"mp3,gif,mov\"\n");
	MSG(0, "  -l label\n");
	MSG(0, "  -o overprovision ratio [default:5]\n");
	MSG(0, "  -q quiet mode\n");
	MSG(0, "  -s # of segments per section [default:1]\n");
	MSG(0, "  -z # of sections per zone [default:1]\n");
	MSG(0, "  -t 0: nodiscard, 1: discard [default:1]\n");
	MSG(0, "sectors: number of sectors. [default: determined by device size]\n");
	exit(1);
}

static void f2fs_show_info()
{
	MSG(0, "\n\tF2FS-tools: mkfs.f2fs Ver: %s (%s)\n\n",
				F2FS_TOOLS_VERSION,
				F2FS_TOOLS_DATE);
	if (config.heap == 0)
		MSG(0, "Info: Disable heap-based policy\n");

	MSG(0, "Info: Debug level = %d\n", config.dbg_lv);
	if (config.extension_list)
		MSG(0, "Info: Add new extension list\n");

	if (config.vol_label)
		MSG(0, "Info: Label = %s\n", config.vol_label);
	MSG(0, "Info: Overprovision ratio = %u%%\n", config.overprovision);
	MSG(0, "Info: Segments per section = %d\n", config.segs_per_sec);
	MSG(0, "Info: Sections per zone = %d\n", config.secs_per_zone);
	MSG(0, "Info: Trim is %s\n", config.trim ? "enabled": "disabled");
}

static void f2fs_parse_options(int argc, char *argv[])
{
	static const char *option_string = "qa:d:e:l:o:s:z:t:";
	int32_t option=0;

	while ((option = getopt(argc,argv,option_string)) != EOF) {
		switch (option) {
		case 'q':
			config.dbg_lv = -1;
			break;
		case 'a':
			config.heap = atoi(optarg);
			break;
		case 'd':
			config.dbg_lv = atoi(optarg);
			break;
		case 'e':
			config.extension_list = strdup(optarg);
			break;
		case 'l':		/*v: volume label */
			if (strlen(optarg) > 512) {
				MSG(0, "Error: Volume Label should be less than\
						512 characters\n");
				mkfs_usage();
			}
			config.vol_label = optarg;
			break;
		case 'o':
			config.overprovision = atoi(optarg);
			break;
		case 's':
			config.segs_per_sec = atoi(optarg);
			break;
		case 'z':
			config.secs_per_zone = atoi(optarg);
			break;
		case 't':
			config.trim = atoi(optarg);
			break;
		default:
			MSG(0, "\tError: Unknown option %c\n",option);
			mkfs_usage();
			break;
		}
	}

	if (optind >= argc) {
		MSG(0, "\tError: Device not specified\n");
		mkfs_usage();
	}
	config.device_name = argv[optind];

	if ((optind + 1) < argc) {
		/* We have a sector count. */
		config.total_sectors = atoll(argv[optind+1]);
		MSG(1, "\ttotal_sectors=%"PRIx64" (%"PRIx64" bytes)\n",
				config.total_sectors,
				config.total_sectors * 512);
	}

	config.reserved_segments  =
			(2 * (100 / config.overprovision + 1) + 6)
			* config.segs_per_sec;
	config.segs_per_zone = config.segs_per_sec * config.secs_per_zone;
}

int main(int argc, char *argv[])
{
	f2fs_init_configuration(&config);

	f2fs_parse_options(argc, argv);

	f2fs_show_info();

	if (f2fs_dev_is_umounted(&config) < 0)
		return -1;

	if (f2fs_get_device_info(&config) < 0)
		return -1;

	if (f2fs_format_device() < 0)
		return -1;

	f2fs_finalize_device(&config);

	MSG(0, "Info: format successful\n");

	return 0;
}
