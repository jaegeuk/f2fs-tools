/**
 * inject.h
 *
 * Copyright (c) 2024 OPPO Mobile Comm Corp., Ltd.
 *             http://www.oppo.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _INJECT_H_
#define _INJECT_H_

#include <stdio.h>
#include <stdint.h>
#include <limits.h>

#include "f2fs_fs.h"
#include "fsck.h"

struct inject_option {
	const char *mb;		/* member name */
	unsigned int idx;	/* slot index */
	long long val;		/* new value */
	char *str;		/* new string */
	int sb;			/* which sb */
	int cp;			/* which cp */
};

void inject_usage(void);
int inject_parse_options(int argc, char *argv[], struct inject_option *inject_opt);
int do_inject(struct f2fs_sb_info *sbi);
#endif
