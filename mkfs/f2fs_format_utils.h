/**
 * f2fs_format_utils.c
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * Dual licensed under the GPL or LGPL version 2 licenses.
 */
#define _LARGEFILE64_SOURCE

#include "f2fs_fs.h"

extern struct f2fs_configuration config;

int f2fs_trim_device(void);
int f2fs_format_device(void);
