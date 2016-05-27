/*
 * This file is copied from libzbc.
 *
 * Copyright (C) 2009-2014, HGST, Inc.  All rights reserved.
 *
 * This software is distributed under the terms of the BSD 2-clause license,
 * "as is," without technical support, and WITHOUT ANY WARRANTY, without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. You should have received a copy of the BSD 2-clause license along
 * with libzbc. If not, see  <http://opensource.org/licenses/BSD-2-Clause>.
 *
 * Author: Damien Le Moal (damien.lemoal@hgst.com)
 *         Christophe Louargant (christophe.louargant@hgst.com)
 */

#ifndef __LIBZBC_SG_H__
#define __LIBZBC_SG_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/types.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <scsi/scsi.h>
#include <scsi/sg.h>

#define zbc_error(format, args...)			\
	fprintf(stderr, "[ERROR] " format, ##args)

/**
 * SG SCSI command names.
 */
enum {

	ZBC_SG_TEST_UNIT_READY = 0,
	ZBC_SG_INQUIRY,
	ZBC_SG_READ_CAPACITY,
	ZBC_SG_READ,
	ZBC_SG_WRITE,
	ZBC_SG_SYNC_CACHE,
	ZBC_SG_REPORT_ZONES,
	ZBC_SG_OPEN_ZONE,
	ZBC_SG_CLOSE_ZONE,
	ZBC_SG_FINISH_ZONE,
	ZBC_SG_RESET_WRITE_POINTER,
	ZBC_SG_SET_ZONES,
	ZBC_SG_SET_WRITE_POINTER,
	ZBC_SG_ATA12,
	ZBC_SG_ATA16,

	ZBC_SG_CMD_NUM,
};

/**
 * Test unit ready command definition.
 */
#define ZBC_SG_TEST_UNIT_READY_CDB_OPCODE       0x00
#define ZBC_SG_TEST_UNIT_READY_CDB_LENGTH       6
#define ZBC_ZONE_DESCRIPTOR_LENGTH		64

/**
 * Number of bytes in the buffer before the first Zone Descriptor.
 */
#define ZBC_ZONE_DESCRIPTOR_OFFSET		64

/**
 * Inquiry command definition.
 */
#define ZBC_SG_INQUIRY_CDB_OPCODE               0x12
#define ZBC_SG_INQUIRY_CDB_LENGTH               6
#define ZBC_SG_INQUIRY_REPLY_LEN                96
#define ZBC_SG_INQUIRY_REPLY_LEN_VPD_PAGE_B1    64
#define ZBC_SG_INQUIRY_REPLY_LEN_VPD_PAGE_B6    64

/**
 * Read capacity command definition.
 */
#define ZBC_SG_READ_CAPACITY_CDB_OPCODE         0x9E
#define ZBC_SG_READ_CAPACITY_CDB_SA             0x10
#define ZBC_SG_READ_CAPACITY_CDB_LENGTH         16
#define ZBC_SG_READ_CAPACITY_REPLY_LEN          32

/**
 * Read command definition.
 */
#define ZBC_SG_READ_CDB_OPCODE                  0x88
#define ZBC_SG_READ_CDB_LENGTH                  16

/**
 * Write command definition.
 */
#define ZBC_SG_WRITE_CDB_OPCODE                 0x8A
#define ZBC_SG_WRITE_CDB_LENGTH                 16

/**
 * Sync cache command definition.
 */
#define ZBC_SG_SYNC_CACHE_CDB_OPCODE            0x91
#define ZBC_SG_SYNC_CACHE_CDB_LENGTH            16

/**
 * Report zones command definition.
 */
#define ZBC_SG_REPORT_ZONES_CDB_OPCODE          0x95
#define ZBC_SG_REPORT_ZONES_CDB_SA              0x00
#define ZBC_SG_REPORT_ZONES_CDB_LENGTH          16

/**
 * Open zone command definition.
 */
#define ZBC_SG_OPEN_ZONE_CDB_OPCODE             0x94
#define ZBC_SG_OPEN_ZONE_CDB_SA                 0x03
#define ZBC_SG_OPEN_ZONE_CDB_LENGTH             16

/**
 * Close zone command definition.
 */
#define ZBC_SG_CLOSE_ZONE_CDB_OPCODE            0x94
#define ZBC_SG_CLOSE_ZONE_CDB_SA                0x01
#define ZBC_SG_CLOSE_ZONE_CDB_LENGTH            16

/**
 * Finish zone command definition.
 */
#define ZBC_SG_FINISH_ZONE_CDB_OPCODE           0x94
#define ZBC_SG_FINISH_ZONE_CDB_SA               0x02
#define ZBC_SG_FINISH_ZONE_CDB_LENGTH           16

/**
 * Reset write pointer command definition.
 */
#define ZBC_SG_RESET_WRITE_POINTER_CDB_OPCODE   0x94
#define ZBC_SG_RESET_WRITE_POINTER_CDB_SA       0x04
#define ZBC_SG_RESET_WRITE_POINTER_CDB_LENGTH   16

/**
 * Set zones command definition.
 */
#define ZBC_SG_SET_ZONES_CDB_OPCODE             0x9F
#define ZBC_SG_SET_ZONES_CDB_SA                 0x15
#define ZBC_SG_SET_ZONES_CDB_LENGTH             16

/**
 * Set write pointer command definition.
 */
#define ZBC_SG_SET_WRITE_POINTER_CDB_OPCODE     0x9F
#define ZBC_SG_SET_WRITE_POINTER_CDB_SA         0x16
#define ZBC_SG_SET_WRITE_POINTER_CDB_LENGTH     16

/**
 * ATA pass through 12.
 */
#define ZBC_SG_ATA12_CDB_OPCODE			0xA1
#define ZBC_SG_ATA12_CDB_LENGTH			12

/**
 * ATA pass through 16.
 */
#define ZBC_SG_ATA16_CDB_OPCODE			0x85
#define ZBC_SG_ATA16_CDB_LENGTH			16

/**
 * Command sense buffer maximum length.
 */
#define ZBC_SG_SENSE_MAX_LENGTH                 64

/**
 * Maximum command CDB length.
 */
#define ZBC_SG_CDB_MAX_LENGTH                   16

/**
 * Status codes.
 */
#define ZBC_SG_CHECK_CONDITION      		0x02

/**
 * Host status codes.
 */
#define ZBC_SG_DID_OK 				0x00 /* No error */
#define ZBC_SG_DID_NO_CONNECT 			0x01 /* Couldn't connect before timeout period */
#define ZBC_SG_DID_BUS_BUSY 			0x02 /* BUS stayed busy through time out period */
#define ZBC_SG_DID_TIME_OUT 			0x03 /* Timed out for other reason */
#define ZBC_SG_DID_BAD_TARGET 			0x04 /* Bad target, device not responding? */
#define ZBC_SG_DID_ABORT 			0x05 /* Told to abort for some other reason. */
#define ZBC_SG_DID_PARITY 			0x06 /* Parity error. */
#define ZBC_SG_DID_ERROR 			0x07 /* Internal error detected in the host adapter. */
#define ZBC_SG_DID_RESET 			0x08 /* The SCSI bus (or this device) has been reset. */
#define ZBC_SG_DID_BAD_INTR 			0x09 /* Got an unexpected interrupt */
#define ZBC_SG_DID_PASSTHROUGH 			0x0a /* Forced command past mid-layer. */
#define ZBC_SG_DID_SOFT_ERROR 			0x0b /* The low level driver wants a retry. */

/**
 * Driver status codes.
 */
#define ZBC_SG_DRIVER_OK 			0x00
#define ZBC_SG_DRIVER_BUSY 			0x01
#define ZBC_SG_DRIVER_SOFT 			0x02
#define ZBC_SG_DRIVER_MEDIA 			0x03
#define ZBC_SG_DRIVER_ERROR 			0x04
#define ZBC_SG_DRIVER_INVALID 			0x05
#define ZBC_SG_DRIVER_TIMEOUT 			0x06
#define ZBC_SG_DRIVER_HARD 			0x07
#define ZBC_SG_DRIVER_SENSE         		0x08
#define ZBC_SG_DRIVER_STATUS_MASK   		0x0f

/**
 * Driver status code flags ('or'ed with code)
 */
#define ZBC_SG_DRIVER_SUGGEST_RETRY 		0x10
#define ZBC_SG_DRIVER_SUGGEST_ABORT 		0x20
#define ZBC_SG_DRIVER_SUGGEST_REMAP 		0x30
#define ZBC_SG_DRIVER_SUGGEST_DIE 		0x40
#define ZBC_SG_DRIVER_SUGGEST_SENSE 		0x80
#define ZBC_SG_DRIVER_FLAGS_MASK   		0xf0

/***** Type definitions *****/

/**
 * SG command descriptor. Used to process SCSI commands.
 */
typedef struct zbc_sg_cmd {

	int                 code;

	int                 cdb_opcode;
	int                 cdb_sa;
	size_t              cdb_sz;
	uint8_t             cdb[ZBC_SG_CDB_MAX_LENGTH];

	size_t              sense_bufsz;
	uint8_t             sense_buf[ZBC_SG_SENSE_MAX_LENGTH];

	int                 out_buf_needfree;
	size_t              out_bufsz;
	uint8_t             *out_buf;

	sg_io_hdr_t         io_hdr;

} zbc_sg_cmd_t;

/**
 * Zone descriptor.
 */
struct zbc_zone {

	uint64_t                    zbz_length;
	uint64_t                    zbz_start;
	uint64_t                    zbz_write_pointer;

	uint8_t                     zbz_type;
	uint8_t                     zbz_condition;
	uint8_t                     zbz_flags;

	uint8_t                     __pad[5];

};
typedef struct zbc_zone zbc_zone_t;

#define ZBC_FORCE_ATA_RW       	0x40000000
#define zbc_open_flags(f)           ((f) & ~ZBC_FORCE_ATA_RW)

/**
 * Zone type.
 */
enum zbc_zone_type {
	ZBC_ZT_CONVENTIONAL         = 0x01,
	ZBC_ZT_SEQUENTIAL_REQ       = 0x02,
	ZBC_ZT_SEQUENTIAL_PREF      = 0x03,
};
#define zbc_zone_type(z)                ((int)(z)->zbz_type)

#define zbc_zone_conventional(z)        ((z)->zbz_type == ZBC_ZT_CONVENTIONAL)
static inline const char *zbc_zone_type_str(enum zbc_zone_type type)
{
	switch( type ) {
	case ZBC_ZT_CONVENTIONAL:
		return( "Conventional" );
	case ZBC_ZT_SEQUENTIAL_REQ:
		return( "Sequential-write-required" );
	case ZBC_ZT_SEQUENTIAL_PREF:
		return( "Sequential-write-preferred" );
	}
	return( "Unknown-type" );
}

/**
 * Zone condition.
 */
enum zbc_zone_condition {
	ZBC_ZC_NOT_WP               = 0x00,
	ZBC_ZC_EMPTY                = 0x01,
	ZBC_ZC_IMP_OPEN             = 0x02,
	ZBC_ZC_EXP_OPEN             = 0x03,
	ZBC_ZC_CLOSED               = 0x04,
	ZBC_ZC_RDONLY               = 0x0d,
	ZBC_ZC_FULL                 = 0x0e,
	ZBC_ZC_OFFLINE              = 0x0f,
};

/**
 * zbc_zone_cond_str - returns a string describing a zone condition.
 * @zone: (IN)  ZBC_ZC_NOT_WP, ZBC_ZC_EMPTY, ZBC_ZC_IMP_OPEN, ZBC_ZC_EXP_OPEN,
 *              ZBC_ZC_CLOSED, ZBC_ZC_RDONLY, ZBC_ZC_FULL or ZBC_ZC_OFFLINE
 *
 * Returns a string describing a zone condition.
 */
static inline const char *zbc_zone_condition_str(enum zbc_zone_condition cond)
{
	switch( cond ) {
	case ZBC_ZC_NOT_WP:
		return "Not-write-pointer";
	case ZBC_ZC_EMPTY:
		return "Empty";
	case ZBC_ZC_IMP_OPEN:
		return "Implicit-open";
	case ZBC_ZC_EXP_OPEN:
		return "Explicit-open";
	case ZBC_ZC_CLOSED:
		return "Closed";
	case ZBC_ZC_RDONLY:
		return "Read-only";
	case ZBC_ZC_FULL:
		return "Full";
	case ZBC_ZC_OFFLINE:
		return "Offline";
	}
	return "Unknown-cond";
}

#define zbc_zone_condition(z)           ((int)(z)->zbz_condition)
#define zbc_zone_start_lba(z)           ((unsigned long long)((z)->zbz_start))
#define zbc_zone_length(z)              ((unsigned long long)((z)->zbz_length))
#define zbc_zone_wp_lba(z)              ((unsigned long long)((z)->zbz_write_pointer))

/**
 * Zone flags: need reset, and non-seq write.
 */
enum zbc_zone_flags {
	ZBC_ZF_NEED_RESET           = 0x0001,
	ZBC_ZF_NON_SEQ              = 0x0002,
};
#define zbc_zone_need_reset(z)          (((z)->zbz_flags & ZBC_ZF_NEED_RESET) != 0)
#define zbc_zone_non_seq(z)          	(((z)->zbz_flags & ZBC_ZF_NON_SEQ) != 0)

#define zbc_sg_cmd_driver_status(cmd)		((cmd)->io_hdr.driver_status & ZBC_SG_DRIVER_STATUS_MASK)
#define zbc_sg_cmd_driver_flags(cmd)		((cmd)->io_hdr.driver_status & ZBC_SG_DRIVER_FLAGS_MASK)

union converter {
	uint8_t         val_buf[8];
	uint16_t        val16;
	uint32_t        val32;
	uint64_t        val64;
};

#endif /* __LIBZBC_SG_H__ */
