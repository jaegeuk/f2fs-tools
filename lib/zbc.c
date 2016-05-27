/*
 * This file is mostly copied from libzbc.
 *
 * Copyright (C) 2009-2014, HGST, Inc.  All rights reserved.
 *
 * This software is distributed under the terms of the BSD 2-clause license,
 * "as is," without technical support, and WITHOUT ANY WARRANTY, without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. You should have received a copy of the BSD 2-clause license along
 * with libzbc. If not, see  <http://opensource.org/licenses/BSD-2-Clause>.
 *
 * Authors: Damien Le Moal (damien.lemoal@hgst.com)
 *          Christophe Louargant (christophe.louargant@hgst.com)
 *
 * Integrated into f2fs-tools by:
 *          Jaegeuk Kim (jaegeuk@kernel.org)
 */

#include <f2fs_fs.h>

#include "zbc.h"

static struct zbc_sg_cmd_s
{

    char                *cdb_cmd_name;
    int                 cdb_opcode;
    int                 cdb_sa;
    size_t              cdb_length;
    int			dir;

} zbc_sg_cmd_list[ZBC_SG_CMD_NUM] = {

    /* ZBC_SG_TEST_UNIT_READY */
    {
        "TEST UNIT READY",
        ZBC_SG_TEST_UNIT_READY_CDB_OPCODE,
        0,
        ZBC_SG_TEST_UNIT_READY_CDB_LENGTH,
	SG_DXFER_NONE
    },

    /* ZBC_SG_INQUIRY */
    {
        "INQUIRY",
        ZBC_SG_INQUIRY_CDB_OPCODE,
        0,
        ZBC_SG_INQUIRY_CDB_LENGTH,
	SG_DXFER_FROM_DEV
    },

    /* ZBC_SG_READ_CAPACITY */
    {
        "READ CAPACITY 16",
        ZBC_SG_READ_CAPACITY_CDB_OPCODE,
        ZBC_SG_READ_CAPACITY_CDB_SA,
        ZBC_SG_READ_CAPACITY_CDB_LENGTH,
	SG_DXFER_FROM_DEV
    },

    /* ZBC_SG_READ */
    {
        "READ 16",
        ZBC_SG_READ_CDB_OPCODE,
        0,
        ZBC_SG_READ_CDB_LENGTH,
	SG_DXFER_FROM_DEV
    },

    /* ZBC_SG_WRITE */
    {
        "WRITE 16",
        ZBC_SG_WRITE_CDB_OPCODE,
        0,
        ZBC_SG_WRITE_CDB_LENGTH,
	SG_DXFER_TO_DEV
    },

    /* ZBC_SG_SYNC_CACHE */
    {
        "SYNCHRONIZE CACHE 16",
        ZBC_SG_SYNC_CACHE_CDB_OPCODE,
        0,
        ZBC_SG_SYNC_CACHE_CDB_LENGTH,
	SG_DXFER_NONE
    },

    /* ZBC_SG_REPORT_ZONES */
    {
        "REPORT ZONES",
        ZBC_SG_REPORT_ZONES_CDB_OPCODE,
        ZBC_SG_REPORT_ZONES_CDB_SA,
        ZBC_SG_REPORT_ZONES_CDB_LENGTH,
	SG_DXFER_FROM_DEV
    },

    /* ZBC_SG_OPEN_ZONE */
    {
        "OPEN ZONE",
        ZBC_SG_OPEN_ZONE_CDB_OPCODE,
        ZBC_SG_OPEN_ZONE_CDB_SA,
        ZBC_SG_OPEN_ZONE_CDB_LENGTH,
	SG_DXFER_NONE
    },

    /* ZBC_SG_CLOSE_ZONE */
    {
        "CLOSE ZONE",
        ZBC_SG_CLOSE_ZONE_CDB_OPCODE,
        ZBC_SG_CLOSE_ZONE_CDB_SA,
        ZBC_SG_CLOSE_ZONE_CDB_LENGTH,
	SG_DXFER_NONE
    },

    /* ZBC_SG_FINISH_ZONE */
    {
        "FINISH ZONE",
        ZBC_SG_FINISH_ZONE_CDB_OPCODE,
        ZBC_SG_FINISH_ZONE_CDB_SA,
        ZBC_SG_FINISH_ZONE_CDB_LENGTH,
	SG_DXFER_NONE
    },

    /* ZBC_SG_RESET_WRITE_POINTER */
    {
        "RESET WRITE POINTER",
        ZBC_SG_RESET_WRITE_POINTER_CDB_OPCODE,
        ZBC_SG_RESET_WRITE_POINTER_CDB_SA,
        ZBC_SG_RESET_WRITE_POINTER_CDB_LENGTH,
	SG_DXFER_NONE
    },

    /* ZBC_SG_SET_ZONES */
    {
        "SET ZONES",
        ZBC_SG_SET_ZONES_CDB_OPCODE,
        ZBC_SG_SET_ZONES_CDB_SA,
        ZBC_SG_SET_ZONES_CDB_LENGTH,
	SG_DXFER_NONE
    },

    /* ZBC_SG_SET_WRITE_POINTER */
    {
        "SET WRITE POINTER",
        ZBC_SG_SET_WRITE_POINTER_CDB_OPCODE,
        ZBC_SG_SET_WRITE_POINTER_CDB_SA,
        ZBC_SG_SET_WRITE_POINTER_CDB_LENGTH,
	SG_DXFER_NONE
    },

    /* ZBC_SG_ATA12 */
    {
	"ATA 12",
	ZBC_SG_ATA12_CDB_OPCODE,
	0,
        ZBC_SG_ATA12_CDB_LENGTH,
	0
    },

    /* ZBC_SG_ATA16 */
    {
	"ATA 16",
	ZBC_SG_ATA16_CDB_OPCODE,
	0,
        ZBC_SG_ATA16_CDB_LENGTH,
	0
    }
};

static void zbc_sg_cmd_set_bytes(uint8_t *cmd, void *buf, int bytes)
{
	uint8_t *v = (uint8_t *) buf;
	int i;

	for (i = 0; i < bytes; i++) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		/* The least significant byte is stored last */
		cmd[bytes - i - 1] = v[i];
#else
		/* The most significant byte is stored first */
		cmd[i] = v[i];
#endif
	}
	return;
}

static void zbc_sg_cmd_get_bytes(uint8_t *val, union converter *conv, int bytes)
{
	uint8_t *v = (uint8_t *) val;
	int i;

	memset(conv, 0, sizeof(union converter));

	for(i = 0; i < bytes; i++) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		conv->val_buf[bytes - i - 1] = v[i];
#else
		conv->val_buf[i] = v[i];
#endif
	}
	return;
}

static inline void zbc_sg_cmd_set_int64(uint8_t *buf, uint64_t val)
{
	zbc_sg_cmd_set_bytes(buf, &val, 8);
	return;
}

static inline void zbc_sg_cmd_set_int32(uint8_t *buf, uint32_t val)
{
	zbc_sg_cmd_set_bytes(buf, &val, 4);
	return;
}

static inline uint32_t zbc_sg_cmd_get_int32(uint8_t *buf)
{
	union converter conv;

	zbc_sg_cmd_get_bytes(buf, &conv, 4);
	return conv.val32;
}

static inline uint64_t zbc_sg_cmd_get_int64(uint8_t *buf)
{
	union converter conv;

	zbc_sg_cmd_get_bytes(buf, &conv, 8);
	return( conv.val64 );

}

static void zbc_sg_cmd_destroy(zbc_sg_cmd_t *cmd)
{
	/* Free the command */
	if (!cmd)
		return;

	if (cmd->out_buf && cmd->out_buf_needfree) {
		free(cmd->out_buf);
		cmd->out_buf = NULL;
		cmd->out_bufsz = 0;
	}
	memset(cmd, 0, sizeof(*cmd));
	return;
}

static int zbc_sg_cmd_init(zbc_sg_cmd_t *cmd, int cmd_code,
				uint8_t *out_buf, size_t out_bufsz)
{
	int ret = 0;

	if ((!cmd) || (cmd_code < 0) || (cmd_code >= ZBC_SG_CMD_NUM) ) {
		ERR_MSG("Invalid command specified\n");
		return -EINVAL;
	}

	/* Set command */
	memset(cmd, 0, sizeof(zbc_sg_cmd_t));
	cmd->code = cmd_code;
	cmd->cdb_sz = zbc_sg_cmd_list[cmd_code].cdb_length;
	cmd->cdb_opcode = zbc_sg_cmd_list[cmd_code].cdb_opcode;
	cmd->cdb_sa = zbc_sg_cmd_list[cmd_code].cdb_sa;

	/* Set output buffer */
	if (out_buf) {
		/* Set specified buffer */
		if (!out_bufsz) {
			ERR_MSG("Invalid 0 output buffer size\n");
			ret = -EINVAL;
			goto out;
		}
		cmd->out_buf = out_buf;
		cmd->out_bufsz = out_bufsz;
	} else if (out_bufsz) {
		/* Allocate a buffer */
		ret = posix_memalign((void **)&cmd->out_buf,
				sysconf(_SC_PAGESIZE), out_bufsz);
		if ( ret != 0 ) {
			ERR_MSG("No memory for output buffer (%zu B)\n",
					out_bufsz);
			ret = -ENOMEM;
			goto out;
		}
		memset(cmd->out_buf, 0, out_bufsz);
		cmd->out_bufsz = out_bufsz;
		cmd->out_buf_needfree = 1;
	}

	/* OK: setup SGIO header */
	memset(&cmd->io_hdr, 0, sizeof(sg_io_hdr_t));

	cmd->io_hdr.interface_id    = 'S';
	cmd->io_hdr.timeout         = 20000;
	cmd->io_hdr.flags           = 0; //SG_FLAG_DIRECT_IO;

	cmd->io_hdr.cmd_len         = cmd->cdb_sz;
	cmd->io_hdr.cmdp            = &cmd->cdb[0];

	cmd->io_hdr.dxfer_direction = zbc_sg_cmd_list[cmd_code].dir;
	cmd->io_hdr.dxfer_len       = cmd->out_bufsz;
	cmd->io_hdr.dxferp          = cmd->out_buf;

	cmd->io_hdr.mx_sb_len       = ZBC_SG_SENSE_MAX_LENGTH;
	cmd->io_hdr.sbp             = cmd->sense_buf;
out:
	if (ret != 0)
		zbc_sg_cmd_destroy(cmd);

	return ret;
}

static char *zbc_sg_cmd_name(zbc_sg_cmd_t *cmd)
{
	char *name;

	if ((cmd->code >= 0)
			&& (cmd->code < ZBC_SG_CMD_NUM)) {
		name = zbc_sg_cmd_list[cmd->code].cdb_cmd_name;
	} else {
		name = "(UNKNOWN COMMAND)";
	}

	return name;
}

static void zbc_sg_set_sense(struct f2fs_configuration *c, uint8_t *sense_buf)
{
	if (sense_buf == NULL) {
		c->zbd_errno.sk       = 0x00;
		c->zbd_errno.asc_ascq = 0x0000;
	} else {
		if ((sense_buf[0] & 0x7F) == 0x72
				|| (sense_buf[0] & 0x7F) == 0x73) {
			/* store sense key, ASC/ASCQ */
			c->zbd_errno.sk       = sense_buf[1] & 0x0F;
			c->zbd_errno.asc_ascq = ((int)sense_buf[2] << 8) |
							(int)sense_buf[3];
		} else if ((sense_buf[0] & 0x7F) == 0x70
				|| (sense_buf[0] & 0x7F) == 0x71) {
			/* store sense key, ASC/ASCQ */
			c->zbd_errno.sk       = sense_buf[2] & 0x0F;
			c->zbd_errno.asc_ascq = ((int)sense_buf[12] << 8) |
							(int)sense_buf[13];
		}
	}
	return;
}

static int zbc_sg_cmd_exec(struct f2fs_configuration *c, zbc_sg_cmd_t *cmd)
{
	int ret;

	/* Send the SG_IO command */
	ret = ioctl(c->fd, SG_IO, &cmd->io_hdr);
	if (ret) {
		ERR_MSG("SG_IO ioctl failed (%s)\n", strerror(errno));
		goto out;
	}

	/* Reset errno */
	zbc_sg_set_sense(c, NULL);

	DBG(1, "Command %s done: status 0x%02x (0x%02x), host status 0x%04x, driver status 0x%04x (flags 0x%04x)\n",
			zbc_sg_cmd_name(cmd),
			(unsigned int)cmd->io_hdr.status,
			(unsigned int)cmd->io_hdr.masked_status,
			(unsigned int)cmd->io_hdr.host_status,
			(unsigned int)zbc_sg_cmd_driver_status(cmd),
			(unsigned int)zbc_sg_cmd_driver_flags(cmd));

	/* Check status */
	if (((cmd->code == ZBC_SG_ATA12) || (cmd->code == ZBC_SG_ATA16))
			&& (cmd->cdb[2] & (1 << 5)) ) {

		/* ATA command status */
		if (cmd->io_hdr.status != ZBC_SG_CHECK_CONDITION) {
			zbc_sg_set_sense(c, cmd->sense_buf);
			ret = -EIO;
			goto out;
		}

		if ((zbc_sg_cmd_driver_status(cmd) == ZBC_SG_DRIVER_SENSE)
				&& (cmd->io_hdr.sb_len_wr > 21)
				&& (cmd->sense_buf[21] != 0x50) ) {
			zbc_sg_set_sense(c, cmd->sense_buf);
			ret = -EIO;
			goto out;
		}
		cmd->io_hdr.status = 0;
	}

	if (cmd->io_hdr.status
			|| (cmd->io_hdr.host_status != ZBC_SG_DID_OK)
			|| (zbc_sg_cmd_driver_status(cmd) &&
			(zbc_sg_cmd_driver_status(cmd) != ZBC_SG_DRIVER_SENSE)) ) {

		ERR_MSG("Command %s failed with status 0x%02x (0x%02x), host status 0x%04x, driver status 0x%04x (flags 0x%04x)\n",
				zbc_sg_cmd_name(cmd),
				(unsigned int)cmd->io_hdr.status,
				(unsigned int)cmd->io_hdr.masked_status,
				(unsigned int)cmd->io_hdr.host_status,
				(unsigned int)zbc_sg_cmd_driver_status(cmd),
				(unsigned int)zbc_sg_cmd_driver_flags(cmd));
		zbc_sg_set_sense(c, cmd->sense_buf);
		ret = -EIO;
		goto out;
	}

	if (cmd->io_hdr.resid) {
		ERR_MSG("Transfer missing %d B of data\n",
				cmd->io_hdr.resid);
		cmd->out_bufsz -= cmd->io_hdr.resid;
	}
out:
	return ret;
}

#define ZBC_SCSI_REPORT_ZONES_BUFSZ     524288

int zbc_scsi_report_zones(struct f2fs_configuration *c)
{
	zbc_sg_cmd_t cmd;
	uint8_t *buf;
	zbc_zone_t *z, *zones = NULL;
	int i, buf_nz, ret;
	size_t bufsz;
	uint32_t idx = 0, nr_zones = 0;
	uint64_t next_lba = 0;
	int phase = 0;
next:
	bufsz = ZBC_ZONE_DESCRIPTOR_OFFSET;
	if (phase) {
		if (c->nr_zones - idx == 0)
			return 0;

		bufsz += (size_t)(c->nr_zones - idx) *
					ZBC_ZONE_DESCRIPTOR_LENGTH;
		if (bufsz > ZBC_SCSI_REPORT_ZONES_BUFSZ)
			bufsz = ZBC_SCSI_REPORT_ZONES_BUFSZ;
	}

	/* For in kernel ATA translation: align to 512 B */
	bufsz = (bufsz + 511) & ~511;

	/* Allocate and intialize report zones command */
	ret = zbc_sg_cmd_init(&cmd, ZBC_SG_REPORT_ZONES, NULL, bufsz);
	if (ret) {
		ERR_MSG("zbc_sg_cmd_init failed\n");
		return ret;
	}

	/* Fill command CDB:
	 * +=============================================================================+
	 * |  Bit|   7    |   6    |   5    |   4    |   3    |   2    |   1    |   0    |
	 * |Byte |        |        |        |        |        |        |        |        |
	 * |=====+==========================+============================================|
	 * | 0   |                           Operation Code (95h)                        |
	 * |-----+-----------------------------------------------------------------------|
	 * | 1   |      Reserved            |       Service Action (00h)                 |
	 * |-----+-----------------------------------------------------------------------|
	 * | 2   | (MSB)                                                                 |
	 * |- - -+---                        Zone Start LBA                           ---|
	 * | 9   |                                                                 (LSB) |
	 * |-----+-----------------------------------------------------------------------|
	 * | 10  | (MSB)                                                                 |
	 * |- - -+---                        Allocation Length                        ---|
	 * | 13  |                                                                 (LSB) |
	 * |-----+-----------------------------------------------------------------------|
	 * | 14  |Partial |Reserved|                 Reporting Options                   |
	 * |-----+-----------------------------------------------------------------------|
	 * | 15  |                           Control                                     |
	 * +=============================================================================+
	 */
	cmd.cdb[0] = ZBC_SG_REPORT_ZONES_CDB_OPCODE;
	cmd.cdb[1] = ZBC_SG_REPORT_ZONES_CDB_SA;
	zbc_sg_cmd_set_int64(&cmd.cdb[2], next_lba);
	zbc_sg_cmd_set_int32(&cmd.cdb[10], (unsigned int) bufsz);
	cmd.cdb[14] = 0;

	/* Send the SG_IO command */
	ret = zbc_sg_cmd_exec(c, &cmd);
	if (ret != 0)
		goto out;

	if (cmd.out_bufsz < ZBC_ZONE_DESCRIPTOR_OFFSET) {
		ERR_MSG("Not enough data received (need at least %d B, got %zu B)\n",
				ZBC_ZONE_DESCRIPTOR_OFFSET,
				cmd.out_bufsz);
		ret = -EIO;
		goto out;
	}

	/* Process output:
	 * +=============================================================================+
	 * |  Bit|   7    |   6    |   5    |   4    |   3    |   2    |   1    |   0    |
	 * |Byte |        |        |        |        |        |        |        |        |
	 * |=====+=======================================================================|
	 * |  0  | (MSB)                                                                 |
	 * |- - -+---               Zone List Length (n - 64)                         ---|
	 * |  3  |                                                                 (LSB) |
	 * |-----+-----------------------------------------------------------------------|
	 * |  4  |              Reserved             |               Same                |
	 * |-----+-----------------------------------------------------------------------|
	 * |  5  |                                                                       |
	 * |- - -+---                        Reserved                                 ---|
	 * |  7  |                                                                       |
	 * |-----+-----------------------------------------------------------------------|
	 * |  8  | (MSB)                                                                 |
	 * |- - -+---                      Maximum LBA                                ---|
	 * | 15  |                                                                 (LSB) |
	 * |-----+-----------------------------------------------------------------------|
	 * | 16  | (MSB)                                                                 |
	 * |- - -+---                        Reserved                                 ---|
	 * | 63  |                                                                 (LSB) |
	 * |=====+=======================================================================|
	 * |     |                       Vendor-Specific Parameters                      |
	 * |=====+=======================================================================|
	 * | 64  | (MSB)                                                                 |
	 * |- - -+---                  Zone Descriptor [first]                        ---|
	 * | 127 |                                                                 (LSB) |
	 * |-----+-----------------------------------------------------------------------|
	 * |                                    .                                        |
	 * |                                    .                                        |
	 * |                                    .                                        |
	 * |-----+-----------------------------------------------------------------------|
	 * |n-63 |                                                                       |
	 * |- - -+---                   Zone Descriptor [last]                        ---|
	 * | n   |                                                                       |
	 * +=============================================================================+
	 */

	/* Get number of zones in result */
	buf = (uint8_t *)cmd.out_buf;
	nr_zones = zbc_sg_cmd_get_int32(buf) / ZBC_ZONE_DESCRIPTOR_LENGTH;

	/* read # of zones and then get all the zone info */
	if (phase == 0) {
		c->nr_zones = nr_zones;
		c->nr_conventional = 0;
		zbc_sg_cmd_destroy(&cmd);
		phase++;
		goto next;
	}

	if (nr_zones > c->nr_zones - idx)
		nr_zones = c->nr_zones - idx;

	buf_nz = (cmd.out_bufsz - ZBC_ZONE_DESCRIPTOR_OFFSET) /
						ZBC_ZONE_DESCRIPTOR_LENGTH;
	if (nr_zones > buf_nz)
		nr_zones = buf_nz;

	if (!nr_zones) {
		ERR_MSG("No more zones\n");
		goto out;
	}

	/* Allocate zone array */
	zones = (zbc_zone_t *)malloc(sizeof(zbc_zone_t) * nr_zones);
	if (!zones) {
		ERR_MSG("No memory\n");
		goto out;
	}
	memset(zones, 0, sizeof(zbc_zone_t) * nr_zones);

	/* Get zone descriptors:
	 * +=============================================================================+
	 * |  Bit|   7    |   6    |   5    |   4    |   3    |   2    |   1    |   0    |
	 * |Byte |        |        |        |        |        |        |        |        |
	 * |=====+=======================================================================|
	 * |  0  |             Reserved              |            Zone type              |
	 * |-----+-----------------------------------------------------------------------|
	 * |  1  |          Zone condition           |    Reserved     |non-seq |  Reset |
	 * |-----+-----------------------------------------------------------------------|
	 * |  2  |                                                                       |
	 * |- - -+---                             Reserved                            ---|
	 * |  7  |                                                                       |
	 * |-----+-----------------------------------------------------------------------|
	 * |  8  | (MSB)                                                                 |
	 * |- - -+---                           Zone Length                           ---|
	 * | 15  |                                                                 (LSB) |
	 * |-----+-----------------------------------------------------------------------|
	 * | 16  | (MSB)                                                                 |
	 * |- - -+---                          Zone Start LBA                         ---|
	 * | 23  |                                                                 (LSB) |
	 * |-----+-----------------------------------------------------------------------|
	 * | 24  | (MSB)                                                                 |
	 * |- - -+---                         Write Pointer LBA                       ---|
	 * | 31  |                                                                 (LSB) |
	 * |-----+-----------------------------------------------------------------------|
	 * | 32  |                                                                       |
	 * |- - -+---                             Reserved                            ---|
	 * | 63  |                                                                       |
	 * +=============================================================================+
	 */
	buf += ZBC_ZONE_DESCRIPTOR_OFFSET;

	for(i = 0; i < nr_zones; i++) {
		zones[i].zbz_type = buf[0] & 0x0f;
		zones[i].zbz_condition = (buf[1] >> 4) & 0x0f;
		zones[i].zbz_length = zbc_sg_cmd_get_int64(&buf[8]);
		zones[i].zbz_start = zbc_sg_cmd_get_int64(&buf[16]);
		zones[i].zbz_write_pointer = zbc_sg_cmd_get_int64(&buf[24]);
		zones[i].zbz_flags = buf[1] & 0x03;

		buf += ZBC_ZONE_DESCRIPTOR_LENGTH;
	}

	for (i = 0; i < nr_zones; i++) {
		z = &zones[i];
		if ( zbc_zone_conventional(z) ) {
			c->nr_conventional++;
			DBG(1, "Zone %05d: type 0x%x (%s), cond 0x%x (%s), LBA %llu, %llu sectors, wp N/A\n",
				i + idx,
				zbc_zone_type(z),
				zbc_zone_type_str(zbc_zone_type(z)),
				zbc_zone_condition(z),
				zbc_zone_condition_str(zbc_zone_condition(z)),
				zbc_zone_start_lba(z),
				zbc_zone_length(z));
		} else {
			DBG(1, "Zone %05d: type 0x%x (%s), cond 0x%x (%s), need_reset %d, non_seq %d, LBA %llu, %llu sectors, wp %llu\n",
				i + idx,
				zbc_zone_type(z),
				zbc_zone_type_str(zbc_zone_type(z)),
				zbc_zone_condition(z),
				zbc_zone_condition_str(zbc_zone_condition(z)),
				zbc_zone_need_reset(z),
				zbc_zone_non_seq(z),
				zbc_zone_start_lba(z),
				zbc_zone_length(z),
				zbc_zone_wp_lba(z));
		}
	}

	idx += nr_zones;
	next_lba = zones[nr_zones - 1].zbz_start + zones[nr_zones - 1].zbz_length;
	c->zone_sectors = zones[nr_zones - 1].zbz_length;
	phase++;
	zbc_sg_cmd_destroy(&cmd);
	free(zones);
	goto next;
out:
	zbc_sg_cmd_destroy(&cmd);
	return ret;
}
