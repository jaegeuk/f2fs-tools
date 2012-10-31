/**
 * f2fs_format.h
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __F2FS_FORMAT_H__
#define __F2FS_FORMAT_H__

#include <linux/types.h>
#include <endian.h>
#include <byteswap.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define le16_to_cpu(x)	((__u16)(x))
#define le32_to_cpu(x)	((__u32)(x))
#define le64_to_cpu(x)	((__u64)(x))
#define cpu_to_le16(x)	((__u16)(x))
#define cpu_to_le32(x)	((__u32)(x))
#define cpu_to_le64(x)	((__u64)(x))
#elif __BYTE_ORDER == __BIG_ENDIAN
#define le16_to_cpu(x)	bswap_16(x)
#define le32_to_cpu(x)	bswap_32(x)
#define le64_to_cpu(x)	bswap_64(x)
#define cpu_to_le16(x)	bswap_16(x)
#define cpu_to_le32(x)	bswap_32(x)
#define cpu_to_le64(x)	bswap_64(x)
#endif

/* these are defined in kernel */
#define PAGE_SIZE		4096
#define PAGE_CACHE_SIZE		4096
#define BITS_PER_BYTE		8

/* for mkfs */
#define F2FS_MIN_VOLUME_SIZE	104857600

#define	F2FS_MAJOR_VERSION	1
#define	F2FS_MINOR_VERSION	0

#define	F2FS_O_DIRECTORY	0x00004000
#define	F2FS_O_EONLY		0x00000040
#define	F2FS_O_WRONLY		0x00000080
#define	F2FS_O_RDONLY		0x00000100

#define	F2FS_NUMBER_OF_CHECKPOINT_PACK	2

#define	DEFAULT_SECTOR_SIZE		512
#define	DEFAULT_SECTORS_PER_BLOCK	8
#define	DEFAULT_BLOCKS_PER_SEGMENT	512
#define DEFAULT_SEGMENTS_PER_SECTION	1
#define F2FS_CP_BLOCK_SIZE		(DEFAULT_SECTOR_SIZE * \
					DEFAULT_SECTORS_PER_BLOCK)

/*
 * For further optimization on multi-head logs, on-disk layout supports maximum
 * 16 logs by default. The number, 16, is expected to cover all the cases
 * enoughly. The implementaion currently uses no more than 6 logs.
 * Half the logs are used for nodes, and the other half are used for data.
 */
#define MAX_ACTIVE_LOGS	16
#define MAX_ACTIVE_NODE_LOGS	8
#define MAX_ACTIVE_DATA_LOGS	8

struct f2fs_global_parameters {
	u_int32_t       sector_size;
	u_int32_t       reserved_segments;
	u_int32_t       overprovision;
	u_int32_t	cur_seg[6];
	u_int32_t       segs_per_sec;
	u_int32_t       secs_per_zone;
	u_int32_t       start_sector;
	u_int64_t	total_sectors;
	u_int32_t       sectors_per_blk;
	u_int32_t       blks_per_seg;
	u_int8_t        vol_label[16];
	int		heap;
	int32_t         fd;
	char   *device_name;
	char   *extension_list;
} __attribute__((packed));

#ifdef CONFIG_64BIT
#define BITS_PER_LONG	64
#else
#define BITS_PER_LONG	32
#endif

#define BIT_MASK(nr)    (1 << (nr % BITS_PER_LONG))
#define BIT_WORD(nr)    (nr / BITS_PER_LONG)

/*
 * For superblock
 */
#define F2FS_SUPER_MAGIC	0xF2F52010	/* F2FS Magic Number */
#define F2FS_SUPER_OFFSET	1024		/* byte-size offset */
#define F2FS_BLKSIZE		4096
#define F2FS_MAX_EXTENSION	64

struct f2fs_super_block {
	__le32 magic;			/* Magic Number */
	__le16 major_ver;		/* Major Version */
	__le16 minor_ver;		/* Minor Version */
	__le32 log_sectorsize;		/* log2 sector size in bytes */
	__le32 log_sectors_per_block;	/* log2 # of sectors per block */
	__le32 log_blocksize;		/* log2 block size in bytes */
	__le32 log_blocks_per_seg;	/* log2 # of blocks per segment */
	__le32 segs_per_sec;		/* # of segments per section */
	__le32 secs_per_zone;		/* # of sections per zone */
	__le32 checksum_offset;		/* checksum offset inside super block */
	__le64 block_count;		/* total # of user blocks */
	__le32 section_count;		/* total # of sections */
	__le32 segment_count;		/* total # of segments */
	__le32 segment_count_ckpt;	/* # of segments for checkpoint */
	__le32 segment_count_sit;	/* # of segments for SIT */
	__le32 segment_count_nat;	/* # of segments for NAT */
	__le32 segment_count_ssa;	/* # of segments for SSA */
	__le32 segment_count_main;	/* # of segments for main area */
	__le32 segment0_blkaddr;	/* start block address of segment 0 */
	__le32 cp_blkaddr;		/* start block address of checkpoint */
	__le32 sit_blkaddr;		/* start block address of SIT */
	__le32 nat_blkaddr;		/* start block address of NAT */
	__le32 ssa_blkaddr;		/* start block address of SSA */
	__le32 main_blkaddr;		/* start block address of main area */
	__le32 root_ino;		/* root inode number */
	__le32 node_ino;		/* node inode number */
	__le32 meta_ino;		/* meta inode number */
	__u8 uuid[16];			/* 128-bit uuid for volume */
	__le16 volume_name[512];	/* volume name */
	__le32 extension_count;		/* # of extensions below */
	__u8 extension_list[F2FS_MAX_EXTENSION][8];	/* extension array */
} __attribute__((packed));

/*
 * For checkpoint
 */
#define CP_ERROR_FLAG		0x00000008
#define CP_COMPACT_SUM_FLAG	0x00000004
#define CP_ORPHAN_PRESENT_FLAG	0x00000002
#define CP_UMOUNT_FLAG		0x00000001

struct f2fs_checkpoint {
	__le64 checkpoint_ver;		/* checkpoint block version number */
	__le64 user_block_count;	/* # of user blocks */
	__le64 valid_block_count;	/* # of valid blocks in main area */
	__le32 rsvd_segment_count;	/* # of reserved segments for gc */
	__le32 overprov_segment_count;	/* # of overprovision segments */
	__le32 free_segment_count;	/* # of free segments in main area */

	/* information of current node segments */
	__le32 cur_node_segno[MAX_ACTIVE_NODE_LOGS];
	__le16 cur_node_blkoff[MAX_ACTIVE_NODE_LOGS];
	/* information of current data segments */
	__le32 cur_data_segno[MAX_ACTIVE_DATA_LOGS];
	__le16 cur_data_blkoff[MAX_ACTIVE_DATA_LOGS];
	__le32 ckpt_flags;		/* Flags : umount and journal_present */
	__le32 cp_pack_total_block_count;	/* total # of one cp pack */
	__le32 cp_pack_start_sum;	/* start block number of data summary */
	__le32 valid_node_count;	/* Total number of valid nodes */
	__le32 valid_inode_count;	/* Total number of valid inodes */
	__le32 next_free_nid;		/* Next free node number */
	__le32 sit_ver_bitmap_bytesize;	/* Default value 64 */
	__le32 nat_ver_bitmap_bytesize; /* Default value 256 */
	__le32 checksum_offset;		/* checksum offset inside cp block */
	__le64 elapsed_time;		/* mounted time */
	/* allocation type of current segment */
	unsigned char alloc_type[MAX_ACTIVE_LOGS];

	/* SIT and NAT version bitmap */
	unsigned char sit_nat_version_bitmap[1];
} __attribute__((packed));

/*
 * For NODE structure
 */
struct f2fs_extent {
	__le32 fofs;		/* start file offset of the extent */
	__le32 blk_addr;	/* start block address of the extent */
	__le32 len;		/* lengh of the extent */
} __attribute__((packed));

#define F2FS_MAX_NAME_LEN	256
#define ADDRS_PER_INODE         923	/* Address Pointers in an Inode */
#define ADDRS_PER_BLOCK         1018	/* Address Pointers in a Direct Block */
#define NIDS_PER_BLOCK          1018	/* Node IDs in an Indirect Block */

struct f2fs_inode {
	__le16 i_mode;			/* file mode */
	__u8 i_advise;			/* file hints */
	__u8 i_reserved;		/* reserved */
	__le32 i_uid;			/* user ID */
	__le32 i_gid;			/* group ID */
	__le32 i_links;			/* links count */
	__le64 i_size;			/* file size in bytes */
	__le64 i_blocks;		/* file size in blocks */
	__le64 i_atime;			/* access time */
	__le64 i_ctime;			/* change time */
	__le64 i_mtime;			/* modification time */
	__le32 i_atime_nsec;		/* access time in nano scale */
	__le32 i_ctime_nsec;		/* change time in nano scale */
	__le32 i_mtime_nsec;		/* modification time in nano scale */
	__le32 i_generation;		/* file version (for NFS) */
	__le32 i_current_depth;		/* only for directory depth */
	__le32 i_xattr_nid;		/* nid to save xattr */
	__le32 i_flags;			/* file attributes */
	__le32 i_pino;			/* parent inode number */
	__le32 i_namelen;		/* file name length */
	__u8 i_name[F2FS_MAX_NAME_LEN];	/* file name for SPOR */

	struct f2fs_extent i_ext;	/* caching a largest extent */

	__le32 i_addr[ADDRS_PER_INODE];	/* Pointers to data blocks */

	__le32 i_nid[5];		/* direct(2), indirect(2),
						double_indirect(1) node id */
} __attribute__((packed));

struct direct_node {
	__le32 addr[ADDRS_PER_BLOCK];	/* aray of data block address */
} __attribute__((packed));

struct indirect_node {
	__le32 nid[NIDS_PER_BLOCK];	/* aray of data block address */
} __attribute__((packed));

struct node_footer {
	__le32 nid;		/* node id */
	__le32 ino;		/* inode nunmber */
	__le32 flag;		/* include cold/fsync/dentry marks and offset */
	__le64 cp_ver;		/* checkpoint version */
	__le32 next_blkaddr;	/* next node page block address */
} __attribute__((packed));

struct f2fs_node {
	/* can be one of three types: inode, direct, and indirect types */
	union {
		struct f2fs_inode i;
		struct direct_node dn;
		struct indirect_node in;
	};
	struct node_footer footer;
} __attribute__((packed));

/*
 * For NAT entries
 */
#define NAT_ENTRY_PER_BLOCK	(PAGE_CACHE_SIZE / sizeof(struct f2fs_nat_entry))

struct f2fs_nat_entry {
	__u8 version;		/* latest version of cached nat entry */
	__le32 ino;		/* inode number */
	__le32 block_addr;	/* block address */
} __attribute__((packed));

struct f2fs_nat_block {
	struct f2fs_nat_entry entries[NAT_ENTRY_PER_BLOCK];
} __attribute__((packed));

/*
 * For SIT entries
 *
 * Each segment is 2MB in size by default so that a bitmap for validity of
 * there-in blocks should occupy 64 bytes, 512 bits.
 * Not allow to change this.
 */
#define SIT_VBLOCK_MAP_SIZE	64
#define SIT_ENTRY_PER_BLOCK (PAGE_CACHE_SIZE / sizeof(struct f2fs_sit_entry))

enum {
	CURSEG_HOT_DATA	= 0,	/* directory entry blocks */
	CURSEG_WARM_DATA,	/* data blocks */
	CURSEG_COLD_DATA,	/* multimedia or GCed data blocks */
	CURSEG_HOT_NODE,	/* direct node blocks of directory files */
	CURSEG_WARM_NODE,	/* direct node blocks of normal files */
	CURSEG_COLD_NODE,	/* indirect node blocks */
};

/*
 * Note that f2fs_sit_entry->vblocks has the following bit-field information.
 * [15:10] : allocation type such as CURSEG_XXXX_TYPE
 * [9:0] : valid block count
 */
#define CURSEG_NULL	((-1 << 10) >> 10)	/* use 6bit - 0x3f */

struct f2fs_sit_entry {
	__le16 vblocks;				/* reference above */
	__u8 valid_map[SIT_VBLOCK_MAP_SIZE];	/* bitmap for valid blocks */
	__le64 mtime;				/* segment age for cleaning */
} __attribute__((packed));

struct f2fs_sit_block {
	struct f2fs_sit_entry entries[SIT_ENTRY_PER_BLOCK];
} __attribute__((packed));

/**
 * For segment summary
 *
 * One summary block contains exactly 512 summary entries, which represents
 * exactly 2MB segment by default. Not allow to change the basic units.
 *
 * NOTE : For initializing fields, you must use set_summary
 *
 * - If data page, nid represents dnode's nid
 * - If node page, nid represents the node page's nid.
 *
 * The ofs_in_node is used by only data page. It represents offset
 * from node's page's beginning to get a data block address.
 * ex) data_blkaddr = (block_t)(nodepage_start_address + ofs_in_node)
 */
#define ENTRIES_IN_SUM		512
#define	SUMMARY_SIZE		(sizeof(struct f2fs_summary))
#define	SUM_FOOTER_SIZE		(sizeof(struct summary_footer))
#define SUM_ENTRY_SIZE		(SUMMARY_SIZE * ENTRIES_IN_SUM)

/* a summary entry for a 4KB-sized block in a segment */
struct f2fs_summary {
	__le32 nid;		/* parent node id */
	union {
		__u8 reserved[3];
		struct {
			__u8 version;		/* node version number */
			__le16 ofs_in_node;	/* block index in parent node */
		} __attribute__((packed));
	};
} __attribute__((packed));

/* summary block type, node or data, is stored to the summary_footer */
#define SUM_TYPE_NODE		(1)
#define SUM_TYPE_DATA		(0)
#define GET_SUM_TYPE(footer) (footer->entry_type)
#define SET_SUM_TYPE(footer, type) (footer->entry_type = type)

struct summary_footer {
	unsigned char entry_type;	/* SUM_TYPE_XXX */
	__u32 check_sum;		/* summary checksum */
} __attribute__((packed));

#define SUM_JOURNAL_SIZE	(PAGE_CACHE_SIZE - SUM_FOOTER_SIZE -\
				SUM_ENTRY_SIZE)
#define NAT_JOURNAL_ENTRIES	((SUM_JOURNAL_SIZE - 2) /\
				sizeof(struct nat_journal_entry))
#define NAT_JOURNAL_RESERVED	((SUM_JOURNAL_SIZE - 2) %\
				sizeof(struct nat_journal_entry))
#define SIT_JOURNAL_ENTRIES	((SUM_JOURNAL_SIZE - 2) /\
				sizeof(struct sit_journal_entry))
#define SIT_JOURNAL_RESERVED	((SUM_JOURNAL_SIZE - 2) %\
				sizeof(struct sit_journal_entry))
/*
 * frequently updated NAT/SIT entries can be stored in the spare area in
 * summary blocks
 */
enum {
	NAT_JOURNAL = 0,
	SIT_JOURNAL
};

struct nat_journal_entry {
	__le32 nid;
	struct f2fs_nat_entry ne;
} __attribute__((packed));

struct nat_journal {
	struct nat_journal_entry entries[NAT_JOURNAL_ENTRIES];
	__u8 reserved[NAT_JOURNAL_RESERVED];
} __attribute__((packed));

struct sit_journal_entry {
	__le32 segno;
	struct f2fs_sit_entry se;
} __attribute__((packed));

struct sit_journal {
	struct sit_journal_entry entries[SIT_JOURNAL_ENTRIES];
	__u8 reserved[SIT_JOURNAL_RESERVED];
} __attribute__((packed));

/* 4KB-sized summary block structure */
struct f2fs_summary_block {
	struct f2fs_summary entries[ENTRIES_IN_SUM];
	union {
		__le16 n_nats;
		__le16 n_sits;
	};
	/* spare area is used by NAT or SIT journals */
	union {
		struct nat_journal nat_j;
		struct sit_journal sit_j;
	};
	struct summary_footer footer;
} __attribute__((packed));

/*
 * For directory operations
 */
/* One directory entry slot covers 8bytes-long file name */
#define F2FS_NAME_LEN		8

/* the number of dentry in a block */
#define NR_DENTRY_IN_BLOCK	214

/* MAX level for dir lookup */
#define MAX_DIR_HASH_DEPTH	63

#define SIZE_OF_DIR_ENTRY	11	/* by byte */
#define SIZE_OF_DENTRY_BITMAP	((NR_DENTRY_IN_BLOCK + BITS_PER_BYTE - 1) / \
				BITS_PER_BYTE)
#define SIZE_OF_RESERVED	(PAGE_SIZE - ((SIZE_OF_DIR_ENTRY + \
				F2FS_NAME_LEN) * \
				NR_DENTRY_IN_BLOCK + SIZE_OF_DENTRY_BITMAP))

/* One directory entry slot representing F2FS_NAME_LEN-sized file name */
struct f2fs_dir_entry {
	__le32 hash_code;	/* hash code of file name */
	__le32 ino;		/* inode number */
	__le16 name_len;	/* lengh of file name */
	__u8 file_type;		/* file type */
} __attribute__((packed));

/* 4KB-sized directory entry block */
struct f2fs_dentry_block {
	/* validity bitmap for directory entries in each block */
	__u8 dentry_bitmap[SIZE_OF_DENTRY_BITMAP];
	__u8 reserved[SIZE_OF_RESERVED];
	struct f2fs_dir_entry dentry[NR_DENTRY_IN_BLOCK];
	__u8 filename[NR_DENTRY_IN_BLOCK][F2FS_NAME_LEN];
} __attribute__((packed));

/* file types used in inode_info->flags */
enum {
	F2FS_FT_UNKNOWN,
	F2FS_FT_REG_FILE,
	F2FS_FT_DIR,
	F2FS_FT_CHRDEV,
	F2FS_FT_BLKDEV,
	F2FS_FT_FIFO,
	F2FS_FT_SOCK,
	F2FS_FT_SYMLINK,
	F2FS_FT_MAX
};

#endif	//__F2FS_FORMAT_H__
