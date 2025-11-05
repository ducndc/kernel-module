#ifndef __DUCNDC_FS_H__
#define __DUCNDC_FS_H__

#define DUCNDC_FS_MAGIC	0xDEACELL

#define DUCNDC_FS_SB_BLOCK_NR	(0)
#define DUCNDC_FS_BLOCK_SIZE	(1 << 12)

#define DUCNDC_FS_MAX_EXTENTS \
	((DUCNDC_FS_BLOCK_SIZE - sizeof(uint32_t)) / sizeof(struct ducndc_fs_extent))

#define DUCNDC_FS_MAX_BLOCKS_PER_EXTENT	(8)
#define DUCNDC_FS_MAX_SIZES_PER_EXTENT \
	((uint64_t) DUCNDC_FS_MAX_BLOCKS_PER_EXTENT * DUCNDC_FS_BLOCK_SIZE * DUCNDC_FS_MAX_EXTENTS)

#define DUCNDC_FS_MAX_FILE_SIZE                                          \
    ((uint64_t) DUCNDC_FS_MAX_BLOCKS_PER_EXTENT * DUCNDC_FS_BLOCK_SIZE * \
     DUCNDC_FS_MAX_EXTENTS)

#define DUCNDC_FS_FILE_NAME_LEN	(255)

#define DUCNDC_FS_FILES_PER_BLOCK \
	(DUCNDC_FS_BLOCK_SIZE / sizeof(struct ducndc_fs_file))

#define DUCNDC_FS_FILES_PER_EXTENT \
	(DUCNDC_FS_FILES_PER_BLOCK * DUCNDC_FS_MAX_BLOCKS_PER_EXTENT)

#define DUCNDC_FS_MAX_SUB_FILES (DUCNDC_FS_FILES_PER_EXTENT * DUCNDC_FS_MAX_EXTENTS)

/* vfs partition layout
 * +---------------+
 * |  superblock   |  1 block
 * +---------------+
 * |  inode store  |  sb->nr_istore_blocks blocks
 * +---------------+
 * | ifree bitmap  |  sb->nr_ifree_blocks blocks
 * +---------------+
 * | bfree bitmap  |  sb->nr_bfree_blocks blocks
 * +---------------+
 * |    data       |
 * |      blocks   |  rest of the blocks
 * +---------------+
 */

#ifdef __KERNEL__
#include <linux/jbd2.h>
#endif

struct ducndc_fs_inode {
	uint32_t i_mode;	/* File mode */
	uint32_t i_uid;		/* Owner id */
	uint32_t i_gid;		/* Group id */
	uint32_t i_size;	/* Size in bytes */
	uint32_t i_ctime;	/* Inode change time */
	uint32_t i_atime;	/* Access time */
	uint32_t i_mtime; 	/* Modification time */
	uint32_t i_blocks; 	/* Block count */
	uint32_t i_nlink;	/* Hard links count */
	uint32_t ei_block; 	/* Block with list of extents for this file */
	char i_data[32];	/* Store symlink content */
};

#define DUCNDC_FS_INODES_PER_BLOCK \
	(DUCNDC_FS_BLOCK_SIZE / sizeof(struct ducndc_fs_inode))

#ifdef __KERNEL__
#include <linux/version.h>
/* compatibility macros */
#define DUCNDC_FS_AT_LEAST(major, minor, rev) \
	LINUX_VERSION_CODE >= KERNEL_VERSION(major, minor, rev)

#define DUCNDC_FS_LESS_EQUAL(major, minor, rev) \
	LINUX_VERSION_CODE <= KERNEL_VERSION(major, minor, rev)

/* A 'container' structure that keeps the VFS inode and additional on-disk
 * data.
 */
struct ducndc_fs_inode_info {
	uint32_t ei_block; /* Block with list of extents for this file */
	char i_data[32];
	struct inode vfs_inode;
};

struct ducndc_fs_extent {
	uint32_t ee_block;	/* first logical block extent covers */
	uint32_t ee_len;	/* number of blocks covered by extent */
	uint32_t ee_start;	/* first physical block extent covers */
	uint32_t nr_files;	/* number of files in this extent */
};

struct ducndc_fs_file_ei_block {
	uint32_t nr_files; /* number of files in directory */
	struct ducndc_fs_extent extents[DUCNDC_FS_MAX_EXTENTS];
};

struct ducndc_fs_file {
	uint32_t inode;
	uint32_t nr_nlk;
	char filename[DUCNDC_FS_FILE_NAME_LEN];
};

struct ducndc_fs_dir_block {
	uint32_t nr_files;
	struct ducndc_fs_file files[DUCNDC_FS_FILES_PER_BLOCK];
};

int 
ducndc_fs_fill_super(
	struct super_block *sb, 
	void *data, 
	int silent
);

void 
ducndc_fs_kill_sb(
	struct super_block *sb
);

int 
ducndc_fs_init_inode_cache(
	void
);

void 
ducndc_fs_destroy_inode_cache(
	void
);

struct inode *
ducndc_fs_iget(
	struct super_block *sb, 
	unsigned long ino
);

struct dentry *
ducndc_fs_mount(
	struct file_system_type *fs_type,
	int flags,
	const char *dev_name,
	void *data
);

extern const struct file_operations ducndc_fs_file_ops;
extern const struct file_operations ducndc_fs_dir_ops;
extern const struct address_space_operations ducndc_fs_aops;

extern uint32_t
ducndc_fs_ext_search(
	struct ducndc_fs_file_ei_block *index,
	uint32_t iblock
);

#define DUCNDC_FS_SB(sb) (sb->s_fs_info)
#define DUCNDC_FS_INODE(inode) \
	(container_of(inode, struct ducndc_fs_inode_info, vfs_inode))

#endif /* __KERNEL__ */

struct ducndc_fs_sb_info {
	uint32_t magic;					/* magic number */
	uint32_t nr_blocks;				/* total number of blocks (incl sb & inodes) */
	uint32_t nr_inodes;				/* total number of inodes */
	uint32_t nr_istore_blocks;		/* number of inode store blocks */
	uint32_t nr_ifree_blocks;		/* number of inode free bitmap blocks */
	uint32_t nr_bfree_blocks;		/* number of block free bitmap blocks */
    uint32_t nr_free_inodes;  		/* number of free inodes */
    uint32_t nr_free_blocks;  		/* number of free blocks */
    unsigned long *ifree_bitmap; 	/* in-memory free inodes bitmap */
    unsigned long *bfree_bitmap; 	/* in-memory free blocks bitmap */
#ifdef __KERNEL__
    journal_t *journal;
    struct block_device *s_journal_bdev; /* v5.10+ external journal device */
#if DUCNDC_FS_AT_LEAST(6, 9, 0)
    struct file *s_journal_bdev_file; /* v6.11 external journal device */
#elif DUCNDC_FS_AT_LEAST(6, 7, 0)
    struct bdev_handle *s_journal_bdev_handle; /* v6.7+ external journal device */
#endif /* DUCNDC_FS_AT_LEAST */
#endif /* __KERNEL__ */
};

#endif /* END __DUCNDC_FS_H__ */