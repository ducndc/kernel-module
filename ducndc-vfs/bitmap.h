#ifndef __BITMAP_H__
#define __BITMAP_H__

#include <linux/bitmap.h>

#include "ducndc_fs.h"

static inline uint32_t 
get_first_free_bits(
	unsigned long *freemap,
	unsigned long size,
	uint32_t len
)
{
    uint32_t bit, prev = 0, count = 0;

    for_each_set_bit (bit, freemap, size) {
        if (prev != bit - 1) {
            count = 0;
        }

        prev = bit;
        
        if (++count == len) {
            bitmap_clear(freemap, bit - len + 1, len);
            return bit - len + 1;
        }
    }
    
    return 0;
}

static inline uint32_t 
get_free_inode(
	struct ducndc_fs_sb_info *sbi
)
{
    uint32_t ret = get_first_free_bits(sbi->ifree_bitmap, sbi->nr_inodes, 1);
    
    if (ret) {
        sbi->nr_free_inodes--;
    }

    return ret;
}

static inline uint32_t 
get_free_blocks(
	struct super_block *sb, 
	uint32_t len
)
{
    struct ducndc_fs_sb_info *sbi = DUCNDC_FS_SB(sb);
    uint32_t ret = get_first_free_bits(sbi->bfree_bitmap, sbi->nr_blocks, len);
    uint32_t i;

    if (!ret) {
    	/* No enough free blocks */
        return 0;
    }

    sbi->nr_free_blocks -= len;
    struct buffer_head *bh;

    for (i = 0; i < len; i++) {
        bh = sb_bread(sb, ret + i);

        if (!bh) {
            pr_err("get_free_blocks: sb_bread failed for block %d\n", ret + i);
            sbi->nr_free_blocks += len;
            return -EIO;
        }

        memset(bh->b_data, 0, DUCNDC_FS_BLOCK_SIZE);
        mark_buffer_dirty(bh);
        sync_dirty_buffer(bh); /* write the buffer to disk */
        brelse(bh);
    }

    return ret;
}

static inline int 
put_free_bits(
	unsigned long *freemap,
	unsigned long size,
	uint32_t i,
	uint32_t len
)
{
    /* i is greater than freemap size */
    if (i + len - 1 > size) {
        return -1;
    }

    bitmap_set(freemap, i, len);

    return 0;
}

static inline void 
put_inode(
	struct ducndc_fs_sb_info *sbi, 
	uint32_t ino
)
{
    if (put_free_bits(sbi->ifree_bitmap, sbi->nr_inodes, ino, 1)) {
        return;
    }

    sbi->nr_free_inodes++;
}

/* Mark len block(s) as unused */
static inline void 
put_blocks(
	struct ducndc_fs_sb_info *sbi,
	uint32_t bno,
	uint32_t len
)
{
    if (put_free_bits(sbi->bfree_bitmap, sbi->nr_blocks, bno, len)) {
        return;
    }

    sbi->nr_free_blocks += len;
}

#endif /* END __BITMAP_H__ */