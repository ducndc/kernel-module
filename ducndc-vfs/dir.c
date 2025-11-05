#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "ducndc_fs.h"

static int 
ducndc_fs_iterate(
	struct file *dir, 
	struct dir_context *ctx
)
{
    struct inode *inode = file_inode(dir);
    struct ducndc_fs_inode_info *ci = DUCNDC_FS_INODE(inode);
    struct super_block *sb = inode->i_sb;
    struct buffer_head *bh = NULL, *bh2 = NULL;
    struct ducndc_fs_file_ei_block *eblock = NULL;
    struct ducndc_fs_dir_block *dblock = NULL;
    int ei = 0, bi = 0, fi = 0;
    int ret = 0;

    /* Check that dir is a directory */
    if (!S_ISDIR(inode->i_mode)) {
        return -ENOTDIR;
    }

    /* Check that ctx->pos is not bigger than what we can handle (including
     * . and ..)
     */
    if (ctx->pos > DUCNDC_FS_MAX_SUB_FILES + 2) {
        return 0;
    }

    /* Commit . and .. to ctx */
    if (!dir_emit_dots(dir, ctx)) {
        return 0;
    }

    /* Read the directory index block on disk */
    bh = sb_bread(sb, ci->ei_block);

    if (!bh) {
        return -EIO;
    }

    eblock = (struct ducndc_fs_file_ei_block *) bh->b_data;

    if (ctx->pos - 2 == eblock->nr_files) {
        goto release_bh;
    }

    int remained_nr_files = eblock->nr_files - (ctx->pos - 2);
    int offset = ctx->pos - 2;

    for (ei = 0; ei < DUCNDC_FS_MAX_EXTENTS; ei++) {
        if (eblock->extents[ei].ee_start == 0) {
            continue;
        }

        if (offset > eblock->extents[ei].nr_files) {
            offset -= eblock->extents[ei].nr_files;
        } else {
            break;
        }
    }

    /* Iterate over the index block and commit subfiles */
    for (; remained_nr_files && ei < DUCNDC_FS_MAX_EXTENTS; ei++) {
        if (eblock->extents[ei].ee_start == 0) {
            continue;
        }

        /* Iterate over blocks in one extent */
        for (bi = 0; bi < eblock->extents[ei].ee_len && remained_nr_files; bi++) {
            bh2 = sb_bread(sb, eblock->extents[ei].ee_start + bi);

            if (!bh2) {
                ret = -EIO;
                goto release_bh;
            }

            dblock = (struct ducndc_fs_dir_block *) bh2->b_data;

            if (offset > dblock->nr_files) {
                offset -= dblock->nr_files;
                brelse(bh2);
                bh2 = NULL;
                continue;
            }

            for (fi = 0; fi < DUCNDC_FS_FILES_PER_BLOCK;) {
                if (dblock->files[fi].inode != 0) {
                    if (offset) {
                        offset--;
                    } else {
                        remained_nr_files--;

                        if (!dir_emit(ctx, dblock->files[fi].filename,
                                      DUCNDC_FS_FILE_NAME_LEN,
                                      dblock->files[fi].inode, DT_UNKNOWN)) {
                            brelse(bh2);
                            bh2 = NULL;
                            goto release_bh;
                        }

                        ctx->pos++;
                    }
                }

                fi += dblock->files[fi].nr_nlk;
            }

            brelse(bh2);
            bh2 = NULL;
        }
    }

release_bh:
    brelse(bh);

    return ret;
}

const struct file_operations ducndc_fs_dir_ops = {
    .owner = THIS_MODULE,
    .iterate_shared = ducndc_fs_iterate,
};