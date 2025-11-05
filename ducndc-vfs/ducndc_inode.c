#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "bitmap.h"
#include "ducndc_fs.h"

static const struct inode_operations ducndc_fs_inode_ops;
static const struct inode_operations symlink_inode_ops;

struct inode *
ducndc_fs_iget(
	struct super_block *sb,
	unsigned long ino
)
{
	struct inode *inode = NULL;
	struct ducndc_fs_inode *cinode = NULL;
	struct ducndc_fs_inode_info *ci = NULL;
	struct ducndc_fs_sb_info *sbi = DUCNDC_FS_SB(sb);
	struct buffer_head *bh = NULL;
	uint32_t inode_block = (ino / DUCNDC_FS_INODES_PER_BLOCK) + 1;
	uint32_t inode_shift = ino % DUCNDC_FS_INODES_PER_BLOCK;
	int ret;

	if (ino >= sbi->nr_inodes) {
		return ERR_PTR(-EINVAL);
	}

	inode = iget_locked(sb, ino);

	if (!inode) {
		return ERR_PTR(-ENOMEM);
	}

	if (!(inode->i_state & I_NEW)) {
		return inode;
	}

	ci = DUCNDC_FS_INODE(inode);
	bh = sb_bread(sb, inode_block);

	if (!bh) {
		ret = -EIO;
		goto failed;
	}

	cinode = (struct ducndc_fs_inode *)bh->b_data;
	cinode += inode_shift;
	inode->i_ino = ino;
	inode->i_sb = sb;
	inode->i_op = &ducndc_fs_inode_ops;
    inode->i_mode = le32_to_cpu(cinode->i_mode);
    i_uid_write(inode, le32_to_cpu(cinode->i_uid));
    i_gid_write(inode, le32_to_cpu(cinode->i_gid));
    inode->i_size = le32_to_cpu(cinode->i_size);

#if DUCNDC_FS_AT_LEAST(6, 6, 0)
    inode_set_ctime(inode, (time64_t) le32_to_cpu(cinode->i_ctime), 0);
#else
    inode->i_ctime.tv_sec = (time64_t) le32_to_cpu(cinode->i_ctime);
    inode->i_ctime.tv_nsec = 0;
#endif

#if DUCNDC_FS_AT_LEAST(6, 7, 0)
    inode_set_atime(inode, (time64_t) le32_to_cpu(cinode->i_atime), 0);
    inode_set_mtime(inode, (time64_t) le32_to_cpu(cinode->i_mtime), 0);
#else
    inode->i_atime.tv_sec = (time64_t) le32_to_cpu(cinode->i_atime);
    inode->i_atime.tv_nsec = 0;
    inode->i_mtime.tv_sec = (time64_t) le32_to_cpu(cinode->i_mtime);
    inode->i_mtime.tv_nsec = 0;
#endif    

    inode->i_blocks = le32_to_cpu(cinode->i_blocks);
    set_nlink(inode, le32_to_cpu(cinode->i_nlink));

    if (S_ISDIR(inode->i_mode)) {
        ci->ei_block = le32_to_cpu(cinode->ei_block);
        inode->i_fop = &ducndc_fs_dir_ops;
    } else if (S_ISREG(inode->i_mode)) {
        ci->ei_block = le32_to_cpu(cinode->ei_block);
        inode->i_fop = &ducndc_fs_file_ops;
        inode->i_mapping->a_ops = &ducndc_fs_aops;
    } else if (S_ISLNK(inode->i_mode)) {
        strncpy(ci->i_data, cinode->i_data, sizeof(ci->i_data));
        inode->i_link = ci->i_data;
        inode->i_op = &symlink_inode_ops;
    }

    brelse(bh);

    /* Unlock the inode to make it usable */
    unlock_new_inode(inode);

    return inode;

failed:
    brelse(bh);
    iget_failed(inode);
    return ERR_PTR(ret);
}

static struct dentry *
ducndc_fs_lookup(
	struct inode *dir,
	struct dentry *dentry,
	unsigned int flags
)
{
	struct super_block *sb = dir->i_sb;
	struct ducndc_fs_inode_info *ci_dir = DUCNDC_FS_INODE(dir);
	struct inode *inode = NULL;
	struct buffer_head *bh = NULL, *bh2 = NULL;
	struct ducndc_fs_file_ei_block *eblock = NULL;
	struct ducndc_fs_dir_block *dblock = NULL;
	struct ducndc_fs_file *f = NULL;
	int ei, bi, fi;

	if (dentry->d_name.len > DUCNDC_FS_FILE_NAME_LEN) {
		return ERR_PTR(-ENAMETOOLONG);
	}

	bh = sb_bread(sb, ci_dir->ei_block);

	if (!bh) {
		return ERR_PTR(-EIO);
	}

	eblock = (struct ducndc_fs_file_ei_block *)bh->b_data;

	for (ei = 0; ei < DUCNDC_FS_MAX_EXTENTS; ei++) {
		if (!eblock->extents[ei].ee_start) {
			break;
		}

		for (bi = 0; bi < eblock->extents[ei].ee_len; bi++) {
			bh2 = sb_bread(sb, eblock->extents[ei].ee_start + bi);

			if (!bh2) {
				return ERR_PTR(-EIO);
			}

			dblock = (struct ducndc_fs_dir_block *)bh2->b_data;

			for (fi = 0; fi < dblock->nr_files;) {
				f = &dblock->files[fi];

				if (!f->inode) {
					brelse(bh2);
					goto search_end;
				}

				if (!strncmp(f->filename, dentry->d_name.name, DUCNDC_FS_FILE_NAME_LEN)) {
					inode = ducndc_fs_iget(sb, f->inode);
					brelse(bh2);
					goto search_end;
				}

				fi += dblock->files[fi].nr_nlk;
			}

			brelse(bh2);
			bh2 = NULL;
		}
	}

search_end:
	brelse(bh);
	bh = NULL;

#if DUCNDC_FS_AT_LEAST(6, 7, 0)
	inode_set_atime_to_ts(dir, current_time(dir));
#else 
	dir->i_atime = current_time(dir);
#endif 

	mark_inode_dirty(dir);
	d_add(dentry, inode);

	return NULL;
}

static struct inode *
ducndc_fs_new_inode(
	struct inode *dir,
	mode_t mode
)
{
	struct inode *inode;
	struct ducndc_fs_inode_info *ci;
	struct super_block *sb;
	struct ducndc_fs_sb_info *sbi;
	uint32_t ino, bno;
	int ret;

#if DUCNDC_FS_AT_LEAST(6, 6, 0) && DUCNDC_FS_LESS_EQUAL(6, 7, 0)
	struct timespec64 cur_time;
#endif

	if (!S_ISDIR(mode) && !S_ISREG(mode) && !S_ISLNK(mode)) {
        pr_err(
            "File type not supported (only directory, regular file and symlink "
            "supported)\n");
        return ERR_PTR(-EINVAL);
	}

	sb = dir->i_sb;
	sbi = DUCNDC_FS_SB(sb);

	if (sbi->nr_free_inodes == 0 || sbi->nr_free_blocks == 0) {
		return ERR_PTR(-ENOSPC);
	}

	inode = get_free_inode(sbi);

	if (!ino) {
		return ERR_PTR(-ENOSPC);
	}

	inode = ducndc_fs_iget(sb, ino);

	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto put_ino;
	}

	if (S_ISLNK(mode)) {
#if DUCNDC_FS_AT_LEAST(6, 3, 0)
		inode_init_owner(&nop_mnt_idmap, inode, dir, mode);
#elif DUCNDC_FS_AT_LEAST(5, 12, 0)
		inode_init_owner(&init_user_ns, inode, dir, mode);
#else
		inode_init_owner(inode, dir, mode);
#endif

		set_nlink(inode, 1);

#if DUCNDC_FS_AT_LEAST(6, 7, 0)
		simple_inode_init_ts(inode);
#elif DUCNDC_FS_AT_LEAST(6, 6, 0)
		cur_time = current_time(inode);
		inode->i_atime = inode->i_mtime = cur_time;
		inode_set_ctime_to_ts(inode, cur_time);
#else 
		inode->i_ctime = inode->i_atime = inode->i_mtime = current_time(inode);
#endif
		inode->i_op = &symlink_inode_ops;

		return inode;
	}

	ci = DUCNDC_FS_INODE(inode);
	bno = get_free_blocks(sb, 1);

	if (!bno) {
		ret = -ENOSPC;
		goto put_inode;
	}

#if DUCNDC_FS_AT_LEAST(6, 3, 0)
	inode_init_owner(&nop_mnt_idmap, inode, dir, mode);
#elif DUCNDC_FS_AT_LEAST(5, 12, 0)
	inode_init_owner(&init_user_ns, inode, dir, mode);
#else
	inode_init_owner(inode, dir, mode);
#endif

	inode->i_blocks = 1;

	if (S_ISDIR(mode)) {
		ci->ei_block = bno;
		inode->i_size = DUCNDC_FS_BLOCK_SIZE;
		inode->i_fop = &ducndc_fs_dir_ops;
		set_nlink(inode, 2);
	} else if (S_ISREG(mode)) {
		ci->ei_block = bno;
		inode->i_size = 0;
		inode->i_fop = &ducndc_fs_file_ops;
		inode->i_mapping->a_ops = &ducndc_fs_aops;
		set_nlink(inode, 1);
	}

#if DUCNDC_FS_AT_LEAST(6, 7, 0)
	simple_inode_init_ts(inode);
#elif DUCNDC_FS_AT_LEAST(6, 6, 0)
	cur_time = current_time(inode);
	inode->i_atime = inode->i_mtime = cur_time;
	inode_set_ctime_to_ts(inode, cur_time);
#else
	inode->i_ctime = inode->i_atime = inode->i_mtime = current_time(inode);
#endif

	return inode;

put_inode:
	iput(inode);

put_ino:
	put_inode(sbi, ino);

	return ERR_PTR(ret);
}

static uint32_t ducndc_fs_get_available_ext_idx(
	int *dir_nr_files,
	struct ducndc_fs_file_ei_block *eblock
)
{
	int ei = 0;
	uint32_t first_empty_blk = -1;

	for (ei = 0; ei < DUCNDC_FS_MAX_EXTENTS; ei++) {
		if (eblock->extents[ei].ee_start &&
			eblock->extents[ei].nr_files != DUCNDC_FS_FILES_PER_EXTENT) {
			first_empty_blk = ei;
			break;
		} else if (!eblock->extents[ei].ee_start) {
			if (first_empty_blk == -1) {
				first_empty_blk = ei;
			}
		} else {
			*dir_nr_files -= eblock->extents[ei].nr_files;

			if (first_empty_blk == -1 && !*dir_nr_files) {
				first_empty_blk = ei + 1;
			}
		}

		if (!*dir_nr_files) {
			break;
		}
	}

	return first_empty_blk;
}

static int 
ducndc_fs_put_new_ext(
	struct super_block *sb,
	uint32_t ei,
	struct ducndc_fs_file_ei_block *eblock
)
{
	int bno, bi;
	struct buffer_head *bh;
	struct ducndc_fs_dir_block *dblock;
	bno = get_free_blocks(sb, DUCNDC_FS_MAX_BLOCKS_PER_EXTENT);

	if (!bno) {
		return -ENOSPC;
	}

	eblock->extents[ei].ee_start = bno;
	eblock->extents[ei].ee_len = DUCNDC_FS_MAX_BLOCKS_PER_EXTENT;
	eblock->extents[ei].ee_block = 
		ei ? eblock->extents[ei - 1].ee_block + eblock->extents[ei - 1].ee_len : 0;
	eblock->extents[ei].nr_files = 0;

	for (bi = 0; bi < eblock->extents[ei].ee_len; bi++) {
		bh = sb_bread(sb, eblock->extents[ei].ee_start + bi);

		if (!bh) {
			return -EIO;
		}

		dblock = (struct ducndc_fs_dir_block *)bh->b_data;
		memset(dblock, 0, sizeof(struct ducndc_fs_dir_block));
		dblock->files[0].nr_nlk = DUCNDC_FS_FILES_PER_BLOCK;
		brelse(bh);
	}

	return 0;
}

static void
ducndc_fs_set_file_into_dir(
	struct ducndc_fs_dir_block *dblock,
	uint32_t inode_no,
	const char *name 
)
{
	int fi;

	if (dblock->nr_files != 0 && dblock->files[0].inode != 0) {
		for (fi = 0; fi < DUCNDC_FS_FILES_PER_BLOCK - 1; fi++) {
			if (dblock->files[fi].nr_nlk != 1) {
				break;
			}
		}

		dblock->files[fi + 1].inode = inode_no;
		dblock->files[fi + 1].nr_nlk = dblock->files[fi].nr_nlk - 1;
		strncpy(dblock->files[fi + 1].filename, name, DUCNDC_FS_FILE_NAME_LEN);
		dblock->files[fi].nr_nlk = 1;
	} else if (dblock->nr_files == 0) {
        dblock->files[fi].inode = inode_no;
        strncpy(dblock->files[fi].filename, name, DUCNDC_FS_FILE_NAME_LEN);
    } else {
        dblock->files[0].inode = inode_no;
        strncpy(dblock->files[fi].filename, name, DUCNDC_FS_FILE_NAME_LEN);
    }

    dblock->nr_files++;
}

#if DUCNDC_FS_AT_LEAST(6, 3, 0)
static int 
ducndc_fs_create(
	struct mnt_idmap *id,
	struct inode *dir,
	struct dentry *dentry,
	umode_t mode,
	bool excl
)
#elif DUCNDC_FS_AT_LEAST(5, 12, 0)
static int 
ducndc_fs_create(
	struct user_namespace *ns,
	struct inode *dir,
	struct dentry *dentry,
	umode_t mode,
	bool excl
)
#else
static int 
ducndc_fs_create(
	struct inode *dir,
	struct dentry *dentry,
	umode_t mode,
	bool excl
)
#endif
{
	struct super_block *sb;
	struct inode *inode;
	struct ducndc_fs_inode_info *ci_dir;
	struct ducndc_fs_file_ei_block *eblock;
	struct ducndc_fs_dir_block *dblock;
	char *fblock;
	struct buffer_head *bh, *bh2;
	uint32_t dir_nr_files = 0, avail;
#if DUCNDC_FS_AT_LEAST(6, 6, 0) && DUCNDC_FS_LESS_EQUAL(6, 7, 0)
	struct timespec64 cur_time;
#endif 
	int ret = 0, alloc = false;
	int bi = 0;

	if (strlen(dentry->d_name.name) > DUCNDC_FS_FILE_NAME_LEN) {
		return -ENAMETOOLONG;
	}

	ci_dir = DUCNDC_FS_INODE(dir);
	sb = dir->i_sb;
	bh = sb_bread(sb, ci_dir->ei_block);

	if (!bh) {
		return -EIO;
	}

	eblock = (struct ducndc_fs_file_ei_block *)bh->b_data;

	if (eblock->nr_files == DUCNDC_FS_MAX_SUB_FILES) {
		ret = -EMLINK;
		goto end;
	}

	inode = ducndc_fs_new_inode(dir, mode);

	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto end;
	}

	bh2 = sb_bread(sb, DUCNDC_FS_INODE(inode)->ei_block);

	if (!bh2) {
		ret = -EIO;
		goto iput;
	}

	fblock = (char *)bh2->b_data;
	memset(fblock, 0, DUCNDC_FS_BLOCK_SIZE);
	mark_buffer_dirty(bh2);
	brelse(bh2);
	dir_nr_files = eblock->nr_files;
	avail = ducndc_fs_get_available_ext_idx(&dir_nr_files, eblock);

	if (!dir_nr_files && !eblock->extents[avail].ee_start) {
		ret = ducndc_fs_put_new_ext(sb, avail, eblock);

		switch (ret) {
		case -ENOSPC:
			ret = -ENOSPC;
			goto iput;
		case -EIO:
			ret = -EIO;
			goto put_block;
		}

		alloc = true;
	}

	for (bi = 0; bi < eblock->extents[avail].ee_len; bi++) {
		bh2 = sb_bread(sb, eblock->extents[avail].ee_start + bi);

		if (!bh2) {
			ret = -EIO;
			goto put_block;
		}

		dblock = (struct ducndc_fs_dir_block *)bh2->b_data;

		if (dblock->nr_files != DUCNDC_FS_FILES_PER_BLOCK) {
			break;
		} else {
			brelse(bh2);
		}
	}

	ducndc_fs_set_file_into_dir(dblock, inode->i_ino, dentry->d_name.name);
	eblock->extents[avail].nr_files++;
	eblock->nr_files++;
	mark_buffer_dirty(bh2);
	mark_buffer_dirty(bh);
	brelse(bh2);
	brelse(bh);
	mark_inode_dirty(inode);

#if DUCNDC_FS_AT_LEAST(6, 7, 0)
	simple_inode_init_ts(dir);
#elif DUCNDC_FS_AT_LEAST(6, 6, 0)
	cur_time = current_time(dir);
	dir->i_mtime = dir->i_atime = cur_time;
	inode_set_ctime_to_ts(dir, cur_time);
#else
	dir->i_mtime = dir->i_atime = dir->i_ctime = current_time(dir);
#endif

	if (S_ISDIR(mode)) {
		inc_nlink(dir);
	}

	mark_inode_dirty(dir);
	d_instantiate(dentry, inode);

	return 0;

put_block:
	if (alloc & eblock->extents[avail].ee_start) {
		put_blocks(DUCNDC_FS_SB(sb), eblock->extents[avail].ee_start,
				   eblock->extents[avail].ee_len);
		memset(&eblock->extents[avail], 0, sizeof(struct ducndc_fs_extent));
	}

iput:
	put_blocks(DUCNDC_FS_SB(sb), DUCNDC_FS_INODE(inode)->ei_block, 1);
	put_inode(DUCNDC_FS_SB(sb), inode->i_ino);
	iput(inode);

end:
	brelse(bh);

	return ret;
}

static int 
ducndc_fs_remove_from_dir(
	struct inode *dir,
	struct dentry *dentry
)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode = d_inode(dentry);
	struct buffer_head *bh = NULL, *bh2 = NULL;
	struct ducndc_fs_file_ei_block *eblock = NULL;
	struct ducndc_fs_dir_block *dirblk = NULL;
	int ei = 0, bi = 0, fi = 0;
	int ret = 0, found = false;

	bh = sb_bread(sb, DUCNDC_FS_INODE(dir)->ei_block);

	if (!bh) {
		return -EIO;
	}

	eblock = (struct ducndc_fs_file_ei_block *)bh->b_data;

	int dir_nr_files = eblock->nr_files;

	for (ei = 0; dir_nr_files; ei++) {
		if (eblock->extents[ei].ee_start) {
			dir_nr_files -= eblock->extents[ei].nr_files;

			for (bi = 0; bi < eblock->extents[ei].ee_len; bi++) {
				bh2 = sb_bread(sb, eblock->extents[ei].ee_start + bi);

				if (!bh2) {
					ret = -EIO;
					goto release_bh;
				}

				dirblk = (struct ducndc_fs_dir_block *)bh2->b_data;
				int blk_nr_files = dirblk->nr_files;

				for (fi = 0; blk_nr_files && fi < DUCNDC_FS_FILES_PER_BLOCK;) {
					if (dirblk->files[fi].inode) {
						if (dirblk->files[fi].inode == inode->i_ino &&
							!strcmp(dirblk->files[fi].filename, dentry->d_name.name)) {
							found = true;
							dirblk->files[fi].inode = 0;

							for (int i = fi - 1; i >= 0; i--) {
								if (dirblk->files[i].inode != 0 || i == 0) {
									dirblk->files[i].nr_nlk += dirblk->files[fi].nr_nlk;
									break;
								}
							}

							dirblk->nr_files--;
							eblock->extents[ei].nr_files--;
							eblock->nr_files--;
							mark_buffer_dirty(bh2);
							brelse(bh2);
							found = true;
							goto found_data;
						}

						blk_nr_files--;
					}

					fi += dirblk->files[fi].nr_nlk;
				}

				brelse(bh2);
			}
		}
	}

found_data:
	if (found) {
		mark_buffer_dirty(bh);
	}

release_bh:
	brelse(bh);

	return ret;
}

static int 
ducndc_fs_unlink(
	struct inode *dir,
	struct dentry *dentry
)
{
	struct super_block *sb = dir->i_sb;
	struct ducndc_fs_sb_info *sbi = DUCNDC_FS_SB(sb);
	struct inode *inode = d_inode(dentry);
	struct buffer_head *bh = NULL, *bh2 = NULL;
	struct ducndc_fs_file_ei_block *file_block = NULL;
	char *block;

#if DUCNDC_FS_AT_LEAST(6, 6, 0) && DUCNDC_FS_LESS_EQUAL(6, 7, 0)
	struct timespec64 cur_time;
#endif 

	int ei = 0, bi = 0;
	int ret = 0;
	uint32_t ino = inode->i_ino;
	uint32_t bno = 0;
	ret = ducndc_fs_remove_from_dir(dir, dentry);

	if (ret != 0) {
		return ret;
	}

	if (S_ISLNK(inode->i_mode)) {
		goto clean_inode;
	}

#if DUCNDC_FS_AT_LEAST(6, 7, 0)
	simple_inode_init_ts(dir);
#elif DUCNDC_FS_AT_LEAST(6, 6, 0)
	cur_time = current_time(dir);
	dir->i_mtime = dir->i_atime = cur_time;
	inode_set_ctime_to_ts(dir, cur_time);
#else
	dir->i_mtime = dir->i_atime = dir->i_ctime = current_time(dir);
#endif 

	if (S_ISDIR(inode->i_mode)) {
		drop_nlink(dir);
		drop_nlink(inode);
	}

	mark_inode_dirty(dir);

	if (inode->i_nlink > 1) {
		inode_dec_link_count(inode);
		return ret;
	}

	bno = DUCNDC_FS_INODE(inode)->ei_block;
	bh = sb_bread(sb, bno);

	if (!bh) {
		goto clean_inode;
	}

	file_block = (struct ducndc_fs_file_ei_block *)bh->b_data;

	for (ei = 0; ei < DUCNDC_FS_MAX_EXTENTS; ei++) {
		if (!file_block->extents[ei].ee_start) {
			break;
		}

		put_blocks(sbi, file_block->extents[ei].ee_start, file_block->extents[ei].ee_len);

		for (bi = 0; bi < file_block->extents[ei].ee_len; bi++) {
			bh2 = sb_bread(sb, file_block->extents[ei].ee_start + bi);

			if (!bh2) {
				continue;
			}

			block = (char *)bh2->b_data;
			memset(block, 0, DUCNDC_FS_BLOCK_SIZE);
			mark_buffer_dirty(bh2);
			brelse(bh2);
		}
	}

	memset(file_block, 0, DUCNDC_FS_BLOCK_SIZE);
    mark_buffer_dirty(bh);
    brelse(bh);

clean_inode:
	inode->i_blocks = 0;
	DUCNDC_FS_INODE(inode)->ei_block = 0;
	inode->i_size = 0;
	i_uid_write(inode, 0);
	i_gid_write(inode, 0);

#if DUCNDC_FS_AT_LEAST(6, 7, 0)
	inode_set_mtime(inode, 0, 0);
	inode_set_atime(inode, 0, 0);
	inode_set_ctime(inode, 0, 0);
#elif DUCNDC_FS_AT_LEAST(6, 6, 0)
	inode->i_mtime.tv_sec = inode->i_atime.tv_sec = 0;
	inode_set_ctime(inode, 0, 0);
#else
	inode->i_ctime.tv_sec = inode->i_mtime.tv_sec = inode->i_atime.tv_sec = 0;
#endif

	inode_dec_link_count(inode);

	if (!S_ISLNK(inode->i_mode)) {
		put_blocks(sbi, bno, 1);
	}

	inode->i_mode = 0;
	put_inode(sbi, ino);

	return ret;
}

#if DUCNDC_FS_AT_LEAST(6, 3, 0)
static int ducndc_fs_rename(struct mnt_idmap *id,
                           struct inode *old_dir,
                           struct dentry *old_dentry,
                           struct inode *new_dir,
                           struct dentry *new_dentry,
                           unsigned int flags)
#elif DUCNDC_FS_AT_LEAST(5, 12, 0)
static int ducndc_fs_rename(struct user_namespace *ns,
                           struct inode *old_dir,
                           struct dentry *old_dentry,
                           struct inode *new_dir,
                           struct dentry *new_dentry,
                           unsigned int flags)
#else 
static int ducndc_fs_rename(struct inode *old_dir,
                           struct dentry *old_dentry,
                           struct inode *new_dir,
                           struct dentry *new_dentry,
                           unsigned int flags)
#endif
{
	struct super_block *sb = old_dir->i_sb;
	struct ducndc_fs_inode_info *ci_new = DUCNDC_FS_INODE(new_dir);
	struct inode *src = d_inode(old_dentry);
	struct buffer_head *bh_new = NULL, *bh2 = NULL;
    struct ducndc_fs_file_ei_block *eblock_new = NULL;
    struct ducndc_fs_dir_block *dblock = NULL;

#if DUCNDC_FS_AT_LEAST(6, 6, 0) && DUCNDC_FS_LESS_EQUAL(6, 7, 0)
    struct timespec64 cur_time;
#endif

    int new_pos = -1, ret = 0;
    int ei = 0, bi = 0, fi = 0, bno = 0;

    /* fail with these unsupported flags */
    if (flags & (RENAME_EXCHANGE | RENAME_WHITEOUT)) {
        return -EINVAL;
    }

	if (strlen(new_dentry->d_name.name) > DUCNDC_FS_FILE_NAME_LEN) {
        return -ENAMETOOLONG;
	}

    bh_new = sb_bread(sb, ci_new->ei_block);
    
    if (!bh_new) {
        return -EIO;
    }

    eblock_new = (struct ducndc_fs_file_ei_block *)bh_new->b_data;

    for (ei = 0; new_pos < 0 && ei < DUCNDC_FS_MAX_EXTENTS; ei++) {
    	if (!eblock_new->extents[ei].ee_start) {
    		break;
    	}

    	for (bi = 0; new_pos < 0 && bi < eblock_new->extents[ei].ee_len; bi++) {
    		bh2 = sb_bread(sb, eblock_new->extents[ei].ee_start + bi);

    		if (!bh2) {
    			ret = -EIO;
    			goto release_new;
    		}

    		dblock = (struct ducndc_fs_dir_block *)bh2->b_data;
    		int blk_nr_files = dblock->nr_files;

    		for (fi = 0; blk_nr_files;) {
    			if (new_dir == old_dir) {
    				if (dblock->files[fi].inode &&
    					!strncmp(dblock->files[fi].filename, old_dentry->d_name.name, DUCNDC_FS_FILE_NAME_LEN)) {
    					strncpy(dblock->files[fi].filename, new_dentry->d_name.name, DUCNDC_FS_FILE_NAME_LEN);
	    				mark_buffer_dirty(bh2);
	    				brelse(bh2);
	    				goto release_new;
    				}
    			} else {
    				if (dblock->files[fi].inode && 
    					!strncmp(dblock->files[fi].filename, new_dentry->d_name.name, DUCNDC_FS_FILE_NAME_LEN)) {
    					brelse(bh2);
    					ret = -EEXIST;
    					goto release_new;
    				}

    				if (new_pos < 0 && dblock->files[fi].nr_nlk != 1) {
    					new_pos = fi + 1;
    					break;
    				}
    			}

    			blk_nr_files--;
    			fi += dblock->files[fi].nr_nlk;
    		}

    		brelse(bh2);
    	}
    }

    if (new_pos < 0 && eblock_new->nr_files == DUCNDC_FS_FILES_PER_BLOCK) {
    	ret = -EMLINK;
    	goto release_new;
    }

    if (new_pos < 0) {
    	bno = get_free_blocks(sb, DUCNDC_FS_MAX_BLOCKS_PER_EXTENT);

    	if (!bno) {
    		ret = -ENOSPC;
    		goto release_new;
    	}

    	eblock_new->extents[ei].ee_start = bno;
    	eblock_new->extents[ei].ee_len = DUCNDC_FS_MAX_BLOCKS_PER_EXTENT;
    	eblock_new->extents[ei].ee_block = ei ? eblock_new->extents[ei - 1].ee_block + eblock_new->extents[ei - 1].ee_len : 0;
    	bh2 = sb_bread(sb, eblock_new->extents[ei].ee_start + 0);

    	if (!bh2) {
    		ret = -EIO;
    		goto put_block;
    	}

    	dblock = (struct ducndc_fs_dir_block *)bh2->b_data;
    	mark_buffer_dirty(bh_new);
    	new_pos = 0;
    }

    dblock->files[new_pos].inode = src->i_ino;
    strncpy(dblock->files[new_pos].filename, new_dentry->d_name.name, DUCNDC_FS_FILE_NAME_LEN);
    mark_buffer_dirty(bh2);
    brelse(bh2);

#if DUCNDC_FS_AT_LEAST(6, 7, 0)
    simple_inode_init_ts(new_dir);
#elif DUCNDC_FS_AT_LEAST(6, 6, 0)
    cur_time = current_time(new_dir);
    new_dir->i_atime = new_dir->i_mtime = cur_time;
    inode_set_ctime_to_ts(new_dir, cur_time);
#else
    new_dir->i_atime = new_dir->i_ctime = new_dir->i_mtime = current_time(new_dir);
#endif

    if (S_ISDIR(src->i_mode)) {
    	inc_nlink(new_dir);
    }

    mark_inode_dirty(new_dir);
    ret = ducndc_fs_remove_from_dir(old_dir, old_dentry);

    if (ret != 0) {
    	goto release_new;
    }

#if DUCNDC_FS_AT_LEAST(6, 7, 0)
    simple_inode_init_ts(old_dir);
#elif DUCNDC_FS_AT_LEAST(6, 6, 0)
    cur_time = current_time(old_dir);
    old_dir->i_atime = old_dir->i_mtime = cur_time;
    inode_set_ctime_to_ts(old_dir, cur_time);
#else 
    old_dir->i_atime = old_dir->i_ctime = old_dir->i_mtime = current_time(old_dir);
#endif

    if (S_ISDIR(src->i_mode)) {
    	drop_nlink(old_dir);
    }

    mark_inode_dirty(old_dir);

    return ret;

put_block:
	if (eblock_new->extents[ei].ee_start) {
		put_blocks(DUCNDC_FS_SB(sb), eblock_new->extents[ei].ee_start, eblock_new->extents[ei].ee_len);
		memset(&eblock_new->extents[ei], 0, sizeof(struct ducndc_fs_extent));
	}

release_new:
	brelse(bh_new);

	return ret;
}

#if DUCNDC_FS_AT_LEAST(6, 3, 0)
static int 
ducndc_fs_mkdir(
	struct mnt_idmap *id,
	struct inode *dir,
	struct dentry *dentry,
	umode_t mode
)
{
    return ducndc_fs_create(id, dir, dentry, mode | S_IFDIR, 0);
}
#elif DUCNDC_FS_AT_LEAST(5, 12, 0)
static int 
ducndc_fs_mkdir(
	struct user_namespace *ns,
	struct inode *dir,
	struct dentry *dentry,
	umode_t mode
)
{
    return ducndc_fs_create(ns, dir, dentry, mode | S_IFDIR, 0);
}
#else
static int 
ducndc_fs_mkdir(
	struct inode *dir,
	struct dentry *dentry,
	umode_t mode
)
{
    return ducndc_fs_create(dir, dentry, mode | S_IFDIR, 0);
}
#endif

static int 
ducndc_fs_rmdir(
	struct inode *dir, 
	struct dentry *dentry
)
{
    struct super_block *sb = dir->i_sb;
    struct inode *inode = d_inode(dentry);
    struct buffer_head *bh;
    struct ducndc_fs_file_ei_block *eblock;

    /* If the directory is not empty, fail */
    if (inode->i_nlink > 2)
        return -ENOTEMPTY;

    bh = sb_bread(sb, DUCNDC_FS_INODE(inode)->ei_block);

    if (!bh) {
        return -EIO;
    }

    eblock = (struct ducndc_fs_file_ei_block *)bh->b_data;

    if (eblock->nr_files != 0) {
        brelse(bh);
        return -ENOTEMPTY;
    }

    brelse(bh);

    /* Remove directory with unlink */
    return ducndc_fs_unlink(dir, dentry);
}

static int 
ducndc_fs_link(
	struct dentry *old_dentry,
	struct inode *dir,
	struct dentry *dentry
)
{
	struct inode *old_inode = d_inode(old_dentry);
	struct super_block *sb = old_inode->i_sb;
	struct ducndc_fs_inode_info *cli_dir = DUCNDC_FS_INODE(dir);
	struct ducndc_fs_file_ei_block *eblock = NULL;
	struct ducndc_fs_dir_block *dblock;
	struct buffer_head *bh = NULL, *bh2 = NULL;
	int ret = 0, alloc = false;
	int ei = 0, bi = 0;
	uint32_t avail;

	bh = sb_bread(sb, cli_dir->ei_block);

	if (!bh) {
		return -EIO;
	}

	eblock = (struct ducndc_fs_file_ei_block *)bh->b_data;

	if (eblock->nr_files == DUCNDC_FS_MAX_SUB_FILES) {
		ret = -EMLINK;
		goto end;
	}

	int dir_nr_files = eblock->nr_files;
	avail = ducndc_fs_get_available_ext_idx(&dir_nr_files, eblock);

	if (!dir_nr_files && !eblock->extents[avail].ee_start) {
		ret = ducndc_fs_put_new_ext(sb, avail, eblock);
		switch (ret) {
		case -ENOSPC:
			ret = -ENOSPC;
			goto end;
		case -EIO:
			ret = -EIO;
			goto put_block;
		}

		alloc = true;
	}

	for (bi = 0; bi < eblock->extents[avail].ee_len; bi++) {
		bh2 = sb_bread(sb, eblock->extents[avail].ee_start + bi);

		if (!bh2) {
			ret = -EIO;
			goto put_block;
		}

		dblock = (struct ducndc_fs_dir_block *)bh2->b_data;

		if (dblock->nr_files != DUCNDC_FS_FILES_PER_BLOCK) {
			break;
		} else {
			brelse(bh2);
		}
	}

	ducndc_fs_set_file_into_dir(dblock, old_inode->i_ino, dentry->d_name.name);
	eblock->nr_files++;
	mark_buffer_dirty(bh2);
	mark_buffer_dirty(bh);
	brelse(bh2);
	brelse(bh);
	inode_inc_link_count(old_inode);
	ihold(old_inode);
	d_instantiate(dentry, old_inode);

	return ret;

put_block:
	if (alloc && eblock->extents[ei].ee_start) {
		put_blocks(DUCNDC_FS_SB(sb), eblock->extents[ei].ee_start, eblock->extents[ei].ee_len);
		memset(&eblock->extents[ei], 0, sizeof(struct ducndc_fs_extent));
	}

end:
	brelse(bh);

	return ret;
}

#if DUCNDC_FS_AT_LEAST(6, 3, 0)
static int
ducndc_fs_symlink(
	struct mnt_idmap *id,
	struct inode *dir,
	struct dentry *dentry,
	const char *symname
)
#elif DUCNDC_FS_AT_LEAST(5, 12, 0)
static int 
ducndc_fs_symlink(
	struct user_namespace *ns,
    struct inode *dir,
    struct dentry *dentry,
    const char *symname
)
#else
static int 
ducndc_fs_symlink(
	struct inode *dir,
    struct dentry *dentry,
    const char *symname
)
#endif
{
	struct super_block *sb = dir->i_sb;
    unsigned int l = strlen(symname) + 1;
    struct inode *inode = ducndc_fs_new_inode(dir, S_IFLNK | S_IRWXUGO);
    struct ducndc_fs_inode_info *ci = DUCNDC_FS_INODE(inode);
    struct ducndc_fs_inode_info *ci_dir = DUCNDC_FS_INODE(dir);
    struct ducndc_fs_file_ei_block *eblock = NULL;
    struct ducndc_fs_dir_block *dblock = NULL;
    struct buffer_head *bh = NULL, *bh2 = NULL;
    int ret = 0, alloc = false;
    int ei = 0, bi = 0;
    uint32_t avail;

    if (l > sizeof(ci->i_data)) {
    	return -ENAMETOOLONG;
    }

    bh = sb_bread(sb, ci_dir->ei_block);

    if (!bh) {
    	return -EIO;
    }

    eblock = (struct ducndc_fs_file_ei_block *)bh->b_data;

    if (eblock->nr_files == DUCNDC_FS_MAX_SUB_FILES) {
    	ret = -EMLINK;
        printk(KERN_INFO "directory is full");
        goto end;
    }

    int dir_nr_files = eblock->nr_files;
    avail = ducndc_fs_get_available_ext_idx(&dir_nr_files, eblock);

    if (!dir_nr_files && !eblock->extents[avail].ee_start) {
    	ret = ducndc_fs_put_new_ext(sb, avail, eblock);

    	switch (ret) {
    	case -ENOSPC:
    		ret = -ENOSPC;
    		goto end;
    	case -EIO:
    		ret = -EIO;
    		goto put_block;
    	}

    	alloc = true;
    }

    for (bi = 0; bi < eblock->extents[avail].ee_len; bi++) {
    	bh2 = sb_bread(sb, eblock->extents[avail].ee_start + bi);

    	if (!bh2) {
    		ret = -EIO;
    		goto put_block;
    	}

    	dblock = (struct ducndc_fs_dir_block *)bh2->b_data;

    	if (dblock->nr_files != DUCNDC_FS_FILES_PER_BLOCK) {
    		break;
    	} else {
    		brelse(bh2);
    	}
    }

	ducndc_fs_set_file_into_dir(dblock, inode->i_ino, dentry->d_name.name);
	eblock->nr_files++;
	mark_buffer_dirty(bh2);
	mark_buffer_dirty(bh);
	brelse(bh2);
	brelse(bh);
	inode->i_link = (char *)ci->i_data;
	memcpy(inode->i_link, symname, l);
	inode->i_size = l - 1;
	mark_inode_dirty(inode);
	d_instantiate(dentry, inode);

	return 0;

put_block:
	if (alloc && eblock->extents[ei].ee_start) {
		put_blocks(DUCNDC_FS_SB(sb), eblock->extents[ei].ee_start, eblock->extents[ei].ee_len);
		memset(&eblock->extents[ei], 0, sizeof(struct ducndc_fs_extent));
	} 

end:
	brelse(bh);

	return ret;
}

static const char *
ducndc_fs_get_link(
	struct dentry *dentry,
	struct inode *inode,
	struct delayed_call *done
)
{
	return inode->i_link;
}

static const struct inode_operations ducndc_fs_inode_ops = {
    .lookup = ducndc_fs_lookup,
    .create = ducndc_fs_create,
    .unlink = ducndc_fs_unlink,
    .mkdir = ducndc_fs_mkdir,
    .rmdir = ducndc_fs_rmdir,
    .rename = ducndc_fs_rename,
    .link = ducndc_fs_link,
    .symlink = ducndc_fs_symlink,
};

static const struct inode_operations symlink_inode_ops = {
    .get_link = ducndc_fs_get_link,
};