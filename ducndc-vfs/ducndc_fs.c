#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "ducndc_fs.h"

struct dentry *
ducndc_fs_mount(
	struct file_system_type *fs_type,
	int flags,
	const char *dev_name,
	void *data
)
{
	struct dentry *dentry = mount_bdev(fs_type, flags, dev_name, data, ducndc_fs_fill_super);

	if (IS_ERR(dentry)) {
		pr_err("'%s' mount failure\n", dev_name);
	} else {
		pr_info("'%s' mount success\n", dev_name);
	}

	return dentry;
}

void 
ducndc_fs_kill_sb(
	struct super_block *sb 
)
{
	struct ducndc_fs_sb_info *sbi = DUCNDC_FS_SB(sb);
#if DUCNDC_FS_AT_LEAST(6, 9, 0)
    if (sbi->s_journal_bdev_file)
        fput(sbi->s_journal_bdev_file);
#elif DUCNDC_FS_AT_LEAST(6, 7, 0)
    if (sbi->s_journal_bdev_handle)
        bdev_release(sbi->s_journal_bdev_handle);
#endif
    kill_block_super(sb);

    pr_info("unmounted disk\n");
}

static struct file_system_type ducndc_fs_file_system_type = {
    .owner = THIS_MODULE,
    .name = "ducndc_fs",
    .mount = ducndc_fs_mount,
    .kill_sb = ducndc_fs_kill_sb,
    .fs_flags = FS_REQUIRES_DEV,
    .next = NULL,
};

static int __init ducndc_fs_init(void)
{
    int ret = ducndc_fs_init_inode_cache();
    if (ret) {
        pr_err("Failed to create inode cache\n");
        goto err;
    }

    ret = register_filesystem(&ducndc_fs_file_system_type);
    if (ret) {
        pr_err("Failed to register file system\n");
        goto err_inode;
    }

    pr_info("module loaded\n");
    return 0;

err_inode:
    ducndc_fs_destroy_inode_cache();
    /* Only after rcu_barrier() is the memory guaranteed to be freed. */
    rcu_barrier();
err:
    return ret;
}

static void __exit ducndc_fs_exit(void)
{
    int ret = unregister_filesystem(&ducndc_fs_file_system_type);
    if (ret)
        pr_err("Failed to unregister file system\n");

    ducndc_fs_destroy_inode_cache();
    /* Only after rcu_barrier() is the memory guaranteed to be freed. */
    rcu_barrier();

    pr_info("module unloaded\n");
}

module_init(ducndc_fs_init);
module_exit(ducndc_fs_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("ducndc");
MODULE_DESCRIPTION("File System Module");