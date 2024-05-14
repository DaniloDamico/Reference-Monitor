#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/timekeeping.h>
#include <linux/time.h>
#include <linux/buffer_head.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mnt_idmapping.h>
#include <linux/version.h>

#include "logfilefs.h"

MODULE_LICENSE("GPL");

static struct super_operations logfilefs_super_ops = {
};


static struct dentry_operations logfilefs_dentry_ops = {
};


int logfilefs_fill_super(struct super_block *sb, void *data, int silent) {   

    struct inode *root_inode;
    struct buffer_head *bh;
    struct logfilefs_sb_info *sb_disk;
    struct timespec64 curr_time;
    uint64_t magic;

    //Unique identifier of the filesystem
    sb->s_magic = MAGIC;

    bh = sb_bread(sb, SB_BLOCK_NUMBER);
    if(!sb) return -EIO;

    sb_disk = (struct logfilefs_sb_info *)bh->b_data;
    magic = sb_disk->magic;
    brelse(bh);

    //check on the expected magic number
    if(magic != sb->s_magic) return -EBADF;

    sb->s_fs_info = NULL; //FS specific data (the magic number) already reported into the generic superblock
    sb->s_op = &logfilefs_super_ops;//set our own operations


    root_inode = iget_locked(sb, LOGFILEFS_ROOT_INODE_NUMBER);//get a root inode from cache
    if (!root_inode) return -ENOMEM;

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0) // nop_mnt_idmap introduced in kernel 6.2
        inode_init_owner(&nop_mnt_idmap, root_inode, NULL, S_IFREG);
    #else
        inode_init_owner(sb->s_user_ns, root_inode, NULL, S_IFREG);
    #endif

    root_inode->i_sb = sb;
    root_inode->i_op = &logfilefs_inode_ops;//set our inode operations
    root_inode->i_fop = &logfilefs_dir_operations;//set our file operations
    //update access permission
    root_inode->i_mode = S_IFDIR | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;

    //baseline alignment of the FS timestamp to the current time
    ktime_get_real_ts64(&curr_time);
    root_inode->i_atime = root_inode->i_mtime = root_inode->i_ctime = curr_time;

    // no inode from device is needed - the root of our file system is an in memory object
    root_inode->i_private = NULL;

    sb->s_root = d_make_root(root_inode);
    if (!sb->s_root)
        return -ENOMEM;

    sb->s_root->d_op = &logfilefs_dentry_ops;//set our dentry operations

    //unlock the inode to make it usable
    unlock_new_inode(root_inode);

    return 0;
}

static void logfilefs_kill_superblock(struct super_block *s) {
    kill_block_super(s);
    printk(KERN_INFO "%s: logfilefs unmount successful.\n", SUBMODULE);
    return;
}

//called on file system mounting 
struct dentry *logfilefs_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data) {

    struct dentry *ret;

    ret = mount_bdev(fs_type, flags, dev_name, data, logfilefs_fill_super);

    if (unlikely(IS_ERR(ret)))
        printk("%s: error mounting logfilefs",SUBMODULE);
    else
        printk("%s: logfilefs successfully mounted from device %s\n",SUBMODULE,dev_name);

    return ret;
}

//file system structure
struct file_system_type logfilefs_type = {
	.owner = THIS_MODULE,
        .name           = FILESYSTEM_NAME,
        .mount          = logfilefs_mount,
        .kill_sb        = logfilefs_kill_superblock,
};




