#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/timekeeping.h>
#include <linux/time.h>
#include <linux/buffer_head.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "logfilefs.h"

MODULE_LICENSE("GPL");

// this iterate function just returns 3 entries: . and .. and then the name of the unique file of the file system
static int logfilefs_iterate(struct file *file, struct dir_context *ctx)
{
	if (ctx->pos)
        return 0;

    // Get inode
    struct inode *inode = file_inode(file);
    if (inode->i_ino != LOGFILEFS_ROOT_INODE_NUMBER)
        return -ENOENT;

    // Add unique file to directory context
    dir_emit(ctx, UNIQUE_FILE_NAME, strlen(UNIQUE_FILE_NAME), LOGFILEFS_FILE_INODE_NUMBER, DT_REG);
    ctx->pos += 1;

    return 0;
}

const struct file_operations logfilefs_dir_operations = {
	.owner = THIS_MODULE,
	.iterate_shared = logfilefs_iterate,
};
