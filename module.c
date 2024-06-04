#include "module.h"

void add_protected_path(const char *path, int isDir)
{
    struct path_node *new_node = kmalloc(sizeof(struct path_node), GFP_KERNEL);
    if (!new_node)
        return;

    new_node->path = kmalloc(strlen(path) + 1, GFP_KERNEL);
    if (!new_node->path)
    {
        kfree(new_node);
        return;
    }
    strcpy(new_node->path, path);

    new_node->isDir = isDir;

    mutex_lock(&protected_paths);
    if (head == NULL)
    {
        new_node->next = NULL;
        head = new_node;
    }
    else
    {
        new_node->next = head;
        head = new_node;
    }
    mutex_unlock(&protected_paths);
}

void free_protected_path(const char *path)
{
    mutex_lock(&protected_paths);
    if (head == NULL)
    {
        mutex_unlock(&protected_paths);
        return;
    }

    struct path_node *prev = NULL;
    struct path_node *curr = head;

    while (1)
    {
        if (strcmp(path, curr->path) == 0)
        {
            if (prev == NULL)
            {
                if (curr->next == NULL)
                {
                    head = NULL;
                }
                else
                {
                    head = curr->next;
                }
            }
            else
            {
                prev->next = curr->next;
            }

            kfree(curr->path);
            kfree(curr);
            break;
        }

        if (curr->next == NULL)
            break;
        prev = curr;
        curr = curr->next;
    }

    mutex_unlock(&protected_paths);
}

void free_all_paths(void)
{
    struct path_node *temp;
    mutex_lock(&protected_paths);
    while (head != NULL)
    {
        temp = head;
        head = head->next;
        kfree(temp->path);
        kfree(temp);
    }
    mutex_unlock(&protected_paths);
}

ssize_t write_proc(struct file *filp, const char *buf, size_t count, loff_t *offp)
{

    int ret = 0;
    int euid = current_euid().val;
    char file_data[SIZE] = {0};
    if (euid != 0)
    {
        printk("%s: set euid to 0 to send commands to the reference monitor\n", MODNAME);
        return 1; // bad euid
    }

    if (buf == NULL || count <= 0 || !access_ok(buf, count))
    {
        printk("%s: error acquiring command\n", MODNAME);
        return 2; // error acquiring command
    }

    ret = copy_from_user(file_data, buf, count);
    if (ret != 0)
    {
        printk("%s: error acquiring command\n", MODNAME);
        return 2; // error acquiring command
    }

    char *data_pointer = file_data;

    char *first_word = NULL; // password
    first_word = strsep(&data_pointer, " ");

    char *second_word = NULL; // command
    second_word = strsep(&data_pointer, " ");

    char *third_word = NULL; // parameter
    if (second_word != NULL)
    {
        if (strcmp(second_word, LOCK) != 0 && strcmp(second_word, UNLOCK) != 0)
        {
            third_word = data_pointer;
        }
    }

    if ((first_word == NULL || second_word == NULL) || (third_word == NULL && (strncmp(second_word, LOCK, strlen(LOCK)) != 0 && strncmp(second_word, UNLOCK, strlen(UNLOCK)) != 0)))
    {
        printk("%s: badly formatted input. Try: password command \"parameter\"\n", MODNAME);
        return 2; // error acquiring command
    }

    if (check_password(first_word) != 1)
    {
        printk("%s: Wrong password.\n", MODNAME);
        return 3; // wrong password
    }

    // perform command
    if (strcmp(second_word, CHANGEPASSW) == 0)
    {
        printk("%s: you chose %s.\n", MODNAME, CHANGEPASSW);

        if (third_word[0] == '\0')
        {
            printk("%s: please insert a non empty password.\n", MODNAME);
            ret = 4; // invalid parameter
            goto end_write;
        }

        encrypt_password(third_word, strlen(third_word));
    }
    else if (strcmp(second_word, SETSTATE) == 0)
    {
        printk("%s: you chose %s.\n", MODNAME, SETSTATE);

        // parse new state
        if (strcmp(third_word, "OFF") == 0)
        {
            mutex_lock(&state);
            current_state = OFF;
            state_char = "OFF";
            mutex_unlock(&state);
        }
        else if (strcmp(third_word, "ON") == 0)
        {
            mutex_lock(&state);
            current_state = ON;
            state_char = "ON";
            mutex_unlock(&state);
        }
        else if (strcmp(third_word, "REC_OFF") == 0)
        {
            mutex_lock(&state);
            current_state = REC_OFF;
            state_char = "REC_OFF";
            mutex_unlock(&state);
        }
        else if (strcmp(third_word, "REC_ON") == 0)
        {
            mutex_lock(&state);
            current_state = REC_ON;
            state_char = "REC_ON";
            mutex_unlock(&state);
        }
        else
        {
            printk("%s: invalid state\n", MODNAME);
            ret = 4; // invalid parameter
            goto end_write;
        }
    }
    else if (strcmp(second_word, ADDPATH) == 0)
    {
        printk("%s: you chose %s.\n", MODNAME, ADDPATH);

        mutex_lock(&state);
        if (current_state == OFF || current_state == ON)
        {
            mutex_unlock(&state);
            printk("%s: the module is not in a reconfigurable state.\n", MODNAME);
            ret = 5; // module not in a reconfigurable state
            goto end_write;
        }
        mutex_unlock(&state);

        struct path path;
        int isDir = 0;
        int err = kern_path(third_word, LOOKUP_FOLLOW, &path);
        if (err != 0)
        {
            pr_info("Path does not exist.\n");
            ret = 4; // invalid parameter
            goto end_write;
        }

        if (S_ISDIR(path.dentry->d_inode->i_mode))
        {
            isDir = 1;
        }

        add_protected_path(third_word, isDir);
    }
    else if (strcmp(second_word, REMOVEPATH) == 0)
    {
        printk("%s: you chose %s.\n", MODNAME, REMOVEPATH);

        mutex_lock(&state);
        if (current_state == OFF || current_state == ON)
        {
            mutex_unlock(&state);
            printk("%s: the module is not in a reconfigurable state.\n", MODNAME);
            ret = 5; // module not in a reconfigurable state
            goto end_write;
        }
        mutex_unlock(&state);

        free_protected_path(third_word);
    }
    else if (strncmp(second_word, LOCK, strlen(LOCK)) == 0)
    {
        mutex_lock(&remove);
        if (rmmod_lock == 0)
        {
            if (!try_module_get(THIS_MODULE))
            {
                printk("%s: failed to increase reference count", MODNAME);
            }
            else
            {
                rmmod_lock = 1;
            }
        }
        else
        {
            printk("%s: module already locked\n", MODNAME);
        }
        mutex_unlock(&remove);
    }
    else if (strncmp(second_word, UNLOCK, strlen(UNLOCK)) == 0)
    {
        mutex_lock(&remove);
        if (rmmod_lock == 1)
        {
            module_put(THIS_MODULE);
            rmmod_lock = 0;
        }
        else
        {
            printk("%s: module already unlocked\n", MODNAME);
        }
        mutex_unlock(&remove);
    }
    else
    {
        printk("%s: invalid choice.\n", MODNAME);
        ret = 6; // invalid command
        goto end_write;
    }

end_write:
    return ret;
}

ssize_t read_protected(struct file *filp, char *buf, size_t count, loff_t *offp)
{

    mutex_lock(&protected_paths);
    if (head == NULL)
    {
        mutex_unlock(&protected_paths);
        return 0;
    }

    struct path_node *curr = head;
    char *kbuf;
    ssize_t len = 0; // file size
    size_t offset = 0;
    int ret;

    // Calculate the total length of the data
    while (curr)
    {
        len += strlen(curr->path) + 1; // +1 for newline
        curr = curr->next;
    }

    if (*offp > len)
    {
        return 0;
    }

    if (count > (len - *offp))
    {
        count = len - *offp;
    }

    kbuf = kmalloc(len, GFP_KERNEL);
    if (!kbuf)
    {
        return -ENOMEM;
    }

    curr = head;
    while (curr)
    {
        offset += snprintf(kbuf + offset, len - offset, "%s\n", curr->path);
        curr = curr->next;
    }

    mutex_unlock(&protected_paths);
    ret = copy_to_user(buf, kbuf, count);
    *offp += (count - ret);

    kfree(kbuf);

    return count - ret;
}

struct deferred_work_data
{
    int tgid;                   // process TGID
    int tid;                    // thread ID
    uid_t uid;                  // user ID
    uid_t euid;                 // effective user ID
    char open_path[PATH_MAX];   // path of the program that is being opened
    char caller_path[PATH_MAX]; // path of the program that is currently attemping to open the file
    struct work_struct real_work;
    char hash[SHA256_LENGTH]; // {deferred work} sha256 of caller file
};

struct sdesc
{
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    return sdesc;
}

static void deferred_work_function(struct work_struct *work)
{

    struct deferred_work_data *data = container_of(work, struct deferred_work_data, real_work);
    set_current_state(TASK_INTERRUPTIBLE);

    struct file *caller_filp = filp_open(data->caller_path, O_RDONLY, 0);
    if (caller_filp == NULL)
        goto defer_out;

    char *buffer = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buffer)
        goto defer_out;

    struct crypto_shash *tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
        goto defer_out;

    struct sdesc *sdesc;

    sdesc = init_sdesc(tfm);
    if (IS_ERR(sdesc))
        goto defer_out;

    ssize_t bytes_read;
    while ((bytes_read = kernel_read(caller_filp, buffer, PAGE_SIZE - 1, &caller_filp->f_pos)) > 0)
    {
        crypto_shash_update(&sdesc->shash, buffer, bytes_read);
        memset(buffer, 0, PAGE_SIZE);
    }

    memset(data->hash, 0, SHA256_LENGTH);
    crypto_shash_final(&sdesc->shash, data->hash);

    struct file *log = filp_open(MOUNTED_IMAGE_PATH, O_WRONLY, 0);
    if (log == NULL || IS_ERR(log))
    {
        printk("%s: failed to open logfile\n", MODNAME);
        goto defer_out;
    }

    /*
    if (data == NULL) {
    printk(KERN_ERR "%s: data is NULL\n", MODNAME);
    } else {
        if (data->open_path == NULL) {
            printk(KERN_ERR "%s: data->open_path is NULL\n", MODNAME);
        }

        if (data->caller_path == NULL) {
            printk(KERN_ERR "%s: data->caller_path is NULL\n", MODNAME);
        }

        printk("%s: tgid: %d, tid:%d, uid:%d, euid:%d, opened file:%s, caller path:%s",
            MODNAME,
            data->tgid,
            data->tid,
            data->uid,
            data->euid,
            data->open_path ? data->open_path : "NULL",
            data->caller_path ? data->caller_path : "NULL");
    }
    */

    char str[sizeof(data->tgid) + sizeof(data->tid) + sizeof(data->uid) + sizeof(data->euid) + sizeof(data->open_path) + sizeof(data->caller_path) + 6 * sizeof(DIVIDER)] = {0};

    snprintf(str, sizeof(str), "%d%s%d%s%d%s%d%s%s%s%s%s",
             data->tgid, DIVIDER,
             data->tid, DIVIDER,
             data->uid, DIVIDER,
             data->euid, DIVIDER,
             data->open_path, DIVIDER,
             data->caller_path, DIVIDER);
    log->f_op->write(log, str, sizeof(str), &log->f_pos);

    int i = 0;
    for (i = 0; i < SHA256_LENGTH; i++)
    {
        memset(str, 0, SHA256_LENGTH);
        snprintf(str, 3, "%02x", data->hash[i]);
        // printk(KERN_CONT "%x", data->hash[i]);
        log->f_op->write(log, str, strlen(str), &log->f_pos);
    }

    log->f_op->write(log, "\n", sizeof("\n"), &log->f_pos);

    filp_close(log, NULL);

defer_out:

    filp_close(caller_filp, NULL);
    kfree(buffer);
    kfree(sdesc);
    crypto_free_shash(tfm);
    kfree(data);
}

int isPathProtected(const char *filename)
{

    mutex_lock(&protected_paths);
    struct path_node *curr = head;

    while (curr != NULL)
    {
        if (strcmp(filename, curr->path) == 0 || (curr->isDir == 1 && strncmp(filename, curr->path, strlen(curr->path)) == 0))
        {
            mutex_unlock(&protected_paths);
            return 1;
        }
        curr = curr->next;
    }

    mutex_unlock(&protected_paths);
    return 0;
}

void initializeDeferredWork(char *path)
{
    struct deferred_work_data *deferred_data;

    deferred_data = kmalloc(sizeof(struct deferred_work_data), GFP_KERNEL);

    if (deferred_data)
    {
        deferred_data->tgid = current->tgid;
        deferred_data->tid = current->pid;
        deferred_data->uid = current_uid().val;
        deferred_data->euid = current_euid().val;
        strcpy(deferred_data->open_path, path);

        char *p = NULL, *pathname;
        struct mm_struct *mm = current->mm;
        if (mm)
        {
            down_read(&mm->mmap_lock);
            if (mm->exe_file)
            {
                pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
                if (pathname)
                {
                    p = d_path(&mm->exe_file->f_path, pathname, PATH_MAX);
                    strcpy(deferred_data->caller_path, p);
                    kfree(pathname);
                }
            }
            up_read(&mm->mmap_lock);
        }
        INIT_WORK(&deferred_data->real_work, deferred_work_function);
        schedule_work(&deferred_data->real_work);
    }
}

static int kretprobe_handler(struct kretprobe_instance *ri, struct pt_regs *the_regs)
{
    regs_set_return_value(the_regs, -EACCES);
    return 0;
}

static int open_pre_handler(struct kprobe *ri, struct pt_regs *regs)
{
    char *buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf)
        return 0;

    // int vfs_open(const struct path *path, struct file *file)
    const struct path *path = (const struct path *) regs->di;
    char *fullpath = d_path(path, buf, PATH_MAX);
    if (IS_ERR(fullpath))
        goto open_buf_out;

    struct file *file = (struct file *)regs->si;
    int flags = (int)file->f_flags;
    unsigned int accessMode = flags & O_ACCMODE;  
        
    mutex_lock(&state);
    if (current_state == OFF || current_state == REC_OFF)
    {
        mutex_unlock(&state);
        goto open_buf_out;
    }
    mutex_unlock(&state);

    mutex_lock(&protected_paths);
    if (head == NULL)
    {
        mutex_unlock(&protected_paths);
        goto open_buf_out;
    }
    mutex_unlock(&protected_paths);

    if (accessMode == O_RDONLY)
        goto open_buf_out;

    if (isPathProtected(fullpath) == 1)
    {
        ((struct file *)regs->si)->f_flags = (file->f_flags & ~O_ACCMODE) | O_RDONLY;
        initializeDeferredWork(fullpath);
        return 0;
    }

open_buf_out:
    kfree(buf);
    return 0;
    
}

static int si_dentry_pre_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    // int security_path_rmdir(const struct path *dir, struct dentry *dentry);
    // int security_path_unlink(const struct path *dir, struct dentry *dentry);
    // int security_path_mkdir(const struct path *dir, struct dentry *dentry, umode_t mode);
    // int security_path_rmdir(const struct path *dir, struct dentry *dentry);
    // int security_path_rename(const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, unsigned int flags);
    // int security_path_symlink(const struct path *dir, struct dentry *dentry, const char *old_name);

    const struct path *pathstruct = regs->di;
    if (!pathstruct)
        return 1;

    struct dentry *dentry = (struct dentry *) regs->si;
    if (!dentry)
        return 1;

    char *fullpath = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!fullpath)
        return 1;

    char *path_buffer = kmalloc(PATH_MAX, GFP_KERNEL);
    char *path = d_path(pathstruct, path_buffer, PATH_MAX);
    if (IS_ERR(path)){
        goto dentry_out;
    }
    
    char *dentry_name = dentry->d_name.name;

    snprintf(fullpath, PATH_MAX, "%s/%s", path, dentry_name);
    kfree(path_buffer);

    mutex_lock(&state);
    if (current_state == OFF || current_state == REC_OFF)
    {
        mutex_unlock(&state);
        goto dentry_out;
    }
    mutex_unlock(&state);

    mutex_lock(&protected_paths);
    if (head == NULL)
    {
        mutex_unlock(&protected_paths);
        goto dentry_out;
    }
    mutex_unlock(&protected_paths);

    if (isPathProtected(fullpath) == 1)
    {
        initializeDeferredWork(fullpath);
        return 0;
    }

dentry_out:
    kfree(fullpath);
    return 1;
}

static int create_pre_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    // int security_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
    struct dentry *dentry = (struct dentry *) regs->si;
    if (!dentry)
        return 1;

    char *dentry_buffer = kmalloc(PATH_MAX, GFP_KERNEL);
    char *fullpath = dentry_path_raw(dentry, dentry_buffer, PATH_MAX);
    if (IS_ERR(fullpath)){
        goto create_out;
    }
    
    mutex_lock(&state);
    if (current_state == OFF || current_state == REC_OFF)
    {
        mutex_unlock(&state);
        goto create_out;
    }
    mutex_unlock(&state);

    mutex_lock(&protected_paths);
    if (head == NULL)
    {
        mutex_unlock(&protected_paths);
        goto create_out;
    }
    mutex_unlock(&protected_paths);

    if (isPathProtected(fullpath) == 1)
    {
        initializeDeferredWork(fullpath);
        return 0;
    }
    
create_out:
    kfree(dentry_buffer);
    return 1;
}

struct kprobe open_probe = {
    .symbol_name = "vfs_open",
    .pre_handler = open_pre_handler,};

struct kretprobe unlink_retprobe = {
    .kp.symbol_name = "security_path_unlink",
    .handler = kretprobe_handler,
    .entry_handler = si_dentry_pre_handler,
    .maxactive = -1};

struct kretprobe rmdir_retprobe = {
    .kp.symbol_name = "security_path_rmdir",
    .handler = kretprobe_handler,
    .entry_handler = si_dentry_pre_handler,
    .maxactive = -1};

struct kretprobe mkdir_retprobe = {
    .kp.symbol_name = "security_path_mkdir",
    .handler = kretprobe_handler,
    .entry_handler = si_dentry_pre_handler,
    .maxactive = -1};

struct kretprobe rename_retprobe = {
    .kp.symbol_name = "security_path_rename",
    .handler = kretprobe_handler,
    .entry_handler = si_dentry_pre_handler,
    .maxactive = -1};

struct kretprobe create_retprobe = {
    .kp.symbol_name = "security_inode_create",
    .handler = kretprobe_handler,
    .entry_handler = create_pre_handler,
    .maxactive = -1};