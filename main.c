#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <asm/errno.h>
#include <linux/fcntl.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <linux/scatterlist.h>
#include <linux/init.h>
#include <linux/crypto.h>
#include <crypto/skcipher.h>

#include <linux/random.h> //

#include "logfilefs/logfilefs.h"

/*
This linux kernel module contains a referenced monitor.

It is based on code samples made available during the course Sistemi Operativi Avanzati.
Checks on the linux kernel version being older than 5.15 have been removed since the module fails its registration in that case.

The code has been developed and tested on an Ubuntu VM having kernel version 6.5.0-28-generic
The code has been further modified for compatibility and tested on an Ubuntu VM having kernel version 5.15.0-91-generic
*/

MODULE_AUTHOR("Danilo D'Amico");
MODULE_DESCRIPTION("A reconfigurable, password-protected reference monitor that prevents write-opens on the files and directories it monitors");
MODULE_LICENSE("GPL");

#define MODNAME "Reference Monitor"

#define DIVIDER ", "
#define SHA256_LENGTH 32 // 256 bit
#define PASSWORD_DATA_SIZE 512

#define SIZE (4096)
#define CONFIG_FILE "rm_config"
#define CONFIG_PATH "/proc/rm_config"

#define PROTECTED_LIST_FILE "rm_protected"
#define PROTECTED_LIST_PATH "/proc/rm_protected"

#define CHANGEPASSW "changepassw"
#define SETSTATE "setstate"
#define ADDPATH "addpath"
#define REMOVEPATH "removepath"
#define UNINSTALL "uninstall"

DEFINE_MUTEX(lock);
DEFINE_MUTEX(probe_lock);
int rmmod_lock = 1;

enum RM_State
{
	OFF,
	ON,
	REC_OFF, // in reconfigurable mode it is possible to add or remove protected paths
	REC_ON
};

enum RM_State current_state = OFF;
static char *state_char = "OFF";
module_param(state_char, charp, S_IRUGO);

struct path_node
{
	char *path;
	struct path_node *next;
};

struct path_node *head = NULL;

void add_protected_path(const char *path)
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
}

void free_protected_path(const char *path)
{
	if (head == NULL)
		return;
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
}

void free_all_paths(void)
{
	struct path_node *temp;
	while (head != NULL)
	{
		temp = head;
		head = head->next;
		kfree(temp->path);
		kfree(temp);
	}
}

u8 *password_data = NULL;
u8 iv[16];	/* AES-256-XTS takes a 16-byte IV */
u8 key[64]; /* AES-256-XTS takes a 64-byte key */

ssize_t write_proc(struct file *filp, const char *buf, size_t count, loff_t *offp);
ssize_t read_protected(struct file *filp, char *buf, size_t count, loff_t *offp);

struct proc_ops proc_fops = {
	.proc_write = write_proc};

struct proc_ops protected_fops = {
	.proc_read = read_protected};

/* tie all data structures together */
struct skcipher_def
{
	struct scatterlist sg;
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct crypto_wait wait;
};

int encrypt_password(char *plaintext, int textsize)
{
	struct crypto_skcipher *tfm = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sg;
	DECLARE_CRYPTO_WAIT(wait);
	int err;
	tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
	if (IS_ERR(tfm))
	{
		pr_err("Error allocating xts(aes) handle: %ld\n", PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	err = crypto_skcipher_setkey(tfm, key, sizeof(key));
	if (err)
	{
		pr_err("Error setting key: %d\n", err);
		goto out;
	}

	/* Allocate a request object */
	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
	{
		err = -ENOMEM;
		goto out;
	}

	/* Prepare the input data */
	kfree(password_data);
	password_data = kzalloc(PASSWORD_DATA_SIZE, GFP_KERNEL);
	if (!password_data)
	{
		err = -ENOMEM;
		goto out;
	}
	int copy_size = (textsize < PASSWORD_DATA_SIZE) ? textsize : (PASSWORD_DATA_SIZE - 1);
	strncpy(password_data, plaintext, copy_size);

	u8 iv_copy[16];
	strncpy(iv_copy, iv, 16);

	sg_init_one(&sg, password_data, PASSWORD_DATA_SIZE);
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
								  crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &sg, &sg, PASSWORD_DATA_SIZE, iv_copy);

	err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	if (err)
	{
		pr_err("Error encrypting data: %d\n", err);
		goto out;
	}

out:
	crypto_free_skcipher(tfm);
	skcipher_request_free(req);
	return err;
}

int check_password(char *password)
{
	struct crypto_skcipher *tfm = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sg;
	DECLARE_CRYPTO_WAIT(wait);
	int err;
	tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
	if (IS_ERR(tfm))
	{
		pr_err("Error allocating xts(aes) handle: %ld\n", PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	err = crypto_skcipher_setkey(tfm, key, sizeof(key));
	if (err)
	{
		pr_err("Error setting key: %d\n", err);
		goto out;
	}

	/* Allocate a request object */
	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
	{
		err = -ENOMEM;
		goto out;
	}

	u8 iv_copy[16];
	strncpy(iv_copy, iv, 16);

	u8 *password_data_copy = kzalloc(PASSWORD_DATA_SIZE, GFP_KERNEL);
	if (!password_data_copy)
	{
		err = -ENOMEM;
		goto out;
	}
	memcpy(password_data_copy, password_data, PASSWORD_DATA_SIZE);

	sg_init_one(&sg, password_data_copy, PASSWORD_DATA_SIZE);
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
								  crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &sg, &sg, PASSWORD_DATA_SIZE, iv_copy);

	err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
	if (err)
	{
		pr_err("Error encrypting data: %d\n", err);
		goto out;
	}

	if (strncmp(password, password_data_copy, strlen(password)) == 0)
	{
		err = 1;
	}
	else
	{
		err = -1;
	}

out:
	kfree(password_data_copy);
	crypto_free_skcipher(tfm);
	skcipher_request_free(req);
	return err;
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
		mutex_unlock(&lock);
		return 2; // error acquiring command
	}

	ret = copy_from_user(file_data, buf, count);
	if (ret != 0)
	{
		printk("%s: error acquiring command\n", MODNAME);
		mutex_unlock(&lock);
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
		if (strcmp(second_word, UNINSTALL) != 0)
		{
			strsep(&data_pointer, "\"");
			third_word = strsep(&data_pointer, "\"");
		}
	}

	if ((first_word == NULL || second_word == NULL) || (third_word == NULL && strncmp(second_word, UNINSTALL, strlen(UNINSTALL)) != 0))
	{
		mutex_unlock(&lock);
		printk("%s: badly formatted input. Try: password command \"parameter\"\n", MODNAME);
		return 2; // error acquiring command
	}

	mutex_lock(&lock);

	if (check_password(first_word) != 1)
	{
		printk("%s: Wrong password.\n", MODNAME);
		mutex_unlock(&lock);
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

		mutex_lock(&probe_lock);

		// parse new state
		if (strcmp(third_word, "OFF") == 0)
		{
			current_state = OFF;
			state_char = "OFF";
		}
		else if (strcmp(third_word, "ON") == 0)
		{
			current_state = ON;
			state_char = "ON";
		}
		else if (strcmp(third_word, "REC_OFF") == 0)
		{
			current_state = REC_OFF;
			state_char = "REC_OFF";
		}
		else if (strcmp(third_word, "REC_ON") == 0)
		{
			current_state = REC_ON;
			state_char = "REC_ON";
		}
		else
		{
			printk("%s: invalid state\n", MODNAME);
			mutex_unlock(&probe_lock);
			ret = 4; // invalid parameter
			goto end_write;
		}

		mutex_unlock(&probe_lock);
	}
	else if (strcmp(second_word, ADDPATH) == 0)
	{
		printk("%s: you chose %s.\n", MODNAME, ADDPATH);

		if (current_state == OFF || current_state == ON)
		{
			printk("%s: the module is not in a reconfigurable state.\n", MODNAME);
			ret = 5; // module not in a reconfigurable state
			goto end_write;
		}

		struct path path;
		int err = kern_path(third_word, LOOKUP_FOLLOW, &path);
		if (err != 0)
		{
			pr_info("Path does not exist.\n");
			ret = 4; // invalid parameter
			goto end_write;
		}

		mutex_lock(&probe_lock);
		add_protected_path(third_word);
		mutex_unlock(&probe_lock);
	}
	else if (strcmp(second_word, REMOVEPATH) == 0)
	{
		printk("%s: you chose %s.\n", MODNAME, REMOVEPATH);

		if (current_state == OFF || current_state == ON)
		{
			printk("%s: the module is not in a reconfigurable state.\n", MODNAME);
			ret = 5; // module not in a reconfigurable state
			goto end_write;
		}

		mutex_lock(&probe_lock);
		free_protected_path(third_word);
		mutex_unlock(&probe_lock);
	}
	else if (strncmp(second_word, UNINSTALL, strlen(UNINSTALL)) == 0)
	{

		if (rmmod_lock == 1)
		{
			module_put(THIS_MODULE);
			rmmod_lock = 0;
		}
		else
		{
			printk("%s: module already unlocked\n", MODNAME);
		}
	}
	else
	{
		printk("%s: invalid choice.\n", MODNAME);
		ret = 6; // invalid command
		goto end_write;
	}

end_write:

	mutex_unlock(&lock);
	return ret;
}

ssize_t read_protected(struct file *filp, char *buf, size_t count, loff_t *offp)
{

	if (head == NULL)
		return 0;

	struct path_node *curr = head;
	char *kbuf;
	ssize_t len = 0; // file size
	size_t offset = 0;
	int ret;

	mutex_lock(&probe_lock);

	// Calculate the total length of the data
	while (curr)
	{
		len += strlen(curr->path) + 1; // +1 for newline
		curr = curr->next;
	}

	if (*offp > len)
	{
		mutex_unlock(&lock);
		return 0;
	}

	if (count > (len - *offp))
	{
		count = len - *offp;
	}

	kbuf = kmalloc(len, GFP_KERNEL);
	if (!kbuf)
	{
		mutex_unlock(&probe_lock);
		return -ENOMEM;
	}

	curr = head;
	while (curr)
	{
		offset += snprintf(kbuf + offset, len - offset, "%s\n", curr->path);
		curr = curr->next;
	}

	ret = copy_to_user(buf, kbuf, count);
	*offp += (count - ret);

	mutex_unlock(&probe_lock);
	kfree(kbuf);

	return count - ret;
}

struct deferred_work_data
{
	int tgid;					// process TGID
	int tid;					// thread ID
	uid_t uid;					// user ID
	uid_t euid;					// effective user ID
	char open_path[PATH_MAX];	// path of the program that is being opened
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

	char str[SHA256_LENGTH] = {0};

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

	snprintf(str, sizeof(str), "%d", data->tgid);
	log->f_op->write(log, str, sizeof(str), &log->f_pos);
	log->f_op->write(log, DIVIDER, sizeof(DIVIDER), &log->f_pos);
	memset(str, 0, sizeof(str));

	snprintf(str, sizeof(str), "%d", data->tid);
	log->f_op->write(log, str, sizeof(str), &log->f_pos);
	log->f_op->write(log, DIVIDER, sizeof(DIVIDER), &log->f_pos);
	memset(str, 0, sizeof(str));

	snprintf(str, sizeof(str), "%d", data->uid);
	log->f_op->write(log, str, sizeof(str), &log->f_pos);
	log->f_op->write(log, DIVIDER, sizeof(DIVIDER), &log->f_pos);
	memset(str, 0, sizeof(str));

	snprintf(str, sizeof(str), "%d", data->euid);
	log->f_op->write(log, str, sizeof(str), &log->f_pos);
	log->f_op->write(log, DIVIDER, sizeof(DIVIDER), &log->f_pos);

	log->f_op->write(log, data->open_path, sizeof(data->open_path), &log->f_pos);
	log->f_op->write(log, DIVIDER, sizeof(DIVIDER), &log->f_pos);

	log->f_op->write(log, data->caller_path, sizeof(data->caller_path), &log->f_pos);
	log->f_op->write(log, DIVIDER, sizeof(DIVIDER), &log->f_pos);

	int i = 0;
	for (i = 0; i < SHA256_LENGTH; i++)
	{
		memset(str, 0, SHA256_LENGTH);
		sprintf(str, "%x", data->hash[i]);
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

	mutex_lock(&probe_lock);
	struct path_node *curr = head;

	while (curr != NULL)
	{
		if (strcmp(filename, curr->path) == 0 || (curr->path[strlen(curr->path) - 1] == '/' && strncmp(filename, curr->path, strlen(curr->path)) == 0))
		{
			mutex_unlock(&probe_lock);
			return 1;
		}
		curr = curr->next;
	}

	mutex_unlock(&probe_lock);
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

static int openat_pre_handler(struct kretprobe_instance *ri, struct pt_regs *the_regs)
{
	struct pt_regs *regs = (struct pt_regs *)the_regs->di;

	// asmlinkage long sys_openat(int dfd, const char __user *filename, int flags, umode_t mode);
	const char __user *filename = (const char __user *)regs->si;
	int flags = (int)regs->dx;
	unsigned int accessMode = flags & O_ACCMODE;

	if (current_state == OFF || current_state == REC_OFF)
		goto openat_out;
	if (accessMode == O_RDONLY || head == NULL)
		goto openat_out;

	char *kernel_filename;

	// Allocate memory for kernel space filename
	kernel_filename = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!kernel_filename)
	{
		printk(KERN_ERR "Memory allocation for kernel_filename failed\n");
		goto openat_kfree_out;
	}

	// Copy the filename from user space to kernel space
	if (copy_from_user(kernel_filename, filename, PATH_MAX))
	{
		printk(KERN_ERR "Failed to copy filename from user space\n");
		goto openat_kfree_out;
	}

	if (kernel_filename[0] != '/')
	{
		struct file *file = fget(regs->di);
		if (!file)
			goto openat_kfree_out;

		char *buffer = kmalloc(PATH_MAX, GFP_KERNEL);
		char *path = d_path(&file->f_path, buffer, PATH_MAX);

		char *concatenated_path = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!concatenated_path)
		{
			printk(KERN_ERR "Memory allocation for concatenated_path failed\n");
			kfree(buffer);
			goto openat_kfree_out;
		}

		snprintf(concatenated_path, PATH_MAX, "%s/%s", path, kernel_filename);

		strncpy(kernel_filename, concatenated_path, PATH_MAX - 1);
		kernel_filename[PATH_MAX - 1] = '\0';

		kfree(concatenated_path);
		kfree(buffer);
	}

	if (isPathProtected(kernel_filename) == 1)
	{
		initializeDeferredWork(kernel_filename);
		regs->si = "";
		return 0;
	}

openat_kfree_out:
	kfree(kernel_filename);
openat_out:
	return 1;
}

static int di_pathname_pre_handler(struct kretprobe_instance *ri, struct pt_regs *the_regs)
{
	struct pt_regs *regs = (struct pt_regs *)the_regs->di;

	// asmlinkage long sys_unlink(const char __user *pathname);
	// asmlinkage long sys_rmdir(const char __user *pathname);
	// asmlinkage long sys_mkdir(const char __user *pathname, umode_t mode);
	// asmlinkage long sys_rename(const char __user *oldname, const char __user *newname);
	const char __user *filename = (const char __user *)regs->di;

	if (current_state == OFF || current_state == REC_OFF || head == NULL)
		goto dipath_out;

	char *kernel_filename;

	// Allocate memory for kernel space filename
	kernel_filename = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!kernel_filename)
	{
		printk(KERN_ERR "Memory allocation for kernel_filename failed\n");
		goto dipath_out;
	}

	// Copy the filename from user space to kernel space
	if (copy_from_user(kernel_filename, filename, PATH_MAX))
	{
		printk(KERN_ERR "Failed to copy filename from user space\n");
		goto dipath_kfree_out;
	}

	if (isPathProtected(kernel_filename) == 1)
	{
		initializeDeferredWork(kernel_filename);
		regs->di = "";
		return 0;
	}

dipath_kfree_out:
	kfree(kernel_filename);
dipath_out:
	return 1;
}

static struct kretprobe openat_retprobe = {
	.kp.symbol_name = "__x64_sys_openat", // (ver 4.17 introduced syscall wrappers)
	.handler = kretprobe_handler,
	.entry_handler = openat_pre_handler,
	.maxactive = -1};

static struct kretprobe unlink_retprobe = {
	.kp.symbol_name = "__x64_sys_unlink",
	.handler = kretprobe_handler,
	.entry_handler = di_pathname_pre_handler,
	.maxactive = -1};

static struct kretprobe rmdir_retprobe = {
	.kp.symbol_name = "__x64_sys_rmdir",
	.handler = kretprobe_handler,
	.entry_handler = di_pathname_pre_handler,
	.maxactive = -1};

static struct kretprobe mkdir_retprobe = {
	.kp.symbol_name = "__x64_sys_mkdir",
	.handler = kretprobe_handler,
	.entry_handler = di_pathname_pre_handler,
	.maxactive = -1};

static struct kretprobe rename_retprobe = {
	.kp.symbol_name = "__x64_sys_rename",
	.handler = kretprobe_handler,
	.entry_handler = di_pathname_pre_handler,
	.maxactive = -1};

int init_module(void)
{

	int ret;

	if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0))
	{
		printk("%s: unsupported kernel version", MODNAME);
		ret = -1;
		goto module_out;
	};

	get_random_bytes(key, sizeof(key));
	get_random_bytes(iv, sizeof(iv));
	encrypt_password("passw", strlen("passw")); // set default password

	proc_create_data(CONFIG_FILE, 0, NULL, &proc_fops, NULL);
	proc_create_data(PROTECTED_LIST_FILE, 0, NULL, &protected_fops, NULL);

	ret = register_kretprobe(&openat_retprobe);
	if (ret < 0)
	{
		printk("%s: hook init failed, returned %d\n", MODNAME, ret);
		goto module_out;
	}

	ret = register_kretprobe(&unlink_retprobe);
	if (ret < 0)
	{
		printk(KERN_ERR "register_kretprobe failed for unlink: %d\n", ret);
		goto module_openat_out;
	}

	ret = register_kretprobe(&mkdir_retprobe);
	if (ret < 0)
	{
		printk(KERN_ERR "register_kretprobe failed for mkdir: %d\n", ret);
		goto module_unlink_out;
	}

	ret = register_kretprobe(&rmdir_retprobe);
	if (ret < 0)
	{
		printk(KERN_ERR "register_kretprobe failed for rmdir: %d\n", ret);
		goto module_mkdir_out;
	}

	ret = register_kretprobe(&rename_retprobe);
	if (ret < 0)
	{
		printk(KERN_ERR "register_kretprobe failed for rmdir: %d\n", ret);
		goto module_rmdir_out;
	}

	printk("%s: module correctly loaded\n", MODNAME);

	ret = register_filesystem(&logfilefs_type);
	if (likely(ret == 0))
	{
		printk("%s: sucessfully registered %s\n", MODNAME, FILESYSTEM_NAME);
		return 0;
	}

	printk("%s: failed to register %s - error %d", MODNAME, FILESYSTEM_NAME, ret);

	unregister_kretprobe(&rename_retprobe);
module_rmdir_out:
	unregister_kretprobe(&rmdir_retprobe);
module_mkdir_out:
	unregister_kretprobe(&mkdir_retprobe);
module_unlink_out:
	unregister_kretprobe(&unlink_retprobe);
module_openat_out:
	unregister_kretprobe(&openat_retprobe);
module_out:
	return ret;
}

void cleanup_module(void)
{
	flush_scheduled_work();
	unregister_kretprobe(&openat_retprobe);
	unregister_kretprobe(&unlink_retprobe);
	unregister_kretprobe(&mkdir_retprobe);
	unregister_kretprobe(&rmdir_retprobe);
	unregister_kretprobe(&rename_retprobe);

	printk("%s: module unloaded\n", MODNAME);

	int ret = unregister_filesystem(&logfilefs_type);

	if (likely(ret == 0))
		printk("%s: sucessfully unregistered logfilefs\n", MODNAME);
	else
		printk("%s: failed to unregister singlefilefs driver - error %d", MODNAME, ret);

	remove_proc_entry(CONFIG_FILE, NULL);
	remove_proc_entry(PROTECTED_LIST_FILE, NULL);
	kfree(password_data);
	free_all_paths();
}