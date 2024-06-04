#include "module.h"

/*
This linux kernel module contains a reference monitor.

It is based on code samples made available during the course Sistemi Operativi Avanzati.
Checks on the linux kernel version being older than 5.15 have been removed since the module fails its registration in that case.

The code has been developed and tested on an Ubuntu VM having kernel version 6.5.0-28-generic
The code has been further modified for compatibility and tested on an Ubuntu VM having kernel version 5.15.0-91-generic
*/

MODULE_AUTHOR("Danilo D'Amico");
MODULE_DESCRIPTION("A reconfigurable, password-protected reference monitor that prevents write-opens on the files and directories it monitors");
MODULE_LICENSE("GPL");

DEFINE_MUTEX(protected_paths);
DEFINE_MUTEX(state);
DEFINE_MUTEX(remove);

enum RM_State current_state = OFF;
char *state_char = "OFF";
module_param(state_char, charp, S_IRUGO);

int rmmod_lock = 0;
module_param(rmmod_lock, int, S_IRUGO);

struct path_node *head = NULL;

u8 *password_data = NULL;
u8 iv[16];	// AES-256-XTS takes a 16-byte IV
u8 key[64]; // AES-256-XTS takes a 64-byte key

struct proc_ops proc_fops = {
	.proc_write = write_proc};

struct proc_ops protected_fops = {
	.proc_read = read_protected};

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

	ret = register_kprobe(&open_probe);
	if (ret < 0)
	{
		printk(KERN_ERR "%s: failure during open kprobe registration\n", MODNAME);
		goto module_out;
	}

	ret = register_kretprobe(&unlink_retprobe);
	if (ret < 0)
	{
		printk(KERN_ERR "%s: failure during unlink kretprobe registration\n", MODNAME);
		goto module_openat_out;
	}

	ret = register_kretprobe(&mkdir_retprobe);
	if (ret < 0)
	{
		printk(KERN_ERR "%s: failure during mkdir kretprobe registration\n", MODNAME);
		goto module_unlink_out;
	}

	ret = register_kretprobe(&rmdir_retprobe);
	if (ret < 0)
	{
		printk(KERN_ERR "%s: failure during rmdir kretprobe registration\n", MODNAME);
		goto module_mkdir_out;
	}

	ret = register_kretprobe(&rename_retprobe);
	if (ret < 0)
	{
		printk(KERN_ERR "%s: failure during rename kretprobe registration\n", MODNAME);
		goto module_rmdir_out;
	}

	ret = register_kretprobe(&create_retprobe);
	if (ret < 0)
	{
		printk(KERN_ERR "%s: failure during create kretprobe registration\n", MODNAME);
		goto module_rename_out;
	}

	ret = register_filesystem(&logfilefs_type);
	if (likely(ret == 0))
	{
		printk("%s: sucessfully registered %s\n", MODNAME, FILESYSTEM_NAME);
		return 0;
	}

	printk("%s: failed to register %s - error %d", MODNAME, FILESYSTEM_NAME, ret);

	unregister_kretprobe(&create_retprobe);
module_rename_out:
	unregister_kretprobe(&rename_retprobe);
module_rmdir_out:
	unregister_kretprobe(&rmdir_retprobe);
module_mkdir_out:
	unregister_kretprobe(&mkdir_retprobe);
module_unlink_out:
	unregister_kretprobe(&unlink_retprobe);
module_openat_out:
	unregister_kprobe(&open_probe);
module_out:
	return ret;
}

void cleanup_module(void)
{
	flush_scheduled_work();
	unregister_kprobe(&open_probe);
	unregister_kretprobe(&unlink_retprobe);
	unregister_kretprobe(&mkdir_retprobe);
	unregister_kretprobe(&rmdir_retprobe);
	unregister_kretprobe(&rename_retprobe);
	unregister_kretprobe(&create_retprobe);

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