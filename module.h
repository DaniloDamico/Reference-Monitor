#ifndef KRETPROBES_H
#define KRETPROBES_H

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
#include <linux/random.h>

#include "logfilefs/logfilefs.h"

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
#define LOCK "lock"
#define UNLOCK "unlock"

extern struct mutex protected_paths;
extern struct mutex state;
extern struct mutex remove;

enum RM_State
{
    OFF,
    ON,
    REC_OFF, // in reconfigurable mode it is possible to add or remove protected paths
    REC_ON
};

extern enum RM_State current_state;
extern char *state_char;
extern int rmmod_lock;

struct path_node
{
    char *path;
    int isDir;
    struct path_node *next;
};

extern struct path_node *head;

// cryptography

extern u8 *password_data;
extern u8 iv[16];  // AES-256-XTS takes a 16-byte IV
extern u8 key[64]; // AES-256-XTS takes a 64-byte key

int encrypt_password(char *plaintext, int textsize);
int check_password(char *password);

// character drivers
ssize_t write_proc(struct file *filp, const char *buf, size_t count, loff_t *offp);
ssize_t read_protected(struct file *filp, char *buf, size_t count, loff_t *offp);

void free_all_paths(void);

// kretprobes
extern struct kprobe open_probe;
extern struct kretprobe unlink_retprobe;
extern struct kretprobe rmdir_retprobe;
extern struct kretprobe mkdir_retprobe;
extern struct kretprobe rename_retprobe;
extern struct kretprobe create_retprobe;

#endif // KRETPROBES_H