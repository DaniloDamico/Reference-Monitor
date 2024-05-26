#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x6ad771c3, "module_layout" },
	{ 0x3f18f6d0, "crypto_alloc_skcipher" },
	{ 0xddef5acd, "d_path" },
	{ 0x2d3385d3, "system_wq" },
	{ 0xd69e5a4f, "kmalloc_caches" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x53b954a2, "up_read" },
	{ 0x51032308, "crypto_alloc_shash" },
	{ 0x754d539c, "strlen" },
	{ 0x41ed3709, "get_random_bytes" },
	{ 0x41b7e8e2, "register_kretprobe" },
	{ 0xd9b85ef6, "lockref_get" },
	{ 0x56470118, "__warn_printk" },
	{ 0xa81d3524, "remove_proc_entry" },
	{ 0x20268e51, "filp_close" },
	{ 0x6c81ecb9, "init_user_ns" },
	{ 0x3213f038, "mutex_unlock" },
	{ 0x301bc87c, "mount_bdev" },
	{ 0x85df9b6c, "strsep" },
	{ 0xf54fa1cf, "crypto_shash_final" },
	{ 0x699d22b2, "d_add" },
	{ 0x3c3ff9fd, "sprintf" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x668b19a1, "down_read" },
	{ 0x6b10bee1, "_copy_to_user" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x25974000, "wait_for_completion" },
	{ 0xc0c7bd8d, "kernel_read" },
	{ 0xc1f851b8, "param_ops_charp" },
	{ 0xea944f22, "kern_path" },
	{ 0xa22a96f7, "current_task" },
	{ 0xdee72273, "__bread_gfp" },
	{ 0x9ec6ca96, "ktime_get_real_ts64" },
	{ 0x97f7ed30, "crypto_shash_update" },
	{ 0xd0760fc0, "kfree_sensitive" },
	{ 0x9166fada, "strncpy" },
	{ 0xdd4253c7, "unregister_kretprobe" },
	{ 0x5a921311, "strncmp" },
	{ 0x4dfa8d4b, "mutex_lock" },
	{ 0x4862983c, "set_nlink" },
	{ 0x6b09b6a1, "crypto_req_done" },
	{ 0x42160169, "flush_workqueue" },
	{ 0x3af226bd, "__brelse" },
	{ 0x3b2da282, "module_put" },
	{ 0xa916b694, "strnlen" },
	{ 0xb9722e47, "crypto_skcipher_decrypt" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0xb8b9f817, "kmalloc_order_trace" },
	{ 0x92997ed8, "_printk" },
	{ 0x12160631, "unlock_new_inode" },
	{ 0x60423cc2, "kill_block_super" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0xde5b3f9d, "crypto_destroy_tfm" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0x4f00afd3, "kmem_cache_alloc_trace" },
	{ 0x1eb5a597, "register_filesystem" },
	{ 0xf83b313d, "crypto_skcipher_setkey" },
	{ 0xe240f6e9, "proc_create_data" },
	{ 0xb320cc0e, "sg_init_one" },
	{ 0x6d544437, "iput" },
	{ 0x37a0cba, "kfree" },
	{ 0x69acdf38, "memcpy" },
	{ 0x86388923, "fget" },
	{ 0x4c236f6f, "__x86_indirect_thunk_r15" },
	{ 0xe8568e92, "d_make_root" },
	{ 0x608741b5, "__init_swait_queue_head" },
	{ 0x45eadf33, "unregister_filesystem" },
	{ 0xc5b6f236, "queue_work_on" },
	{ 0x656e4a6e, "snprintf" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0x2ca2c90b, "iget_locked" },
	{ 0xebbb5688, "inode_init_owner" },
	{ 0xe914e41e, "strcpy" },
	{ 0x4f7eefcb, "filp_open" },
	{ 0xf63dde74, "crypto_skcipher_encrypt" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "D877610BD1E76570E5E3C29");
