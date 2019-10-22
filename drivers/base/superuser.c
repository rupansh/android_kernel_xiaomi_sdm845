// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2015-2018, 2019 Jason A. Donenfeld <Jason@zx2c4.com>,
*  Rupansh Sekar <rupanshsekar@hotmail.com> 
*  All Rights Reserved.
*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/flex_array.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>

#define MAGIC_CLEAR_UID 69696969
#define MAGIC_CLEAR_READ 420420420

static struct flex_array* uid_list;
static unsigned int num_elem;
static unsigned int num_read;
bool safe_mode_su;
bool add_dev_app;

static int is_allowed(uid_t uid){
    int idx;

    if (!safe_mode_su && strncmp(current->comm, "sh", TASK_COMM_LEN) && num_elem == 0){
        safe_mode_su = 1;
        pr_warn("No apps in UID list! Bypassing Safe Mode!\n");
        return 0;
    } else if(add_dev_app == 1 && num_elem == 0) {
        add_dev_app = 0;
        pr_warn("No apps in UID list! KernSU App detected!\n");
        idx = flex_array_put(uid_list, num_elem, &uid, GFP_KERNEL);
        if (idx)
            return idx;

        num_elem++;

        return 0;
    } else {
        for (idx=0; idx<num_elem; idx++){
            uid_t *cur = flex_array_get(uid_list, idx);
            if (cur != NULL && *cur == uid)
                return 0;
        }
        return 1;
    }
}

static bool is_su(const char __user *filename)
{
	static const char su_path[] = "/system/bin/su";
	char ufn[sizeof(su_path)];

	return likely(!copy_from_user(ufn, filename, sizeof(ufn))) &&
	       unlikely(!memcmp(ufn, su_path, sizeof(ufn)));
}

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	/* To avoid having to mmap a page in userspace, just write below the stack pointer. */
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(void)
{
	static const char sh_path[] = "/system/bin/sh";

	return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static long(*old_newfstatat)(int dfd, const char __user *filename,
			     struct stat *statbuf, int flag);
static long new_newfstatat(int dfd, const char __user *filename,
			   struct stat __user *statbuf, int flag)
{
	if (!is_su(filename))
		return old_newfstatat(dfd, filename, statbuf, flag);
	return old_newfstatat(dfd, sh_user_path(), statbuf, flag);
}

static long(*old_faccessat)(int dfd, const char __user *filename, int mode);
static long new_faccessat(int dfd, const char __user *filename, int mode)
{
	if (!is_su(filename))
		return old_faccessat(dfd, filename, mode);
	return old_faccessat(dfd, sh_user_path(), mode);
}

extern int selinux_enforcing;
static long (*old_execve)(const char __user *filename,
			  const char __user *const __user *argv,
			  const char __user *const __user *envp);
static long new_execve(const char __user *filename,
		       const char __user *const __user *argv,
		       const char __user *const __user *envp)
{
	struct cred *cred;
    int res;

	if (!is_su(filename))
		return old_execve(filename, argv, envp);

	if (!old_execve(filename, argv, envp))
		return 0;

	/* It might be enough to just change the security ctx of the
	 * current task, but that requires slightly more thought than
	 * just axing the whole thing here.
	 */
	selinux_enforcing = 0;

	/* Rather than the usual commit_creds(prepare_kernel_cred(NULL)) idiom,
	 * we manually zero out the fields in our existing one, so that we
	 * don't have to futz with the task's key ring for disk access.
	 */
	cred = (struct cred *)__task_cred(current);
    res = is_allowed(__kuid_val(cred->uid));
    if (res){
        pr_warn("Denied SU for UID %d, res %d\n", __kuid_val(cred->uid), res);
        selinux_enforcing = 1;
        return 0;
    }

	memset(&cred->uid, 0, sizeof(cred->uid));
	memset(&cred->gid, 0, sizeof(cred->gid));
	memset(&cred->suid, 0, sizeof(cred->suid));
	memset(&cred->euid, 0, sizeof(cred->euid));
	memset(&cred->egid, 0, sizeof(cred->egid));
	memset(&cred->fsuid, 0, sizeof(cred->fsuid));
	memset(&cred->fsgid, 0, sizeof(cred->fsgid));
	memset(&cred->cap_inheritable, 0xff, sizeof(cred->cap_inheritable));
	memset(&cred->cap_permitted, 0xff, sizeof(cred->cap_permitted));
	memset(&cred->cap_effective, 0xff, sizeof(cred->cap_effective));
	memset(&cred->cap_bset, 0xff, sizeof(cred->cap_bset));
	memset(&cred->cap_ambient, 0xff, sizeof(cred->cap_ambient));

	pr_info("Granted root for UID %d", __kuid_val(cred->uid));
	return old_execve(sh_user_path(), argv, envp);
}

extern const unsigned long sys_call_table[];
static void read_syscall(void **ptr, unsigned int syscall)
{
	*ptr = READ_ONCE(*((void **)sys_call_table + syscall));
}
static void replace_syscall(unsigned int syscall, void *ptr)
{
	WRITE_ONCE(*((void **)sys_call_table + syscall), ptr);
}
#define read_and_replace_syscall(name) do { \
	read_syscall((void **)&old_ ## name, __NR_ ## name); \
	replace_syscall(__NR_ ## name, &new_ ## name); \
} while (0)

static int param_uid_add(const char *buf, const struct kernel_param *kp){
    unsigned int w_uid = 0;
    int res;

    if (num_elem == 31){
        return -EINVAL;
    }

    res = kstrtouint(buf, 10, &w_uid);
    if (res)
		return res;

    res = flex_array_put(uid_list, num_elem, &w_uid, GFP_KERNEL);
    if (res)
        return res;

    num_elem++;

    return 0;
}

static int param_uid_show(char *buffer, const struct kernel_param *kp){
    uid_t *cur_uid;
    int res;

    if (num_elem == 0)
        return 0;

    num_read %= num_elem;
    cur_uid = flex_array_get(uid_list, num_read);
    res = scnprintf(buffer, PAGE_SIZE, "%u %u", *cur_uid, num_elem);

    num_read++;
    return res;
}

static int param_uid_del(const char *buf, const struct kernel_param *kp){
    unsigned int w_uid = 0;
    unsigned int idx;
    int res;

    res = kstrtouint(buf, 10, &w_uid);
    if (res)
		return res;

    if (w_uid == MAGIC_CLEAR_UID){
        flex_array_free(uid_list);
        uid_list = flex_array_alloc(sizeof(uid_t), 31, GFP_KERNEL);
        num_elem = 0;
    } else if (w_uid == MAGIC_CLEAR_READ){
        num_read = 0;
    } else {
        for (idx=0; idx<=num_elem; idx++){
            uid_t *cur = flex_array_get(uid_list, idx);
            if (*cur == w_uid){
                res = flex_array_clear(uid_list, idx);
                if (res)
                    return res;
                num_elem -= 1;
                break;
            }
        }
    }

    return 0;
}

static int param_uid_del_show(char *buf, const struct kernel_param *kp){
    pr_err("YOU SHOULDN'T BE DOING THIS!!!");
    return -EINVAL;
}

static const struct kernel_param_ops uid_param_ops = {
    .set = param_uid_add,
    .get = param_uid_show,
};

static const struct kernel_param_ops uid_param_del = {
    .set = param_uid_del,
    .get = param_uid_del_show,
};

module_param_cb(add_uid, &uid_param_ops, &uid_list, 0644);
module_param_cb(del_uid, &uid_param_del, &uid_list, 0644);

static int superuser_init(void)
{
	pr_info("Hi from KernSU+\n");

	read_and_replace_syscall(newfstatat);
	read_and_replace_syscall(faccessat);
	read_and_replace_syscall(execve);

    uid_list = flex_array_alloc(sizeof(uid_t), 31, GFP_KERNEL);

    num_elem = 0;
    num_read = 0;
    safe_mode_su = 1;
    add_dev_app = 0;

	return 0;
}

static void superuser_exit(void){
    pr_info("BYE FROM KERNSU+!");
    flex_array_free(uid_list);
}

module_init(superuser_init);
module_exit(superuser_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("KernSU+ for Android");
MODULE_AUTHOR("rupansh <rupanshsekar@hotmail.com>");
