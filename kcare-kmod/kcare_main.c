#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/ctype.h>
#include <linux/kallsyms.h>
#include <linux/notifier.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0) && defined(CONFIG_KCARE_BUILD_CRASHREPORT)
#include <asm/traps.h>
#endif
#include <linux/preempt.h>
#include <linux/completion.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
#include <linux/hardirq.h>
#endif
#include <linux/kdebug.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/signal.h>
#endif
#include <asm/tlbflush.h>

#include <kcare/kcare_file.h>
#include "crash_report/mem_dumper.h"
#include "crash_report/mem_dumper_helper.h"

#include <asm/atomic.h>
#include <asm/cacheflush.h>

#include "kcare.h"
#include "kcare_gcov.h"

/* rhel5 kernels older than 5.6 (238) lack this helper macro */
#ifndef pr_err

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

#define pr_err(fmt, ...) \
        printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#endif

/* To prevent double open */
static atomic_t kcare_opened = ATOMIC_INIT(0);
static char kpatch_desc[512];
static const char *kpatch_effective_version = kpatch_desc;
static uint64_t kpatch_wait_period = KPATCH_DEFAULT_WAIT_PERIOD_SEC;

static DEFINE_MUTEX(_kpatch_ctx_lock);

struct kpatch_context kpatch_ctx = {
	/*
	 * NOTE: kpatch_ctx.lock protects all kpatch-related data (kmod_data, patch, undo_data)
	 * around 'kcare_apply'/'kcare_undo', ensuring their mutual exclusion and synchronicity
	 */
	.lock = &_kpatch_ctx_lock,
	.kmod_data = {
		.kpatch_retries = KPATCH_DEFAULT_RETRIES_NUM,
	},
};
EXPORT_SYMBOL_GPL(kpatch_ctx);

bool patch_sig_enforce = false;
module_param_named(patch_sig_enforce, patch_sig_enforce, bool, S_IRUSR | S_IWUSR);

module_param_named(kpatch_debug, kpatch_ctx.kmod_data.debug, int,
		   S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(kpatch_debug, "Turn debug logs on/off. kpatch_debug=1 enables debug logs.");

module_param_named(kcore_output, kpatch_ctx.kmod_data.kcore_output, uint,
		   S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(kcore_output, 	"Turn saving vmcore on kernel oops:\n"
				"	kcore_output=n 	- save n MB of vmcore (where n is positive integer).\n"
				"	kcore_output=0 	- disable saving vmcore.");

module_param_named(kmsg_output, kpatch_ctx.kmod_data.kmsg_output, uint,
		   S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(kmsg_output, "Turn saving dmesg logs on/off. kmsg_output=1 enables saving.");

char *kdumps_dirp = NULL;
module_param_named(kdumps_dir, kdumps_dirp, charp, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(kdumps_dir, "Path to save kmsg and kcore.");

static int crashreport_enabled_param_set(const char *,
				   const struct kernel_param *);

bool crashreporter_enabled = false;
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,14,0)
static const struct kernel_param_ops crashreport_enabled_param_ops = {
	.set =	crashreport_enabled_param_set,
	.get =	param_get_bool,
};
module_param_cb(enable_crashreporter, &crashreport_enabled_param_ops,
		&crashreporter_enabled, S_IRUSR | S_IWUSR);

#else

module_param_call(enable_crashreporter, crashreport_enabled_param_set, param_get_bool,
		  &crashreporter_enabled, S_IRUSR | S_IWUSR);
#endif
MODULE_PARM_DESC(enable_crashreporter, "Turn crashreporter functionality on/off:\n"
				"	enable_crashreporter=1 	- enable saving artifacts.\n"
				"	enable_crashreporter=0 	- disable saving artifacts.");

struct kpatch_query_info info;

static struct proc_dir_entry *freeze_entry;
static struct proc_dir_entry *effective_ver_entry;
static struct proc_dir_entry *patchinfo_entry;
static struct proc_dir_entry *cvelist_entry;
static struct proc_dir_entry *opt_safety_method_entry;
static struct proc_dir_entry *opt_faultinject_entry;
static struct proc_dir_entry *opt_faultinject_call_entry;
static struct proc_dir_entry *opt_skip_cpus_entry;
static struct proc_dir_entry *opt_time_wait_period_entry;
static struct proc_dir_entry *opt_kpatch_retries_entry;
static DEFINE_MUTEX(freeze_lock);
static DEFINE_MUTEX(kpatch_desc_lock);
static LIST_HEAD(freeze_blacklist);

struct freeze_entry {
	struct list_head list;
	char comm[TASK_COMM_LEN];
	unsigned long flags;
};

static size_t freeze_blacklist_counter;

static int kcare_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (atomic_cmpxchg(&kcare_opened, 0, 1))
		return -EBUSY;

	return 0;
}

static int kcare_release(struct inode *inode, struct file *file)
{
	atomic_set(&kcare_opened, 0);

	return 0;
}

#ifdef CONFIG_X86_32
static inline int kcare_relocate(struct kpatch_file *file, unsigned long size,
				 unsigned long delta)
{
	/*
	 * There is no need for special allocation from mudule address space
	 * on 32-bit arch. Everything is accessible from everywhere.
	 */
	return 0;
}
#else

static void *kpatch_module_alloc(size_t size)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,10,0)
	if (kcare_module_alloc)
		return kcare_module_alloc(size);
#else
	if (kcare_execmem_alloc)
		return kcare_execmem_alloc(EXECMEM_BPF, size);
#endif
	return NULL;
}

static int kcare_relocate(struct kpatch_file *file, unsigned long size,
			  unsigned long delta)
{
	struct kpatch_file *new;

	printk(KERN_DEBUG "kcare: allocating memory in module space...\n");
	new = kpatch_module_alloc(size);
	if (!new) {
		printk(KERN_DEBUG "kcare: failed to allocate memory\n");
		return -ENOMEM;
	}

	/*
	 * module space memory has to be aligned otherwise last page could be not
	 * handled by set_memory_x.
	 * we don't get out of bound inasmuch as module_alloc() uses PAGE_ALIGN inside.
	 */
	if (kcare_set_mem_x)
		kcare_set_mem_x((unsigned long)new, PAGE_ALIGN(size) >> PAGE_SHIFT);
	printk(KERN_DEBUG "kcare: allocated %lu bytes at %px\n", size, new);
	memcpy(new, file, size);
	vfree(file);
	kpatch_ctx.patch = new;
	return 0;
}
#endif

#ifndef for_each_process
#define for_each_process(p) for_each_process_all(p)
#endif

static void freeze_blacklist_apply(void)
{
	struct freeze_entry *e;
	struct task_struct *p;

	mutex_lock(&freeze_lock);
	/* Common case */
	if (list_empty(&freeze_blacklist))
		return;

	rcu_read_lock();
	for_each_process(p) {
		list_for_each_entry(e, &freeze_blacklist, list) {
			if (!strncmp(e->comm, p->comm, TASK_COMM_LEN)) {
				e->flags = (p->flags ^ PF_NOFREEZE) & PF_NOFREEZE;
				p->flags |= PF_NOFREEZE;
			}
		}
	};
	rcu_read_unlock();
}
static void freeze_blacklist_undo(void)
{
	struct freeze_entry *e;
	struct task_struct *p;

	/* Common case */
	if (list_empty(&freeze_blacklist)) {
		mutex_unlock(&freeze_lock);
		return;
	}

	rcu_read_lock();
	for_each_process(p) {
		list_for_each_entry(e, &freeze_blacklist, list) {
			if (!strncmp(e->comm, p->comm, TASK_COMM_LEN))
				p->flags &= ~e->flags;
		}
	};
	rcu_read_unlock();
	mutex_unlock(&freeze_lock);
}

static const char *get_effective_version(const char *desc)
{
	const char *ptr = desc;
	while (*ptr != 0)
		if (*ptr++ == ';')
			return ptr;
	return desc;
}

static long kcare_update_kpatch_desc(const char __user *desc, size_t size)
{
	long copied;

	if (!desc)
		return 0;

	mutex_lock(&kpatch_desc_lock);
	if ((copied = strncpy_from_user(kpatch_desc, desc, size)) >= 0) {
		kpatch_desc[copied] = '\0';
		kpatch_effective_version = get_effective_version(kpatch_desc);
	}
	mutex_unlock(&kpatch_desc_lock);
	return copied;
}

static void kcare_clear_kpatch_desc(void)
{
	mutex_lock(&kpatch_desc_lock);
	memset(kpatch_desc, 0, sizeof(kpatch_desc));
	mutex_unlock(&kpatch_desc_lock);
}

#ifndef __PAGE_KERNEL_EXEC
#define __PAGE_KERNEL_EXEC _PAGE_KERNEL_EXEC
#endif

static long kcare_apply(void __user *paddr)
{
	kpatch_entry entry;
	struct kpatch_payload p;
	int err = 0;
	long delta = 0;

	if (kpatch_ctx.patch != NULL)
		return -EBUSY;
	if (!try_module_get(THIS_MODULE))
		return -EAGAIN;

	kpatch_ctx.kmod_data.max_wait_period = get_jiffies_64() + (kpatch_wait_period * HZ);

	if ((err = copy_from_user(&p, paddr, sizeof(p))))
		goto err;
	if ((err = kcare_update_kpatch_desc(p.description, sizeof(kpatch_desc) - 1)) < 0)
		goto err;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
	kpatch_ctx.patch = __vmalloc(p.size, GFP_KERNEL);
#else
	kpatch_ctx.patch = __vmalloc(p.size, GFP_KERNEL, PAGE_KERNEL_EXEC);
#endif
	if (!kpatch_ctx.patch) {
		err = -ENOMEM;
		goto err;
	}
	printk(KERN_DEBUG "kcare: allocated %zu bytes for patch at %px\n",
			p.size, kpatch_ctx.patch);
	if ((err = copy_from_user(kpatch_ctx.patch, p.patch, p.size)))
		goto err;

	if ((err = kcare_verify_patch_signature(kpatch_ctx.patch, &p.size)))
		goto err;

	if ((err = kcare_verify(kpatch_ctx.patch, p.size, &delta)))
		goto err;
	if (kcare_resolve_symbols_legacy) {
		err = kcare_resolve_symbols_legacy(kpatch_ctx.patch, delta);
		if (err)
			goto err;
	}
	if ((err = kcare_relocate(kpatch_ctx.patch, p.size, delta)))
		goto err;
	if ((err = kcare_apply_relocations(kpatch_ctx.patch, delta)))
		goto err;

	entry = (void *)kpatch_ctx.patch + kpatch_ctx.patch->kpatch_offset +
		kpatch_ctx.patch->kpatch_entry;
	printk(KERN_DEBUG "kcare: jumping to %px\n", entry);

	if (kpatch_time_expired(kpatch_ctx.kmod_data.max_wait_period)) {
		printk(KERN_ERR "kcare[%s:%d]: Time expired for patching\n",
				__func__, __LINE__);
		err = -ETIMEDOUT;
		goto err;
	}

	freeze_blacklist_apply();
	err = entry(kpatch_ctx.patch, p.size, &kpatch_ctx.undo_data);
	freeze_blacklist_undo();

	gcov_kcare_cache_update(&kpatch_ctx.kmod_data, kpatch_ctx.patch->csum, false);

	if (err && kpatch_ctx.undo_data == NULL)
		goto err;
	return err;
err:
	if (kpatch_ctx.patch)
		vfree(kpatch_ctx.patch);
	kpatch_ctx.patch = NULL;
	kcare_clear_kpatch_desc();
	kpatch_ctx.kmod_data.patchinfo = 0;
	kpatch_ctx.kmod_data.patchinfo_size = 0;
	kpatch_ctx.kmod_data.cvelist = 0;
	kpatch_ctx.kmod_data.cvelist_size = 0;
	kpatch_ctx.kmod_data.gcov.info = NULL;
	kpatch_ctx.kmod_data.gcov.nr_info = 0;
	module_put(THIS_MODULE);
	return err;
}

static long kcare_undo(void)
{
	kpatch_undo_patch undo;
	int err = 0;

	if (!kpatch_ctx.patch)
		return -ENOENT;

	kpatch_ctx.kmod_data.max_wait_period = get_jiffies_64() + (kpatch_wait_period * HZ);

	if (kpatch_ctx.undo_data) {
		undo = (void *)kpatch_ctx.patch + kpatch_ctx.patch->kpatch_offset +
			kpatch_ctx.patch->kpatch_unpatch;
		freeze_blacklist_apply();
		err = undo(kpatch_ctx.undo_data);
		freeze_blacklist_undo();
		if (err)
			return err;
		kpatch_ctx.undo_data = NULL;
		kcare_clear_kpatch_desc();
		kpatch_ctx.kmod_data.patchinfo = 0;
		kpatch_ctx.kmod_data.patchinfo_size = 0;
		kpatch_ctx.kmod_data.cvelist = 0;
		kpatch_ctx.kmod_data.cvelist_size = 0;

		gcov_kcare_cache_update(&kpatch_ctx.kmod_data, kpatch_ctx.patch->csum, true);
		kpatch_ctx.kmod_data.gcov.info = NULL;
		kpatch_ctx.kmod_data.gcov.nr_info = 0;
	}

	vfree(kpatch_ctx.patch);
	kpatch_ctx.patch = NULL;
	module_put(THIS_MODULE);
	return 0;

}

static long kcare_info(void __user *uinfo)
{
	if (!uinfo)
		return -EINVAL;

	memset(&info, 0, sizeof(info));
	info.state = !kpatch_ctx.patch ? KPATCH_STATE_NONE : KPATCH_STATE_APPLIED;
	if (info.state == KPATCH_STATE_APPLIED) {
		memcpy(info.uname, kpatch_ctx.patch->uname, sizeof(info.uname));
		info.build_time = kpatch_ctx.patch->build_time;
	}
	strncpy(info.description, kpatch_desc, sizeof(info.description) - 1);
	return copy_to_user(uinfo, (void *)&info, sizeof(info));
}

static long kcare_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err;
	switch (cmd) {
	case KPATCH_APPLY:
		mutex_lock(kpatch_ctx.lock);
		err = kcare_apply((void __user *)arg);
		mutex_unlock(kpatch_ctx.lock);
		return err;
	case KPATCH_UNDO:
		mutex_lock(kpatch_ctx.lock);
		err = kcare_undo();
		mutex_unlock(kpatch_ctx.lock);
		return err;
	case KPATCH_INFO:
		return kcare_info((void *)arg);
	case KPATCH_REPORT:
		return kcare_crashmem_read_ioctl((void *)arg);
	}
	return -EINVAL;
}

static const struct file_operations kcare_fops = {
	.owner = THIS_MODULE,
	.open = kcare_open,
	.release = kcare_release,
	.unlocked_ioctl = kcare_ioctl,
};

static struct miscdevice kcare_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "kcare",
	.fops = &kcare_fops,
};

static int freeze_blacklist_show(struct seq_file *m, void *v)
{
	struct freeze_entry *e;

	seq_printf(m, "blacklist:");

	mutex_lock(&freeze_lock);
	if (list_empty(&freeze_blacklist)) {
		seq_printf(m, " <none>");
	} else {
		list_for_each_entry(e, &freeze_blacklist, list)
			seq_printf(m, " %s", e->comm);
	}
	mutex_unlock(&freeze_lock);
	seq_printf(m, "\n");
	return 0;
}

static int freeze_blacklist_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, freeze_blacklist_show, NULL);
}

static ssize_t freeze_blacklist_add(char *name)
{
	struct freeze_entry *e;

	/* Limit freeze_blacklist expansion */
	if (freeze_blacklist_counter >= PID_MAX_LIMIT) {
		printk(KERN_WARNING "freeze_blacklist size reached PID_MAX_LIMIT");
		return -ENOMEM;
	}

	e = kmalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;
	memset(e, 0, sizeof(*e));
	strncpy(e->comm, name, TASK_COMM_LEN - 1);
	list_add_tail(&e->list, &freeze_blacklist);
	freeze_blacklist_counter++;
	return 0;
}

static ssize_t freeze_blacklist_del(char *name)
{
	struct freeze_entry *e, *tmp;

	list_for_each_entry_safe(e, tmp, &freeze_blacklist, list) {
		if (!strncmp(e->comm, name, TASK_COMM_LEN)) {
			list_del(&e->list);
			kfree(e);
			freeze_blacklist_counter--;
		}
	}
	return 0;
}

static ssize_t freeze_blacklist_clear(void)
{
	struct freeze_entry *e, *tmp;

	list_for_each_entry_safe(e, tmp, &freeze_blacklist, list) {
		list_del(&e->list);
		kfree(e);
	}

	freeze_blacklist_counter = 0;
	return 0;
}

/*
 * Format:
 *   a:<name> - add process to blacklist
 *   d:<name> - delete process from blacklist
 *   c - clear the blacklist
 */
static ssize_t freeze_blacklist_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos)
{
	char buffer[TASK_COMM_LEN + 3];
	ssize_t ret;

	memset(buffer, 0, sizeof(buffer));
	if (count > sizeof(buffer) - 1)
		count = sizeof(buffer) - 1;
	if (copy_from_user(buffer, buf, count))
		return -EFAULT;
	if ((buffer[0] != 'c') && count < 3)
		return -EINVAL;
	mutex_lock(&freeze_lock);
	switch (buffer[0]) {
	case 'a':
		ret = freeze_blacklist_add(buffer + 2); break;
	case 'd':
		ret = freeze_blacklist_del(buffer + 2); break;
	case 'c':
		ret = freeze_blacklist_clear(); break;
	default:
		ret = -EINVAL;
	}
	mutex_unlock(&freeze_lock);
	if (ret < 0)
		return ret;

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops freeze_blacklist_fops = {
	.proc_open	= freeze_blacklist_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_write	= freeze_blacklist_write,
	.proc_release	= single_release,
#else
static const struct file_operations freeze_blacklist_fops = {
	.owner	= THIS_MODULE,
	.open	= freeze_blacklist_proc_open,
	.read	= seq_read,
	.llseek	= seq_lseek,
	.write	= freeze_blacklist_write,
	.release= single_release,
#endif
};

static int effective_ver_show(struct seq_file *m, void *v)
{
	mutex_lock(&kpatch_desc_lock);
	seq_printf(m, "%s\n", kpatch_effective_version);
	mutex_unlock(&kpatch_desc_lock);
	return 0;
}

static int effective_ver_open(struct inode *inode, struct file *file)
{
	return single_open(file, effective_ver_show, NULL);
}

static ssize_t effective_ver_write(struct file *file, const char *buffer, size_t size,
		   loff_t *data)
{
	if (kpatch_ctx.patch == NULL)
		return -EINVAL;

	size = min(size, sizeof(kpatch_desc) - 1);
	return kcare_update_kpatch_desc(buffer, size);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops effective_ver_fops = {
	.proc_open    = effective_ver_open,
	.proc_write   = effective_ver_write,
	.proc_read    = seq_read,
	.proc_lseek  = seq_lseek,
	.proc_release = single_release,
#else
static const struct file_operations effective_ver_fops = {
	.owner   = THIS_MODULE,
	.open    = effective_ver_open,
	.write   = effective_ver_write,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
#endif
};

static ssize_t
cvelist_read(struct file *file, char __user *buf, size_t len, loff_t * offset)
{
	ssize_t ret = 0;

	mutex_lock(kpatch_ctx.lock);
	if (kpatch_ctx.kmod_data.cvelist)
		ret = simple_read_from_buffer(buf, len, offset,
					      (void *)kpatch_ctx.kmod_data.cvelist,
					      kpatch_ctx.kmod_data.cvelist_size);
	mutex_unlock(kpatch_ctx.lock);
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops cvelist_fops = {
	.proc_read    = cvelist_read,
	.proc_lseek   = default_llseek,
#else
static const struct file_operations cvelist_fops = {
	.owner        = THIS_MODULE,
	.read         = cvelist_read,
	.llseek       = default_llseek,
#endif
};

static ssize_t
patchinfo_read(struct file *file, char __user *buf, size_t len, loff_t * offset)
{
	ssize_t ret = 0;

	mutex_lock(kpatch_ctx.lock);
	if (kpatch_ctx.kmod_data.patchinfo)
		ret = simple_read_from_buffer(buf, len, offset,
					      (void *)kpatch_ctx.kmod_data.patchinfo,
					      kpatch_ctx.kmod_data.patchinfo_size);
	mutex_unlock(kpatch_ctx.lock);
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops patchinfo_fops = {
	.proc_read    = patchinfo_read,
	.proc_lseek   = default_llseek,
#else
static const struct file_operations patchinfo_fops = {
	.owner        = THIS_MODULE,
	.read         = patchinfo_read,
	.llseek       = default_llseek,
#endif
};

static const char *safety_methods[KPATCH_SAFETY_METHOD_MAX] = {
	[KPATCH_SAFETY_METHOD_DEFAULT]         = "default",
	[KPATCH_SAFETY_METHOD_FREEZE_ALL]      = "freeze_all",
	[KPATCH_SAFETY_METHOD_FREEZE_NONE]     = "freeze_none",
	[KPATCH_SAFETY_METHOD_FREEZE_CONFLICT] = "freeze_conflict",
};

static int opt_safety_method_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", safety_methods[kpatch_ctx.kmod_data.safety_method]);
	return 0;
}

static int opt_safety_method_open(struct inode *inode, struct file *file)
{
	return single_open(file, opt_safety_method_show, NULL);
}

static ssize_t opt_safety_method_write(struct file *file, const char __user *buf,
		size_t size, loff_t *data)
{
	char buffer[32];
	ssize_t ret, i;
	const char *method;

	memset(buffer, 0, sizeof(buffer));
	ret = strncpy_from_user(buffer, buf, min(size, sizeof(buffer)));
	if (ret < 0)
		return -EFAULT;

	for (i = 0; i < KPATCH_SAFETY_METHOD_MAX; i++) {
		method = safety_methods[i];
		if (!strncmp(method, buffer, strlen(method))) {
			kpatch_ctx.kmod_data.safety_method = i;
			return ret;
		};
	}
	return -EINVAL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops opt_safety_method_ops = {
	.proc_open    = opt_safety_method_open,
	.proc_write   = opt_safety_method_write,
	.proc_read    = seq_read,
	.proc_lseek  = seq_lseek,
	.proc_release = single_release,
#else
static const struct file_operations opt_safety_method_ops = {
	.owner   = THIS_MODULE,
	.open    = opt_safety_method_open,
	.write   = opt_safety_method_write,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
#endif
};

static const char *fi_values[] = {
	[KPATCH_FI_SAFETY_CHECK]            = "safety-check",
	[KPATCH_FI_SAFETY_CHECK_USER]       = "safety-check-user",
	[KPATCH_FI_SAFETY_CHECK_RELOCK]     = "safety-check-relock",
	[KPATCH_FI_SWITCH_CPUS_ONLINE]      = "switch-cpus-online",
	[KPATCH_FI_DELAY_TASK_VERIFICATION] = "delay-task-verification",
	[KPATCH_FI_TIMEOUT_EXECUTE_SAFE]    = "timeout-execute-safe",
	[KPATCH_FI_FAIL_PATCHING]           = "fail-patching",
};

static ssize_t opt_faultinject_write(struct file *file, const char __user *data,
		size_t count, loff_t *off)
{
	char str[50], *pstr = str;
	int rc, i;
	unsigned newmask = 0, op = 0;

	if (!data || count > (sizeof(str) - 1) || *off)
		return -EINVAL;

	rc = copy_from_user(str, data, count);
	if (rc)
		return -EFAULT;
	str[count] = '\0';

	/* add subsystems to the list */
	if (str[0] == '+') {
		op = +1;
		pstr++;
	}
	/* remove subsystems from the list */
	if (str[0] == '-') {
		op = -1;
		pstr++;
	}

	while (*pstr) {
		char *lstr;

		while (*pstr == ' ' || *pstr == '\t' || *pstr == '\n')
			pstr++;

		if (!*pstr)
			break;

		lstr = pstr;
		while (*lstr != ' ' && *lstr != '\t' && *lstr != '\n' && *lstr)
			lstr++;

		for (i = 0; i < ARRAY_SIZE(fi_values); i++) {
			if (strlen(fi_values[i]) == (lstr - pstr) &&
			    !strncmp(fi_values[i], pstr, lstr - pstr)) {
				newmask |= (1 << i);
				break;
			}
		}

		if (i == ARRAY_SIZE(fi_values))
			return -EINVAL;

		pstr = lstr;
	}

	switch (op) {
	case -1:
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,3,0)
		atomic_and(~newmask, &kpatch_ctx.kmod_data.fi.fimask);
#else
		atomic_clear_mask(newmask, &kpatch_ctx.kmod_data.fi.fimask);
#endif
		break;
	case  0:
		atomic_set(&kpatch_ctx.kmod_data.fi.fimask, newmask);
		break;
	case +1:
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,3,0)
		atomic_or(newmask, &kpatch_ctx.kmod_data.fi.fimask);
#else
		atomic_set_mask(newmask, &kpatch_ctx.kmod_data.fi.fimask);
#endif
		break;
	default:
		BUG();
	}

	return count;
}

static int opt_faultinject_show(struct seq_file *m, void *v)
{
	unsigned mask, i;
	mask = atomic_read(&kpatch_ctx.kmod_data.fi.fimask);

	for (i = 0; i < ARRAY_SIZE(fi_values); i++, mask >>= 1) {
		if (mask & 1) {
			seq_puts(m, fi_values[i]);
			if (mask > 1)
				seq_putc(m, ' ');
		}
	}

	seq_putc(m, '\n');

	return 0;
}

static int opt_faultinject_open(struct inode *inode, struct file *file)
{
	return single_open(file, opt_faultinject_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops opt_faultinject_ops = {
	.proc_open    = opt_faultinject_open,
	.proc_write   = opt_faultinject_write,
	.proc_read    = seq_read,
	.proc_lseek  = seq_lseek,
	.proc_release = single_release,
#else
static const struct file_operations opt_faultinject_ops = {
	.owner   = THIS_MODULE,
	.open    = opt_faultinject_open,
	.write   = opt_faultinject_write,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
#endif
};

static int opt_faultinject_call_show(struct seq_file *m, void *v)
{
	seq_printf(m, "Format: <call> <module> <index>\n"
		   "Supported call flags:\n"
		   "\tKPATCH_FI_INITCALL = %u\n",
		   KPATCH_FI_INITCALL);

	seq_printf(m, "Current: %d %s %u executed calls: %u\n", kpatch_ctx.kmod_data.fi.call,
		   kpatch_ctx.kmod_data.fi.mod, kpatch_ctx.kmod_data.fi.idx,
		   kpatch_ctx.kmod_data.fi.cur_idx-1);
	return 0;
}

static int opt_faultinject_call_open(struct inode *inode, struct file *file)
{
	return single_open(file, opt_faultinject_call_show, NULL);
}

/* Rough size for user buffer */
#define FAULTINJECT_USER_BUF_SIZE (sizeof(kpatch_ctx.kmod_data.fi.mod) * 2)

static ssize_t opt_faultinject_call_write(struct file *file, const char __user *buf,
					   size_t count, loff_t *ppos)
{
	char user_buf[FAULTINJECT_USER_BUF_SIZE + 1] = {0};
	char mod[MOD_STR_LEN];
	int call;
	uint8_t idx;

	if (!buf || *ppos || count > FAULTINJECT_USER_BUF_SIZE) {
		pr_err("kpatch: Invalid input buffer or position or count exceeds limit\n");
		return -EINVAL;
	}

	if (copy_from_user(user_buf, buf, count)) {
		pr_err("kpatch: Failed to copy data from user space\n");
		return -EFAULT;
	}

	/* Handle blank string case */
	if (strspn(user_buf, " \t\r\n") == strlen(user_buf)) {
		mutex_lock(kpatch_ctx.lock);
		kpatch_ctx.kmod_data.fi.call = 0;
		kpatch_ctx.kmod_data.fi.mod[0] = '\0';
		kpatch_ctx.kmod_data.fi.idx = 0;
		mutex_unlock(kpatch_ctx.lock);
		return count;
	}

	if (sscanf(user_buf, "%u %"__stringify(MOD_STR_LEN_SCANF)"s %hhu", &call, mod, &idx) != 3) {
		pr_err("kpatch: Failed to parse input data. Expected format: <call> <module> <number>\n");
		return -EINVAL;
	}

	if (call >= KPATCH_FI_MOD_MAX) {
		pr_err("kpatch: call number isn't valid. Supported [0,%d)\n", KPATCH_FI_MOD_MAX);
		return -EINVAL;
	}

	mutex_lock(kpatch_ctx.lock);
	if (kpatch_ctx.patch) {
		mutex_unlock(kpatch_ctx.lock);
		pr_err("kpatch: the kernel is patched\n");
		return -EBUSY;
	}

	kpatch_ctx.kmod_data.fi.call = call;
	strncpy(kpatch_ctx.kmod_data.fi.mod, mod, sizeof(mod));
	kpatch_ctx.kmod_data.fi.idx = idx;
	mutex_unlock(kpatch_ctx.lock);

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops opt_faultinject_call_ops = {
	.proc_open    = opt_faultinject_call_open,
	.proc_write   = opt_faultinject_call_write,
	.proc_read    = seq_read,
	.proc_lseek  = seq_lseek,
	.proc_release = single_release,
#else
static const struct file_operations opt_faultinject_call_ops = {
	.owner   = THIS_MODULE,
	.open    = opt_faultinject_call_open,
	.write   = opt_faultinject_call_write,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
#endif
};

static int opt_skip_cpus_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", kpatch_ctx.kmod_data.skip_cpus);
	return 0;
}

static int opt_skip_cpus_open(struct inode *inode, struct file *file)
{
	return single_open(file, opt_skip_cpus_show, NULL);
}

static ssize_t opt_skip_cpus_write(struct file *file, const char __user *data,
		size_t count, loff_t *off)
{
	int rc;
	char str[2] = {0};
	int val;
	rc = copy_from_user(str, data, 1);
	if (rc)
		return -EFAULT;
	rc = sscanf(str, "%d", &val);
	if (rc == 1 && (val >= 0 && val <= 1))
		kpatch_ctx.kmod_data.skip_cpus = val;
	else
		return -EINVAL;
	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops opt_skip_cpus_ops = {
	.proc_open	= opt_skip_cpus_open,
	.proc_read	= seq_read,
	.proc_write	= opt_skip_cpus_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
#else
static const struct file_operations opt_skip_cpus_ops = {
	.open	= opt_skip_cpus_open,
	.read	= seq_read,
	.write	= opt_skip_cpus_write,
	.llseek	= seq_lseek,
	.release= single_release,
#endif
};

static int opt_time_wait_period_show(struct seq_file *m, void *v)
{
	seq_printf(m, "Max wait period: %llu sec\n", kpatch_wait_period);
	return 0;
}

static int opt_time_wait_period_open(struct inode *inode, struct file *file)
{
	return single_open(file, opt_time_wait_period_show, NULL);
}

static ssize_t opt_time_wait_period_write(struct file *file, const char __user *data,
		size_t count, loff_t *off)
{
	int rc;
	char str[11] = {0};
	uint64_t val = 0;

	if (count == 0)
		return -EINVAL;

	count = min(count, sizeof(str) - 1);

	rc = copy_from_user(str, data, count);
	if (rc)
		return -EFAULT;

	rc = sscanf(str, "%llu", &val);
	if (rc == 1 && val >= 1)
		kpatch_wait_period = val;
	else
		return -EINVAL;
	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops opt_time_wait_period_ops = {
	.proc_open	= opt_time_wait_period_open,
	.proc_read	= seq_read,
	.proc_write	= opt_time_wait_period_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
#else
static const struct file_operations opt_time_wait_period_ops = {
	.open	= opt_time_wait_period_open,
	.read	= seq_read,
	.write	= opt_time_wait_period_write,
	.llseek	= seq_lseek,
	.release= single_release,
#endif
};

static int opt_kpatch_retries_show(struct seq_file *m, void *v)
{
	seq_printf(m, "Patching retries: %u \n", kpatch_ctx.kmod_data.kpatch_retries);
	return 0;
}

static int opt_kpatch_retries_open(struct inode *inode, struct file *file)
{
	return single_open(file, opt_kpatch_retries_show, NULL);
}

static ssize_t opt_kpatch_retries_write(struct file *file, const char __user *data,
					size_t count, loff_t *off)
{
	int rc;
	char str[11] = {0};
	uint32_t val = 0;

	if (count == 0)
		return -EINVAL;

	count = min(count, sizeof(str) - 1);

	rc = copy_from_user(str, data, count);
	if (rc)
		return -EFAULT;

	rc = sscanf(str, "%u", &val);
	if (rc == 1 && (val >= 1 && val <= KPATCH_DEFAULT_RETRIES_NUM))
		kpatch_ctx.kmod_data.kpatch_retries = val;
	else
		return -EINVAL;
	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops opt_kpatch_retries_ops = {
	.proc_open	= opt_kpatch_retries_open,
	.proc_read	= seq_read,
	.proc_write	= opt_kpatch_retries_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
#else
static const struct file_operations opt_kpatch_retries_ops = {
	.open	= opt_kpatch_retries_open,
	.read	= seq_read,
	.write	= opt_kpatch_retries_write,
	.llseek	= seq_lseek,
	.release= single_release,
#endif
};

static void kcare_clean_proc(void)
{
	if (effective_ver_entry)
		remove_proc_entry("kcare/effective_version", NULL);
	if (freeze_entry)
		remove_proc_entry("kcare/freeze_blacklist", NULL);
	if (patchinfo_entry)
		remove_proc_entry("kcare/patchinfo.json.gz", NULL);
	if (cvelist_entry)
		remove_proc_entry("kcare/cvelist", NULL);
	if (opt_safety_method_entry)
		remove_proc_entry("kcare/opt/safety_method", NULL);
	if (opt_faultinject_entry)
		remove_proc_entry("kcare/opt/faultinject", NULL);
	if (opt_faultinject_call_entry)
		remove_proc_entry("kcare/opt/faultinject_call", NULL);
	if (opt_skip_cpus_entry)
		remove_proc_entry("kcare/opt/skip_cpus", NULL);
	if (opt_time_wait_period_entry)
		remove_proc_entry("kcare/opt/kpatch_wait_period", NULL);
	if (opt_kpatch_retries_entry)
		remove_proc_entry("kcare/opt/kpatch_retries", NULL);

	remove_proc_entry("kcare/opt", NULL);
	remove_proc_entry("kcare", NULL);
}

static __init int kcare_init_proc(void)
{
	int ret = -ENODEV;

	if (!proc_mkdir("kcare", NULL)) {
		pr_err("kcare: failed to create proc directory\n");
		return ret;
	}

	if (!proc_mkdir("kcare/opt", NULL)) {
		pr_err("kcare: failed to create proc directory\n");
		remove_proc_entry("kcare", NULL);
		return ret;
	}

	freeze_entry = proc_create("kcare/freeze_blacklist", 0, NULL,
			&freeze_blacklist_fops);
	if (!freeze_entry) {
		pr_err("kcare: failed to create freeze_blacklist procfs entry\n");
		goto out_error;
	}

	effective_ver_entry = proc_create("kcare/effective_version", 0644, NULL,
			&effective_ver_fops);
	if (!effective_ver_entry) {
		pr_err("kcare: failed to create effective_version procfs "
				"entry\n");
		goto out_error;
	}
	patchinfo_entry = proc_create("kcare/patchinfo.json.gz", 0444, NULL,
			&patchinfo_fops);
	if (!patchinfo_entry) {
		pr_err("kcare: failed to create patchinfo.json.gz procfs "
				"entry\n");
		goto out_error;
	}
	cvelist_entry = proc_create("kcare/cvelist", 0444, NULL,
			&cvelist_fops);
	if (!cvelist_entry) {
		pr_err("kcare: failed to create cvelist procfs "
				"entry\n");
		goto out_error;
	}

	opt_safety_method_entry = proc_create("kcare/opt/safety_method", 0644, NULL,
			&opt_safety_method_ops);
	if (!opt_safety_method_entry) {
		pr_err("kcare: failed to create opt/safety_method procfs "
				"entry\n");
		goto out_error;
	}

	opt_faultinject_entry = proc_create("kcare/opt/faultinject", 0644, NULL,
			&opt_faultinject_ops);
	if (!opt_faultinject_entry) {
		pr_err("kcare: failed to create opt/faultinject procfs "
				"entry\n");
		goto out_error;
	}

	opt_faultinject_call_entry = proc_create("kcare/opt/faultinject_call", 0644, NULL,
			&opt_faultinject_call_ops);
	if (!opt_faultinject_call_entry) {
		pr_err("kcare: failed to create opt/faultinject_call procfs "
				"entry\n");
		goto out_error;
	}

	opt_skip_cpus_entry = proc_create("kcare/opt/skip_cpus", 0644, NULL,
			&opt_skip_cpus_ops);
	if (!opt_skip_cpus_entry) {
		pr_err("kcare: failed to create opt/skip_cpus procfs "
				"entry\n");
		goto out_error;
	}

	opt_time_wait_period_entry = proc_create("kcare/opt/kpatch_wait_period", 0644, NULL,
			&opt_time_wait_period_ops);
	if (!opt_time_wait_period_entry) {
		pr_err("kcare: failed to create opt/kpatch_wait_period procfs "
				"entry\n");
		goto out_error;
	}

	opt_kpatch_retries_entry = proc_create("kcare/opt/kpatch_retries", 0644, NULL,
			&opt_kpatch_retries_ops);
	if (!opt_kpatch_retries_entry) {
		pr_err("kcare: failed to create opt/kpatch_retries procfs "
				"entry\n");
		goto out_error;
	}

	return 0;
out_error:
	kcare_clean_proc();
	return -ENODEV;
}

#if defined(CONFIG_KCARE_BUILD_CRASHREPORT) && defined(CONFIG_X86_64)

static int save_kcore_output(ktime_t time)
{
	char kcore_output[KCORE_FORMAT_STRING_LEN] = { 0 };
	char kcore_count[30] = { 0 };

	char *argv_kcore[] = {
			"/bin/dd",
			"if=/proc/kcore",
			NULL, /* kcore_output */
			"bs=1MB",
			NULL, /* kcore_count */
			NULL
	};

	char *envp[] = {
			"HOME=/",
			"PATH=/sbin:/usr/sbin:/bin:/usr/bin:/bin",
			NULL
	};
	size_t len = 0;
	int err = 0;

	if (!kdumps_dirp || kdumps_dirp[0] == '\0') {
		pr_err("[%s] kdump dir parameter wasn't setup.", __func__);
		return 0;
	}

	len = verify_kdumps_dir_path(kdumps_dirp, strlen(kdumps_dirp));

	if (len > KDUMP_PATH_MAX) {
		pr_err("[%s] kdumps dir path is too long\n", __func__);
		return -E2BIG;
	}

	if (!len) {
		pr_err("[%s] kdumps dir path is invalid\n", __func__);
		return -EINVAL;
	}

	err = snprintf(kcore_output, KDUMP_PATH_MAX,"of=/%s/kcore%llu.dump", kdumps_dirp, time);
	if (err < 0) {
		pr_err("[%s] couldn't prepare kcore path [%d]\n", __func__, err);
		return err;
	}

	err = snprintf(kcore_count, 23, "count=%u", kpatch_ctx.kmod_data.kcore_output);
	if (err < 0) {
		pr_err("[%s] couldn't prepare kcore count[%d]\n", __func__, err);
		return err;
	}

	argv_kcore[2] = kcore_output;
	argv_kcore[4] = kcore_count;

	return call_usermodehelper(argv_kcore[0], argv_kcore, envp, UMH_WAIT_EXEC);
}

static int save_kmsg_output(ktime_t time)
{
	char kmsg_output[KMSG_FORMAT_STRING_LEN] = { 0 };

	char *argv_kmsg[] = {
			"/bin/sh",
			"-c",
			NULL, /* kmsg_output */
			NULL
	};

	char *envp[] = {
			"HOME=/",
			"PATH=/sbin:/usr/sbin:/bin:/usr/bin:/bin",
			NULL
	};
	size_t len = 0;
	int err = 0;

	if (!kdumps_dirp || kdumps_dirp[0] == '\0') {
		pr_err("[%s] kdump dir parameter wasn't setup.", __func__);
		return 0;
	}

	len = verify_kdumps_dir_path(kdumps_dirp, strlen(kdumps_dirp));
	if (len > KDUMP_PATH_MAX) {
		pr_err("[%s] kdumps dir path is too long\n", __func__);
		return -E2BIG;
	}

	if (!len) {
		pr_err("[%s] kdumps dir path is invalid\n", __func__);
		return -EINVAL;
	}

	err = snprintf(kmsg_output, KDUMP_PATH_MAX, "/bin/dmesg > /%s/kmsg%llu.log", kdumps_dirp, time);
	if (err < 0) {
		pr_err("[%s] couldn't prepare kmsg count [%d]\n", __func__, err);
		return err;
	}
	argv_kmsg[2] = kmsg_output;

	return call_usermodehelper(argv_kmsg[0], argv_kmsg, envp, UMH_WAIT_EXEC);
}


static bool filter_user_mode_dies(struct die_args *args, unsigned long action)
{
	/* usermode dies are not needed */
	return user_mode(args->regs);
}


static bool filter_in_atomic_preempt_off(struct die_args *args, unsigned long action)
{
	/* in atomic preempt context */
	return in_atomic_preempt_off();
}


static bool filter_debug_dies(struct die_args *args, unsigned long action)
{
	/* do not catch debug die */
	return action == DIE_DEBUG;
}


#ifndef X86_TRAP_UD
#define X86_TRAP_UD 6
#endif

#ifndef X86_TRAP_DE
#define X86_TRAP_DE 0
#endif

static bool filter_kvm_guest_emulation_dies(struct die_args *args, unsigned long action)
{
	/* do not catch kvm emulation traps */
	return 	action 		== DIE_TRAP &&
		args->trapnr 	== X86_TRAP_DE &&
		args->signr 	== SIGFPE;
}

static bool filter_kernel_illegal_opcode_die_trap(struct die_args *args, unsigned long action)
{
	/* do not catch illegal die traps which do not lead to bug */
	return  action 		== DIE_TRAP &&
		args->trapnr 	== X86_TRAP_UD &&
		args->signr 	== SIGILL;
}


typedef bool (*filter_t)(struct die_args *args, unsigned long action);

static filter_t die_filters[] = {
	filter_user_mode_dies,
	filter_in_atomic_preempt_off,
	filter_debug_dies,
	filter_kernel_illegal_opcode_die_trap,
	filter_kvm_guest_emulation_dies
};


static inline bool filter_die_catching(struct die_args *args, unsigned long action)
{
	int fnum;

	for (fnum = 0; fnum < ARRAY_SIZE(die_filters); fnum++)
		if (die_filters[fnum](args, action))
			return false;

	return true;
}


static void save_kcore_and_kmsg_work_func(struct work_struct *work)
{
	ktime_t time = ktime_get_real();
	int ret;

	if (kpatch_ctx.kmod_data.kcore_output) {
		ret = save_kcore_output(time);
		if (ret < 0 && kpatch_ctx.kmod_data.debug)
			pr_err("kcare: cannot save vmcore [%d]\n", ret);
	}

	if (kpatch_ctx.kmod_data.kmsg_output) {
		ret = save_kmsg_output(time);
		if (ret < 0 && kpatch_ctx.kmod_data.debug)
			pr_err("kcare: cannot save dmesg [%d]\n", ret);
	}
}
DECLARE_WORK(save_kcore_and_kmsg_work, save_kcore_and_kmsg_work_func);

static int die_notifier(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct die_args *args = data;

	if (!args) {
		printk(KERN_INFO "args is NULL\n");
		return 0;
	}

	if (!kdumps_dirp || kdumps_dirp[0] == '\0') {
		return 0;
	}

	if (!filter_die_catching(args, action)) {
		return 0;
	}

	pr_debug("kcare: catch die with action [%lu] str[%s] err[%ld] trapnr[%d] signr[%d]\n",
		 action, args->str ? args->str : "undefined", args->err, args->trapnr, args->signr);


	schedule_work(&save_kcore_and_kmsg_work);
	return 0;
}

static struct notifier_block die_notifier_nb = {
	.notifier_call = die_notifier,
};

static atomic_t registered_notifiers_cnt = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(module_finit_wait);

static void setup_crashreport_work_func(struct work_struct *work)
{
	int ret;

	ret = kcare_register_dumper();
	if (ret < 0 && kpatch_ctx.kmod_data.debug) {
		pr_err("kcare: error %d registering kmsg dumper failed. refcnt [%d]\n",
			 ret,  atomic_read(&registered_notifiers_cnt));
	}

	ret = register_die_notifier(&die_notifier_nb);
	if (ret < 0 && kpatch_ctx.kmod_data.debug) {
		pr_err("kcare: error %d registering die notifier. refcnt [%d]\n",
			 ret,  atomic_read(&registered_notifiers_cnt));
	}

	atomic_inc(&registered_notifiers_cnt);

	printk(KERN_INFO "[%s] crashreporter notifiers were successfully registered. refcnt [%d]\n",
		__func__, atomic_read(&registered_notifiers_cnt));

	wake_up(&module_finit_wait);
}
DECLARE_WORK(setup_crashreport_work, setup_crashreport_work_func);

static atomic_t disable_crashreport_arm = ATOMIC_INIT(0);

static int convert_to_bool(const char *val, bool *tmp)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	return kstrtobool(val, tmp);
#else
	return strtobool(val, tmp);
#endif
}

static int crashreport_enabled_param_set(const char *val,
				   const struct kernel_param *kp)
{
	int ret = 0;
	bool tmp = false;

	if (!kp->arg) {
		printk(KERN_ERR "[%s] invalid kernel param\n", __func__);
		return -EINVAL;
	}

	/* Usually NO equals means "set"... but let's skip implicit set */
	if (!val) {
		printk(KERN_ERR "[%s] invalid value passed\n", __func__);
		return -EINVAL;
	}

	ret = convert_to_bool(val, &tmp);
	if (ret) {
		printk(KERN_ERR "[%s] Failed to convert value[%d]\n", __func__, ret);
		return ret;
	}

	if (tmp == *(bool*)kp->arg) {
		printk(KERN_INFO "[%s] Nothing to do[%d]\n", __func__, ret);
		return 0;
	}

	if (atomic_read(&disable_crashreport_arm)) {
		printk(KERN_ERR "[%s] arm disabled [%d]. Do not try to change the value during module exit\n",
		                __func__,  atomic_read(&registered_notifiers_cnt));
		wake_up(&module_finit_wait);
		return -EBUSY;
	}

	ret = param_set_bool(val, kp);
	if (ret) {
		printk(KERN_ERR "[%s] Failed to convert given value to module param with err[%d]\n", __func__, ret);
		return ret;
	}

	/* NOTE(anesterenko):
	 * This module callback is also started during insmod kcare.ko.
	 * Default value of enable_crashreporter param is False and when
	 * it's changed to True via `insmod kcare.ko enable_crashreporter=1`
	 * or via arm /sys/modules/kcare/parameters/enable_crashreporter
	 * we schedule the work.
	 */
	if (*(bool*)kp->arg) {
		if (!work_pending(&setup_crashreport_work)) {
			schedule_work(&setup_crashreport_work);
			printk(KERN_INFO "[%s] enable crashreporter. start work [%d]\n",
				__func__, atomic_read(&registered_notifiers_cnt));
		}
	} else {
		cancel_work_sync(&setup_crashreport_work);
		cancel_work_sync(&save_kcore_and_kmsg_work);

		unregister_die_notifier(&die_notifier_nb);
		kcare_unregister_dumper();

		atomic_dec(&registered_notifiers_cnt);

		printk(KERN_INFO "[%s] disabled crashreporter. wake up waiter[%d]\n",
			__func__, atomic_read(&registered_notifiers_cnt));
		wake_up(&module_finit_wait);
	}

	return ret;
}

static void kc_crashreporter_deinitializer(void)
{
	atomic_set(&disable_crashreport_arm, 1);
	if (!crashreporter_enabled) {
		printk(KERN_INFO "[%s] crashreporter is already disabled\n", __func__);
	} else {
		cancel_work_sync(&setup_crashreport_work);
		cancel_work_sync(&save_kcore_and_kmsg_work);

		unregister_die_notifier(&die_notifier_nb);
		kcare_unregister_dumper();
		atomic_dec(&registered_notifiers_cnt);
		printk(KERN_INFO "[%s] disabled crashreporter[%d]\n", __func__, atomic_read(&registered_notifiers_cnt));
	}
	printk(KERN_INFO "[%s] wait unregistering notifiers and work finishing[%d]\n", __func__, atomic_read(&registered_notifiers_cnt));
	wait_event_interruptible(module_finit_wait, atomic_read(&registered_notifiers_cnt) <= 0);
}

/**
 * @brief constructor is called after the module_param_cb (crashreport_enabled_param_set)
 * and it will serve as initializer
 *
 * @return 0 		- on success
 *         negative val - on fail
 */
static int kc_crashreporter_initializer(void)
{
	if (!crashreporter_enabled) {
		printk(KERN_INFO "kcare: crashreporter disabled \n");
	} else {
		printk(KERN_INFO "kcare: crashreporter is already enabled by callback\n");
	}

	return 0;
}
#else /* !(CONFIG_KCARE_BUILD_CRASHREPORT && CONFIG_X86_64) */

static int crashreport_enabled_param_set(const char *val,
				   const struct kernel_param *kp)
{
	return 0;
}

static void kc_crashreporter_deinitializer(void)
{
	printk(KERN_INFO "[%s] crashreporter isn't supported\n", __func__);
}

static int kc_crashreporter_initializer(void)
{
	printk(KERN_INFO "[%s] crashreporter isn't supported\n", __func__);
	return 0;
}
#endif /* CONFIG_KCARE_BUILD_CRASHREPORT && CONFIG_X86_64 */

static __init int kcare_init(void)
{
	int ret = -ENODEV;

	BUILD_BUG_ON(sizeof(struct kpatch_kmod_data) != PAGE_SIZE);

	ret = kcare_resolve_symbols_init();
	if (ret)
		goto err_resolve_symbols;

	ret = kcare_init_proc();
	if (ret < 0)
		goto err_init_proc;

	ret = gcov_kcare_debugfs_init();
	if (ret < 0)
		goto err_gcov_debugfs_init;

	ret = misc_register(&kcare_dev);
	if (ret < 0) {
		pr_err("kcare: error %d registering device\n", ret);
		goto err_misc_register;
	} else
		pr_info("kcare: registered device with node %d:%d\n",
				MISC_MAJOR, kcare_dev.minor);

	ret = kc_crashreporter_initializer();
	if (ret < 0) {
		pr_err("kcare: error %d initialize crashreporter\n", ret);
	}

	return 0;
err_misc_register:
	gcov_kcare_debugfs_cleanup();
err_gcov_debugfs_init:
	kcare_clean_proc();
err_init_proc:
	kcare_resolve_symbols_exit();
err_resolve_symbols:
	return ret;
}

static void kcare_deinit(void)
{
	misc_deregister(&kcare_dev);
	gcov_kcare_debugfs_cleanup();
	kcare_clean_proc();
	kcare_resolve_symbols_exit();
	mutex_lock(&freeze_lock);
	freeze_blacklist_clear();
	mutex_unlock(&freeze_lock);
	gcov_kcare_cache_cleanup();
	kc_crashreporter_deinitializer();
}

module_init(kcare_init);
module_exit(kcare_deinit);

MODULE_LICENSE("GPL v2");
MODULE_VERSION("1.36");
