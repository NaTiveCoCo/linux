#include <linux/mm.h>
#include <linux/errno.h>
// #include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/panic.h>
#include <linux/pagemap.h>
#include <linux/pagewalk.h>
#include <linux/page_ref.h>
#include <linux/percpu.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <asm/nacc.h>

#include <asm/sbi.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/csr.h>
#include <asm/tlbflush.h>

extern unsigned long nacc_mappings_virt;

#ifdef NACC_PROFILE
enum nacc_profile_linux_counter {
	NACC_PROFILE_LINUX_MM_ACTIVE_ENTER = 0,
	NACC_PROFILE_LINUX_MM_ACTIVE_EXIT,
	NACC_PROFILE_LINUX_ROOT_TAG,
	NACC_PROFILE_LINUX_ROOT_RETIRE,
	NACC_PROFILE_LINUX_SYSCALL_REGISTER,
	NACC_PROFILE_LINUX_FORK_CHILD_REGISTER,
	NACC_PROFILE_LINUX_UNREGISTER_SUCCESS,
	NACC_PROFILE_LINUX_UNREGISTER_FAIL,
	NACC_PROFILE_LINUX_SECURE_PTP_RECLAIM_QUEUE,
	NACC_PROFILE_LINUX_SECURE_PTP_RECLAIM_FLUSH,
	NACC_PROFILE_LINUX_LIVE_MM_ACTIVE,
	NACC_PROFILE_LINUX_LIVE_ROOT_L0,
	NACC_PROFILE_LINUX_LIVE_SECURE_PTP_QUEUED,
	NACC_PROFILE_LINUX_COUNTER_MAX,
};

#define NACC_PROFILE_LINUX_LIVE_FIRST NACC_PROFILE_LINUX_LIVE_MM_ACTIVE

static const char * const nacc_profile_linux_names[] = {
	[NACC_PROFILE_LINUX_MM_ACTIVE_ENTER] = "mm_active_enter",
	[NACC_PROFILE_LINUX_MM_ACTIVE_EXIT] = "mm_active_exit",
	[NACC_PROFILE_LINUX_ROOT_TAG] = "root_l0_tag",
	[NACC_PROFILE_LINUX_ROOT_RETIRE] = "root_l0_retire",
	[NACC_PROFILE_LINUX_SYSCALL_REGISTER] = "syscall_register",
	[NACC_PROFILE_LINUX_FORK_CHILD_REGISTER] = "fork_child_register",
	[NACC_PROFILE_LINUX_UNREGISTER_SUCCESS] = "task_unregister_success",
	[NACC_PROFILE_LINUX_UNREGISTER_FAIL] = "task_unregister_fail",
	[NACC_PROFILE_LINUX_SECURE_PTP_RECLAIM_QUEUE] = "secure_ptp_reclaim_queue",
	[NACC_PROFILE_LINUX_SECURE_PTP_RECLAIM_FLUSH] = "secure_ptp_reclaim_flush",
	[NACC_PROFILE_LINUX_LIVE_MM_ACTIVE] = "mm_active",
	[NACC_PROFILE_LINUX_LIVE_ROOT_L0] = "root_l0",
	[NACC_PROFILE_LINUX_LIVE_SECURE_PTP_QUEUED] = "secure_ptp_reclaim_queued",
};

static const char * const nacc_profile_sbi_names[] = {
	[NACC_PROFILE_SBI_CONTAINER_REGISTER] = "container_register",
	[NACC_PROFILE_SBI_CONTAINER_UNREGISTER] = "container_unregister",
	[NACC_PROFILE_SBI_TASK_REGISTER] = "task_register",
	[NACC_PROFILE_SBI_TASK_UNREGISTER] = "task_unregister",
	[NACC_PROFILE_SBI_TASK_REGISTER_FAIL] = "task_register_fail",
	[NACC_PROFILE_SBI_TASK_UNREGISTER_FAIL] = "task_unregister_fail",
	[NACC_PROFILE_SBI_METADATA_CONTAINER_ALLOC] = "metadata_container_alloc",
	[NACC_PROFILE_SBI_METADATA_CONTAINER_FREE] = "metadata_container_free",
	[NACC_PROFILE_SBI_METADATA_PROCESS_ALLOC] = "metadata_process_alloc",
	[NACC_PROFILE_SBI_METADATA_PROCESS_FREE] = "metadata_process_free",
	[NACC_PROFILE_SBI_METADATA_PID_HASH_ALLOC] = "metadata_pid_hash_alloc",
	[NACC_PROFILE_SBI_METADATA_PID_HASH_FREE] = "metadata_pid_hash_free",
	[NACC_PROFILE_SBI_METADATA_THREAD_CTX_ALLOC] = "metadata_thread_ctx_alloc",
	[NACC_PROFILE_SBI_METADATA_THREAD_CTX_FREE] = "metadata_thread_ctx_free",
	[NACC_PROFILE_SBI_METADATA_ALLOC_FAIL] = "metadata_alloc_fail",
	[NACC_PROFILE_SBI_SECURE_PTP_ALLOC] = "secure_ptp_alloc",
	[NACC_PROFILE_SBI_SECURE_PTP_FREE] = "secure_ptp_free",
	[NACC_PROFILE_SBI_SECURE_PTP_ALLOC_FAIL] = "secure_ptp_alloc_fail",
	[NACC_PROFILE_SBI_ROOT_L0_TAG] = "root_l0_tag",
	[NACC_PROFILE_SBI_ROOT_L0_RETIRE] = "root_l0_retire",
	[NACC_PROFILE_SBI_ROOT_L0_TAG_FAIL] = "root_l0_tag_fail",
	[NACC_PROFILE_SBI_PRIVATE_PFN_ACQUIRE] = "private_pfn_acquire",
	[NACC_PROFILE_SBI_PRIVATE_PFN_RETIRE] = "private_pfn_retire",
	[NACC_PROFILE_SBI_PRIVATE_PFN_FIRST_REF] = "private_pfn_first_ref",
	[NACC_PROFILE_SBI_PRIVATE_PFN_LAST_REF] = "private_pfn_last_ref",
	[NACC_PROFILE_SBI_PRIVATE_PFN_ACQUIRE_FAIL] = "private_pfn_acquire_fail",
	[NACC_PROFILE_SBI_LIVE_CONTAINER] = "container",
	[NACC_PROFILE_SBI_LIVE_TASK] = "task",
	[NACC_PROFILE_SBI_LIVE_METADATA_CONTAINER] = "metadata_container",
	[NACC_PROFILE_SBI_LIVE_METADATA_PROCESS] = "metadata_process",
	[NACC_PROFILE_SBI_LIVE_METADATA_PID_HASH] = "metadata_pid_hash",
	[NACC_PROFILE_SBI_LIVE_METADATA_THREAD_CTX] = "metadata_thread_ctx",
	[NACC_PROFILE_SBI_LIVE_SECURE_PTP] = "secure_ptp",
	[NACC_PROFILE_SBI_LIVE_ROOT_L0] = "root_l0",
	[NACC_PROFILE_SBI_LIVE_PRIVATE_PFN] = "private_pfn",
};

#define NACC_PROFILE_SBI_LIVE_FIRST NACC_PROFILE_SBI_LIVE_CONTAINER

static atomic64_t nacc_profile_linux_counters[NACC_PROFILE_LINUX_COUNTER_MAX];
static s64 nacc_profile_linux_live_baseline[NACC_PROFILE_LINUX_COUNTER_MAX];
static s64 nacc_profile_sbi_live_baseline[NACC_PROFILE_SBI_COUNTER_MAX];
static atomic64_t nacc_profile_reset_count;

static void nacc_profile_linux_inc(enum nacc_profile_linux_counter id)
{
	atomic64_inc(&nacc_profile_linux_counters[id]);
}

static void nacc_profile_linux_add(enum nacc_profile_linux_counter id, long value)
{
	atomic64_add(value, &nacc_profile_linux_counters[id]);
}

static s64 nacc_profile_linux_read(enum nacc_profile_linux_counter id)
{
	return atomic64_read(&nacc_profile_linux_counters[id]);
}

static int nacc_profile_sbi_read(enum nacc_profile_sbi_counter id, s64 *value)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_PROFILE_READ, id,
			0, 0, 0, 0, 0);
	if (ret.error)
		return ret.error;

	*value = ret.value;
	return 0;
}

static void nacc_profile_reset_counters(void)
{
	struct sbiret ret;
	s64 value;
	int i;

	for (i = 0; i < NACC_PROFILE_LINUX_LIVE_FIRST; i++)
		atomic64_set(&nacc_profile_linux_counters[i], 0);
	for (i = NACC_PROFILE_LINUX_LIVE_FIRST;
	     i < NACC_PROFILE_LINUX_COUNTER_MAX; i++)
		nacc_profile_linux_live_baseline[i] =
			nacc_profile_linux_read(i);

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_PROFILE_RESET,
			0, 0, 0, 0, 0, 0);
	if (!ret.error) {
		for (i = NACC_PROFILE_SBI_LIVE_FIRST;
		     i < NACC_PROFILE_SBI_COUNTER_MAX; i++) {
			if (nacc_profile_sbi_read(i, &value))
				value = 0;
			nacc_profile_sbi_live_baseline[i] = value;
		}
	}

	atomic64_inc(&nacc_profile_reset_count);
}

void nacc_profile_mm_active_enter(void)
{
	nacc_profile_linux_inc(NACC_PROFILE_LINUX_MM_ACTIVE_ENTER);
	nacc_profile_linux_inc(NACC_PROFILE_LINUX_LIVE_MM_ACTIVE);
}
EXPORT_SYMBOL(nacc_profile_mm_active_enter);

void nacc_profile_mm_active_exit(void)
{
	nacc_profile_linux_inc(NACC_PROFILE_LINUX_MM_ACTIVE_EXIT);
	nacc_profile_linux_add(NACC_PROFILE_LINUX_LIVE_MM_ACTIVE, -1);
}
EXPORT_SYMBOL(nacc_profile_mm_active_exit);

void nacc_profile_root_tag(void)
{
	nacc_profile_linux_inc(NACC_PROFILE_LINUX_ROOT_TAG);
	nacc_profile_linux_inc(NACC_PROFILE_LINUX_LIVE_ROOT_L0);
}
EXPORT_SYMBOL(nacc_profile_root_tag);

void nacc_profile_root_retire(void)
{
	nacc_profile_linux_inc(NACC_PROFILE_LINUX_ROOT_RETIRE);
	nacc_profile_linux_add(NACC_PROFILE_LINUX_LIVE_ROOT_L0, -1);
}
EXPORT_SYMBOL(nacc_profile_root_retire);

void nacc_profile_sys_register(void)
{
	nacc_profile_linux_inc(NACC_PROFILE_LINUX_SYSCALL_REGISTER);
}
EXPORT_SYMBOL(nacc_profile_sys_register);

void nacc_profile_fork_child_register(void)
{
	nacc_profile_linux_inc(NACC_PROFILE_LINUX_FORK_CHILD_REGISTER);
}
EXPORT_SYMBOL(nacc_profile_fork_child_register);

void nacc_profile_unregister_success(void)
{
	nacc_profile_linux_inc(NACC_PROFILE_LINUX_UNREGISTER_SUCCESS);
}
EXPORT_SYMBOL(nacc_profile_unregister_success);

void nacc_profile_unregister_fail(void)
{
	nacc_profile_linux_inc(NACC_PROFILE_LINUX_UNREGISTER_FAIL);
}
EXPORT_SYMBOL(nacc_profile_unregister_fail);

void nacc_profile_secure_ptp_queue(unsigned long count)
{
	nacc_profile_linux_add(NACC_PROFILE_LINUX_SECURE_PTP_RECLAIM_QUEUE,
			       count);
	nacc_profile_linux_add(NACC_PROFILE_LINUX_LIVE_SECURE_PTP_QUEUED,
			       count);
}
EXPORT_SYMBOL(nacc_profile_secure_ptp_queue);

void nacc_profile_secure_ptp_flush(unsigned long count)
{
	nacc_profile_linux_add(NACC_PROFILE_LINUX_SECURE_PTP_RECLAIM_FLUSH,
			       count);
	nacc_profile_linux_add(NACC_PROFILE_LINUX_LIVE_SECURE_PTP_QUEUED,
			       -(long)count);
}
EXPORT_SYMBOL(nacc_profile_secure_ptp_flush);

static void nacc_profile_seq_counter_object(struct seq_file *m,
					    const char * const *names,
					    int first, int last,
					    s64 (*read_fn)(int))
{
	int i;

	seq_puts(m, "{");
	for (i = first; i < last; i++) {
		if (i != first)
			seq_puts(m, ",");
		seq_printf(m, "\"%s\":%lld", names[i],
			   (long long)read_fn(i));
	}
	seq_puts(m, "}");
}

static s64 nacc_profile_linux_read_by_int(int id)
{
	return nacc_profile_linux_read(id);
}

static void nacc_profile_seq_linux_live(struct seq_file *m)
{
	int i;

	seq_puts(m, "{");
	for (i = NACC_PROFILE_LINUX_LIVE_FIRST;
	     i < NACC_PROFILE_LINUX_COUNTER_MAX; i++) {
		s64 baseline = nacc_profile_linux_live_baseline[i];
			s64 live_value = nacc_profile_linux_read(i);

		if (i != NACC_PROFILE_LINUX_LIVE_FIRST)
			seq_puts(m, ",");
		seq_printf(m,
				   "\"%s\":{\"baseline\":%lld,\"current\":%lld,\"delta\":%lld}",
				   nacc_profile_linux_names[i], (long long)baseline,
				   (long long)live_value,
				   (long long)(live_value - baseline));
	}
	seq_puts(m, "}");
}

static int nacc_profile_read_sbi_all(s64 *values)
{
	int first_error = 0;
	int i;

	for (i = 0; i < NACC_PROFILE_SBI_COUNTER_MAX; i++) {
		int ret = nacc_profile_sbi_read(i, &values[i]);

		if (ret) {
			values[i] = 0;
			if (!first_error)
				first_error = ret;
		}
	}

	return first_error;
}

static void nacc_profile_seq_sbi_counters(struct seq_file *m, s64 *values)
{
	int i;

	seq_puts(m, "{");
	for (i = 0; i < NACC_PROFILE_SBI_LIVE_FIRST; i++) {
		if (i)
			seq_puts(m, ",");
		seq_printf(m, "\"%s\":%lld", nacc_profile_sbi_names[i],
			   (long long)values[i]);
	}
	seq_puts(m, "}");
}

static void nacc_profile_seq_sbi_live(struct seq_file *m, s64 *values)
{
	int i;

	seq_puts(m, "{");
	for (i = NACC_PROFILE_SBI_LIVE_FIRST;
	     i < NACC_PROFILE_SBI_COUNTER_MAX; i++) {
		s64 baseline = nacc_profile_sbi_live_baseline[i];
			s64 live_value = values[i];

		if (i != NACC_PROFILE_SBI_LIVE_FIRST)
			seq_puts(m, ",");
		seq_printf(m,
				   "\"%s\":{\"baseline\":%lld,\"current\":%lld,\"delta\":%lld}",
				   nacc_profile_sbi_names[i], (long long)baseline,
				   (long long)live_value,
				   (long long)(live_value - baseline));
	}
	seq_puts(m, "}");
}

static int nacc_lifecycle_snapshot_show(struct seq_file *m, void *v)
{
	s64 sbi_values[NACC_PROFILE_SBI_COUNTER_MAX];
	int sbi_error;

	(void)v;

	sbi_error = nacc_profile_read_sbi_all(sbi_values);

	seq_puts(m, "{");
	seq_puts(m, "\"format\":\"nacc_lifecycle_v1\",");
	seq_printf(m, "\"profile_enabled\":true,\"reset_count\":%lld,",
		   (long long)atomic64_read(&nacc_profile_reset_count));
	seq_puts(m, "\"linux\":{");
	seq_puts(m, "\"counters\":");
	nacc_profile_seq_counter_object(m, nacc_profile_linux_names, 0,
					NACC_PROFILE_LINUX_LIVE_FIRST,
					nacc_profile_linux_read_by_int);
	seq_puts(m, ",\"live\":");
	nacc_profile_seq_linux_live(m);
	seq_puts(m, "},");
	seq_printf(m, "\"opensbi\":{\"available\":%s,\"last_error\":%d",
		   sbi_error ? "false" : "true", sbi_error);
	if (!sbi_error) {
		seq_puts(m, ",\"counters\":");
		nacc_profile_seq_sbi_counters(m, sbi_values);
		seq_puts(m, ",\"live\":");
		nacc_profile_seq_sbi_live(m, sbi_values);
	}
	seq_puts(m, "}}\n");

	return 0;
}

static int nacc_lifecycle_snapshot_open(struct inode *inode, struct file *file)
{
	return single_open(file, nacc_lifecycle_snapshot_show, inode->i_private);
}

static const struct file_operations nacc_lifecycle_snapshot_fops = {
	.open = nacc_lifecycle_snapshot_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static ssize_t nacc_lifecycle_reset_write(struct file *file,
					  const char __user *buf,
					  size_t count, loff_t *ppos)
{
	(void)file;
	(void)buf;
	(void)ppos;

	if (count)
		nacc_profile_reset_counters();
	return count;
}

static const struct file_operations nacc_lifecycle_reset_fops = {
	.write = nacc_lifecycle_reset_write,
	.llseek = noop_llseek,
};

static int __init nacc_lifecycle_debugfs_init(void)
{
	struct dentry *root;
	struct dentry *dir;

	nacc_profile_reset_counters();

	root = debugfs_create_dir("nacc", NULL);
	dir = debugfs_create_dir("lifecycle", root);
	debugfs_create_file("snapshot", 0444, dir, NULL,
			    &nacc_lifecycle_snapshot_fops);
	debugfs_create_file("reset", 0200, dir, NULL,
			    &nacc_lifecycle_reset_fops);

	return 0;
}
late_initcall(nacc_lifecycle_debugfs_init);
#endif /* NACC_PROFILE */

static const char *nacc_ptp_level_name(unsigned int level)
{
       if (level == 1)
               return "pmd";
       if (level == 0)
               return "pte";
       return "invalid";
}

static void nacc_dump_ptdesc_state(const char *tag, unsigned long pfn,
                                      unsigned int level, struct ptdesc *ptdesc)
{
       struct page *page = ptdesc_page(ptdesc);
       int mapcount = atomic_read(&page->_mapcount);

       mapcount = page_mapcount_is_type(mapcount) ? 0 : mapcount + 1;

       nacc_debug("[Linux]: %s: pfn=%lx level=%u(%s) ptdesc=%px ptl=%px flags=%lx page_type=%x refcount=%d mapcount=%d\n",
                  tag, pfn, level, nacc_ptp_level_name(level), ptdesc,
                  ptlock_ptr(ptdesc), ptdesc->__page_flags,
                  ptdesc->__page_type,
                  atomic_read(&ptdesc->__page_refcount), mapcount);
}

static unsigned long *nacc_mapping_slot(unsigned long pfn)
{
       if (pfn < NACC_PTP_PFN_BASE || pfn >= NACC_PTP_PFN_END)
               return NULL;

       return (unsigned long *)(nacc_mappings_virt +
                                ((pfn - NACC_PTP_PFN_BASE) << 4));
}

static unsigned long nacc_ptdesc_raw_ptl(struct ptdesc *ptdesc)
{
       return READ_ONCE(*(unsigned long *)&ptdesc->ptl);
}

DEFINE_PER_CPU_PAGE_ALIGNED(struct nacc_reclaim_list, nacc_reclaim_list);

unsigned long nacc_mm_state(struct mm_struct *mm)
{
	if (!mm)
		return 0;

	return READ_ONCE(mm->context.nacc_state);
}
EXPORT_SYMBOL(nacc_mm_state);

void nacc_mm_set_state(struct mm_struct *mm, unsigned long mask)
{
	unsigned long state;

	if (!mm)
		return;

	state = READ_ONCE(mm->context.nacc_state);
	WRITE_ONCE(mm->context.nacc_state, state | mask);
}
EXPORT_SYMBOL(nacc_mm_set_state);

bool nacc_mm_is_active(struct mm_struct *mm)
{
	return !!(nacc_mm_state(mm) & NACC_MM_ACTIVE);
}
EXPORT_SYMBOL(nacc_mm_is_active);

static const char *nacc_copy_user_highpage_result_name(long result)
{
	switch (result) {
	case NACC_COPY_USER_HIGHPAGE_NOT_HANDLED:
		return "not_handled";
	case NACC_COPY_USER_HIGHPAGE_HANDLED:
		return "handled";
	default:
		return "unknown";
	}
}

static void nacc_log_copy_user_highpage_context(const char *stage,
						struct page *to,
						struct page *from,
						unsigned long vaddr,
						struct vm_area_struct *vma,
						unsigned long root_pgd_pa,
						unsigned long from_pfn,
						unsigned long to_pfn,
						long result,
						void *caller)
{
#ifndef NACC_LOG_DEBUG
	(void)stage;
	(void)to;
	(void)from;
	(void)vaddr;
	(void)vma;
	(void)root_pgd_pa;
	(void)from_pfn;
	(void)to_pfn;
	(void)result;
	(void)caller;
#else
	struct mm_struct *mm = vma ? vma->vm_mm : NULL;
	unsigned long vm_start = vma ? vma->vm_start : 0;
	unsigned long vm_end = vma ? vma->vm_end : 0;
	unsigned long vm_flags = vma ? READ_ONCE(vma->vm_flags) : 0;
	unsigned long vm_pgoff = vma ? vma->vm_pgoff : 0;
	unsigned long mm_state = mm ? nacc_mm_state(mm) : 0;
	int from_map;
	int to_map;

	from_map = atomic_read(&from->_mapcount);
	from_map = page_mapcount_is_type(from_map) ? 0 : from_map + 1;
	to_map = atomic_read(&to->_mapcount);
	to_map = page_mapcount_is_type(to_map) ? 0 : to_map + 1;

	nacc_debug("[NACC][copy-user-highpage] linux %s comm=%s pid=%d tgid=%d caller=%pS mm=%px mm_state=%lx vaddr=%lx root=%lx vma=[%lx,%lx) vm_flags=%lx vm_pgoff=%lx has_file=%u from_pfn=%lx from_ref=%d from_map=%d to_pfn=%lx to_ref=%d to_map=%d result=%s(%ld)\n",
		   stage, current->comm, current->pid, current->tgid, caller,
		   mm, mm_state, vaddr, root_pgd_pa, vm_start, vm_end,
		   vm_flags, vm_pgoff, vma && vma->vm_file, from_pfn,
		   page_ref_count(from), from_map, to_pfn, page_ref_count(to),
		   to_map,
		   nacc_copy_user_highpage_result_name(result), result);
#endif
}

bool nacc_copy_mc_user_highpage_sbi(struct page *to, struct page *from,
				    unsigned long vaddr,
				    struct vm_area_struct *vma)
{
	struct sbiret ret;
	unsigned long from_pfn;
	unsigned long to_pfn;
	unsigned long root_pgd_pa;
	void *caller = __builtin_return_address(0);

	if (!vma || !vma->vm_mm || !nacc_mm_is_active(vma->vm_mm))
		return false;

	from_pfn = page_to_pfn(from);
	to_pfn = page_to_pfn(to);
	root_pgd_pa = __pa(vma->vm_mm->pgd);

	nacc_log_copy_user_highpage_context("enter", to, from, vaddr, vma,
					    root_pgd_pa, from_pfn, to_pfn,
					    -1, caller);

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_COPY_USER_HIGHPAGE,
			from_pfn, to_pfn, vaddr, root_pgd_pa,
			current->pid, 0);
	if (ret.error) {
		printk(KERN_ERR "[NACC][copy-user-highpage] linux ecall failed comm=%s pid=%d caller=%pS vaddr=%lx root=%lx from_pfn=%lx to_pfn=%lx err=%ld val=%ld\n",
		       current->comm, current->pid, caller, vaddr, root_pgd_pa,
		       from_pfn, to_pfn, ret.error, ret.value);
		panic("NaCC copy_user_highpage ecall failed");
	}

	nacc_log_copy_user_highpage_context("result", to, from, vaddr, vma,
					    root_pgd_pa, from_pfn, to_pfn,
					    ret.value, caller);

	switch (ret.value) {
	case NACC_COPY_USER_HIGHPAGE_NOT_HANDLED:
		return false;
	case NACC_COPY_USER_HIGHPAGE_HANDLED:
		return true;
	default:
		panic("NaCC copy_user_highpage ecall returned unknown result");
	}
}
EXPORT_SYMBOL(nacc_copy_mc_user_highpage_sbi);

struct nacc_leaf_detach_stats {
	unsigned long vmas;
	unsigned long private_hint_vmas;
	unsigned long resident_ptes;
	unsigned long resident_skipped_ptes;
	unsigned long already_nacc_ptes;
	unsigned long special_ptes;
	unsigned long non_user_ptes;
	unsigned long empty_ptes;
};

static bool nacc_vma_private_anon_hint(struct vm_area_struct *vma)
{
	if (!vma)
		return false;
	if (vma->vm_file)
		return false;
	if (vma->vm_flags & (VM_NACC | VM_IO | VM_PFNMAP | VM_MIXEDMAP))
		return false;
	if (vma->vm_flags & (VM_SHARED | VM_MAYSHARE))
		return false;

	return vma_is_anonymous(vma);
}

static bool nacc_pte_is_linux_special_leaf(pte_t pte)
{
	if (pte_special(pte))
		return true;
#ifdef CONFIG_ARCH_HAS_PTE_DEVMAP
	if (pte_devmap(pte))
		return true;
#endif
	return false;
}

static int nacc_detach_pre_vma(unsigned long start, unsigned long end,
			       struct mm_walk *walk)
{
	struct nacc_leaf_detach_stats *stats = walk->private;

	if (walk->vma) {
		stats->vmas++;
		if (nacc_vma_private_anon_hint(walk->vma)) {
			vm_flags_set(walk->vma, VM_NACC_APP);
			stats->private_hint_vmas++;
		}
	}

	return 0;
}

static int nacc_detach_pte_entry(pte_t *ptep, unsigned long addr,
				 unsigned long next, struct mm_walk *walk)
{
	struct nacc_leaf_detach_stats *stats = walk->private;
	pte_t oldpte;

	oldpte = ptep_get(ptep);
	if (!pte_present(oldpte)) {
		stats->empty_ptes++;
		return 0;
	}

	if (!pte_user(oldpte)) {
		stats->non_user_ptes++;
		return 0;
	}

	if (pte_nacc(oldpte))
		stats->already_nacc_ptes++;
	else if (!nacc_vma_private_anon_hint(walk->vma))
		stats->resident_skipped_ptes++;
	else if (nacc_pte_is_linux_special_leaf(oldpte)) {
		stats->special_ptes++;
		if (nacc_vma_is_vvar_abi_data(walk->vma) &&
		    nacc_record_vvar_sbi(__pa(walk->mm->pgd), addr,
					 pte_pfn(oldpte)))
			return -EIO;
	} else {
		nacc_update_pte_sbi(NACC_UPDATE_PTE_XCHG_ONE, __pa(ptep),
				    pte_val(pte_mknacc(oldpte)), addr,
				    __pa(walk->mm->pgd), 0);
		stats->resident_ptes++;
	}

	return 0;
}

int nacc_detach_user_leaf_pages(struct mm_struct *mm, const char *tag)
{
	static const struct mm_walk_ops nacc_detach_walk_ops = {
		.pre_vma = nacc_detach_pre_vma,
		.pte_entry = nacc_detach_pte_entry,
		.walk_lock = PGWALK_WRLOCK,
	};
	struct nacc_leaf_detach_stats stats = { 0 };
	unsigned long end;
	int ret;

	if (!mm)
		return -EINVAL;

	end = min_t(unsigned long, TASK_SIZE, NACC_USER_VPN2_PROTECTED_END);

	ret = mmap_write_lock_killable(mm);
	if (ret) {
		printk(KERN_ERR "[Linux]: nacc_detach_user_leaf_pages: mmap lock failed tag=%s mm=%px err=%d\n",
		       tag, mm, ret);
		return ret;
	}

	ret = walk_page_range(mm, 0, end, &nacc_detach_walk_ops, &stats);
	mmap_write_unlock(mm);

	if (!ret)
		flush_tlb_mm(mm);

	nacc_debug("[Linux]: nacc_detach_user_leaf_pages tag=%s mm=%px ret=%d range=[0,%lx) vmas=%lu private_hint_vmas=%lu tagged_resident_ptes=%lu resident_skipped=%lu already_nacc=%lu special=%lu non_user=%lu empty=%lu\n",
		   tag, mm, ret, end, stats.vmas, stats.private_hint_vmas,
		   stats.resident_ptes, stats.resident_skipped_ptes,
		   stats.already_nacc_ptes, stats.special_ptes,
		   stats.non_user_ptes, stats.empty_ptes);

	return ret;
}
EXPORT_SYMBOL(nacc_detach_user_leaf_pages);

static const char *nacc_uaccess_scope_class_name(enum nacc_uaccess_scope_class scope_class)
{
	switch (scope_class) {
	case NACC_UACCESS_SCOPE_STRING_READ:
		return "string_read";
	case NACC_UACCESS_SCOPE_CLASS_UNKNOWN:
	default:
		return "unknown";
	}
}

static const char *nacc_uaccess_scope_direction_name(enum nacc_uaccess_scope_direction direction)
{
	switch (direction) {
	case NACC_UACCESS_SCOPE_DIR_FROM_USER:
		return "from_user";
	case NACC_UACCESS_SCOPE_DIR_TO_USER:
		return "to_user";
	case NACC_UACCESS_SCOPE_DIR_UNKNOWN:
	default:
		return "unknown";
	}
}

static unsigned long nacc_user_access_save_enable(void)
{
	unsigned long status = csr_read(CSR_STATUS);

	if (!(status & SR_SUM))
		csr_set(CSR_STATUS, SR_SUM);
	return status;
}

static void nacc_user_access_restore(unsigned long status)
{
	if (!(status & SR_SUM))
		csr_clear(CSR_STATUS, SR_SUM);
}

bool nacc_uaccess_scope_begin(enum nacc_uaccess_scope_class scope_class,
			      enum nacc_uaccess_scope_direction direction,
			      unsigned long user_va,
			      unsigned long bytes,
			      unsigned long caller_pc)
{
	struct sbiret ret;
	unsigned long status;

	if (!current->mm || !current->mm->pgd)
		return true;
	if (!current->thread.nacc_cid)
		return true;
	if (!nacc_thread_is_inited() && !nacc_mm_is_active(current->mm))
		return true;
	if (!bytes)
		return false;

	status = nacc_user_access_save_enable();
	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_UACCESS_SCOPE_BEGIN,
			scope_class, direction, user_va, bytes, 0,
			current->pid);
	nacc_user_access_restore(status);
	if (ret.error) {
		printk_ratelimited(KERN_ERR "[NACC][uaccess-scope-begin-failed] pid=%d comm=%s cid=%lx class=%s direction=%s user_va=%lx bytes=%lu caller=%lx err=%ld val=%ld\n",
				   current->pid, current->comm,
				   current->thread.nacc_cid,
				   nacc_uaccess_scope_class_name(scope_class),
				   nacc_uaccess_scope_direction_name(direction),
				   user_va, bytes, caller_pc, ret.error,
				   ret.value);
		return false;
	}

	return true;
}
EXPORT_SYMBOL(nacc_uaccess_scope_begin);

int nacc_uaccess_string_read_begin(unsigned long user_va,
				   unsigned long bytes,
				   struct nacc_uaccess_string_read_desc *desc)
{
	struct sbiret ret;
	unsigned long status;

	if (!current->mm || !current->mm->pgd)
		return 0;
	if (!current->thread.nacc_cid)
		return 0;
	if (current->thread.nacc_flag & NACC_EXEC)
		return 0;
	if (!nacc_thread_is_inited() && !nacc_mm_is_active(current->mm))
		return 0;
	if (!bytes || !desc)
		return -EFAULT;
	if (desc->version != NACC_UACCESS_STRING_READ_DESC_VERSION)
		return -EFAULT;

	status = nacc_user_access_save_enable();
	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_UACCESS_SCOPE_BEGIN,
			NACC_UACCESS_SCOPE_STRING_READ,
			NACC_UACCESS_SCOPE_DIR_FROM_USER,
			user_va, bytes, (unsigned long)desc, current->pid);
	nacc_user_access_restore(status);
	if (!ret.error)
		return 1;
	if (ret.error == SBI_ERR_NOT_SUPPORTED)
		return 0;

	printk_ratelimited(KERN_ERR "[NACC][uaccess-string-read-begin-failed] pid=%d comm=%s cid=%lx user_va=%lx bytes=%lu op=%lu buffer_va=%lx buffer_bytes=%lu caller=%lx err=%ld val=%ld\n",
			   current->pid, current->comm, current->thread.nacc_cid,
			   user_va, bytes, desc->op, desc->buffer_va,
			   desc->buffer_bytes, desc->caller_pc, ret.error,
			   ret.value);
	return -EFAULT;
}
EXPORT_SYMBOL(nacc_uaccess_string_read_begin);

bool nacc_uaccess_scope_end(enum nacc_uaccess_scope_class scope_class,
			    enum nacc_uaccess_scope_direction direction,
			    unsigned long user_va,
			    unsigned long bytes,
			    long result)
{
	struct sbiret ret;

	if (!current->mm || !current->mm->pgd)
		return true;
	if (!current->thread.nacc_cid)
		return true;
	if (!nacc_thread_is_inited() && !nacc_mm_is_active(current->mm))
		return true;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_UACCESS_SCOPE_END,
			scope_class, direction, user_va, bytes,
			(unsigned long)result, current->pid);
	if (ret.error) {
		printk_ratelimited(KERN_ERR "[NACC][uaccess-scope-end-failed] pid=%d comm=%s cid=%lx class=%s direction=%s user_va=%lx bytes=%lu result=%ld err=%ld val=%ld\n",
				   current->pid, current->comm,
				   current->thread.nacc_cid,
				   nacc_uaccess_scope_class_name(scope_class),
				   nacc_uaccess_scope_direction_name(direction),
				   user_va, bytes, result, ret.error,
				   ret.value);
		return false;
	}

	return true;
}
EXPORT_SYMBOL(nacc_uaccess_scope_end);

int nacc_private_data_get_user_read(unsigned long user_va,
				    unsigned long bytes,
				    unsigned long *value)
{
	struct sbiret ret;

	if (value)
		*value = 0;

	if (!current->mm || !current->mm->pgd)
		return 0;
	if (!current->thread.nacc_cid)
		return 0;
	if (!nacc_thread_is_inited() && !nacc_mm_is_active(current->mm))
		return 0;
	if (!value)
		return -EFAULT;
	if ((bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8) ||
	    bytes > sizeof(unsigned long))
		return 0;

	ret = sbi_ecall(SBI_EXT_NACC,
			SBI_EXT_NACC_UACCESS_PRIVATE_GET_USER_READ,
			user_va, bytes, 0, 0, 0, 0);
	if (!ret.error) {
		*value = ret.value;
		return 1;
	}

	if (ret.error == SBI_ERR_NOT_SUPPORTED)
		return 0;

	printk_ratelimited(KERN_ERR "[NACC][private-get-user-read-denied] pid=%d comm=%s cid=%lx user_va=%lx bytes=%lu err=%ld val=%ld\n",
			   current->pid, current->comm, current->thread.nacc_cid,
			   user_va, bytes, ret.error, ret.value);
	return -EFAULT;
}
EXPORT_SYMBOL(nacc_private_data_get_user_read);

static int nacc_private_data_fault_in_writeable(unsigned long user_va,
						unsigned long bytes)
{
	unsigned long status;
	size_t left;

	status = csr_read(CSR_STATUS);
	if (status & SR_SUM)
		csr_clear(CSR_STATUS, SR_SUM);

	left = fault_in_safe_writeable((const char __user *)user_va, bytes);

	if (status & SR_SUM)
		csr_set(CSR_STATUS, SR_SUM);

	return left ? -EFAULT : 0;
}

int nacc_private_data_put_user_write(unsigned long user_va,
				     const void *value,
				     unsigned long bytes)
{
	struct sbiret ret;
	bool cow_retried = false;
	u64 raw = 0;

	if (!current->mm || !current->mm->pgd)
		return 0;
	if (!nacc_private_data_uaccess_active())
		return 0;
	if (!value)
		return -EFAULT;
	if (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8)
		return 0;

	memcpy(&raw, value, bytes);
retry:
	ret = sbi_ecall(SBI_EXT_NACC,
			SBI_EXT_NACC_UACCESS_PRIVATE_PUT_USER_WRITE,
			user_va, (unsigned long)raw,
			(unsigned long)(raw >> 32), bytes, 0,
			current->pid);
	if (!ret.error)
		return 1;
	/* NaCC uses DENIED_LOCKED as private put_user COW-needed. */
	if (ret.error == SBI_ERR_DENIED_LOCKED && !cow_retried) {
		int fault_ret;

		cow_retried = true;
		fault_ret = nacc_private_data_fault_in_writeable(user_va,
								 bytes);
		if (!fault_ret)
			goto retry;

		printk_ratelimited(KERN_ERR "[NACC][private-put-user-cow-failed] pid=%d comm=%s cid=%lx user_va=%lx bytes=%lu err=%d\n",
				   current->pid, current->comm,
				   current->thread.nacc_cid, user_va, bytes,
				   fault_ret);
		return -EFAULT;
	}
	if (ret.error == SBI_ERR_NOT_SUPPORTED)
		return 0;

	printk_ratelimited(KERN_ERR "[NACC][private-put-user-write-denied] pid=%d comm=%s cid=%lx user_va=%lx bytes=%lu err=%ld val=%ld\n",
			   current->pid, current->comm, current->thread.nacc_cid,
			   user_va, bytes, ret.error, ret.value);
	return -EFAULT;
}
EXPORT_SYMBOL(nacc_private_data_put_user_write);

int nacc_private_data_copy_to_user(unsigned long user_va,
				   unsigned long kernel_va,
				   unsigned long bytes,
				   unsigned long caller_pc,
				   unsigned long *left)
{
	unsigned long copied = 0;

	if (left)
		*left = bytes;

	if (!current->mm || !current->mm->pgd)
		return 0;
	if (!nacc_private_data_uaccess_active())
		return 0;
	if (!left)
		return -EFAULT;
	if (!bytes) {
		*left = 0;
		return 1;
	}

	while (copied < bytes) {
		unsigned long dst = user_va + copied;
		unsigned long src = kernel_va + copied;
		unsigned long chunk = bytes - copied;
		unsigned long page_left;
		struct sbiret ret;
		bool write_fault_retried = false;

		page_left = PAGE_SIZE - (dst & (PAGE_SIZE - 1));
		if (chunk > page_left)
			chunk = page_left;
		page_left = PAGE_SIZE - (src & (PAGE_SIZE - 1));
		if (chunk > page_left)
			chunk = page_left;

retry:
		ret = sbi_ecall(SBI_EXT_NACC,
				SBI_EXT_NACC_UACCESS_PRIVATE_COPY_TO_USER,
				dst, src, chunk, caller_pc, current->pid, 0);
		if ((ret.error == SBI_ERR_NOT_SUPPORTED ||
		     ret.error == SBI_ERR_DENIED_LOCKED) &&
		    !write_fault_retried) {
			int fault_ret;

			write_fault_retried = true;
			fault_ret = nacc_private_data_fault_in_writeable(dst,
									 chunk);
			if (!fault_ret)
				goto retry;

			printk_ratelimited(KERN_ERR "[NACC][private-copy-to-user-prefault-failed] pid=%d comm=%s cid=%lx user_va=%lx kernel_va=%lx bytes=%lu dst=%lx src=%lx chunk=%lu copied=%lu sbi_err=%ld err=%d\n",
					   current->pid, current->comm,
					   current->thread.nacc_cid,
					   user_va, kernel_va, bytes, dst,
					   src, chunk, copied, ret.error,
					   fault_ret);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}
		if (ret.error == SBI_ERR_NOT_SUPPORTED) {
			/*
			 * After one successful write-prefault, preserve the
			 * existing fallback contract for non-private/unhandled
			 * destinations.
			 */
			if (!copied)
				return 0;
			*left = bytes - copied;
			return 1;
		}
		if (ret.error) {
			printk_ratelimited(KERN_ERR "[NACC][private-copy-to-user-denied] pid=%d comm=%s cid=%lx user_va=%lx kernel_va=%lx bytes=%lu copied=%lu err=%ld val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacc_cid,
					   user_va, kernel_va, bytes, copied,
					   ret.error, ret.value);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}
		if (!ret.value || ret.value > chunk) {
			printk_ratelimited(KERN_ERR "[NACC][private-copy-to-user-bad-result] pid=%d comm=%s cid=%lx user_va=%lx kernel_va=%lx chunk=%lu copied=%lu val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacc_cid,
					   dst, src, chunk, copied,
					   ret.value);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}

		copied += ret.value;
	}

	*left = 0;
	return 1;
}
EXPORT_SYMBOL(nacc_private_data_copy_to_user);

int nacc_private_data_copy_from_user(unsigned long kernel_va,
				     unsigned long user_va,
				     unsigned long bytes,
				     unsigned long caller_pc,
				     unsigned long *left)
{
	unsigned long copied = 0;

	if (left)
		*left = bytes;

	if (!current->mm || !current->mm->pgd)
		return 0;
	if (!nacc_private_data_uaccess_active())
		return 0;
	if (!left)
		return -EFAULT;
	if (!bytes) {
		*left = 0;
		return 1;
	}

	while (copied < bytes) {
		unsigned long dst = kernel_va + copied;
		unsigned long src = user_va + copied;
		unsigned long chunk = bytes - copied;
		unsigned long page_left;
		struct sbiret ret;

		page_left = PAGE_SIZE - (src & (PAGE_SIZE - 1));
		if (chunk > page_left)
			chunk = page_left;
		page_left = PAGE_SIZE - (dst & (PAGE_SIZE - 1));
		if (chunk > page_left)
			chunk = page_left;

		ret = sbi_ecall(SBI_EXT_NACC,
				SBI_EXT_NACC_UACCESS_PRIVATE_COPY_FROM_USER,
				src, dst, chunk, caller_pc, current->pid, 0);
		if (ret.error == SBI_ERR_NOT_SUPPORTED) {
			if (!copied)
				return 0;
			*left = bytes - copied;
			return 1;
		}
		if (ret.error) {
			printk_ratelimited(KERN_ERR "[NACC][private-copy-from-user-denied] pid=%d comm=%s cid=%lx kernel_va=%lx user_va=%lx bytes=%lu copied=%lu err=%ld val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacc_cid,
					   kernel_va, user_va, bytes, copied,
					   ret.error, ret.value);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}
		if (!ret.value || ret.value > chunk) {
			printk_ratelimited(KERN_ERR "[NACC][private-copy-from-user-bad-result] pid=%d comm=%s cid=%lx kernel_va=%lx user_va=%lx chunk=%lu copied=%lu val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacc_cid,
					   dst, src, chunk, copied,
					   ret.value);
			*left = bytes - copied;
			return copied ? 1 : -EFAULT;
		}

		copied += ret.value;
	}

	*left = 0;
	return 1;
}
EXPORT_SYMBOL(nacc_private_data_copy_from_user);

int nacc_private_data_clear_user(unsigned long user_va,
				 unsigned long bytes,
				 unsigned long caller_pc,
				 unsigned long *left)
{
	unsigned long cleared = 0;

	if (left)
		*left = bytes;

	if (!current->mm || !current->mm->pgd)
		return 0;
	if (!nacc_private_data_uaccess_active())
		return 0;
	if (!left)
		return -EFAULT;
	if (!bytes) {
		*left = 0;
		return 1;
	}

	while (cleared < bytes) {
		unsigned long dst = user_va + cleared;
		unsigned long chunk = bytes - cleared;
		unsigned long page_left;
		unsigned long status;
		struct sbiret ret;

		page_left = PAGE_SIZE - (dst & (PAGE_SIZE - 1));
		if (chunk > page_left)
			chunk = page_left;

		status = csr_read(CSR_STATUS);
		if (!(status & SR_SUM))
			csr_set(CSR_STATUS, SR_SUM);
		ret = sbi_ecall(SBI_EXT_NACC,
				SBI_EXT_NACC_UACCESS_PRIVATE_CLEAR_USER,
				dst, chunk, caller_pc, current->pid, 0, 0);
		if (!(status & SR_SUM))
			csr_clear(CSR_STATUS, SR_SUM);

		if (ret.error == SBI_ERR_NOT_SUPPORTED) {
			if (!cleared)
				return 0;
			*left = bytes - cleared;
			return 1;
		}
		if (ret.error) {
			printk_ratelimited(KERN_ERR "[NACC][private-clear-user-denied] pid=%d comm=%s cid=%lx user_va=%lx bytes=%lu cleared=%lu err=%ld val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacc_cid,
					   user_va, bytes, cleared,
					   ret.error, ret.value);
			*left = bytes - cleared;
			return cleared ? 1 : -EFAULT;
		}
		if (!ret.value || ret.value > chunk) {
			printk_ratelimited(KERN_ERR "[NACC][private-clear-user-bad-result] pid=%d comm=%s cid=%lx user_va=%lx chunk=%lu cleared=%lu val=%ld\n",
					   current->pid, current->comm,
					   current->thread.nacc_cid,
					   dst, chunk, cleared,
					   ret.value);
			*left = bytes - cleared;
			return cleared ? 1 : -EFAULT;
		}

		cleared += ret.value;
	}

	*left = 0;
	return 1;
}
EXPORT_SYMBOL(nacc_private_data_clear_user);

void add_to_reclaim_list(unsigned long pfn)
{
    if (pfn < NACC_PTP_PFN_BASE || pfn >= NACC_PTP_PFN_END) {
        return;
    }
    
	struct nacc_reclaim_list *reclaim_list = &get_cpu_var(nacc_reclaim_list);
	reclaim_list->pfns[reclaim_list->count++] = pfn;
	nacc_profile_secure_ptp_queue(1);
    nacc_debug("[Linux]: add pfn: %lx to reclaim list, count: %lx\n",
               reclaim_list->pfns[reclaim_list->count - 1],
               reclaim_list->count);
    // when it meets the max size, flush it.
	if (reclaim_list->count == NACC_RECLAIM_LIST_SIZE) {
		flush_reclaim_list();
	}
	put_cpu_var(reclaim_list);
}

void flush_reclaim_list(void)
{
    // After the full transfer function, flush_reclaim_list function should be called.
	struct nacc_reclaim_list *reclaim_list = &get_cpu_var(nacc_reclaim_list);
	if (reclaim_list->count > 0) {
		unsigned long count = reclaim_list->count;

        for (int i = 0; i < reclaim_list->count; i++)
            nacc_debug("[Linux]: calling flush_reclaim_list with pfn: %lx\n",
                       reclaim_list->pfns[i]);
        sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_RECLAIM_PTP,
				  __pa(reclaim_list->pfns), reclaim_list->count,
				  0, 0, 0, 0);
		nacc_profile_secure_ptp_flush(count);
		reclaim_list->count = 0;
	}
	put_cpu_var(reclaim_list);
}

void pgtbl_debug(unsigned long pgd)
{
#ifdef NACC_LOG_DEBUG
    struct sbiret ret;

    nacc_debug("[Linux]: calling pgtbl_debug SBI call pgd=%lx\n", pgd);
    ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_LINUX_DEBUG,
                    pgd, 0,
                    0, 0, 0, 0);
    nacc_debug("[Linux]: pgtbl_debug SBI returned error=%ld value=%ld\n",
               ret.error, ret.value);
#else
    (void)pgd;
#endif
}

void nacc_reclaim_ptp_dtor(struct ptdesc *ptdesc, unsigned long pfn,
			   unsigned int level, const char *tag)
{
	unsigned long *slot = nacc_mapping_slot(pfn);
	unsigned long old_ptl = nacc_ptdesc_raw_ptl(ptdesc);
	unsigned long old_slot = slot ? READ_ONCE(*slot) : 0;

	if (level == 1)
		pagetable_pmd_dtor(ptdesc);
	else
		pagetable_pte_dtor(ptdesc);

	/*
	 * Pure NACC pages skip buddy free, so they never get prep_new_page().
	 * Reset the split-ptlock storage explicitly to make the next ctor
	 * observe the same zero state that the allocator would have provided.
	 */
	WRITE_ONCE(*(unsigned long *)&ptdesc->ptl, 0);
	if (slot && old_slot == pfn)
		WRITE_ONCE(*slot, 0);
	nacc_debug("[Linux]: %s: reclaimed pfn=%lx level=%u old_ptl=%lx new_ptl=%lx old_slot=%lx new_slot=%lx\n",
		   tag, pfn, level, old_ptl,
		   nacc_ptdesc_raw_ptl(ptdesc), old_slot,
		   slot ? READ_ONCE(*slot) : 0);
}
EXPORT_SYMBOL(nacc_reclaim_ptp_dtor);

static int __page_nacc_register_ptp(struct mm_struct *mm,
				    unsigned long pfn, unsigned int level)
{
       unsigned long *slot;
       struct ptdesc *ptdesc;
       unsigned long pgtables_before = 0;

       slot = nacc_mapping_slot(pfn);
       if (!slot)
               return -EINVAL;

       if (*slot && *slot != pfn) {
               printk(KERN_ERR "[Linux]: page_nacc_register_ptp: conflicting mapping pfn=%lx slot=%lx level=%u(%s)\n",
                      pfn, *slot, level, nacc_ptp_level_name(level));
               return -EINVAL;
       }

       if (*slot == pfn) {
               ptdesc = page_ptdesc(pfn_to_page(pfn));
               if (nacc_ptdesc_raw_ptl(ptdesc)) {
               nacc_debug("[Linux]: page_nacc_register_ptp: pfn=%lx already registered as %s ptdesc=%px ptl=%lx\n",
                          pfn, nacc_ptp_level_name(level),
                          ptdesc, nacc_ptdesc_raw_ptl(ptdesc));
                       return 0;
               }

               nacc_debug("[Linux]: page_nacc_register_ptp: recovering stale slot for pfn=%lx level=%u(%s)\n",
                          pfn, level, nacc_ptp_level_name(level));
               WRITE_ONCE(*slot, 0);
       }

       ptdesc = page_ptdesc(pfn_to_page(pfn));
       nacc_dump_ptdesc_state("page_nacc_register_ptp: before ctor",
                              pfn, level, ptdesc);
       if (mm)
	       pgtables_before = mm_pgtables_bytes(mm);

       if (level == 1) {
               if (!pagetable_pmd_ctor(ptdesc)) {
                       printk(KERN_ERR "[Linux]: page_nacc_register_ptp: pagetable_pmd_ctor failed for pfn=%lx ptdesc=%px\n",
                              pfn, ptdesc);
                       return -ENOMEM;
               }
       } else if (level == 0) {
               if (!pagetable_pte_ctor(ptdesc)) {
                       printk(KERN_ERR "[Linux]: page_nacc_register_ptp: pagetable_pte_ctor failed for pfn=%lx ptdesc=%px\n",
                              pfn, ptdesc);
                       return -ENOMEM;
               }
       } else {
               printk(KERN_ERR "[Linux]: page_nacc_register_ptp: invalid level=%u for pfn=%lx\n",
                      level, pfn);
               return -EINVAL;
       }

       if (mm) {
	       if (level == 1)
		       mm_inc_nr_pmds(mm);
	       else
		       mm_inc_nr_ptes(mm);
	       nacc_debug("[Linux]: page_nacc_register_ptp: mm=%px pfn=%lx level=%u pgtables_bytes %lu -> %lu\n",
			  mm, pfn, level, pgtables_before,
			  mm_pgtables_bytes(mm));
       }

       *slot = pfn;
       nacc_dump_ptdesc_state("page_nacc_register_ptp: after ctor",
                              pfn, level, ptdesc);
       return 0;
}

int page_nacc_register_ptp(unsigned long pfn, unsigned int level)
{
	return __page_nacc_register_ptp(NULL, pfn, level);
}
EXPORT_SYMBOL(page_nacc_register_ptp);
