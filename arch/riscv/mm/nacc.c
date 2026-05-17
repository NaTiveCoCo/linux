#include <linux/mm.h>
#include <linux/errno.h>
// #include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/pagewalk.h>
#include <linux/percpu.h>
#include <linux/string.h>
#include <asm/nacc.h>

#include <asm/sbi.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

extern unsigned long nacc_mappings_virt;

enum nacc_uaccess_tx_report_mode {
	NACC_UACCESS_TX_REPORT_ALL = 0,
	NACC_UACCESS_TX_REPORT_BULK = 1,
	NACC_UACCESS_TX_REPORT_CENSUS = 2,
};

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

       printk(KERN_ERR "[Linux]: %s: pfn=%lx level=%u(%s) ptdesc=%px ptl=%px flags=%lx page_type=%x refcount=%d mapcount=%d\n",
              tag, pfn, level, nacc_ptp_level_name(level), ptdesc,
              ptlock_ptr(ptdesc), ptdesc->__page_flags, ptdesc->__page_type,
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
static atomic64_t nacc_uaccess_tx_next_id = ATOMIC64_INIT(0);
#ifdef NACC_PROFILE
static int nacc_uaccess_tx_report_mode = NACC_UACCESS_TX_REPORT_BULK;
#else
static int nacc_uaccess_tx_report_mode = NACC_UACCESS_TX_REPORT_ALL;
#endif

static int __init nacc_uaccess_tx_report_setup(char *str)
{
	if (!str)
		return 0;

	if (sysfs_streq(str, "all")) {
		nacc_uaccess_tx_report_mode = NACC_UACCESS_TX_REPORT_ALL;
		return 1;
	}

	if (sysfs_streq(str, "bulk")) {
		nacc_uaccess_tx_report_mode = NACC_UACCESS_TX_REPORT_BULK;
		return 1;
	}

	if (sysfs_streq(str, "census")) {
		nacc_uaccess_tx_report_mode = NACC_UACCESS_TX_REPORT_CENSUS;
		return 1;
	}

	pr_warn("[NACC][uaccess-tx] unknown nacc.uaccess_tx_report=%s, keeping current mode\n",
		str);
	return 1;
}
__setup("nacc.uaccess_tx_report=", nacc_uaccess_tx_report_setup);

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

struct nacc_leaf_detach_stats {
	unsigned long vmas;
	unsigned long resident_ptes;
	unsigned long already_nacc_ptes;
	unsigned long non_user_ptes;
	unsigned long empty_ptes;
};

static int nacc_detach_pre_vma(unsigned long start, unsigned long end,
			       struct mm_walk *walk)
{
	struct nacc_leaf_detach_stats *stats = walk->private;

	if (walk->vma) {
		vm_flags_set(walk->vma, VM_NACC_APP);
		stats->vmas++;
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
	else
		stats->resident_ptes++;

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

	printk(KERN_ERR "[Linux]: nacc_detach_user_leaf_pages tag=%s mm=%px ret=%d range=[0,%lx) vmas=%lu resident_ptes=%lu already_nacc=%lu non_user=%lu empty=%lu\n",
	       tag, mm, ret, end, stats.vmas, stats.resident_ptes,
	       stats.already_nacc_ptes, stats.non_user_ptes,
	       stats.empty_ptes);

	return ret;
}
EXPORT_SYMBOL(nacc_detach_user_leaf_pages);

static const char *nacc_private_data_path_category_name(unsigned long category)
{
	switch (category) {
	case NACC_PD_PATH_USER_BUFFER_READ:
		return "user_buffer_read";
	case NACC_PD_PATH_USER_BUFFER_WRITE:
		return "user_buffer_write";
	case NACC_PD_PATH_FILE_PATH:
		return "file_path";
	case NACC_PD_PATH_PIPE:
		return "pipe";
	case NACC_PD_PATH_FORK_EXEC:
		return "fork_exec";
	case NACC_PD_PATH_MAPPING_UPDATE:
		return "mapping_update";
	case NACC_PD_PATH_EXIT_TEARDOWN:
		return "exit_teardown";
	case NACC_PD_PATH_SHARED_MEMORY:
		return "shared_memory";
	case NACC_PD_PATH_UNKNOWN:
	default:
		return "unknown";
	}
}

static void nacc_private_data_syscall_context_sbi(unsigned long syscall_nr,
						  unsigned long path_category,
						  bool active,
						  const char *syscall_name)
{
	unsigned long root_pgd_pa;
	struct sbiret ret;

	if (!current->mm || !current->mm->pgd)
		return;
	if (!current->thread.nacc_cid)
		return;
	if (!nacc_thread_is_inited() && !nacc_mm_is_active(current->mm))
		return;

	root_pgd_pa = virt_to_phys(current->mm->pgd);
	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_PRIVATE_DATA_CONTEXT,
			current->pid, (unsigned long)current, root_pgd_pa,
			syscall_nr, path_category, active ? 1UL : 0UL);
	if (ret.error) {
		printk_ratelimited(KERN_ERR "[Linux]: PRIVATE_DATA syscall context update failed pid=%d syscall=%lu path=%s active=%d err=%ld val=%ld\n",
				   current->pid, syscall_nr,
				   nacc_private_data_path_category_name(path_category),
				   active ? 1 : 0, ret.error, ret.value);
		return;
	}

	if (active) {
		printk(KERN_ERR "[Linux]: PRIVATE_DATA syscall context enter pid=%d comm=%s cid=%lx task=%px root=%lx syscall=%lu name=%s path=%s\n",
		       current->pid, current->comm, current->thread.nacc_cid,
		       current, root_pgd_pa, syscall_nr,
		       syscall_name ? syscall_name : "unknown",
		       nacc_private_data_path_category_name(path_category));
	}
}

void nacc_private_data_syscall_enter(unsigned long syscall_nr,
				     unsigned long path_category,
				     const char *syscall_name)
{
	nacc_private_data_syscall_context_sbi(syscall_nr, path_category, true,
					      syscall_name);
}

void nacc_private_data_syscall_exit(unsigned long syscall_nr,
				    unsigned long path_category)
{
	nacc_private_data_syscall_context_sbi(syscall_nr, path_category, false,
					      NULL);
}

static void nacc_private_data_uaccess_context_sbi(unsigned long direction,
						  unsigned long caller_pc,
						  unsigned long user_va,
						  unsigned long bytes,
						  bool active)
{
	unsigned long root_pgd_pa;
	struct sbiret ret;

	if (!current->mm || !current->mm->pgd)
		return;
	if (!current->thread.nacc_cid)
		return;
	if (!nacc_thread_is_inited() && !nacc_mm_is_active(current->mm))
		return;

	root_pgd_pa = virt_to_phys(current->mm->pgd);
	ret = sbi_ecall(SBI_EXT_NACC,
			SBI_EXT_NACC_PRIVATE_DATA_UACCESS_CONTEXT,
			current->pid, (unsigned long)current, root_pgd_pa,
			direction, caller_pc, active ? bytes : 0UL);
	if (ret.error) {
		printk_ratelimited(KERN_ERR "[Linux]: PRIVATE_DATA uaccess context update failed pid=%d direction=%lu active=%d err=%ld val=%ld\n",
				   current->pid, direction, active ? 1 : 0,
				   ret.error, ret.value);
		return;
	}

	if (active) {
		printk_ratelimited(KERN_ERR "[Linux]: PRIVATE_DATA uaccess context enter pid=%d comm=%s cid=%lx direction=%lu caller=%lx user_va=%lx bytes=%lu\n",
				   current->pid, current->comm,
				   current->thread.nacc_cid, direction,
				   caller_pc, user_va, bytes);
	}
}

void nacc_private_data_uaccess_enter(unsigned long direction,
				     unsigned long caller_pc,
				     unsigned long user_va,
				     unsigned long bytes)
{
	nacc_private_data_uaccess_context_sbi(direction, caller_pc, user_va,
					      bytes, true);
}
EXPORT_SYMBOL(nacc_private_data_uaccess_enter);

void nacc_private_data_uaccess_exit(void)
{
	nacc_private_data_uaccess_context_sbi(NACC_PD_UACCESS_UNKNOWN, 0, 0, 0,
					      false);
}
EXPORT_SYMBOL(nacc_private_data_uaccess_exit);

static const char *nacc_uaccess_tx_api_kind_name(enum nacc_uaccess_tx_api_kind api_kind)
{
	switch (api_kind) {
	case NACC_UACCESS_TX_COPY_FROM_USER:
		return "copy_from_user";
	case NACC_UACCESS_TX_COPY_TO_USER:
		return "copy_to_user";
	case NACC_UACCESS_TX_GET_USER:
		return "get_user";
	case NACC_UACCESS_TX_PUT_USER:
		return "put_user";
	case NACC_UACCESS_TX_CLEAR_USER:
		return "clear_user";
	default:
		return "unknown";
	}
}

static const char *nacc_uaccess_tx_direction_name(enum nacc_uaccess_tx_direction direction)
{
	switch (direction) {
	case NACC_UACCESS_TX_DIR_FROM_USER:
		return "from_user";
	case NACC_UACCESS_TX_DIR_TO_USER:
		return "to_user";
	case NACC_UACCESS_TX_DIR_ZERO_TO_USER:
		return "zero_to_user";
	case NACC_UACCESS_TX_DIR_UNKNOWN:
	default:
		return "unknown";
	}
}

static bool nacc_uaccess_tx_should_report(enum nacc_uaccess_tx_api_kind api_kind)
{
	if (nacc_uaccess_tx_report_mode == NACC_UACCESS_TX_REPORT_CENSUS)
		return false;

	if (nacc_uaccess_tx_report_mode != NACC_UACCESS_TX_REPORT_BULK)
		return true;

	return api_kind != NACC_UACCESS_TX_GET_USER &&
	       api_kind != NACC_UACCESS_TX_PUT_USER;
}

static bool nacc_uaccess_tx_census_enabled(void)
{
	return nacc_uaccess_tx_report_mode == NACC_UACCESS_TX_REPORT_CENSUS;
}

static void nacc_uaccess_tx_context_sbi(enum nacc_uaccess_tx_api_kind api_kind,
					enum nacc_uaccess_tx_direction direction,
					bool active)
{
	unsigned long root_pgd_pa;
	struct sbiret ret;

	if (!current->mm || !current->mm->pgd)
		return;
	if (!current->thread.nacc_cid)
		return;
	if (!nacc_thread_is_inited() && !nacc_mm_is_active(current->mm))
		return;

	root_pgd_pa = virt_to_phys(current->mm->pgd);
	ret = sbi_ecall(SBI_EXT_NACC,
			SBI_EXT_NACC_PRIVATE_DATA_TX_CONTEXT,
			current->pid, (unsigned long)current, root_pgd_pa,
			api_kind, direction, active ? 1UL : 0UL);
	if (ret.error) {
		printk_ratelimited(KERN_ERR "[Linux]: PRIVATE_DATA tx context update failed pid=%d api=%s active=%d err=%ld val=%ld\n",
				   current->pid,
				   nacc_uaccess_tx_api_kind_name(api_kind),
				   active ? 1 : 0, ret.error, ret.value);
	}
}

u64 nacc_uaccess_tx_begin(enum nacc_uaccess_tx_api_kind api_kind,
			  enum nacc_uaccess_tx_direction direction,
			  unsigned long caller_pc,
			  unsigned long user_va,
			  unsigned long bytes)
{
	u64 tx_id;

	if (!current->mm)
		return 0;
	if (!current->thread.nacc_cid)
		return 0;
	if (!nacc_thread_is_inited() && !nacc_mm_is_active(current->mm))
		return 0;

	if (nacc_uaccess_tx_census_enabled()) {
		tx_id = atomic64_inc_return(&nacc_uaccess_tx_next_id);
		nacc_uaccess_tx_context_sbi(api_kind, direction, true);
		return tx_id;
	}

	if (!nacc_uaccess_tx_should_report(api_kind))
		return 0;

	tx_id = atomic64_inc_return(&nacc_uaccess_tx_next_id);
	printk(KERN_ERR "[NACC][uaccess-tx-begin] tx_id=%llu api_kind=%s direction=%s pid=%d tgid=%d cid=%lx user_va=%lx len=%lu caller=%lx\n",
	       tx_id, nacc_uaccess_tx_api_kind_name(api_kind),
	       nacc_uaccess_tx_direction_name(direction), current->pid,
	       current->tgid, current->thread.nacc_cid, user_va, bytes,
	       caller_pc);

	return tx_id;
}
EXPORT_SYMBOL(nacc_uaccess_tx_begin);

void nacc_uaccess_tx_end(u64 tx_id,
			 enum nacc_uaccess_tx_api_kind api_kind,
			 enum nacc_uaccess_tx_direction direction,
			 unsigned long caller_pc,
			 unsigned long user_va,
			 unsigned long bytes,
			 long result)
{
	if (!tx_id)
		return;

	if (nacc_uaccess_tx_census_enabled()) {
		nacc_uaccess_tx_context_sbi(api_kind, direction, false);
		return;
	}

	printk(KERN_ERR "[NACC][uaccess-tx-end] tx_id=%llu api_kind=%s direction=%s pid=%d tgid=%d cid=%lx user_va=%lx len=%lu caller=%lx result=%ld\n",
	       tx_id, nacc_uaccess_tx_api_kind_name(api_kind),
	       nacc_uaccess_tx_direction_name(direction), current->pid,
	       current->tgid, current->thread.nacc_cid, user_va, bytes,
	       caller_pc, result);
}
EXPORT_SYMBOL(nacc_uaccess_tx_end);

void add_to_reclaim_list(unsigned long pfn)
{
    if (pfn < NACC_PTP_PFN_BASE || pfn >= NACC_PTP_PFN_END) {
        return;
    }
    
	struct nacc_reclaim_list *reclaim_list = &get_cpu_var(nacc_reclaim_list);
	reclaim_list->pfns[reclaim_list->count++] = pfn;
    printk(KERN_ERR "[Linux]: add pfn: %lx to reclaim list, count: %lx\n", reclaim_list->pfns[reclaim_list->count - 1], reclaim_list->count);
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
        for (int i = 0; i < reclaim_list->count; i++)
            printk(KERN_ERR "[Linux]: calling flush_reclaim_list with pfn: %lx\n", reclaim_list->pfns[i]);
        sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_RECLAIM_PTP,
				  __pa(reclaim_list->pfns), reclaim_list->count,
				  0, 0, 0, 0);
		reclaim_list->count = 0;
	}
	put_cpu_var(reclaim_list);
}

void pgtbl_debug(unsigned long pgd)
{
    struct sbiret ret;

    printk(KERN_ERR "[Linux]: calling pgtbl_debug SBI call pgd=%lx\n", pgd);
    ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_LINUX_DEBUG,
                    pgd, 0,
                    0, 0, 0, 0);
    printk(KERN_ERR "[Linux]: pgtbl_debug SBI returned error=%ld value=%ld\n",
           ret.error, ret.value);
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
	printk(KERN_ERR "[Linux]: %s: reclaimed pfn=%lx level=%u old_ptl=%lx new_ptl=%lx old_slot=%lx new_slot=%lx\n",
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
                       printk(KERN_ERR "[Linux]: page_nacc_register_ptp: pfn=%lx already registered as %s ptdesc=%px ptl=%lx\n",
                              pfn, nacc_ptp_level_name(level),
                              ptdesc, nacc_ptdesc_raw_ptl(ptdesc));
                       return 0;
               }

               printk(KERN_ERR "[Linux]: page_nacc_register_ptp: recovering stale slot for pfn=%lx level=%u(%s)\n",
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
	       printk(KERN_ERR "[Linux]: page_nacc_register_ptp: mm=%px pfn=%lx level=%u pgtables_bytes %lu -> %lu\n",
		      mm, pfn, level, pgtables_before, mm_pgtables_bytes(mm));
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
