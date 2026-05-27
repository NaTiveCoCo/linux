#include <linux/mm.h>
#include <linux/errno.h>
// #include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/panic.h>
#include <linux/pagemap.h>
#include <linux/pagewalk.h>
#include <linux/percpu.h>
#include <linux/string.h>
#include <asm/nacc.h>

#include <asm/sbi.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/csr.h>
#include <asm/tlbflush.h>

extern unsigned long nacc_mappings_virt;

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

bool nacc_copy_mc_user_highpage_sbi(struct page *to, struct page *from,
				    unsigned long vaddr,
				    struct vm_area_struct *vma)
{
	struct sbiret ret;
	unsigned long from_pfn;
	unsigned long to_pfn;
	unsigned long root_pgd_pa;

	if (!vma || !vma->vm_mm || !nacc_mm_is_active(vma->vm_mm))
		return false;

	from_pfn = page_to_pfn(from);
	to_pfn = page_to_pfn(to);
	root_pgd_pa = __pa(vma->vm_mm->pgd);

	printk(KERN_ERR "[NACC][copy-user-highpage] linux enter mm=%px pid=%d vaddr=%lx root=%lx from_pfn=%lx to_pfn=%lx\n",
	       vma->vm_mm, current->pid, vaddr, root_pgd_pa, from_pfn, to_pfn);

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_COPY_USER_HIGHPAGE,
			from_pfn, to_pfn, vaddr, root_pgd_pa,
			current->pid, 0);
	if (ret.error) {
		printk(KERN_ERR "[NACC][copy-user-highpage] linux ecall failed vaddr=%lx from_pfn=%lx to_pfn=%lx err=%ld val=%ld\n",
		       vaddr, from_pfn, to_pfn, ret.error, ret.value);
		panic("NaCC copy_user_highpage ecall failed");
	}

	printk(KERN_ERR "[NACC][copy-user-highpage] linux result vaddr=%lx from_pfn=%lx to_pfn=%lx result=%s(%ld)\n",
	       vaddr, from_pfn, to_pfn,
	       nacc_copy_user_highpage_result_name(ret.value), ret.value);

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
	else if (nacc_pte_is_linux_special_leaf(oldpte))
		stats->special_ptes++;
	else {
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

	printk(KERN_ERR "[Linux]: nacc_detach_user_leaf_pages tag=%s mm=%px ret=%d range=[0,%lx) vmas=%lu private_hint_vmas=%lu tagged_resident_ptes=%lu resident_skipped=%lu already_nacc=%lu special=%lu non_user=%lu empty=%lu\n",
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

		page_left = PAGE_SIZE - (dst & (PAGE_SIZE - 1));
		if (chunk > page_left)
			chunk = page_left;
		page_left = PAGE_SIZE - (src & (PAGE_SIZE - 1));
		if (chunk > page_left)
			chunk = page_left;

		ret = sbi_ecall(SBI_EXT_NACC,
				SBI_EXT_NACC_UACCESS_PRIVATE_COPY_TO_USER,
				dst, src, chunk, caller_pc, current->pid, 0);
		if (ret.error == SBI_ERR_NOT_SUPPORTED) {
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
