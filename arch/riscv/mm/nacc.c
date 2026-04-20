#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/percpu.h>
#include <linux/fs.h>
#include <linux/shmem_fs.h>
#include <linux/string.h>
#include <asm/nacc.h>

#include <asm/sbi.h>
#include <asm/page.h>
#include <asm/pgtable.h>

extern unsigned long nacc_mappings_virt;

#define NACC_REGION_PROVENANCE_LOG_LIMIT 16

enum nacc_manifest_mode {
	NACC_MANIFEST_MODE_OFF = 0,
	NACC_MANIFEST_MODE_AUDIT = 1,
	NACC_MANIFEST_MODE_ENFORCE = 2,
};

static enum nacc_manifest_mode nacc_manifest_mode = NACC_MANIFEST_MODE_OFF;

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

static const char *nacc_manifest_mode_name(enum nacc_manifest_mode mode)
{
	switch (mode) {
	case NACC_MANIFEST_MODE_OFF:
		return "off";
	case NACC_MANIFEST_MODE_AUDIT:
		return "audit";
	case NACC_MANIFEST_MODE_ENFORCE:
		return "enforce";
	default:
		return "invalid";
	}
}

static int __init nacc_manifest_mode_setup(char *str)
{
	if (!str)
		return 0;

	if (!strcmp(str, "off"))
		nacc_manifest_mode = NACC_MANIFEST_MODE_OFF;
	else if (!strcmp(str, "audit"))
		nacc_manifest_mode = NACC_MANIFEST_MODE_AUDIT;
	else if (!strcmp(str, "enforce"))
		nacc_manifest_mode = NACC_MANIFEST_MODE_ENFORCE;
	else {
		printk(KERN_ERR "[Linux]: invalid nacc.manifest_mode=%s, defaulting to off\n",
		       str);
		nacc_manifest_mode = NACC_MANIFEST_MODE_OFF;
		return 1;
	}

	printk(KERN_ERR "[Linux]: nacc.manifest_mode=%s (PR0 scaffold only; startup sealing unchanged)\n",
	       nacc_manifest_mode_name(nacc_manifest_mode));
	return 1;
}
__setup("nacc.manifest_mode=", nacc_manifest_mode_setup);

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

static const char *nacc_region_sync_reason_name(enum nacc_region_sync_reason reason)
{
	switch (reason) {
	case NACC_REGION_SYNC_REASON_INVOKE:
		return "invoke";
	case NACC_REGION_SYNC_REASON_EXEC:
		return "exec";
	case NACC_REGION_SYNC_REASON_MMAP:
		return "mmap";
	case NACC_REGION_SYNC_REASON_BRK:
		return "brk";
	case NACC_REGION_SYNC_REASON_MPROTECT:
		return "mprotect";
	case NACC_REGION_SYNC_REASON_MREMAP:
		return "mremap";
	case NACC_REGION_SYNC_REASON_MUNMAP:
		return "munmap";
	case NACC_REGION_SYNC_REASON_FORK:
		return "fork";
	case NACC_REGION_SYNC_REASON_EXIT_MMAP:
		return "exit_mmap";
	default:
		return "invalid";
	}
}

static bool nacc_region_sync_is_startup_reason(enum nacc_region_sync_reason reason)
{
	switch (reason) {
	case NACC_REGION_SYNC_REASON_INVOKE:
	case NACC_REGION_SYNC_REASON_EXEC:
	case NACC_REGION_SYNC_REASON_FORK:
		return true;
	default:
		return false;
	}
}

static void nacc_manifest_log_startup_scaffold(struct mm_struct *mm,
					       unsigned long root_pgd_pa,
					       unsigned long cid,
					       enum nacc_region_sync_reason reason,
					       bool clear_only,
					       unsigned long emitted)
{
	if (!nacc_region_sync_is_startup_reason(reason))
		return;

	printk(KERN_ERR "[Linux]: manifest scaffold mode=%s mm=%px root=%lx cid=%lx reason=%s clear_only=%d ranges=%lu note=PR0 logging only, no startup policy change\n",
	       nacc_manifest_mode_name(nacc_manifest_mode), mm, root_pgd_pa, cid,
	       nacc_region_sync_reason_name(reason), clear_only, emitted);
}

static const char *nacc_region_class_name(enum nacc_region_class class_id)
{
	switch (class_id) {
	case NACC_REGION_CLASS_PRIVATE_STRICT_ANON:
		return "PRIVATE_STRICT_ANON";
	case NACC_REGION_CLASS_PRIVATE_FILE_COW:
		return "PRIVATE_FILE_COW";
	case NACC_REGION_CLASS_SHARED_EXPLICIT:
		return "SHARED_EXPLICIT";
	case NACC_REGION_CLASS_SPECIAL_EXCLUDED:
		return "SPECIAL_EXCLUDED";
	default:
		return "INVALID";
	}
}

static int nacc_region_sync_begin_sbi(unsigned long root_pgd_pa,
				      unsigned long cid,
				      enum nacc_region_sync_reason reason)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_REGION_SYNC_BEGIN,
			root_pgd_pa, cid, reason, 0, 0, 0);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: region sync begin failed: root=%lx cid=%lx reason=%s err=%ld val=%ld\n",
		       root_pgd_pa, cid, nacc_region_sync_reason_name(reason),
		       ret.error, ret.value);
		return -EIO;
	}

	return 0;
}

static int nacc_region_sync_range_sbi(unsigned long root_pgd_pa,
				      unsigned long start, unsigned long end,
				      enum nacc_region_class class_id,
				      unsigned long flags)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_REGION_SYNC_RANGE,
			root_pgd_pa, start, end, class_id, flags, 0);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: region sync range failed: root=%lx range=[%lx,%lx) class=%s flags=%lx err=%ld val=%ld\n",
		       root_pgd_pa, start, end,
		       nacc_region_class_name(class_id), flags,
		       ret.error, ret.value);
		return -EIO;
	}

	return 0;
}

static int nacc_region_sync_end_sbi(unsigned long root_pgd_pa)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_REGION_SYNC_END,
			root_pgd_pa, 0, 0, 0, 0, 0);
	if (ret.error) {
		printk(KERN_ERR "[Linux]: region sync end failed: root=%lx err=%ld val=%ld\n",
		       root_pgd_pa, ret.error, ret.value);
		return -EIO;
	}

	return 0;
}

bool nacc_mm_needs_region_sync(struct mm_struct *mm)
{
	return mm && mm->pgd && nacc_mm_root_tagged(mm);
}
EXPORT_SYMBOL(nacc_mm_needs_region_sync);

static enum nacc_region_class nacc_classify_vma(struct vm_area_struct *vma,
						unsigned long *flags_out)
{
	unsigned long flags = 0;
	bool shmem = false;

	/*
	 * Phase-1 default-private uses VMA class only as attribution.
	 * OpenSBI still forces PRIVATE_DATA on every ordinary user leaf.
	 */

	if (vma->vm_flags & VM_NACC)
		flags |= NACC_REGION_FLAG_VM_NACC;
	if (vma->vm_flags & VM_IO)
		flags |= NACC_REGION_FLAG_VM_IO;
	if (vma->vm_flags & VM_PFNMAP)
		flags |= NACC_REGION_FLAG_VM_PFNMAP;
	if (vma->vm_flags & VM_MIXEDMAP)
		flags |= NACC_REGION_FLAG_VM_MIXEDMAP;
	if (vma->vm_flags & VM_SHARED)
		flags |= NACC_REGION_FLAG_SHARED;
	if (vma_is_anonymous(vma))
		flags |= NACC_REGION_FLAG_ANON;
	if (vma->vm_file) {
		flags |= NACC_REGION_FLAG_FILE;
		shmem = shmem_mapping(vma->vm_file->f_mapping);
		if (shmem)
			flags |= NACC_REGION_FLAG_SHMEM;
	}

	if (vma->vm_flags & (VM_NACC | VM_IO | VM_PFNMAP | VM_MIXEDMAP))
		goto excluded;
	if (vma->vm_flags & VM_SHARED)
		goto shared;
	if (vma_is_anonymous(vma))
		goto strict_anon;
	if ((vma->vm_file || shmem) && is_cow_mapping(vma->vm_flags))
		goto private_file_cow;

	flags |= NACC_REGION_FLAG_AMBIGUOUS;
	goto excluded;

strict_anon:
	if (flags_out)
		*flags_out = flags;
	return NACC_REGION_CLASS_PRIVATE_STRICT_ANON;

private_file_cow:
	if (flags_out)
		*flags_out = flags;
	return NACC_REGION_CLASS_PRIVATE_FILE_COW;

shared:
	if (flags_out)
		*flags_out = flags;
	return NACC_REGION_CLASS_SHARED_EXPLICIT;

excluded:
	if (flags_out)
		*flags_out = flags;
	return NACC_REGION_CLASS_SPECIAL_EXCLUDED;
}

static const char *nacc_region_provenance_name(struct vm_area_struct *vma,
					       char *buf, size_t buf_len)
{
	char *path;

	if (!vma->vm_file) {
		if (vma_is_anonymous(vma))
			return "[anon]";
		return "[no-file]";
	}

	path = file_path(vma->vm_file, buf, buf_len);
	if (!IS_ERR(path))
		return path;

	return vma->vm_file->f_path.dentry->d_name.name;
}

static int nacc_region_sync_mm_emit_locked(struct mm_struct *mm,
					   enum nacc_region_sync_reason reason,
					   bool clear_only)
{
	VMA_ITERATOR(vmi, mm, 0);
	struct vm_area_struct *vma;
	unsigned long cid = current->thread.nacc_cid;
	unsigned long root_pgd_pa;
	unsigned long prev_flags = 0;
	unsigned long prev_start = 0;
	unsigned long prev_end = 0;
	unsigned long emitted = 0;
	unsigned int provenance_logs = 0;
	bool provenance_truncated = false;
	enum nacc_region_class prev_class = NACC_REGION_CLASS_INVALID;
	bool have_prev = false;
	int ret;

	if (!nacc_mm_needs_region_sync(mm))
		return 0;
	if (!cid) {
		printk(KERN_ERR "[Linux]: skip region sync without cid: mm=%px reason=%s state=%lx\n",
		       mm, nacc_region_sync_reason_name(reason),
		       nacc_mm_state(mm));
		return -EINVAL;
	}

	root_pgd_pa = virt_to_phys(mm->pgd);
	ret = nacc_region_sync_begin_sbi(root_pgd_pa, cid, reason);
	if (ret)
		return ret;

	if (!clear_only) {
		for_each_vma(vmi, vma) {
			enum nacc_region_class class_id;
			unsigned long flags;

			class_id = nacc_classify_vma(vma, &flags);
			if (!clear_only && vma->vm_file) {
				char path_buf[256];
				const char *source;

				if (provenance_logs < NACC_REGION_PROVENANCE_LOG_LIMIT) {
					source = nacc_region_provenance_name(
						vma, path_buf, sizeof(path_buf));
					printk(KERN_ERR "[Linux]: region provenance mm=%px root=%lx range=[%lx,%lx) pgoff=%lx class=%s flags=%lx reason=%s source=%s\n",
					       mm, root_pgd_pa,
					       vma->vm_start, vma->vm_end,
					       ((unsigned long)vma->vm_pgoff)
						       << PAGE_SHIFT,
					       nacc_region_class_name(class_id),
					       flags,
					       nacc_region_sync_reason_name(reason),
					       source);
					provenance_logs++;
				} else if (!provenance_truncated) {
					printk(KERN_ERR "[Linux]: region provenance mm=%px root=%lx reason=%s truncated_after=%u\n",
					       mm, root_pgd_pa,
					       nacc_region_sync_reason_name(reason),
					       NACC_REGION_PROVENANCE_LOG_LIMIT);
					provenance_truncated = true;
				}
			}
			if (have_prev && prev_end == vma->vm_start &&
			    prev_class == class_id && prev_flags == flags) {
				prev_end = vma->vm_end;
				continue;
			}

			if (have_prev) {
				ret = nacc_region_sync_range_sbi(root_pgd_pa,
								 prev_start,
								 prev_end,
								 prev_class,
								 prev_flags);
				if (ret)
					return ret;
				emitted++;
			}

			if (flags & NACC_REGION_FLAG_AMBIGUOUS) {
				printk(KERN_ERR "[Linux]: region sync ambiguous VMA mm=%px root=%lx range=[%lx,%lx) vm_flags=%lx class=%s flags=%lx reason=%s\n",
				       mm, root_pgd_pa, vma->vm_start, vma->vm_end,
				       vma->vm_flags, nacc_region_class_name(class_id),
				       flags, nacc_region_sync_reason_name(reason));
			}

			prev_start = vma->vm_start;
			prev_end = vma->vm_end;
			prev_class = class_id;
			prev_flags = flags;
			have_prev = true;
		}

		if (have_prev) {
			ret = nacc_region_sync_range_sbi(root_pgd_pa, prev_start,
							 prev_end, prev_class,
							 prev_flags);
			if (ret)
				return ret;
			emitted++;
		}
	}

	ret = nacc_region_sync_end_sbi(root_pgd_pa);
	if (ret)
		return ret;

	printk(KERN_ERR "[Linux]: region sync mm=%px root=%lx cid=%lx reason=%s clear_only=%d ranges=%lu\n",
	       mm, root_pgd_pa, cid, nacc_region_sync_reason_name(reason),
	       clear_only, emitted);
	nacc_manifest_log_startup_scaffold(mm, root_pgd_pa, cid, reason,
					    clear_only, emitted);
	return 0;
}

int nacc_region_sync_mm_locked(struct mm_struct *mm,
			       enum nacc_region_sync_reason reason)
{
	return nacc_region_sync_mm_emit_locked(mm, reason, false);
}
EXPORT_SYMBOL(nacc_region_sync_mm_locked);

int nacc_region_clear_mm_locked(struct mm_struct *mm,
				enum nacc_region_sync_reason reason)
{
	return nacc_region_sync_mm_emit_locked(mm, reason, true);
}
EXPORT_SYMBOL(nacc_region_clear_mm_locked);

int nacc_region_sync_mm(struct mm_struct *mm,
			enum nacc_region_sync_reason reason)
{
	int ret;

	if (!nacc_mm_needs_region_sync(mm))
		return 0;

	mmap_read_lock(mm);
	ret = nacc_region_sync_mm_locked(mm, reason);
	mmap_read_unlock(mm);

	return ret;
}
EXPORT_SYMBOL(nacc_region_sync_mm);

int nacc_region_clear_mm(struct mm_struct *mm,
			 enum nacc_region_sync_reason reason)
{
	int ret;

	if (!nacc_mm_needs_region_sync(mm))
		return 0;

	mmap_read_lock(mm);
	ret = nacc_region_clear_mm_locked(mm, reason);
	mmap_read_unlock(mm);

	return ret;
}
EXPORT_SYMBOL(nacc_region_clear_mm);

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
    printk(KERN_ERR "[Linux]: calling pgtbl_debug SBI call\n");
    sbi_ecall(SBI_EXT_NACC, SBI_EXT_LINUX_DEBUG,
              pgd, 0,
              0, 0, 0, 0);
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
