#include <linux/mm.h>
#include <linux/errno.h>
// #include <linux/kernel.h>
#include <linux/percpu.h>
#include <asm/nacc.h>

#include <asm/sbi.h>
#include <asm/page.h>
#include <asm/pgtable.h>

extern unsigned long nacc_mappings_virt;

static const char *nacc_fork_ptp_level_name(unsigned int level)
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
              tag, pfn, level, nacc_fork_ptp_level_name(level), ptdesc,
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
                      pfn, *slot, level, nacc_fork_ptp_level_name(level));
               return -EINVAL;
       }

       if (*slot == pfn) {
               ptdesc = page_ptdesc(pfn_to_page(pfn));
               if (nacc_ptdesc_raw_ptl(ptdesc)) {
                       printk(KERN_ERR "[Linux]: page_nacc_register_ptp: pfn=%lx already registered as %s ptdesc=%px ptl=%lx\n",
                              pfn, nacc_fork_ptp_level_name(level),
                              ptdesc, nacc_ptdesc_raw_ptl(ptdesc));
                       return 0;
               }

               printk(KERN_ERR "[Linux]: page_nacc_register_ptp: recovering stale slot for pfn=%lx level=%u(%s)\n",
                      pfn, level, nacc_fork_ptp_level_name(level));
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

int nacc_register_fork_ptp_list(struct mm_struct *mm,
				struct nacc_fork_ptp_list *ptp_list,
				unsigned long ptp_list_bytes)
{
	unsigned long capacity;
	unsigned long nr_entries;
	unsigned long i;

	if (!ptp_list || ptp_list_bytes < sizeof(*ptp_list))
		return -EINVAL;

	capacity = (ptp_list_bytes - sizeof(*ptp_list)) /
		   sizeof(ptp_list->entries[0]);
	if (ptp_list->nr_entries > capacity)
		return -EOVERFLOW;

	nr_entries = ptp_list->nr_entries;
	if (mm) {
		printk(KERN_ERR "[Linux]: nacc_register_fork_ptp_list: mm=%px nr_entries=%lu pgtables_bytes(before)=%lu\n",
		       mm, nr_entries, mm_pgtables_bytes(mm));
	}
	for (i = 0; i < nr_entries; i++) {
		unsigned long packed = ptp_list->entries[i];
		unsigned long new_pfn = NACC_FORK_PTP_DECODE_PFN(packed);
		unsigned int level = NACC_FORK_PTP_DECODE_LEVEL(packed);
		struct ptdesc *ptdesc;
		unsigned long *slot;

		if (new_pfn < NACC_PTP_PFN_BASE || new_pfn >= NACC_PTP_PFN_END)
			return -EINVAL;

        slot = nacc_mapping_slot(new_pfn);
        if (!slot)
            return -EINVAL;
		ptdesc = page_ptdesc(pfn_to_page(new_pfn));
        nacc_dump_ptdesc_state("nacc_register_fork_ptp_list: entry",
                                new_pfn, level, ptdesc);
	        if (__page_nacc_register_ptp(mm, new_pfn, level)) {
            printk(KERN_ERR "[Linux]: nacc_register_fork_ptp_list: register failed for pfn=%lx level=%u packed=%lx\n",
                       new_pfn, level, packed);
            return -EINVAL;
	    }
    }
	if (mm) {
		printk(KERN_ERR "[Linux]: nacc_register_fork_ptp_list: mm=%px pgtables_bytes(after)=%lu\n",
		       mm, mm_pgtables_bytes(mm));
	}
	return 0;
}
