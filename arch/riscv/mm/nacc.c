#include <linux/mm.h>
#include <linux/errno.h>
// #include <linux/kernel.h>
#include <linux/percpu.h>
#include <asm/nacc.h>

#include <asm/sbi.h>
#include <asm/page.h>
#include <asm/pgtable.h>

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

DEFINE_PER_CPU_PAGE_ALIGNED(struct nacc_reclaim_list, nacc_reclaim_list);

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

unsigned long page_nacc_mappings(unsigned long pfn)
{
	unsigned long *slot = nacc_mapping_slot(pfn);
    unsigned long actual_pfn;

    if (!slot)
            return pfn;

    actual_pfn = *slot;
    if (!actual_pfn) {
            printk(KERN_ERR "[page_nacc_mappings]: missing mapping for pfn=%lx, fallback to self\n",
                   pfn);
            return pfn;
    }

    return actual_pfn;
}

EXPORT_SYMBOL(page_nacc_mappings);

int page_nacc_register_ptp(unsigned long pfn, unsigned int level)
{
       unsigned long *slot;
       struct ptdesc *ptdesc;

       slot = nacc_mapping_slot(pfn);
       if (!slot)
               return -EINVAL;

       if (*slot && *slot != pfn) {
               printk(KERN_ERR "[Linux]: page_nacc_register_ptp: conflicting mapping pfn=%lx slot=%lx level=%u(%s)\n",
                      pfn, *slot, level, nacc_fork_ptp_level_name(level));
               return -EINVAL;
       }

       if (*slot == pfn) {
               printk(KERN_ERR "[Linux]: page_nacc_register_ptp: pfn=%lx already registered as %s\n",
                      pfn, nacc_fork_ptp_level_name(level));
               return 0;
       }

       *slot = pfn;
       ptdesc = page_ptdesc(pfn_to_page(pfn));
       nacc_dump_ptdesc_state("page_nacc_register_ptp: before ctor",
                              pfn, level, ptdesc);

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

       nacc_dump_ptdesc_state("page_nacc_register_ptp: after ctor",
                              pfn, level, ptdesc);
       return 0;
}
EXPORT_SYMBOL(page_nacc_register_ptp);

int nacc_register_fork_ptp_list(struct nacc_fork_ptp_list *ptp_list,
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
        if (page_nacc_register_ptp(new_pfn, level)) {
            printk(KERN_ERR "[Linux]: nacc_register_fork_ptp_list: register failed for pfn=%lx level=%u packed=%lx\n",
                       new_pfn, level, packed);
            return -EINVAL;
	    }
    }
	return 0;
}
