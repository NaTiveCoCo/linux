#include <linux/mm.h>
#include <linux/errno.h>
// #include <linux/kernel.h>
#include <linux/percpu.h>
#include <asm/nacc.h>

#include <asm/sbi.h>
#include <asm/page.h>
#include <asm/pgtable.h>

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
	unsigned long actual_pfn = 0;
	if(pfn >= NACC_PTP_PFN_BASE && pfn < NACC_PTP_PFN_END) {
		actual_pfn = *((unsigned long *)(nacc_mappings_virt + ((pfn - NACC_PTP_PFN_BASE) << 4)));
        if(!actual_pfn) {
            printk(KERN_ERR "[page_nacc_mappings]: newly allocated and will be registered. \n");
            actual_pfn = pfn;
            /* Set it to mark it as newly allocated if actual_pfn is equal to pfn. */
            *((unsigned long *)(nacc_mappings_virt + ((pfn - NACC_PTP_PFN_BASE) << 4))) = pfn;
            pagetable_pte_ctor(page_ptdesc(pfn_to_page(pfn)));
        }
        printk(KERN_ERR "[page_nacc_mappings]: already allocated and registered. \n");
	} else {
		actual_pfn = pfn;
	}
	return actual_pfn;
}

EXPORT_SYMBOL(page_nacc_mappings);

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

		slot = (unsigned long *)(nacc_mappings_virt +
					 ((new_pfn - NACC_PTP_PFN_BASE) << 4));
		*slot = new_pfn;

		ptdesc = page_ptdesc(pfn_to_page(new_pfn));
		if (level == 1) {
			if (!pagetable_pmd_ctor(ptdesc))
				return -ENOMEM;
		} else if (level == 0) {
			if (!pagetable_pte_ctor(ptdesc))
				return -ENOMEM;
		} else {
			return -EINVAL;
		}
	}

	return 0;
}
