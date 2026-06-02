/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_GENERIC_PGALLOC_H
#define __ASM_GENERIC_PGALLOC_H

#ifdef CONFIG_MMU

#define GFP_PGTABLE_KERNEL	(GFP_KERNEL | __GFP_ZERO)
#define GFP_PGTABLE_USER	(GFP_PGTABLE_KERNEL | __GFP_ACCOUNT)

#ifdef NACC
#include <asm/nacc.h>
#include <asm/sbi.h>

static inline bool nacc_free_secure_ptdesc(struct ptdesc *ptdesc,
					       unsigned int level,
					       const char *tag)
{
	unsigned long pfn = page_to_pfn(ptdesc_page(ptdesc));

	if (!nacc_pfn_is_secure_ptp(pfn))
		return false;

	nacc_track_secure_ptp_pfn(pfn);
	nacc_reclaim_ptp_dtor(ptdesc, pfn, level, tag);
	return true;
}
#endif /* NACC */

/**
 * __pte_alloc_one_kernel - allocate memory for a PTE-level kernel page table
 * @mm: the mm_struct of the current context
 *
 * This function is intended for architectures that need
 * anything beyond simple page allocation.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
static inline pte_t *__pte_alloc_one_kernel_noprof(struct mm_struct *mm)
{
	struct ptdesc *ptdesc = pagetable_alloc_noprof(GFP_PGTABLE_KERNEL &
			~__GFP_HIGHMEM, 0);

	if (!ptdesc)
		return NULL;
	return ptdesc_address(ptdesc);
}
#define __pte_alloc_one_kernel(...)	alloc_hooks(__pte_alloc_one_kernel_noprof(__VA_ARGS__))

#ifndef __HAVE_ARCH_PTE_ALLOC_ONE_KERNEL
/**
 * pte_alloc_one_kernel - allocate memory for a PTE-level kernel page table
 * @mm: the mm_struct of the current context
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
static inline pte_t *pte_alloc_one_kernel_noprof(struct mm_struct *mm)
{
	return __pte_alloc_one_kernel_noprof(mm);
}
#define pte_alloc_one_kernel(...)	alloc_hooks(pte_alloc_one_kernel_noprof(__VA_ARGS__))
#endif

/**
 * pte_free_kernel - free PTE-level kernel page table memory
 * @mm: the mm_struct of the current context
 * @pte: pointer to the memory containing the page table
 */
static inline void pte_free_kernel(struct mm_struct *mm, pte_t *pte)
{
	pagetable_free(virt_to_ptdesc(pte));
}

/**
 * __pte_alloc_one - allocate memory for a PTE-level user page table
 * @mm: the mm_struct of the current context
 * @gfp: GFP flags to use for the allocation
 *
 * Allocate memory for a page table and ptdesc and runs pagetable_pte_ctor().
 *
 * This function is intended for architectures that need
 * anything beyond simple page allocation or must have custom GFP flags.
 *
 * Return: `struct page` referencing the ptdesc or %NULL on error
 */
static inline pgtable_t __pte_alloc_one_noprof(struct mm_struct *mm, gfp_t gfp)
{
	struct ptdesc *ptdesc;
	unsigned long new_pte_pfn = 0;

#ifdef NACC
	if (mm && nacc_use_secure_pt(mm)) {
		unsigned long *new_pte_pfn_buf =
			kmalloc(sizeof(unsigned long), GFP_KERNEL);

		if (!new_pte_pfn_buf)
			return NULL;

		nacc_debug("[__pte_alloc] request pmd for address space, position: %lx\n",
			   (unsigned long)virt_to_phys(new_pte_pfn_buf));
		sbi_ecall(SBI_EXT_NACC, SBI_EXT_LINUX_REQ_PTP,
			  virt_to_phys(new_pte_pfn_buf), 0, 0, 0, 0, 0);
		new_pte_pfn = (*new_pte_pfn_buf) >> 12;
		kfree(new_pte_pfn_buf);
		nacc_debug("[__pte_alloc] new_pmd_pfn = %lx\n", new_pte_pfn);
		if (page_nacc_register_ptp(new_pte_pfn, 0))
			return NULL;
		ptdesc = page_ptdesc(pfn_to_page(new_pte_pfn));
		return ptdesc_page(ptdesc);
	}
#endif

	ptdesc = pagetable_alloc_noprof(gfp, 0);
	if (!ptdesc)
		return NULL;
	if (!pagetable_pte_ctor(ptdesc)) {
		pagetable_free(ptdesc);
		return NULL;
	}

	return ptdesc_page(ptdesc);
}
#define __pte_alloc_one(...)	alloc_hooks(__pte_alloc_one_noprof(__VA_ARGS__))

#ifndef __HAVE_ARCH_PTE_ALLOC_ONE
/**
 * pte_alloc_one - allocate a page for PTE-level user page table
 * @mm: the mm_struct of the current context
 *
 * Allocate memory for a page table and ptdesc and runs pagetable_pte_ctor().
 *
 * Return: `struct page` referencing the ptdesc or %NULL on error
 */
static inline pgtable_t pte_alloc_one_noprof(struct mm_struct *mm)
{
	return __pte_alloc_one_noprof(mm, GFP_PGTABLE_USER);
}
#define pte_alloc_one(...)	alloc_hooks(pte_alloc_one_noprof(__VA_ARGS__))
#endif

/*
 * Should really implement gc for free page table pages. This could be
 * done with a reference count in struct page.
 */

/**
 * pte_free - free PTE-level user page table memory
 * @mm: the mm_struct of the current context
 * @pte_page: the `struct page` referencing the ptdesc
 */
static inline void pte_free(struct mm_struct *mm, struct page *pte_page)
{
	struct ptdesc *ptdesc = page_ptdesc(pte_page);

#ifdef NACC
	if (nacc_free_secure_ptdesc(ptdesc, 0, "pte_free"))
		return;
#endif
	pagetable_pte_dtor(ptdesc);
	pagetable_free(ptdesc);
}


#if CONFIG_PGTABLE_LEVELS > 2

#ifndef __HAVE_ARCH_PMD_ALLOC_ONE
/**
 * pmd_alloc_one - allocate memory for a PMD-level page table
 * @mm: the mm_struct of the current context
 *
 * Allocate memory for a page table and ptdesc and runs pagetable_pmd_ctor().
 *
 * Allocations use %GFP_PGTABLE_USER in user context and
 * %GFP_PGTABLE_KERNEL in kernel context.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
static inline pmd_t *pmd_alloc_one_noprof(struct mm_struct *mm, unsigned long addr)
{
	struct ptdesc *ptdesc;
	gfp_t gfp = GFP_PGTABLE_USER;
	unsigned long new_pmd_pfn = 0;

	if (mm == &init_mm)
		gfp = GFP_PGTABLE_KERNEL;

#ifdef NACC
	if (mm && nacc_use_secure_pt(mm)) {
		if (addr < 0x4000000000) {
			unsigned long *new_pte_pfn_buf =
				kmalloc(sizeof(unsigned long), GFP_KERNEL);

			if (!new_pte_pfn_buf)
				return NULL;

			nacc_debug("[__pmd_alloc] request pmd for address space, position: %lx\n",
				   (unsigned long)virt_to_phys(new_pte_pfn_buf));
			sbi_ecall(SBI_EXT_NACC, SBI_EXT_LINUX_REQ_PTP,
				  virt_to_phys(new_pte_pfn_buf), 0, 0, 0, 0, 0);
			new_pmd_pfn = (*new_pte_pfn_buf) >> 12;
			kfree(new_pte_pfn_buf);
			nacc_debug("[__pmd_alloc] new_pmd_pfn = %lx\n",
				   new_pmd_pfn);
			if (page_nacc_register_ptp(new_pmd_pfn, 1))
				return NULL;
			ptdesc = page_ptdesc(pfn_to_page(new_pmd_pfn));
			return ptdesc_address(ptdesc);
		}
	}
#endif

	ptdesc = pagetable_alloc_noprof(gfp, 0);
	if (!ptdesc)
		return NULL;

	if (!pagetable_pmd_ctor(ptdesc)) {
		pagetable_free(ptdesc);
		return NULL;
	}
	return ptdesc_address(ptdesc);
}
#define pmd_alloc_one(...)	alloc_hooks(pmd_alloc_one_noprof(__VA_ARGS__))
#endif

#ifndef __HAVE_ARCH_PMD_FREE
static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
{
	struct ptdesc *ptdesc = virt_to_ptdesc(pmd);

	BUG_ON((unsigned long)pmd & (PAGE_SIZE-1));
#ifdef NACC
	if (nacc_free_secure_ptdesc(ptdesc, 1, "pmd_free"))
		return;
#endif
	pagetable_pmd_dtor(ptdesc);
	pagetable_free(ptdesc);
}
#endif

#endif /* CONFIG_PGTABLE_LEVELS > 2 */

#if CONFIG_PGTABLE_LEVELS > 3

static inline pud_t *__pud_alloc_one_noprof(struct mm_struct *mm, unsigned long addr)
{
	gfp_t gfp = GFP_PGTABLE_USER;
	struct ptdesc *ptdesc;

	if (mm == &init_mm)
		gfp = GFP_PGTABLE_KERNEL;
	gfp &= ~__GFP_HIGHMEM;

	ptdesc = pagetable_alloc_noprof(gfp, 0);
	if (!ptdesc)
		return NULL;

	pagetable_pud_ctor(ptdesc);
	return ptdesc_address(ptdesc);
}
#define __pud_alloc_one(...)	alloc_hooks(__pud_alloc_one_noprof(__VA_ARGS__))

#ifndef __HAVE_ARCH_PUD_ALLOC_ONE
/**
 * pud_alloc_one - allocate memory for a PUD-level page table
 * @mm: the mm_struct of the current context
 *
 * Allocate memory for a page table using %GFP_PGTABLE_USER for user context
 * and %GFP_PGTABLE_KERNEL for kernel context.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
static inline pud_t *pud_alloc_one_noprof(struct mm_struct *mm, unsigned long addr)
{
	return __pud_alloc_one_noprof(mm, addr);
}
#define pud_alloc_one(...)	alloc_hooks(pud_alloc_one_noprof(__VA_ARGS__))
#endif

static inline void __pud_free(struct mm_struct *mm, pud_t *pud)
{
	struct ptdesc *ptdesc = virt_to_ptdesc(pud);

	BUG_ON((unsigned long)pud & (PAGE_SIZE-1));
	pagetable_pud_dtor(ptdesc);
	pagetable_free(ptdesc);
}

#ifndef __HAVE_ARCH_PUD_FREE
static inline void pud_free(struct mm_struct *mm, pud_t *pud)
{
	__pud_free(mm, pud);
}
#endif

#endif /* CONFIG_PGTABLE_LEVELS > 3 */

#ifndef __HAVE_ARCH_PGD_FREE
static inline void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	pagetable_free(virt_to_ptdesc(pgd));
}
#endif

#endif /* CONFIG_MMU */

#endif /* __ASM_GENERIC_PGALLOC_H */
