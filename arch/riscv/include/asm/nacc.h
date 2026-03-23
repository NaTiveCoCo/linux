#ifndef _ASM_RISCV_NACC_H
#define _ASM_RISCV_NACC_H

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/sched.h>
#define NACC_RECLAIM_LIST_SIZE 511

struct mm_struct;
struct ptdesc;

struct nacc_reclaim_list {
	unsigned long pfns[NACC_RECLAIM_LIST_SIZE];
	unsigned long count;
};

/* another macro for nacc_flag in nacc->thread field */
#define NACC_PREPARE     0b001
#define NACC_INITED      0b010

#define NACC_MM_ACTIVE	0x1UL

/* 
 * The agent has already been initialized, and the new child process is forked.
 * This flag is set in the child process.
 */
#define NACC_FORKED      0b1000

/*
 * Exec rebuild state for an already NaCC-protected task.
 * Covers both same-PID re-exec and fork+exec before final re-attach.
 */
#define NACC_EXEC        0b10000

#define NACC_PTP_PFN_BASE  0x1b0000
#define NACC_PTP_PFN_END   0x1c0000

#define NACC_FORK_PTP_LEVEL_MASK	0x3UL
#define NACC_FORK_PTP_ENCODE(new_pfn, level) \
	((((unsigned long)(new_pfn)) << 2) | \
	 ((unsigned long)(level) & NACC_FORK_PTP_LEVEL_MASK))
#define NACC_FORK_PTP_DECODE_PFN(entry)	((unsigned long)(entry) >> 2)
#define NACC_FORK_PTP_DECODE_LEVEL(entry) \
	((unsigned int)((entry) & NACC_FORK_PTP_LEVEL_MASK))

/*
 * NaCC fork PTP list:
 * OpenSBI fills child-owned non-leaf page-table pages that Linux must
 * register with the proper pagetable ctor. Each list element is a packed
 * 64-bit value holding new_pfn and level.
 */
struct nacc_fork_ptp_list {
	unsigned int nr_entries;
	unsigned int reserved;
	unsigned long entries[];
};

#define NACC_FORK_RANGE_DONTCOPY	0x1UL
#define NACC_FORK_RANGE_WIPEONFORK	0x2UL
#define NACC_FORK_RANGE_VM_NACC         0x4UL

struct nacc_fork_range {
	unsigned long start;
	unsigned long end;
	unsigned long type;
};

struct nacc_fork_filter {
	unsigned int nr_ranges;
	unsigned int reserved;
	struct nacc_fork_range ranges[];
};

void add_to_reclaim_list(unsigned long pfn);
void flush_reclaim_list(void);

unsigned long nacc_mm_state(struct mm_struct *mm);
void nacc_mm_set_state(struct mm_struct *mm, unsigned long mask);
bool nacc_mm_is_active(struct mm_struct *mm);

static inline bool nacc_thread_is_inited(void)
{
	return !!(current->thread.nacc_flag & NACC_INITED);
}

static inline bool nacc_use_secure_pt(struct mm_struct *mm)
{
	/*
	 * Two windows need secure page-table handling:
	 * - fork/bootstrap construction while the current NaCC thread is
	 *   still building a child/new mm
	 * - steady-state or teardown of an mm that already owns secure PTPs
	 */
	return nacc_thread_is_inited() || nacc_mm_is_active(mm);
}

static inline bool nacc_pfn_is_secure_ptp(unsigned long pfn)
{
	return pfn >= NACC_PTP_PFN_BASE && pfn < NACC_PTP_PFN_END;
}

static inline void nacc_track_secure_ptp_pfn(unsigned long pfn)
{
	if (nacc_pfn_is_secure_ptp(pfn))
		add_to_reclaim_list(pfn);
}

void nacc_invoke(void);
void nacc_exec(void);
void nacc_invoke_child(void);
void nacc_attach_forked_child_if_needed(void);
void nacc_register_forked_child_pid(unsigned long child_pid);
int nacc_reserve_agent_slot_mm(struct mm_struct *mm, const char *tag);

void pgtbl_debug(unsigned long pgd);


unsigned long page_nacc_mappings(unsigned long pfn);
int page_nacc_register_ptp(unsigned long pfn, unsigned int level);
void nacc_reclaim_ptp_dtor(struct ptdesc *ptdesc, unsigned long pfn,
			   unsigned int level, const char *tag);

int nacc_register_fork_ptp_list(struct mm_struct *mm,
				struct nacc_fork_ptp_list *ptp_list,
				unsigned long ptp_list_bytes);

/*
 * Legacy fork-bypass path. Current fork mainline relies on standard Linux
 * dup_mmap/copy_page_range hooks instead of calling this helper directly.
 */
int __maybe_unused nacc_fork(unsigned long parent_pgd_pa,
			     unsigned long child_pgd_pa,
			     struct nacc_fork_filter *filter,
			     unsigned long filter_bytes,
			     struct mm_struct *child_mm);

void nacc_set_ptes_sbi(unsigned long ptep_pa, unsigned long pteval,
		       unsigned int nr);
void nacc_wrprotect_ptes_sbi(unsigned long ptep_pa, unsigned int nr);
#endif

#endif /* _ASM_RISCV_NACC_H */
