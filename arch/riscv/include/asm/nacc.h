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

#define NACC_MM_ACTIVE		0x1UL

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
	 * Secure page-table handling is needed when:
	 * - the current task already owns secure page tables (fork/COW path)
	 * - an mm has entered the NaCC secure PTP lifecycle, including a
	 *   freshly created exec mm before it becomes current
	 */
	return nacc_thread_is_inited() ||
	       nacc_mm_is_active(mm);
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

int page_nacc_register_ptp(unsigned long pfn, unsigned int level);
void nacc_reclaim_ptp_dtor(struct ptdesc *ptdesc, unsigned long pfn,
			   unsigned int level, const char *tag);

void nacc_set_ptes_sbi(unsigned long ptep_pa, unsigned long pteval,
		       unsigned int nr);
void nacc_wrprotect_ptes_sbi(unsigned long ptep_pa, unsigned int nr);
#endif

#endif /* _ASM_RISCV_NACC_H */
