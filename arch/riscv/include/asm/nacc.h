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
#define NACC_MM_ROOT_TAGGED	0x2UL

enum nacc_region_class {
	NACC_REGION_CLASS_INVALID = 0,
	NACC_REGION_CLASS_PRIVATE_STRICT_ANON = 1,
	NACC_REGION_CLASS_PRIVATE_FILE_COW = 2,
	NACC_REGION_CLASS_SHARED_EXPLICIT = 3,
	NACC_REGION_CLASS_SPECIAL_EXCLUDED = 4,
};

enum nacc_region_sync_reason {
	NACC_REGION_SYNC_REASON_INVALID = 0,
	NACC_REGION_SYNC_REASON_INVOKE = 1,
	NACC_REGION_SYNC_REASON_EXEC = 2,
	NACC_REGION_SYNC_REASON_MMAP = 3,
	NACC_REGION_SYNC_REASON_BRK = 4,
	NACC_REGION_SYNC_REASON_MPROTECT = 5,
	NACC_REGION_SYNC_REASON_MREMAP = 6,
	NACC_REGION_SYNC_REASON_MUNMAP = 7,
	NACC_REGION_SYNC_REASON_FORK = 8,
	NACC_REGION_SYNC_REASON_EXIT_MMAP = 9,
};

enum nacc_region_flag {
	NACC_REGION_FLAG_VM_NACC = (1U << 0),
	NACC_REGION_FLAG_VM_IO = (1U << 1),
	NACC_REGION_FLAG_VM_PFNMAP = (1U << 2),
	NACC_REGION_FLAG_VM_MIXEDMAP = (1U << 3),
	NACC_REGION_FLAG_SHARED = (1U << 4),
	NACC_REGION_FLAG_ANON = (1U << 5),
	NACC_REGION_FLAG_FILE = (1U << 6),
	NACC_REGION_FLAG_SHMEM = (1U << 7),
	NACC_REGION_FLAG_AMBIGUOUS = (1U << 8),
};

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

static inline bool nacc_thread_has_root_l0_lifecycle(void)
{
	unsigned long flag = current->thread.nacc_flag;

	return flag == NACC_PREPARE || flag == NACC_FORKED ||
	       flag == NACC_EXEC || !!(flag & NACC_INITED);
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

static inline bool nacc_mm_root_tagged(struct mm_struct *mm)
{
	return !!(nacc_mm_state(mm) & NACC_MM_ROOT_TAGGED);
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
bool nacc_mm_needs_region_sync(struct mm_struct *mm);
int nacc_region_sync_mm(struct mm_struct *mm,
			enum nacc_region_sync_reason reason);
int nacc_region_sync_mm_locked(struct mm_struct *mm,
			       enum nacc_region_sync_reason reason);
int nacc_region_clear_mm(struct mm_struct *mm,
			 enum nacc_region_sync_reason reason);
int nacc_region_clear_mm_locked(struct mm_struct *mm,
				enum nacc_region_sync_reason reason);

int page_nacc_register_ptp(unsigned long pfn, unsigned int level);
void nacc_reclaim_ptp_dtor(struct ptdesc *ptdesc, unsigned long pfn,
			   unsigned int level, const char *tag);

void nacc_set_ptes_sbi(unsigned long ptep_pa, unsigned long pteval,
		       unsigned int nr, unsigned long start_va,
		       unsigned long root_pgd_pa);
void nacc_wrprotect_ptes_sbi(unsigned long ptep_pa, unsigned int nr);
int nacc_tag_root_sbi(unsigned long pgd_pa, unsigned long cid);
void nacc_retire_root_sbi(unsigned long pgd_pa);
#endif

#endif /* _ASM_RISCV_NACC_H */
