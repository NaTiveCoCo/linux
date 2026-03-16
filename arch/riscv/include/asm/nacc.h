#ifndef _ASM_RISCV_NACC_H
#define _ASM_RISCV_NACC_H

#ifndef __ASSEMBLY__
#include <linux/types.h>
#define NACC_RECLAIM_LIST_SIZE 511

struct mm_struct;

struct nacc_reclaim_list {
	unsigned long pfns[NACC_RECLAIM_LIST_SIZE];
	unsigned long count;
};

/* another macro for nacc_flag in nacc->thread field */
#define NACC_PREPARE     0b001
#define NACC_INITED      0b010
#define NACC_RECLAIM     0b100

/* 
 * The agent has already been initialized, and the new child process is forked.
 * This flag is set in the child process.
 */
#define NACC_FORKED      0b1000

/*
 * Re-exec path on the same PID for an already NaCC-protected task.
 * Use lightweight re-attach (no agent re-initialization jump).
 */
#define NACC_REEXEC      0b10000

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

void nacc_invoke(void);
void nacc_reexec(void);
void nacc_invoke_child(void);
int nacc_reserve_agent_slot_mm(struct mm_struct *mm, const char *tag);

void pgtbl_debug(unsigned long pgd);


unsigned long page_nacc_mappings(unsigned long pfn);

int nacc_register_fork_ptp_list(struct nacc_fork_ptp_list *ptp_list,
				unsigned long ptp_list_bytes);

int nacc_fork(unsigned long parent_pgd_pa, unsigned long child_pgd_pa,
              struct nacc_fork_filter *filter,
              unsigned long filter_bytes);
#endif

#endif /* _ASM_RISCV_NACC_H */
