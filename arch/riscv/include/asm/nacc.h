#ifndef _ASM_RISCV_NACC_H
#define _ASM_RISCV_NACC_H

#ifndef __ASSEMBLY__
#define NACC_RECLAIM_LIST_SIZE 511

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

void add_to_reclaim_list(unsigned long pfn);
void flush_reclaim_list(void);

void nacc_invoke(void);
void nacc_invoke_child(void);

void pgtbl_debug(unsigned long pgd);


unsigned long page_nacc_mappings(unsigned long pfn);

#endif

#endif /* _ASM_RISCV_NACC_H */
