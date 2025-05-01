/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MM_CMA_H__
#define __MM_CMA_H__

#include <linux/debugfs.h>
#include <linux/kobject.h>

#ifdef CONFIG_MP_ION_PATCH_FAKE_MEM
#define CMA_FAKEMEM 0x01
#endif

struct cma_kobject {
	struct kobject kobj;
	struct cma *cma;
};

struct cma {
	unsigned long   base_pfn;
	unsigned long   count;
	unsigned long   *bitmap;
	unsigned int order_per_bit; /* Order of pages represented by one bit */
	spinlock_t	lock;
#ifdef CONFIG_MSTAR_CHIP
	struct mutex    mlock;
#endif
#ifdef CONFIG_CMA_DEBUGFS
	struct hlist_head mem_head;
	spinlock_t mem_head_lock;
	struct debugfs_u32_array dfs_bitmap;
#endif
#ifdef CONFIG_MP_CMA_PATCH_COUNT_TIMECOST
	struct cma_measurement *cma_measurement_ptr;
#endif
	char name[CMA_MAX_NAME];
#ifdef CONFIG_MP_ION_PATCH_FAKE_MEM
	unsigned int flags;				// cma area flags, example:CMA_FAKEMEM
#endif
#ifdef CONFIG_CMA_SYSFS
	/* the number of CMA page successful allocations */
	atomic64_t nr_pages_succeeded;
	/* the number of CMA page allocation failures */
	atomic64_t nr_pages_failed;
	/* kobject requires dynamic object */
	struct cma_kobject *cma_kobj;
#endif
};
#if defined(CONFIG_MP_CMA_PATCH_COUNT_TIMECOST)
# define CMA_HEAP_MEASUREMENT_LENG 96
#endif

#ifdef CONFIG_MP_CMA_PATCH_COUNT_TIMECOST
struct cma_measurement {
	const char *cma_heap_name;
	unsigned int cma_heap_id;
	struct mutex cma_measurement_lock;

	/* Measure Node Start */
	unsigned long total_alloc_size_kb;
	unsigned long total_alloc_time_cost_ms;

	unsigned long total_migration_size_kb;
	unsigned long total_migration_time_cost_ms;
	/* Measure Node End */

	/* Reset Node Start */
	unsigned long cma_measurement_reset;
	/* Reset Node End */
};
#endif

extern struct cma cma_areas[MAX_CMA_AREAS];
extern unsigned cma_area_count;

static inline unsigned long cma_bitmap_maxno(struct cma *cma)
{
	return cma->count >> cma->order_per_bit;
}

#ifdef CONFIG_CMA_SYSFS
void cma_sysfs_account_success_pages(struct cma *cma, unsigned long nr_pages);
void cma_sysfs_account_fail_pages(struct cma *cma, unsigned long nr_pages);
#else
static inline void cma_sysfs_account_success_pages(struct cma *cma,
						   unsigned long nr_pages) {};
static inline void cma_sysfs_account_fail_pages(struct cma *cma,
						unsigned long nr_pages) {};
#endif
#endif
