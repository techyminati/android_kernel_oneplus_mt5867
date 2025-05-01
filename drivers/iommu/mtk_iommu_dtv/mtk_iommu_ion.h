/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright (c) 2020 MediaTek Inc.
 * Author: Benson liang <benson.liang@mediatek.com>
 */

#ifndef _MTK_IOMMU_ION_H_
#define _MTK_IOMMU_ION_H_

#if IS_ENABLED(CONFIG_ION)
#include <linux/ion.h>
#endif

#define ION_IOMMU_MAGIC 0xabc66

struct ion_iommu_buffer_info {
	int magic;
	unsigned long attrs;
	void *cpu_addr;
	dma_addr_t handle;
	unsigned long len;
	struct sg_table *table;
};

#if IS_ENABLED(CONFIG_ION)
bool is_ion_iommu_heap(struct ion_heap *heap);
int __init mtk_ion_iommu_init(void);
void __exit mtk_ion_iommu_deinit(void);

extern size_t ion_query_heaps_kernel(struct ion_heap_data *hdata, size_t size);
extern struct dma_buf *ion_alloc(size_t len, unsigned int heap_id_mask,
				unsigned int flags);
int mtk_iommu_ion_query_heap(void);
int mtk_iommu_get_id_flag(int heap_type, int miu, int zone_flag,
		bool secure, unsigned int *heap_mask, unsigned int *ion_flag,
		u32 size, const char *buf_tag, unsigned long attrs);

int mtk_iommu_ion_alloc(size_t size, unsigned int heap_mask,
			unsigned int flags, struct dma_buf **db);

struct sg_table *get_ion_buffer_sgtable(struct dma_buf *db);
#else
#ifndef ION_FLAG_CACHED
#define ION_FLAG_CACHED 1 /* Alignd with ion definition */
#endif
static inline int mtk_iommu_get_id_flag(int heap_type, int miu, int zone_flag,
		bool secure, unsigned int *heap_mask, unsigned int *ion_flag,
		u32 size, const char *buf_tag, unsigned long attrs)
{
	return -EOPNOTSUPP;
}

static inline int mtk_iommu_ion_alloc(size_t size, unsigned int heap_mask,
			unsigned int flags, struct dma_buf **db)
{
	return -EOPNOTSUPP;
}

static inline struct sg_table *get_ion_buffer_sgtable(struct dma_buf *db)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static int __init mtk_ion_iommu_init(void)
{
	return 0;
}

void __exit mtk_ion_iommu_deinit(void) { }

static inline bool is_ion_iommu_heap(void *heap)
{
	return false;
}
#endif
#endif
