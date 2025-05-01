/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright (c) 2020 MediaTek Inc.
 */

#ifndef __MTK_IOMMU_DMAHEAP_H__
#define __MTK_IOMMU_DMAHEAP_H__

#include <linux/err.h>
#include "mtk_iommu_of.h"
#include "deferred-free-helper.h"

// should be aligned with struct system_heap_buffer
struct mtk_dmaheap_buffer {
	struct dma_heap *heap;
	struct list_head attachments;
	struct mutex lock;
	unsigned long len;
	struct sg_table sg_table;
	int vmap_cnt;
	void *vaddr;
	struct deferred_freelist_item deferred_free;

	bool uncached;
};

struct mtk_dmaheap_buffer_info {
	struct mtk_dmaheap_buffer buffer;
	struct mtk_iommu_buf_handle *handler;
	int magic;
	unsigned long attrs;
	dma_addr_t handle;	// iova or pa
	bool is_dma;
};

#define to_dmaheap_info(x) container_of(x, struct mtk_dmaheap_buffer_info, buffer)

#define IOMMU_DMAHEAP_MASK 34
#define IOMMU_DMAHEAP_MAGIC 0x5566

/* XXX: Remove CONFIG_MTK_DMABUF_HEAPS_SYSTEM after Google issue b/243501482 done */
#if IS_ENABLED(CONFIG_DMABUF_HEAPS_SYSTEM) || IS_ENABLED(CONFIG_MTK_DMABUF_HEAPS_SYSTEM)
int is_dmaheap_ops(struct dma_buf *db);
int mtk_iommu_dmaheap_alloc(struct buf_tag_info *tag_info, int *heap_type, size_t size,
			unsigned long attrs, struct dma_buf **db);

struct sg_table *get_dmaheaps_buffer_sgtable(struct dma_buf *db);

int __init mtk_iommu_dmaheap_init(struct device *dev);
void __exit mtk_iommu_dmaheap_deinit(void);
#else
static int mtk_iommu_dmaheap_alloc(struct buf_tag_info *tag_info, int *heap_type, size_t size,
			unsigned long attrs, struct dma_buf **db)
{
	return -EOPNOTSUPP;
}

static struct sg_table *get_dmaheaps_buffer_sgtable(struct dma_buf *db)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static __init int mtk_iommu_dmaheap_init(struct device *dev)
{
	return -EOPNOTSUPP;
}

static __exit void mtk_iommu_dmaheap_deinit(void) { }
#endif

#endif
