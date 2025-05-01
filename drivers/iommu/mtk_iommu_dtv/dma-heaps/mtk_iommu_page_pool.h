/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DMA BUF PagePool implementation
 * Based on earlier ION code by Google
 *
 * Copyright (C) 2011 Google, Inc.
 * Copyright (C) 2020 Linaro Ltd.
 */

#ifndef _mtk_iommu_dmabuf_page_pool_H
#define _mtk_iommu_dmabuf_page_pool_H

#include <linux/device.h>
#include <linux/kref.h>
#include <linux/mm_types.h>
#include <linux/mutex.h>
#include <linux/shrinker.h>
#include <linux/types.h>
#include <linux/atomic.h>

extern atomic_t total_pool_size;
extern atomic_t total_alloc_size;

/* page types we track in the pool */
enum {
	POOL_LOWPAGE,      /* Clean lowmem pages */
	POOL_HIGHPAGE,     /* Clean highmem pages */

	POOL_TYPE_SIZE,
};

/**
 * struct mtk_iommu_dmabuf_page_pool - pagepool struct
 * @count[]:		array of number of pages of that type in the pool
 * @items[]:		array of list of pages of the specific type
 * @mutex:		lock protecting this struct and especially the count
 *			item list
 * @gfp_mask:		gfp_mask to use from alloc
 * @order:		order of pages in the pool
 * @list:		list node for list of pools
 *
 * Allows you to keep a pool of pre allocated pages to use
 */
struct mtk_iommu_dmabuf_page_pool {
	int count[POOL_TYPE_SIZE];
	struct list_head items[POOL_TYPE_SIZE];
	struct mutex mutex;
	gfp_t gfp_mask;
	unsigned int order;
	struct list_head list;
	bool is_agile;
};

struct mtk_iommu_dmabuf_page_pool *mtk_iommu_dmabuf_page_pool_create(gfp_t gfp_mask,
						 unsigned int order);
void mtk_iommu_dmabuf_page_pool_destroy(struct mtk_iommu_dmabuf_page_pool *pool);
struct page *mtk_iommu_dmabuf_page_pool_alloc(struct mtk_iommu_dmabuf_page_pool *pool,
		bool uncached);
void mtk_iommu_dmabuf_page_pool_free(struct mtk_iommu_dmabuf_page_pool *pool, struct page *page,
		bool uncached);
int mtk_iommu_dmabuf_page_pool_init_shrinker(struct device *dev);

static inline unsigned int get_total_pool_size(void)
{
	return atomic_read(&total_pool_size);
}

static inline unsigned int get_total_alloc_size(void)
{
	return atomic_read(&total_alloc_size);
}
#endif /* _mtk_iommu_dmabuf_page_pool_H */
