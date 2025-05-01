// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright (c) 2020 MediaTek Inc.
 */

#include <linux/version.h>
#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/dma-heap.h>
#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#ifdef CONFIG_ANDROID_VENDOR_HOOKS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
#include <trace/hooks/mm.h>
#endif
#endif
#include <linux/oom.h>

#include "mtk_iommu_page_pool.h"
#include "mtk_iommu_dmaheap.h"
#include "mtk_iommu_dmaheap_ops.h"
#include "mtk_iommu_sys_dmaheap.h"
#include "mtk_iommu_dmaheap_name.h"
#include "mtk_iommu_internal.h"
#include "mtk_iommu_trace.h"

static struct dma_heap *sys_heap;		/* Other Zone */
static struct dma_heap *sys_uncached_heap;	/* Other Zone */
static struct dma_heap *sys_dma_heap;		/* DMA Zone */
static struct dma_heap *sys_dma_uncached_heap;	/* DMA Zone */
static struct device *sys_dev;

#define HIGH_ORDER_GFP  (((GFP_HIGHUSER | __GFP_NOWARN \
				| __GFP_NORETRY) & ~__GFP_RECLAIM) \
				| __GFP_COMP)
#define LOW_ORDER_GFP (GFP_HIGHUSER | __GFP_COMP)
static gfp_t order_flags[] = {HIGH_ORDER_GFP,	// order 8
		HIGH_ORDER_GFP,	// order 4
		LOW_ORDER_GFP}; // order 0

static const unsigned int orders[NUM_ORDERS] = {8, 4, 0};

struct mtk_iommu_dmabuf_page_pool *dma_pools[NUM_ORDERS];
struct mtk_iommu_dmabuf_page_pool *nor_pools[NUM_ORDERS];

static void heap_buf_free(struct deferred_freelist_item *item,
				 enum df_reason reason)
{
	int i, j;
	struct scatterlist *sg;
	struct sg_table *table;
	struct mtk_dmaheap_buffer *buffer;
	struct mtk_dmaheap_buffer_info *info;

	buffer = container_of(item, struct mtk_dmaheap_buffer, deferred_free);
	info = to_dmaheap_info(buffer);
	if (WARN_ON(info->magic != IOMMU_DMAHEAP_MAGIC)) {
		pr_err("%s: dmabuf magic (0x%x) is not below to dma-heaps\n",
			__func__, (int)info->magic);
		return;
	}

	table = &buffer->sg_table;
	for_each_sg(table->sgl, sg, table->orig_nents, i) {
		struct page *page = sg_page(sg);

		if (reason == DF_UNDER_PRESSURE) {
			__free_pages(page, compound_order(page));
		} else {
			for (j = 0; j < NUM_ORDERS; j++) {
				if (compound_order(page) == orders[j]) {
					if (info->is_dma) {
						mtk_iommu_dmabuf_page_pool_free(dma_pools[j],
								page, buffer->uncached);
					} else {
						mtk_iommu_dmabuf_page_pool_free(nor_pools[j],
								page, buffer->uncached);
					}
					break;
				}
			}
		}
	}
	sg_free_table(table);
	kfree(info);
}

static void sys_heap_dma_buf_release(struct dma_buf *dmabuf)
{
	int npages;
	struct mtk_dmaheap_buffer *buffer;

	if (!dmabuf || !dmabuf->priv)
		return;

	buffer = (struct mtk_dmaheap_buffer *)dmabuf->priv;
	npages = PAGE_ALIGN(buffer->len) / PAGE_SIZE;

	deferred_free(&buffer->deferred_free, heap_buf_free, npages);

	dmabuf->priv = NULL;
}

static const struct dma_buf_ops mtk_sys_dmaheap_buf_ops = {
	.attach = mtk_dmaheap_buf_attach,
	.detach = mtk_dmaheap_buf_detach,
	.map_dma_buf = mtk_dmaheap_buf_map_dma_buf,
	.unmap_dma_buf = mtk_dmaheap_buf_unmap_dma_buf,
	.begin_cpu_access = mtk_dmaheap_buf_begin_cpu_access,
	.end_cpu_access = mtk_dmaheap_buf_end_cpu_access,
	.mmap = mtk_dmaheap_buf_mmap,
	.vmap = mtk_dmaheap_buf_vmap,
	.vunmap = mtk_dmaheap_buf_vunmap,
	.release = sys_heap_dma_buf_release,	// self impl
};

static bool _is_dma_zone_heap(struct dma_heap *heap)
{
	if (heap == sys_dma_heap || heap == sys_dma_uncached_heap)
		return true;
	return false;
}

static struct page *alloc_largest_available(unsigned long size,
					    unsigned int max_order,
					    struct dma_heap *heap,
					    bool uncached)
{
	struct page *page;
	unsigned int i;

	for (i = 0; i < NUM_ORDERS; i++) {
		if (size <  (PAGE_SIZE << orders[i]))
			continue;

		if (max_order < orders[i])
			continue;

		if (_is_dma_zone_heap(heap)) {
			page = mtk_iommu_dmabuf_page_pool_alloc(dma_pools[i], uncached);
			if (!page)
				continue;
		} else {
			page = mtk_iommu_dmabuf_page_pool_alloc(nor_pools[i], uncached);
			if (!page)
				continue;
		}

		return page;
	}
	return NULL;
}

static struct dma_buf *mtk_system_heap_do_allocate(struct dma_heap *heap,
					       unsigned long len,
					       unsigned long fd_flags,
					       unsigned long heap_flags,
					       bool uncached)
{
	struct mtk_dmaheap_buffer_info *info;
	struct mtk_dmaheap_buffer *buffer;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	unsigned long size_remaining = len;
	unsigned int max_order = orders[0];
	struct dma_buf *dmabuf;
	struct sg_table *table;
	struct scatterlist *sg;
	struct list_head pages;
	struct page *page, *tmp_page;
	struct timespec64 tv0 = {0}, tv1 = {0};
	int i, ret = -ENOMEM;
	u32 elapsed_time = 0;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return ERR_PTR(-ENOMEM);

	// setup the DMAHEAP label
	info->magic = IOMMU_DMAHEAP_MAGIC;
	info->is_dma = _is_dma_zone_heap(heap);

	buffer = &info->buffer;

	INIT_LIST_HEAD(&buffer->attachments);
	mutex_init(&buffer->lock);
	buffer->heap = heap;
	buffer->len = len;
	buffer->uncached = uncached;

	INIT_LIST_HEAD(&pages);

	ktime_get_real_ts64(&tv0);

	i = 0;
	while (size_remaining > 0) {
		/*
		 * Avoid trying to allocate memory if the process
		 * has been killed by SIGKILL
		 */
		if (fatal_signal_pending(current))
			goto free_buffer;

		page = alloc_largest_available(size_remaining, max_order, heap, uncached);
		if (!page)
			goto free_buffer;

		list_add_tail(&page->lru, &pages);
		size_remaining -= page_size(page);
		max_order = compound_order(page);
		i++;
	}

	ktime_get_real_ts64(&tv1);
	elapsed_time = (tv1.tv_sec - tv0.tv_sec) * USEC_PER_SEC +
			(tv1.tv_nsec - tv0.tv_nsec) / NSEC_PER_USEC;
	trace_mtk_iommu_alloc(dma_heap_get_name(heap), TPS("system"), len, elapsed_time);

	table = &buffer->sg_table;
	if (sg_alloc_table(table, i, GFP_KERNEL))
		goto free_buffer;

	sg = table->sgl;
	list_for_each_entry_safe(page, tmp_page, &pages, lru) {
		sg_set_page(sg, page, page_size(page), 0);
		sg = sg_next(sg);
		list_del(&page->lru);
	}

	/* create the dmabuf */
	exp_info.exp_name = dma_heap_get_name(heap);
	exp_info.ops = &mtk_sys_dmaheap_buf_ops;
	exp_info.size = len;
	exp_info.flags = fd_flags;
	exp_info.priv = &info->buffer;
	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto free_pages;
	}

	return dmabuf;

free_pages:
	for_each_sgtable_sg(table, sg, i) {
		struct page *p = sg_page(sg);

		__free_pages(p, compound_order(p));
	}
	sg_free_table(table);
free_buffer:
	list_for_each_entry_safe(page, tmp_page, &pages, lru)
		__free_pages(page, compound_order(page));
	kfree(info);

	return ERR_PTR(ret);
}

static struct dma_buf *system_heap_allocate(struct dma_heap *heap,
					    unsigned long len,
					    unsigned long fd_flags,
					    unsigned long heap_flags)
{
	return mtk_system_heap_do_allocate(heap, len, fd_flags, heap_flags, false);
}

static const struct dma_heap_ops mtk_system_heap_ops = {
	.allocate = system_heap_allocate,
};

static struct dma_buf *system_uncached_heap_allocate(struct dma_heap *heap,
						     unsigned long len,
						     unsigned long fd_flags,
						     unsigned long heap_flags)
{
	return mtk_system_heap_do_allocate(heap, len, fd_flags, heap_flags, true);
}

/* Dummy function to be used until we can call coerce_mask_and_coherent */
static struct dma_buf *system_uncached_heap_not_initialized(struct dma_heap *heap,
							    unsigned long len,
							    unsigned long fd_flags,
							    unsigned long heap_flags)
{
	return ERR_PTR(-EBUSY);
}

static struct dma_heap_ops mtk_system_uncached_heap_ops = {
	/* After system_heap_create is complete, we will swap this */
	.allocate = system_uncached_heap_not_initialized,
};

#ifdef CONFIG_ANDROID_VENDOR_HOOKS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
void sys_dmaheap_meminfo_show(void *data, struct oom_control *oc, int *ret)
{
	int i, j;
	int total_page = 0;

	for (i = 0; i < NUM_ORDERS; i++)
		for (j = 0; j < POOL_TYPE_SIZE; j++)
			total_page += dma_pools[i]->count[j] << dma_pools[i]->order;
	pr_info("[IOMMU] dma pools: %d pages\n", total_page);

	total_page = 0;
	for (i = 0; i < NUM_ORDERS; i++)
		for (j = 0; j < POOL_TYPE_SIZE; j++)
			total_page += nor_pools[i]->count[j] << nor_pools[i]->order;
	pr_info("[IOMMU] nor_pools: %d pages\n", total_page);

}
#endif
#endif

int mtk_system_dmaheap_create(struct device *dev)
{
	int i;
	struct dma_heap_export_info exp_info = { };

	sys_dev = dev;
	for (i = 0; i < NUM_ORDERS; i++) {
		/* create dma_zone pool */
		dma_pools[i] = mtk_iommu_dmabuf_page_pool_create(order_flags[i], orders[i]);
		if (!dma_pools[i]) {
			int j;

			pr_err("%s: page pool creation failed!\n", __func__);
			for (j = 0; j < i; j++)
				mtk_iommu_dmabuf_page_pool_destroy(dma_pools[j]);
			return -ENOMEM;
		}
		_update_gfp_mask(&dma_pools[i]->gfp_mask);

		/* create normal_zone pool */
		nor_pools[i] = mtk_iommu_dmabuf_page_pool_create(order_flags[i], orders[i]);

		if (!nor_pools[i]) {
			int j;

			pr_err("%s: page pool creation failed!\n", __func__);
			for (j = 0; j < i; j++)
				mtk_iommu_dmabuf_page_pool_destroy(nor_pools[j]);
			return -ENOMEM;
		}
	}

	/* System Heap at Normal zone: Cached */
	exp_info.name = MTK_SYSTEM_DMAHEAP;
	exp_info.ops = &mtk_system_heap_ops;
	exp_info.priv = NULL;

	sys_heap = dma_heap_add(&exp_info);
	if (IS_ERR(sys_heap))
		return PTR_ERR(sys_heap);

	/* System Heap at Normal zone: Non-cached */
	exp_info.name = MTK_SYSTEM_DMAHEAP_UC;
	exp_info.ops = &mtk_system_uncached_heap_ops;
	exp_info.priv = NULL;

	sys_uncached_heap = dma_heap_add(&exp_info);
	if (IS_ERR(sys_uncached_heap))
		return PTR_ERR(sys_uncached_heap);

	dma_coerce_mask_and_coherent(dma_heap_get_dev(sys_uncached_heap),
				DMA_BIT_MASK(IOMMU_DMAHEAP_MASK));
	mb(); /* make sure we only set allocate after dma_mask is set */

	mtk_system_uncached_heap_ops.allocate = system_uncached_heap_allocate;

	/* System heap at DMA zone: Cached */
	exp_info.name = MTK_SYSTEM_DMA_DMAHEAP;
	exp_info.ops = &mtk_system_heap_ops;
	exp_info.priv = NULL;

	sys_dma_heap = dma_heap_add(&exp_info);
	if (IS_ERR(sys_dma_heap))
		return PTR_ERR(sys_dma_heap);

	/* System Heap at DMA zone: Non-cached */
	exp_info.name = MTK_SYSTEM_DMA_DMAHEAP_UC;
	exp_info.ops = &mtk_system_uncached_heap_ops;
	exp_info.priv = NULL;

	sys_dma_uncached_heap = dma_heap_add(&exp_info);
	if (IS_ERR(sys_dma_uncached_heap))
		return PTR_ERR(sys_dma_uncached_heap);

	dma_coerce_mask_and_coherent(dma_heap_get_dev(sys_dma_uncached_heap),
				DMA_BIT_MASK(IOMMU_DMAHEAP_MASK));
	mb(); /* make sure we only set allocate after dma_mask is set */

#ifdef CONFIG_ANDROID_VENDOR_HOOKS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
	if (register_trace_android_vh_oom_check_panic(sys_dmaheap_meminfo_show, NULL))
		dev_info(dma_heap_get_dev(sys_uncached_heap), "register oom_check_panic failed\n");
#endif
#endif
	return 0;
}

void mtk_system_dmaheap_destroy(void)
{
#ifdef CONFIG_ANDROID_VENDOR_HOOKS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
	unregister_trace_android_vh_oom_check_panic(sys_dmaheap_meminfo_show, NULL);
#endif
#endif
	dma_heap_put(sys_heap);
	dma_heap_put(sys_uncached_heap);
	dma_heap_put(sys_dma_heap);
	dma_heap_put(sys_dma_uncached_heap);
}
