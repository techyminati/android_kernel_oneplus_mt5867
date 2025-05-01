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
#include <linux/kthread.h>
#ifdef CONFIG_ANDROID_VENDOR_HOOKS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
#include <trace/hooks/mm.h>
#endif
#endif
#include <linux/oom.h>

#include "mtk_iommu_page_pool.h"
#include "mtk_iommu_dmaheap.h"
#include "mtk_iommu_dmaheap_ops.h"
#include "mtk_iommu_agile_dmaheap.h"
#include "mtk_iommu_dmaheap_name.h"
#include "mtk_iommu_internal.h"
#include "mtk_iommu_trace.h"

static struct dma_heap *agile_heap;		/* Other Zone */
static struct dma_heap *agile_uncached_heap;	/* Other Zone */
static struct device *agile_dev;

#define HIGH_ORDER_GFP  (((GFP_HIGHUSER | __GFP_NOWARN \
				| __GFP_NORETRY) & ~__GFP_RECLAIM) \
				| __GFP_COMP)
#define LOW_ORDER_GFP (GFP_HIGHUSER | __GFP_COMP)
static gfp_t order_flags[] = {HIGH_ORDER_GFP,	// order 8
		HIGH_ORDER_GFP,	// order 4
		LOW_ORDER_GFP}; // order 0

static const unsigned int orders[NUM_ORDERS] = {8, 4, 0};

struct mtk_iommu_dmabuf_page_pool *agile_pools[NUM_ORDERS];

unsigned int out_of_pool_times;

static void agile_heap_dma_buf_release(struct dma_buf *dmabuf)
{
	int i, j;
	struct scatterlist *sg;
	struct sg_table *table;
	struct mtk_dmaheap_buffer *buffer;
	struct mtk_dmaheap_buffer_info *info;

	if (!dmabuf || !dmabuf->priv)
		return;

	buffer = (struct mtk_dmaheap_buffer *)dmabuf->priv;
	info = to_dmaheap_info(buffer);
	if (WARN_ON(info->magic != IOMMU_DMAHEAP_MAGIC)) {
		pr_err("%s: dmabuf magic (0x%x) is not below to dma-heaps\n",
			__func__, (int)info->magic);
		return;
	}

	table = &buffer->sg_table;
	for_each_sg(table->sgl, sg, table->orig_nents, i) {
		struct page *page = sg_page(sg);

		for (j = 0; j < NUM_ORDERS; j++) {
			if (compound_order(page) == orders[j]) {
				mtk_iommu_dmabuf_page_pool_free(agile_pools[j],
						page, buffer->uncached);
				break;
			}
		}
	}
	sg_free_table(table);
	kfree(info);
	dmabuf->priv = NULL;

	trace_mtk_iommu_pool_event(TPS("free: allocated size"),
			-IOMMU_DMAHEAP_MAGIC, get_total_alloc_size());
}

static const struct dma_buf_ops mtk_agile_dmaheap_buf_ops = {
	.attach = mtk_dmaheap_buf_attach,
	.detach = mtk_dmaheap_buf_detach,
	.map_dma_buf = mtk_dmaheap_buf_map_dma_buf,
	.unmap_dma_buf = mtk_dmaheap_buf_unmap_dma_buf,
	.begin_cpu_access = mtk_dmaheap_buf_begin_cpu_access,
	.end_cpu_access = mtk_dmaheap_buf_end_cpu_access,
	.mmap = mtk_dmaheap_buf_mmap,
	.vmap = mtk_dmaheap_buf_vmap,
	.vunmap = mtk_dmaheap_buf_vunmap,
	.release = agile_heap_dma_buf_release,	// self impl
};

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

		page = mtk_iommu_dmabuf_page_pool_alloc(agile_pools[i], uncached);
		if (!page)
			continue;

		return page;
	}
	return NULL;
}

static struct dma_buf *mtk_agile_heap_do_allocate(struct dma_heap *heap,
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

	buffer = &info->buffer;

	INIT_LIST_HEAD(&buffer->attachments);
	mutex_init(&buffer->lock);
	buffer->heap = heap;
	buffer->len = len;
	buffer->uncached = uncached;

	INIT_LIST_HEAD(&pages);

	ktime_get_real_ts64(&tv0);

	i = 0;
	if (get_total_pool_size() << PAGE_SHIFT < size_remaining) {
		unsigned long diff = size_remaining - (get_total_pool_size() << PAGE_SHIFT);

		out_of_pool_times++;
		IOMMU_DEBUG_INFO(E_LOG_ALERT,
				"it may allocate from system, pool size=%x, need size=%lx, diff=%lx\n",
				get_total_pool_size() << PAGE_SHIFT, size_remaining, diff);
	}

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
	trace_mtk_iommu_alloc(dma_heap_get_name(heap), TPS("agile"), len, elapsed_time);

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
	exp_info.ops = &mtk_agile_dmaheap_buf_ops;
	exp_info.size = len;
	exp_info.flags = fd_flags;
	exp_info.priv = &info->buffer;
	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto free_pages;
	}
	trace_mtk_iommu_pool_event(TPS("allocate: allocated size"),
			-IOMMU_DMAHEAP_MAGIC, get_total_alloc_size());
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

static struct dma_buf *agile_heap_allocate(struct dma_heap *heap,
					    unsigned long len,
					    unsigned long fd_flags,
					    unsigned long heap_flags)
{
	return mtk_agile_heap_do_allocate(heap, len, fd_flags, heap_flags, false);
}

static const struct dma_heap_ops mtk_agile_heap_ops = {
	.allocate = agile_heap_allocate,
};

static struct dma_buf *agile_uncached_heap_allocate(struct dma_heap *heap,
						     unsigned long len,
						     unsigned long fd_flags,
						     unsigned long heap_flags)
{
	return mtk_agile_heap_do_allocate(heap, len, fd_flags, heap_flags, true);
}

/* Dummy function to be used until we can call coerce_mask_and_coherent */
static struct dma_buf *agile_uncached_heap_not_initialized(struct dma_heap *heap,
							    unsigned long len,
							    unsigned long fd_flags,
							    unsigned long heap_flags)
{
	return ERR_PTR(-EBUSY);
}

static struct dma_heap_ops mtk_agile_uncached_heap_ops = {
	/* After agile_heap_create is complete, we will swap this */
	.allocate = agile_uncached_heap_not_initialized,
};

#ifdef CONFIG_ANDROID_VENDOR_HOOKS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
void agile_dmaheap_meminfo_show(void *data, struct oom_control *oc, int *ret)
{
	pr_info("[IOMMU] agile pools: watermark 0x%x, reset to 0\n", get_pool_water_mark());
	pr_info("[IOMMU] agile pools: total alloc 0x%x pages\n", get_total_alloc_size());
	pr_info("[IOMMU] agile pools: 0x%x pages still in pools\n", get_total_pool_size());

	pool_water_mark = 0;
}
#endif
#endif

int mtk_agile_dmaheap_create(struct device *dev)
{
	int i;
	struct dma_heap_export_info exp_info = { };

	agile_dev = dev;
	for (i = 0; i < NUM_ORDERS; i++) {
		/* create normal_zone pool */
		agile_pools[i] = mtk_iommu_dmabuf_page_pool_create(order_flags[i], orders[i]);
		if (!agile_pools[i]) {
			int j;

			pr_err("%s: page pool creation failed!\n", __func__);
			for (j = 0; j < i; j++)
				mtk_iommu_dmabuf_page_pool_destroy(agile_pools[j]);
			return -ENOMEM;
		}
		agile_pools[i]->is_agile = true;
	}

	/* agile Heap at Normal zone: Cached */
	exp_info.name = MTK_AGILE_DMAHEAP;
	exp_info.ops = &mtk_agile_heap_ops;
	exp_info.priv = NULL;

	agile_heap = dma_heap_add(&exp_info);
	if (IS_ERR(agile_heap))
		return PTR_ERR(agile_heap);

	/* agile Heap at Normal zone: Non-cached */
	exp_info.name = MTK_AGILE_DMAHEAP_UC;
	exp_info.ops = &mtk_agile_uncached_heap_ops;
	exp_info.priv = NULL;

	agile_uncached_heap = dma_heap_add(&exp_info);
	if (IS_ERR(agile_uncached_heap))
		return PTR_ERR(agile_uncached_heap);

	dma_coerce_mask_and_coherent(dma_heap_get_dev(agile_uncached_heap),
				DMA_BIT_MASK(IOMMU_DMAHEAP_MASK));
	mb(); /* make sure we only set allocate after dma_mask is set */

	mtk_agile_uncached_heap_ops.allocate = agile_uncached_heap_allocate;

	mtk_iommu_dmabuf_page_pool_init_shrinker(dma_heap_get_dev(agile_uncached_heap));
#ifdef CONFIG_ANDROID_VENDOR_HOOKS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
	if (register_trace_android_vh_oom_check_panic(agile_dmaheap_meminfo_show, NULL))
		dev_info(dma_heap_get_dev(agile_uncached_heap), "register oom_check_panic failed\n");
#endif
#endif
	return 0;
}

void mtk_agile_dmaheap_destroy(void)
{
#ifdef CONFIG_ANDROID_VENDOR_HOOKS
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
	unregister_trace_android_vh_oom_check_panic(agile_dmaheap_meminfo_show, NULL);
#endif
#endif
	dma_heap_put(agile_heap);
	dma_heap_put(agile_uncached_heap);
}
