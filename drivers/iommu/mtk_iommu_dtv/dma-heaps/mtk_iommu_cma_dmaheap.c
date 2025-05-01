// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright (c) 2020 MediaTek Inc.
 */

#include <asm/page.h>
#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/dma-heap.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/seq_file.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/cma.h>
#include <linux/sizes.h>
#include <linux/dma-direct.h>
#include <linux/swap.h>

#include "cma.h"
#include "mtk_iommu_cma_dmaheap.h"
#include "mtk_iommu_dmaheap.h"
#include "mtk_iommu_dmaheap_ops.h"
#include "mtk_iommu_dmaheap_name.h"
#include "mtk_iommu_trace.h"
#include "mtk_iommu_sys_dmaheap.h"
#include "mtk_iommu_page_pool.h"

#define MAX_IOMMU_HEAP_CMA_AREAS 4
#define IOMMU_HEAP_CMA_ALIGN	SZ_2M

static const unsigned int orders[NUM_ORDERS] = {8, 4, 0};

struct mtk_iommu_cma_dmaheap {
	struct dma_heap *heap;
	struct cma *cma[MAX_IOMMU_HEAP_CMA_AREAS];
	void *priv;
};

static struct mtk_iommu_cma_dmaheap *cma_heap;
static struct mtk_iommu_cma_dmaheap *cma_uncached_heap;

struct iommu_cma_heap_node {
	struct list_head list;
	struct page *page;
	unsigned long len;
};

static bool cma_range(struct cma *cma_area, struct page *page)
{
	unsigned long pfn = page_to_pfn(page);

	if (!cma_area)
		return false;

	if (pfn >= cma_area->base_pfn
		&& pfn < (cma_area->base_pfn + cma_area->count))
		return true;

	return false;
}

static void cma_heap_dma_buf_release(struct dma_buf *dmabuf)
{
	struct mtk_dmaheap_buffer *buffer;
	int i, j, k;
	struct scatterlist *sg;
	struct sg_table *table;
	struct mtk_dmaheap_buffer_info *info;
	struct mtk_iommu_cma_dmaheap *cma_heap;
	struct page *page;
	unsigned long nr_pages;
	int in_cma;

	if (!dmabuf || !dmabuf->priv)
		return;

	buffer = (struct mtk_dmaheap_buffer *)dmabuf->priv;

	info = to_dmaheap_info(buffer);
	if (WARN_ON(info->magic != IOMMU_DMAHEAP_MAGIC)) {
		pr_err("%s: dmabuf magic (0x%x) is not below to dma-heaps\n",
			__func__, (int)info->magic);
		return;
	}

	cma_heap = dma_heap_get_drvdata(buffer->heap);
	if (!cma_heap) {
		pr_err("%s: get drvdata fail\n", __func__);
		return;
	}


	table = &buffer->sg_table;
	for_each_sg(table->sgl, sg, table->orig_nents, i) {
		page = sg_page(sg);
		nr_pages = sg->length >> PAGE_SHIFT;
		in_cma = 0;
		for (j = 0; j < MAX_IOMMU_HEAP_CMA_AREAS && cma_heap->cma[j]; j++) {
			if (cma_range(cma_heap->cma[j], page)) {
				in_cma = 1;
				cma_release(cma_heap->cma[j], page, nr_pages);
			}
		}
		if (!in_cma) {
			for (k = 0; k < NUM_ORDERS; k++) {
				if (compound_order(page) == orders[k]) {
					mtk_iommu_dmabuf_page_pool_free(nor_pools[k],
							page, buffer->uncached);
					break;
				}
			}
		}
	}
	sg_free_table(table);
	kfree(info);

	dmabuf->priv = NULL;
}

static const struct dma_buf_ops mtk_cma_dmaheap_buf_ops = {
	.attach = mtk_dmaheap_buf_attach,
	.detach = mtk_dmaheap_buf_detach,
	.map_dma_buf = mtk_dmaheap_buf_map_dma_buf,
	.unmap_dma_buf = mtk_dmaheap_buf_unmap_dma_buf,
	.begin_cpu_access = mtk_dmaheap_buf_begin_cpu_access,
	.end_cpu_access = mtk_dmaheap_buf_end_cpu_access,
	.mmap = mtk_dmaheap_buf_mmap,
	.vmap = mtk_dmaheap_buf_vmap,
	.vunmap = mtk_dmaheap_buf_vunmap,
	.release = cma_heap_dma_buf_release,	// self impl
};

static struct page *alloc_largest_available(unsigned long size,
					    unsigned int max_order,
					    bool uncached)
{
	struct page *page;
	unsigned int i;

	for (i = 0; i < NUM_ORDERS; i++) {
		if (size <  (PAGE_SIZE << orders[i]))
			continue;

		if (max_order < orders[i])
			continue;
		page = mtk_iommu_dmabuf_page_pool_alloc(nor_pools[i], uncached);
		if (!page)
			continue;

		return page;
	}
	return NULL;
}

static int alloc_from_buddy(struct list_head *pages,
			size_t *remaining, unsigned long flags,
			unsigned int *max_order, bool uncached)
{
	int i = 0;
	struct page *page;
	struct iommu_cma_heap_node *node;

	while (*remaining > 0) {
		page = alloc_largest_available(*remaining, *max_order, uncached);
		if (!page) {
			pr_err("%s: alloc_pages fail\n", __func__);
			return -ENOMEM;
		}
		*max_order = compound_order(page);
		node = kzalloc(sizeof(struct iommu_cma_heap_node),
				GFP_KERNEL);
		if (!node)
			return -ENOMEM;

		node->len = page_size(page);
		node->page = page;
		INIT_LIST_HEAD(&node->list);
		list_add_tail(&node->list, pages);
		*remaining -= page_size(page);
		i++;
	}

	return i;
}

static int alloc_from_cma(struct mtk_iommu_cma_dmaheap *cma_heap, struct list_head *pages,
			size_t *remaining)
{
	int i = 0;
	int j;
	size_t len;
	struct iommu_cma_heap_node *node;
	struct page *page = NULL;
	unsigned long nr_pages;
	unsigned long align;

	while (*remaining > 0) {
		len = min_t(size_t, *remaining, IOMMU_HEAP_CMA_ALIGN);
		nr_pages = len >> PAGE_SHIFT;
		align = get_order(len);

		for (j = 0; j < MAX_IOMMU_HEAP_CMA_AREAS && !page && cma_heap->cma[j]; j++)
			page = cma_alloc(cma_heap->cma[j], nr_pages, align, false);

		// seen null page as cma has not enough space to alloc
		if (!page) {
			pr_info("%s : alloc %d-th times no available cma space\n", __func__, i);
			break;
		}

		if (PageHighMem(page)) {
			unsigned long nr_clear_pages = nr_pages;
			struct page *p = page;

			while (nr_clear_pages > 0) {
				void *vaddr = kmap_atomic(p);

				memset(vaddr, 0, PAGE_SIZE);
				kunmap_atomic(vaddr);
				p++;
				nr_clear_pages--;
			}
		} else {
			memset(page_address(page), 0, len);
		}

		node = kzalloc(sizeof(struct iommu_cma_heap_node), GFP_KERNEL);
		if (!node)
			return -ENOMEM;

		node->len = len;
		node->page = page;
		INIT_LIST_HEAD(&node->list);
		list_add_tail(&node->list, pages);
		*remaining -= len;
		i++;
		page = NULL;
		if (j > 0) {
			pr_info("%s: %s alloc %zu\n",
				__func__, cma_get_name(cma_heap->cma[j-1]), len);
		}

	}

	return i;
}

static struct dma_buf *mtk_cma_heap_do_allocate(struct dma_heap *dma_heap,
					       unsigned long len,
					       unsigned long fd_flags,
					       unsigned long heap_flags,
					       bool uncached)
{
	struct mtk_iommu_cma_dmaheap *cma_heap = dma_heap_get_drvdata(dma_heap);
	struct mtk_dmaheap_buffer_info *info;
	struct mtk_dmaheap_buffer *buffer;
	unsigned int nents = 0;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	size_t size_remaining = PAGE_ALIGN(len);
	struct iommu_cma_heap_node *node, *tmp;
	struct dma_buf *dmabuf;
	struct sg_table *table = NULL;
	struct scatterlist *sg;
	struct list_head pages;
	struct timespec64 tv0 = {0}, tv1 = {0};
	int in_cma;
	int j, ret = -ENOMEM;
	u32 elapsed_time = 0;
	unsigned int max_order = orders[0];

	if (!cma_heap)
		return ERR_PTR(-EINVAL);

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return ERR_PTR(-ENOMEM);

	// setup the DMAHEAP label
	info->magic = IOMMU_DMAHEAP_MAGIC;

	buffer = &info->buffer;

	INIT_LIST_HEAD(&buffer->attachments);
	mutex_init(&buffer->lock);
	buffer->heap = dma_heap;
	buffer->len = len;
	buffer->uncached = uncached;

	INIT_LIST_HEAD(&pages);

	ktime_get_real_ts64(&tv0);

	ret = alloc_from_cma(cma_heap, &pages, &size_remaining);
	if (ret < 0)
		goto free_buffer;
	nents += ret;

	ktime_get_real_ts64(&tv1);
	elapsed_time = (tv1.tv_sec - tv0.tv_sec) * USEC_PER_SEC +
			(tv1.tv_nsec - tv0.tv_nsec) / NSEC_PER_USEC;
	trace_mtk_iommu_alloc(dma_heap_get_name(dma_heap), TPS("cma"),
		(size_remaining > 0) ? PAGE_ALIGN(len) - size_remaining : PAGE_ALIGN(len),
		elapsed_time);

	if (size_remaining > 0) {
		size_t size_from_buddy = size_remaining;

		ktime_get_real_ts64(&tv0);

		pr_info("%s: 0x%zx size remain\n", __func__, size_remaining);
		ret = alloc_from_buddy(&pages, &size_remaining, 0, &max_order, uncached);
		if (ret < 0)
			goto free_buffer;
		nents += ret;

		ktime_get_real_ts64(&tv1);
		elapsed_time = (tv1.tv_sec - tv0.tv_sec) * USEC_PER_SEC +
				(tv1.tv_nsec - tv0.tv_nsec) / NSEC_PER_USEC;
		trace_mtk_iommu_alloc(dma_heap_get_name(dma_heap), TPS("cma->buddy"),
				size_from_buddy, elapsed_time);
	}

	table = &buffer->sg_table;
	if (sg_alloc_table(table, nents, GFP_KERNEL))
		goto free_buffer;

	sg = table->sgl;

	list_for_each_entry_safe(node, tmp, &pages, list) {
		sg_set_page(sg, node->page, node->len, 0);
		sg = sg_next(sg);
		list_del(&node->list);
		kfree(node);
	}

	/* create the dmabuf */
	exp_info.exp_name = dma_heap_get_name(dma_heap);
	exp_info.ops = &mtk_cma_dmaheap_buf_ops;
	exp_info.size = len;
	exp_info.flags = fd_flags;
	exp_info.priv = &info->buffer;
	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto free_buffer;
	}

	/*
	 * For uncached buffers, we need to initially flush cpu cache, since
	 * the __GFP_ZERO on the allocation means the zeroing was done by the
	 * cpu and thus it is likely cached. Map (and implicitly flush) and
	 * unmap it now so we don't get corruption later on.
	 */
	if (uncached) {
		ktime_get_real_ts64(&tv0);

		//dma_map_sgtable(dma_heap_get_dev(dma_heap), table, DMA_BIDIRECTIONAL, 0);
		//dma_unmap_sgtable(dma_heap_get_dev(dma_heap), table, DMA_BIDIRECTIONAL, 0);

		ktime_get_real_ts64(&tv1);
		elapsed_time = (tv1.tv_sec - tv0.tv_sec) * USEC_PER_SEC +
				(tv1.tv_nsec - tv0.tv_nsec) / NSEC_PER_USEC;
		trace_mtk_iommu_alloc_sync(dma_heap_get_name(dma_heap), len, elapsed_time);
	}

	return dmabuf;

free_buffer:
	if (nents == 0)
		return ERR_PTR(ret);

	list_for_each_entry_safe(node, tmp, &pages, list) {
		in_cma = 0;
		for (j = 0; j < MAX_IOMMU_HEAP_CMA_AREAS && cma_heap->cma[j]; j++) {
			if (cma_range(cma_heap->cma[j], node->page)) {
				in_cma = 1;
				cma_release(cma_heap->cma[j], node->page, node->len >> PAGE_SHIFT);
			}
		}
		if (!in_cma)
			__free_pages(node->page, get_order(node->len));
		list_del(&node->list);
		kfree(node);
	}
	if (table)
		sg_free_table(table);
	kfree(info);
	return ERR_PTR(ret);
	//return NULL;
}

static struct dma_buf *cma_heap_allocate(struct dma_heap *heap,
					    unsigned long len,
					    unsigned long fd_flags,
					    unsigned long heap_flags)
{
	return mtk_cma_heap_do_allocate(heap, len, fd_flags, heap_flags, false);
}

static const struct dma_heap_ops mtk_cma_heap_ops = {
	.allocate = cma_heap_allocate,
};

static struct dma_buf *cma_uncached_heap_allocate(struct dma_heap *heap,
						     unsigned long len,
						     unsigned long fd_flags,
						     unsigned long heap_flags)
{
	return mtk_cma_heap_do_allocate(heap, len, fd_flags, heap_flags, true);
}

/* Dummy function to be used until we can call coerce_mask_and_coherent */
static struct dma_buf *cma_uncached_heap_not_initialized(struct dma_heap *heap,
							    unsigned long len,
							    unsigned long fd_flags,
							    unsigned long heap_flags)
{
	return ERR_PTR(-EBUSY);
}

static struct dma_heap_ops mtk_cma_uncached_heap_ops = {
	/* After system_heap_create is complete, we will swap this */
	.allocate = cma_uncached_heap_not_initialized,
};

static int __find_and_add_cma_heap(struct cma *cma_area, void *data)
{
	unsigned int *nr = data;

	if (!cma_area)
		return -EINVAL;
	if (strstr(cma_get_name(cma_area), "cma_22")) {
		if (*nr >= MAX_IOMMU_HEAP_CMA_AREAS)
			return -EINVAL;

		cma_heap->cma[*nr] = cma_area;
		cma_uncached_heap->cma[*nr] = cma_area;
		pr_crit("%s: add %d-th iommu cma heaps, cma area: %s base_pfn = %lx, count = %lx\n",
				__func__, *nr, cma_get_name(cma_area), cma_area->base_pfn, cma_area->count);
		*nr += 1;
	}
	return 0;
}

int mtk_cma_dmaheap_create(void)
{
	int nr = 0;
	int ret;
	struct dma_heap_export_info exp_info = { };

	cma_heap = kzalloc(sizeof(*cma_heap), GFP_KERNEL);
	if (!cma_heap)
		return -ENOMEM;
	cma_uncached_heap = kzalloc(sizeof(*cma_uncached_heap), GFP_KERNEL);
	if (!cma_uncached_heap) {
		kfree(cma_heap);
		return -ENOMEM;
	}
	ret = cma_for_each_area(__find_and_add_cma_heap, &nr);
	if (ret)
		goto out;

	exp_info.name = MTK_CMA_DMAHEAP;
	exp_info.ops = &mtk_cma_heap_ops;
	exp_info.priv = cma_heap;

	cma_heap->heap = dma_heap_add(&exp_info);
	if (IS_ERR(cma_heap->heap))
		return PTR_ERR(cma_heap->heap);

	exp_info.name = MTK_CMA_DMAHEAP_UC;
	exp_info.ops = &mtk_cma_uncached_heap_ops;
	exp_info.priv = cma_uncached_heap;

	cma_uncached_heap->heap = dma_heap_add(&exp_info);
	if (IS_ERR(cma_uncached_heap->heap))
		return PTR_ERR(cma_uncached_heap->heap);

	dma_coerce_mask_and_coherent(dma_heap_get_dev(cma_uncached_heap->heap),
				DMA_BIT_MASK(IOMMU_DMAHEAP_MASK));
	mb(); /* make sure we only set allocate after dma_mask is set */

	mtk_cma_uncached_heap_ops.allocate = cma_uncached_heap_allocate;
out:
	return 0;
}

void mtk_cma_dmaheap_destroy(void)
{
	dma_heap_put(cma_heap->heap);
	dma_heap_put(cma_uncached_heap->heap);
	kfree(cma_heap);
	kfree(cma_uncached_heap);
}
