// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright (c) 2020 MediaTek Inc.
 */

#include <linux/dma-heap.h>
#include <linux/dma-mapping.h>
#include <uapi/linux/dma-heap.h>
#include <linux/scatterlist.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include "mtk_iommu_dtv.h"
#include "mtk_iommu_internal.h"
#include "mtk_iommu_statist.h"
#include "mtk_iommu_dmaheap.h"
#include "dma-heaps/mtk_iommu_dmaheap_ops.h"
#include "dma-heaps/mtk_iommu_dmaheap_name.h"
#include <linux/atomic.h>

static void _heap_zero_buffer(struct sg_table *sgt)
{
	struct sg_page_iter piter;
	struct page *p;
	void *vaddr;

	for_each_sgtable_page(sgt, &piter, 0) {
		p = sg_page_iter_page(&piter);
		vaddr = kmap_atomic(p);
		memset(vaddr, 0, PAGE_SIZE);
		kunmap_atomic(vaddr);
	}
}

struct sg_table *get_dmaheaps_buffer_sgtable(struct dma_buf *db)
{
	struct mtk_dmaheap_buffer *buffer;

	if (!db || !db->priv)
		return NULL;

	buffer = (struct mtk_dmaheap_buffer *)db->priv;

	return &(buffer->sg_table);
}

static int is_under_mali_threshold(struct mem_cust_policy_info *info)
{
	struct mem_statistics *stat_mali;
	struct mem_statistics *stat_mali_dma;
	unsigned int mali_size = 0;

	stat_mali = get_buf_tag_statistics("mali_gop");
	if (IS_ERR_OR_NULL(stat_mali))
		return -EINVAL;

	stat_mali_dma = get_buf_tag_statistics("mali_gop_dma");
	if (IS_ERR_OR_NULL(stat_mali_dma))
		return -EINVAL;
	mali_size = atomic64_read(&stat_mali->total_sz) + atomic64_read(&stat_mali_dma->total_sz);
	if (mali_size < info->mali_threshold)
		return 1;

	return 0;
}

static int is_cma_full(struct mem_cust_policy_info *info)
{
	struct mtk_dtv_iommu_data *data = NULL;
	u64 cma_size = 0;
	int ret;

	ret = get_iommu_data(&data);
	if (ret)
		return -EINVAL;

	get_curr_cma_heap_size(&cma_size);

	IOMMU_DEBUG(E_LOG_DEBUG, "curr_cma_size: 0x%llx, cma_region_maxsize: 0x%llx\n",
			cma_size, info->cma_region_maxsize);

	if (cma_size >= info->cma_region_maxsize)
		return 1;

	return 0;
}

static void _mali_choose_heap(int *mali_heap_type)
{
	struct mem_cust_policy_info *info = NULL;
	int ret;

	ret = get_mem_cust_policy_info(&info);
	if (ret) {
		pr_err("[IOMMU][%s] get_policy_info failed\n", __func__);
		return;
	}

	if (is_under_mali_threshold(info)
		&& (!is_cma_full(info) || !info->mali_reduce_migration)) {
		*mali_heap_type = HEAP_TYPE_CMA_IOMMU;
		return;
	}
}

int mtk_iommu_dmaheap_alloc(struct buf_tag_info *tag_info, int *heap_type, size_t size,
			unsigned long attrs, struct dma_buf **db)
{
	struct mtk_dtv_iommu_data *data = NULL;
	struct dma_heap *heap;
	struct sg_table *sgt;
	struct scatterlist *sg;
	char *heap_name;
	bool need_zero_page = false;
	int ret, i;

	ret = get_iommu_data(&data);
	if (ret)
		return -EINVAL;

	if (!size || !tag_info) {
		pr_err("[IOMMU][%s] tag_info is null\n", __func__);
		return -EINVAL;
	}

	*heap_type = tag_info->heap_type;

	if (attrs & IOMMUMD_FLAG_ZEROPAGE)
		need_zero_page = true;

	if (strstr(tag_info->name, "mali")) {
		_mali_choose_heap(heap_type);
		need_zero_page = true;
	}

	switch (*heap_type) {
	case HEAP_TYPE_IOMMU:
		if (attrs & DMA_ATTR_WRITE_COMBINE) {
			if (attrs & IOMMUMD_FLAG_DMAZONE)
				heap_name = MTK_SYSTEM_DMA_DMAHEAP_UC;
			else
				heap_name = MTK_SYSTEM_DMAHEAP_UC;
		} else {
			if (attrs & IOMMUMD_FLAG_DMAZONE)
				heap_name = MTK_SYSTEM_DMA_DMAHEAP;
			else
				heap_name = MTK_SYSTEM_DMAHEAP;
		}
		break;
	case HEAP_TYPE_AGILE:
		if (attrs & DMA_ATTR_WRITE_COMBINE)
			heap_name = MTK_AGILE_DMAHEAP_UC;
		else
			heap_name = MTK_AGILE_DMAHEAP;
		break;
	case HEAP_TYPE_CMA_IOMMU:
		// TODO: cma heap seperation
		if (attrs & DMA_ATTR_WRITE_COMBINE)
			heap_name = MTK_CMA_DMAHEAP_UC;
		else
			heap_name = MTK_CMA_DMAHEAP;
		break;
	case HEAP_TYPE_CARVEOUT:
		if (attrs & DMA_ATTR_WRITE_COMBINE)
			heap_name = MTK_CARVEOUT_DMAHEAP_UC;
		else
			heap_name = MTK_CARVEOUT_DMAHEAP;
		break;
	default:
		pr_err("[IOMMU][%s]: [%s] use wrong dma-heaps...\n", __func__, tag_info->name);
		return -EINVAL;
	}

	heap = dma_heap_find(heap_name);
	if (!heap) {
		pr_err("[IOMMU][%s]: [%s] could not find [%s]\n", __func__,
				tag_info->name, heap_name);
		return -ENODEV;
	}

	IOMMU_DEBUG(E_LOG_CRIT, "[%s] choose [%s] dma-heap\n", tag_info->name, heap_name);

	*db = dma_heap_buffer_alloc(heap, size,
			DMA_HEAP_VALID_FD_FLAGS, DMA_HEAP_VALID_HEAP_FLAGS);
	if (IS_ERR(*db))
		return PTR_ERR(*db);

	// zero buffer here
	if (need_zero_page) {
		sgt = get_dmaheaps_buffer_sgtable(*db);
		if (IS_ERR_OR_NULL(sgt)) {
			pr_err("[IOMMU][%s]: [%s] heap [%s], get sgt failed\n", __func__,
					tag_info->name, heap_name);
			dma_buf_put(*db);
			dma_heap_put(heap);
			return PTR_ERR(sgt);
		}

		_heap_zero_buffer(sgt);

		/* flush cache directly */
		for_each_sgtable_sg(sgt, sg, i) {
			dma_sync_single_for_device(data->direct_dev,
				sg_phys(sg), sg->length, DMA_BIDIRECTIONAL);
		}
	}

	dma_heap_put(heap);
	return 0;
}
