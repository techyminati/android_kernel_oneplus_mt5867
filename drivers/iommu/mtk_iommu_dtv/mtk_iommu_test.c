// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright (c) 2020 MediaTek Inc.
 */
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>

#include "mtk_iommu_dtv.h"
#include "mtk_iommu_of.h"
#include "mtk_iommu_common.h"
#include "mtk_iommu_dmaheap.h"
#include "mtk_iommu_tee_interface.h"

/* Valid FD_FLAGS are O_CLOEXEC, O_RDONLY, O_WRONLY, O_RDWR */
#define DMA_HEAP_VALID_FD_FLAGS (O_CLOEXEC | O_ACCMODE)

/* Currently no heap flags */
#define DMA_HEAP_VALID_HEAP_FLAGS (0)

int mtk_iommu_test_tee(void)
{
	int ret;
	struct dma_heap *dmaheap;
	struct dma_buf *dmabuf;
	struct sg_table *table;
	size_t size = 10 * 1024 * 1024;
	struct buf_tag_info tag_info = { };

	tag_info.id = 1;	// vdec_fb
	ret = mtk_iommu_get_buftag_info(&tag_info);
	if (ret)
		return ret;

	dmaheap = dma_heap_find(tag_info.name);
	if (!dmaheap) {
		pr_emerg("find [%s] fail\n", tag_info.name);
		return false;
	}

	dmabuf = dma_heap_buffer_alloc(dmaheap, size,
			DMA_HEAP_VALID_FD_FLAGS,
			DMA_HEAP_VALID_HEAP_FLAGS);
	if (IS_ERR_OR_NULL(dmabuf)) {
		pr_err("%s: alloc %zu byte failed\n", __func__, size);
		goto put_heap;
	}

	table = get_dmaheaps_buffer_sgtable(dmabuf);
	if (IS_ERR_OR_NULL(table)) {
		pr_err("%s: cannot find sgtable\n", __func__);
		ret = -ENODEV;
		goto put;
	}

	ret = mtk_iommu_tee_test(table, tag_info.name);
	if (ret)
		pr_err("%s: tee test fail ret = 0x%x\n", __func__, ret);
	else
		pr_info("%s: tee test success!\n", __func__);

put:
	dma_buf_put(dmabuf);
put_heap:
	dma_heap_put(dmaheap);
	return ret;
}
