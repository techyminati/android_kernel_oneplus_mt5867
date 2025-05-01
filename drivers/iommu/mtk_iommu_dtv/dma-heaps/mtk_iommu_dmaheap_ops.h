/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright (c) 2020 MediaTek Inc.
 */

#ifndef __MTK_IOMMU_DMAHEAP_OPS_H__
#define __MTK_IOMMU_DMAHEAP_OPS_H__

#include <linux/version.h>

int mtk_dmaheap_buf_attach(struct dma_buf *dmabuf,
				struct dma_buf_attachment *attachment);

void mtk_dmaheap_buf_detach(struct dma_buf *dmabuf,
				struct dma_buf_attachment *attachment);

struct sg_table *mtk_dmaheap_buf_map_dma_buf(struct dma_buf_attachment *attachment,
						enum dma_data_direction direction);

void mtk_dmaheap_buf_unmap_dma_buf(struct dma_buf_attachment *attachment,
					struct sg_table *table,
					enum dma_data_direction direction);

int mtk_dmaheap_buf_begin_cpu_access(struct dma_buf *dmabuf,
						enum dma_data_direction direction);

int mtk_dmaheap_buf_end_cpu_access(struct dma_buf *dmabuf,
						enum dma_data_direction direction);

int mtk_dmaheap_buf_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
int mtk_dmaheap_buf_vmap(struct dma_buf *dmabuf, struct iosys_map *map);

void mtk_dmaheap_buf_vunmap(struct dma_buf *dmabuf, struct iosys_map *map);
#else
int mtk_dmaheap_buf_vmap(struct dma_buf *dmabuf, struct dma_buf_map *map);

void mtk_dmaheap_buf_vunmap(struct dma_buf *dmabuf, struct dma_buf_map *map);
#endif

#endif
