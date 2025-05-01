// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 MediaTek Inc.
 * Author: Jay Ting <jay.ting@mediatek.com>
 */
#define CREATE_TRACE_POINTS
#define EXPORT_TRACE_MTK_IOMMU 0

#include "mtk_iommu_trace.h"

/* mtk iommu buf_handle */
EXPORT_TRACEPOINT_SYMBOL_GPL(mtk_buf_handle);

#if EXPORT_TRACE_MTK_IOMMU
/* mtk iommu event */
EXPORT_TRACEPOINT_SYMBOL_GPL(mtk_iommu);
EXPORT_TRACEPOINT_SYMBOL_GPL(mtk_iommu_resize);
EXPORT_TRACEPOINT_SYMBOL_GPL(mtk_iommu_sg);
EXPORT_TRACEPOINT_SYMBOL_GPL(mtk_iommu_pool_event);
EXPORT_TRACEPOINT_SYMBOL_GPL(mtk_iommu_alloc);
EXPORT_TRACEPOINT_SYMBOL_GPL(mtk_iommu_alloc_sync);

/* mtk iommu dmaheap event */
EXPORT_TRACEPOINT_SYMBOL_GPL(mtk_iommu_dmaheap_dmabuf_map);
EXPORT_TRACEPOINT_SYMBOL_GPL(mtk_iommu_dmaheap_dmabuf_unmap);
EXPORT_TRACEPOINT_SYMBOL_GPL(mtk_iommu_dmaheap_dmabuf_sync_begin);
EXPORT_TRACEPOINT_SYMBOL_GPL(mtk_iommu_dmaheap_dmabuf_sync_end);
#endif
