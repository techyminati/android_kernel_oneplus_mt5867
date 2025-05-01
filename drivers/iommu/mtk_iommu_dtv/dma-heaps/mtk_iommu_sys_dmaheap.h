/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright (c) 2020 MediaTek Inc.
 */
#ifndef __MTK_IOMMU_SYS_DMAHEAP_H__
#define __MTK_IOMMU_SYS_DMAHEAP_H__

#define NUM_ORDERS 3
extern struct mtk_iommu_dmabuf_page_pool *nor_pools[NUM_ORDERS];
int mtk_system_dmaheap_create(struct device *dev);
void mtk_system_dmaheap_destroy(void);

#endif
