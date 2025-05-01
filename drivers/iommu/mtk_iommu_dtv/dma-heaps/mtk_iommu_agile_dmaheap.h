/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright (c) 2020 MediaTek Inc.
 */
#ifndef __MTK_IOMMU_AGILE_DMAHEAP_H__
#define __MTK_IOMMU_AGILE_DMAHEAP_H__


#define NUM_ORDERS 3
extern struct mtk_iommu_dmabuf_page_pool *agile_pools[NUM_ORDERS];
extern unsigned int out_of_pool_times;
int mtk_agile_dmaheap_create(struct device *dev);
void mtk_agile_dmaheap_destroy(void);

#endif
