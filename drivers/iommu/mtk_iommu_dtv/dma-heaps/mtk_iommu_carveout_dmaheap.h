/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright (c) 2020 MediaTek Inc.
 */
#ifndef __MTK_IOMMU_CARV_DMAHEAP_H___
#define __MTK_IOMMU_CARV_DMAHEAP_H___

int mtk_carveout_dmaheap_init(struct device *dev);
void mtk_carveout_dmaheap_exit(void);

#endif
