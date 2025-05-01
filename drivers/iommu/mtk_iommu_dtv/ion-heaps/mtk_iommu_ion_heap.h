/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright (c) 2020 MediaTek Inc.
 * Author: Benson liang <benson.liang@mediatek.com>
 */


#ifndef _LINUX_ION_IOMMU_HEAP_H
#define _LINUX_ION_IOMMU_HEAP_H

#define to_iommu_heap(x) container_of(x, struct ion_iommu_heap, heap)

struct ion_iommu_heap {
	struct ion_heap heap;
	struct device *dev;
};
#endif	//_LINUX_ION_IOMMU_HEAP_H
