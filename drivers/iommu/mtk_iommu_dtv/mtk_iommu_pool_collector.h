/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright (c) 2020 MediaTek Inc.
 * Author: Benson liang <benson.liang@mediatek.com>
 */
#include <linux/list.h>
#include <linux/device.h>

#define IOMMU_SCHED_PRIOR 19

struct mtk_iommu_alloclist_item {
	void (*alloc)(void *data);
	struct list_head list;
	void *data;
};

void add_collector(void (*free)(void *data),
			void *data);

void renice_pool_collector(int status);
int mtk_iommu_pool_collector_init(struct device *dev);
void mtk_iommu_pool_collector_exit(void);
