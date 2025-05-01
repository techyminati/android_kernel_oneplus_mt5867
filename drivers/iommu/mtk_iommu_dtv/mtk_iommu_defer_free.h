/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright (c) 2020 MediaTek Inc.
 * Author: Benson liang <benson.liang@mediatek.com>
 */
#include <linux/list.h>
#include <linux/device.h>

struct deferred_iommu_freelist_item {
	void (*free)(void *data);
	struct list_head list;
	void *data;
};

void deferred_iommu_free(void (*free)(void *data),
			void *data);

bool flush_free_list(void);
int defer_free_init(struct device *dev);
void defer_free_exit(void);
