// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright (c) 2020 MediaTek Inc.
 * Author: Benson liang <benson.liang@mediatek.com>
 */
#include <linux/freezer.h>
#include <uapi/linux/sched/types.h>
#include <linux/sched/signal.h>
#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/device.h>
#include <linux/slab.h>
#include "mtk_iommu_pool_collector.h"

static LIST_HEAD(alloc_list);
static wait_queue_head_t alloclist_waitqueue;
static DEFINE_SPINLOCK(alloc_list_lock);
static struct task_struct *mtk_iommu_alloclist_task;
static struct device *iommu_dev;

void add_collector(void (*alloc)(void *data),
			void *data)
{
	unsigned long flags;
	struct mtk_iommu_alloclist_item *item;

	item = kmalloc(sizeof(*item), GFP_KERNEL);

	INIT_LIST_HEAD(&item->list);
	item->alloc = alloc;
	item->data = data;
	spin_lock_irqsave(&alloc_list_lock, flags);
	list_add(&item->list, &alloc_list);
	spin_unlock_irqrestore(&alloc_list_lock, flags);
	wake_up(&alloclist_waitqueue);
}

static int alloc_one_item(void)
{
	unsigned long flags;
	struct mtk_iommu_alloclist_item *item;

	spin_lock_irqsave(&alloc_list_lock, flags);
	if (list_empty(&alloc_list)) {
		spin_unlock_irqrestore(&alloc_list_lock, flags);
		return 0;
	}
	item = list_first_entry(&alloc_list, struct mtk_iommu_alloclist_item, list);
	list_del(&item->list);
	spin_unlock_irqrestore(&alloc_list_lock, flags);

	item->alloc(item->data);
	kfree(item);
	return 1;
}

static bool is_list_empty(void)
{
	unsigned long flags;

	spin_lock_irqsave(&alloc_list_lock, flags);
	if (list_empty(&alloc_list)) {
		spin_unlock_irqrestore(&alloc_list_lock, flags);
		return true;
	}
	spin_unlock_irqrestore(&alloc_list_lock, flags);
	return false;
}

static int collector_thread(void *data)
{
	while (iommu_dev) {
		wait_event_freezable(alloclist_waitqueue,
				     !is_list_empty());
		while (alloc_one_item())
			;
	}

	return 0;
}

void renice_pool_collector(int status)
{
	sched_set_normal(mtk_iommu_alloclist_task, status);
}

int mtk_iommu_pool_collector_init(struct device *dev)
{
	iommu_dev = dev;
	init_waitqueue_head(&alloclist_waitqueue);
	mtk_iommu_alloclist_task = kthread_run(collector_thread, NULL,
				    "%s", "mtk_iommu-collector-worker");
	if (IS_ERR(mtk_iommu_alloclist_task)) {
		pr_err("Creating thread for iommu collector failed\n");
		return -1;
	}
	sched_set_normal(mtk_iommu_alloclist_task, -IOMMU_SCHED_PRIOR);
	return 0;
}

void mtk_iommu_pool_collector_exit(void)
{
	while (alloc_one_item())
		;
	iommu_dev = NULL;
}
