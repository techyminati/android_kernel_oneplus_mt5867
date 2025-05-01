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
#include "mtk_iommu_defer_free.h"

#define IOMMU_SCHED_PRIOR 30
static LIST_HEAD(free_list);
static wait_queue_head_t freelist_waitqueue;
static DEFINE_SPINLOCK(free_list_lock);
static struct task_struct *mtk_iommu_freelist_task;
static struct device *iommu_dev;

void deferred_iommu_free(void (*free)(void *data),
			void *data)
{
	unsigned long flags;
	struct deferred_iommu_freelist_item *item;

	item = kmalloc(sizeof(*item), GFP_KERNEL);

	INIT_LIST_HEAD(&item->list);
	item->free = free;
	item->data = data;
	spin_lock_irqsave(&free_list_lock, flags);
	list_add(&item->list, &free_list);
	spin_unlock_irqrestore(&free_list_lock, flags);
	wake_up(&freelist_waitqueue);
}

static int free_one_item(void)
{
	unsigned long flags;
	struct deferred_iommu_freelist_item *item;

	spin_lock_irqsave(&free_list_lock, flags);
	if (list_empty(&free_list)) {
		spin_unlock_irqrestore(&free_list_lock, flags);
		return 0;
	}
	item = list_first_entry(&free_list, struct deferred_iommu_freelist_item, list);
	list_del(&item->list);
	spin_unlock_irqrestore(&free_list_lock, flags);

	item->free(item->data);
	kfree(item);
	return 1;
}

static bool is_list_empty(void)
{
	unsigned long flags;

	spin_lock_irqsave(&free_list_lock, flags);
	if (list_empty(&free_list)) {
		spin_unlock_irqrestore(&free_list_lock, flags);
		return true;
	}
	spin_unlock_irqrestore(&free_list_lock, flags);
	return false;
}

bool flush_free_list(void)
{
	bool is_empty = is_list_empty();

	while (free_one_item())
		;

	return !is_empty;
}

static int deferred_free_thread(void *data)
{
	while (iommu_dev) {
		wait_event_freezable(freelist_waitqueue,
				     !is_list_empty());
		while (free_one_item())
			;
	}

	return 0;
}

int defer_free_init(struct device *dev)
{
	struct sched_param param = { .sched_priority = IOMMU_SCHED_PRIOR };

	iommu_dev = dev;
	init_waitqueue_head(&freelist_waitqueue);
	mtk_iommu_freelist_task = kthread_run(deferred_free_thread, NULL,
				    "%s", "mtk_iommu-deferred-free-worker");
	if (IS_ERR(mtk_iommu_freelist_task)) {
		pr_err("Creating thread for deferred free failed\n");
		return -1;
	}
	sched_setscheduler(mtk_iommu_freelist_task, SCHED_RR, &param);
	return 0;
}

void defer_free_exit(void)
{
	while (free_one_item())
		;
	iommu_dev = NULL;
}
