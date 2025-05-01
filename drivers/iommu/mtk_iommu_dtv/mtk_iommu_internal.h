/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright (c) 2020 MediaTek Inc.
 */

#ifndef __MTK_IOMMU_INTERNAL_H_
#define __MTK_IOMMU_INTERNAL_H_
#include <linux/spinlock.h>
#include "mtk_iommu_dtv.h"
#include "mtk_iommu_of.h"
#include "mtk_iommu_mixed_mma.h"

extern u32 dbg_level;
extern u32 ratio_x_100;
extern u32 pool_water_mark;
extern int en_lv2_carv;

enum {
	E_LOG_ALERT = 3,	/* alloc + free */
	E_LOG_CRIT,		/* alloc + free + ops + util */
	E_LOG_NOTICE,		/* alloc + free + ops + util + map + unmap */
	E_LOG_INFO,		/* alloc + free + ops + util + map + unmap + sync */
	E_LOG_DEBUG,		/* verbose */
};

#define IOMMU_DEBUG_INFO(_loglevel, fmt, args...)	do {				\
	if (_loglevel <= dbg_level)							\
		pr_info("[IOMMU][%s][%d][tgid:%d][pid:%d] " fmt,			\
			__func__, __LINE__, current->tgid, current->pid, ## args);	\
} while (0)

#define IOMMU_DEBUG(_loglevel, fmt, args...)	do {					\
	if (_loglevel <= dbg_level)							\
		pr_emerg("[IOMMU][%s][%d][tgid:%d][pid:%d] " fmt,			\
			__func__, __LINE__, current->tgid, current->pid, ## args);	\
} while (0)

static inline int get_ratio(void)
{
	return ratio_x_100;
}

static inline unsigned int get_pool_water_mark(void)
{
	return pool_water_mark;
}

unsigned int get_carv_size(void);

int __mma_callback_register(struct mma_callback *mma_cb);

int get_iommu_data(struct mtk_dtv_iommu_data **data);

int get_mem_cust_policy_info(struct mem_cust_policy_info **info);

void get_curr_cma_heap_size(u64 *cma_size);

int get_curr_buftag_size(const char *buf_tag, unsigned int *size);

void *__mtk_iommu_alloc_attrs(struct device *dev, size_t size,
		dma_addr_t *dma_addr, gfp_t flag, unsigned long attrs);

void __mtk_iommu_free_attrs(struct device *dev,
		size_t size, void *cpu_addr,
		dma_addr_t handle, unsigned long attrs);

void __free_internal(struct mtk_iommu_buf_handle *buf_handle);

void __do_TEEMap_internal(struct mtk_iommu_buf_handle *handle);

int iommud_misc_register(struct mtk_dtv_iommu_data *data);

int seal_register(struct device *dev);

void __internal_direct_begin_cpu_access(dma_addr_t iova, enum dma_data_direction dir);

void __internal_direct_end_cpu_access(dma_addr_t iova, enum dma_data_direction dir);

static inline void _update_gfp_mask(gfp_t *gfp_mask)
{
	*gfp_mask &= ~__GFP_HIGHMEM;
#ifdef CONFIG_ZONE_DMA32
	*gfp_mask |= GFP_DMA32;
#elif defined(CONFIG_ZONE_DMA)
	*gfp_mask |= GFP_DMA;
#else
	*gfp_mask |= __GFP_HIGHMEM;
#endif
}

static atomic_t serial_num = ATOMIC_INIT(0);

static inline struct mtk_iommu_buf_handle *__mtk_iommu_create_buf_handle(u32 length,
						const char *buf_tag)
{

	struct mtk_iommu_buf_handle *buf_handle = NULL;

	buf_handle = kzalloc(sizeof(*buf_handle), GFP_KERNEL);
	if (!buf_handle)
		return NULL;

	buf_handle->length = length;
	if (buf_tag) {
		strncpy(buf_handle->buf_tag, buf_tag, MAX_NAME_SIZE);
		buf_handle->buf_tag[MAX_NAME_SIZE - 1] = '\0';
	}
	buf_handle->pid = current->pid;
	buf_handle->tgid = current->tgid;
	scnprintf(buf_handle->comm, sizeof(buf_handle->comm),
			"%s", current->comm);
	buf_handle->kvaddr = NULL;
	buf_handle->serial = atomic_inc_return(&serial_num);
	buf_handle->entry = NULL;
	buf_handle->tee_map = TEE_MAP_DEFAULT;
	mutex_init(&buf_handle->handle_lock);

	return buf_handle;
}

static inline struct mtk_iommu_buf_handle *__mtk_iommu_find_name(dma_addr_t name,
			struct mtk_dtv_iommu_data *data)
{
	struct mtk_iommu_buf_handle *buf_handle = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&(data->buf_lock), flags);
	buf_handle = idr_find(&data->global_name_idr, (unsigned long)name);
	if (IS_ERR_OR_NULL(buf_handle)) {
		spin_unlock_irqrestore(&(data->buf_lock), flags);
		return NULL;
	}
	spin_unlock_irqrestore(&(data->buf_lock), flags);

	return buf_handle;
}

static inline struct mtk_iommu_buf_handle *__mtk_iommu_find_buf_handle(dma_addr_t addr,
			struct mtk_dtv_iommu_data *data)
{
	struct mtk_iommu_buf_handle *buf_handle = NULL;
	unsigned long flags = 0;

	if (!addr)
		return NULL;

	spin_lock_irqsave(&(data->buf_lock), flags);
	list_for_each_entry(buf_handle,
		&(data->buf_list_head), buf_list_node) {
		if (buf_handle->addr <= addr && buf_handle->addr + buf_handle->length > addr) {
			spin_unlock_irqrestore(&(data->buf_lock), flags);
			return buf_handle;
		}
	}
	spin_unlock_irqrestore(&(data->buf_lock), flags);

	return NULL;
}

static inline struct mtk_iommu_space_handle *__mtk_iommu_find_space_handle(
		const char *space_tag, struct mtk_dtv_iommu_data *data)
{
	struct mtk_iommu_space_handle *handle = NULL;
	unsigned long flags = 0;

	if (!space_tag)
		return NULL;

	spin_lock_irqsave(&(data->buf_lock), flags);
	list_for_each_entry(handle, &(data->space_list_head),
				list_node) {
		if (!strncmp(handle->data.space_tag, space_tag,
				MAX_NAME_SIZE)) {
			spin_unlock_irqrestore(&(data->buf_lock), flags);
			return handle;
		}
	}
	spin_unlock_irqrestore(&(data->buf_lock), flags);
	return NULL;
}

static inline struct mtk_iommu_buf_handle *__mtk_iommu_find_kva(void *kva,
			struct mtk_dtv_iommu_data *data)
{
	struct mtk_iommu_buf_handle *buf_handle = NULL;
	unsigned long flags = 0;

	if (!kva)
		return NULL;

	spin_lock_irqsave(&(data->buf_lock), flags);
	list_for_each_entry(buf_handle,
		&(data->buf_list_head), buf_list_node) {
		if (buf_handle->kvaddr == kva) {
			spin_unlock_irqrestore(&(data->buf_lock), flags);
			return buf_handle;
		}
	}
	spin_unlock_irqrestore(&(data->buf_lock), flags);

	return NULL;
}

static inline struct mtk_iommu_buf_handle *__mtk_iommu_find_page(void *page,
			struct mtk_dtv_iommu_data *data)
{
	struct mtk_iommu_buf_handle *buf_handle = NULL;
	unsigned long flags = 0;

	if (!page)
		return NULL;

	spin_lock_irqsave(&(data->buf_lock), flags);
	list_for_each_entry(buf_handle,
		&(data->buf_list_head), buf_list_node) {
		if (buf_handle->sgt && sg_page(buf_handle->sgt->sgl) == page) {
			spin_unlock_irqrestore(&(data->buf_lock), flags);
			return buf_handle;
		}
	}
	spin_unlock_irqrestore(&(data->buf_lock), flags);

	return NULL;
}


static inline bool has_buf_handle(struct mtk_iommu_buf_handle *buf_handle,
			struct mtk_dtv_iommu_data *data, bool remove)
{
	struct mtk_iommu_buf_handle *tmp = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&(data->buf_lock), flags);
	list_for_each_entry(tmp, &(data->buf_list_head), buf_list_node) {
		if (tmp == buf_handle) {
			if (remove)
				list_del(&buf_handle->buf_list_node);
			spin_unlock_irqrestore(&(data->buf_lock), flags);
			return true;

		}
	}
	spin_unlock_irqrestore(&(data->buf_lock), flags);
	return false;
}

static inline int __mtk_iommu_get_space_tag(unsigned int buf_tag,
			char **space_tag, struct mtk_dtv_iommu_data *data)
{
	int i;
	struct mtk_iommu_space_handle *handle = NULL;
	unsigned long flags = 0;

	buf_tag = buf_tag & BUFTAGMASK;
	*space_tag = NULL;
	if (list_empty(&(data->space_list_head)))
		return 0;

	spin_lock_irqsave(&(data->buf_lock), flags);
	list_for_each_entry(handle, &(data->space_list_head), list_node) {
		for (i = 0; i < handle->data.buf_tag_num; i++) {
			if (buf_tag == handle->data.buf_tag_array[i]) {
				*space_tag = handle->data.space_tag;
				spin_unlock_irqrestore(&(data->buf_lock), flags);
				return 0;
			}
		}
	}
	spin_unlock_irqrestore(&(data->buf_lock), flags);

	return 0;
}
#endif
