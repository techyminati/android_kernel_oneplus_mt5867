// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright (c) 2020 MediaTek Inc.
 */

#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/dma-heap.h>
#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "mtk_iommu_internal.h"
#include "mtk_iommu_dmaheap.h"
#include "mtk_iommu_dmaheap_ops.h"
#include "mtk_iommu_trace.h"

/* USE_DMA_UNMAP_OPS: 1, use dma_unmap_sgtable; 0, decrease sg_map_count directly */
#define USE_DMA_UNMAP_OPS 1

struct mtk_dmaheap_attachment {
	struct device *dev;
	struct sg_table *table;
	struct list_head list;
	struct mtk_dmaheap_buffer_info *info;
	bool mapped;
	bool uncached;
};

static struct sg_table *__dup_sg_table(struct sg_table *table)
{
	struct sg_table *new_table;
	int ret, i;
	struct scatterlist *sg, *new_sg;

	new_table = kzalloc(sizeof(*new_table), GFP_KERNEL);
	if (!new_table)
		return ERR_PTR(-ENOMEM);

	ret = sg_alloc_table(new_table, table->orig_nents, GFP_KERNEL);
	if (ret) {
		kfree(new_table);
		return ERR_PTR(-ENOMEM);
	}

	new_sg = new_table->sgl;
	for_each_sgtable_sg(table, sg, i) {
		sg_set_page(new_sg, sg_page(sg), sg->length, sg->offset);
		new_sg->dma_address = sg->dma_address;
		new_sg->dma_length = sg->length;
		new_sg = sg_next(new_sg);
	}

	return new_table;
}

int mtk_dmaheap_buf_attach(struct dma_buf *dmabuf,
			      struct dma_buf_attachment *attachment)
{
	struct mtk_dmaheap_buffer *buffer;
	struct mtk_dmaheap_attachment *a;
	struct mtk_dmaheap_buffer_info *info = NULL;
	struct sg_table *table;

	if (!dmabuf || !dmabuf->priv)
		return -EINVAL;

	buffer = (struct mtk_dmaheap_buffer *)dmabuf->priv;

	info = to_dmaheap_info(buffer);
	if (IS_ERR_OR_NULL(info))
		pr_err("[IOMMU][%s] cannot get dmaheap_buffer_info\n", __func__);

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;

	table = __dup_sg_table(&buffer->sg_table);
	if (IS_ERR(table)) {
		kfree(a);
		return -ENOMEM;
	}

	a->table = table;
	a->dev = attachment->dev;
	INIT_LIST_HEAD(&a->list);
	a->mapped = false;
	a->uncached = buffer->uncached;
	a->info = info;
	attachment->priv = a;

	mutex_lock(&buffer->lock);
	list_add(&a->list, &buffer->attachments);
	mutex_unlock(&buffer->lock);

	return 0;
}

void mtk_dmaheap_buf_detach(struct dma_buf *dmabuf,
			       struct dma_buf_attachment *attachment)
{
	struct mtk_dmaheap_buffer *buffer;
	struct mtk_dmaheap_attachment *a;

	if (!dmabuf || !dmabuf->priv || !attachment || !attachment->priv)
		return;

	buffer = (struct mtk_dmaheap_buffer *)dmabuf->priv;
	a = attachment->priv;

	mutex_lock(&buffer->lock);
	list_del(&a->list);
	mutex_unlock(&buffer->lock);

	sg_free_table(a->table);
	kfree(a->table);
	kfree(a);
}

struct sg_table *mtk_dmaheap_buf_map_dma_buf(struct dma_buf_attachment *attachment,
						enum dma_data_direction direction)
{
	struct mtk_dmaheap_attachment *a = attachment->priv;
	struct sg_table *table = a->table;
	int attr = 0;
	int ret;
	struct timespec64 tv0 = {0}, tv1 = {0};
	u32 elapsed_time = 0;

	if (a->uncached)
		attr = DMA_ATTR_SKIP_CPU_SYNC;

	ktime_get_real_ts64(&tv0);
	ret = dma_map_sgtable(attachment->dev, table, direction, attr);
	if (ret)
		return ERR_PTR(ret);
	ktime_get_real_ts64(&tv1);
	elapsed_time = (tv1.tv_sec - tv0.tv_sec) * USEC_PER_SEC +
			(tv1.tv_nsec - tv0.tv_nsec) / NSEC_PER_USEC;

	trace_mtk_iommu_dmaheap_dmabuf_map(
			TPS(__func__),
			dev_name(attachment->dev),
			attachment->dmabuf->size,
			attachment->dmabuf->exp_name,
			elapsed_time);
	a->mapped = true;
	return table;
}

void mtk_dmaheap_buf_unmap_dma_buf(struct dma_buf_attachment *attachment,
				      struct sg_table *table,
				      enum dma_data_direction direction)
{
	struct mtk_dmaheap_attachment *a = attachment->priv;
	struct timespec64 tv0 = {0}, tv1 = {0};
	u32 elapsed_time = 0;
#if USE_DMA_UNMAP_OPS
	int attr = 0;
#else
	struct mtk_dmaheap_buffer_info *info = a->info;
#endif

	if (!a->mapped) {
		pr_err("[IOMMU][%s][%d] not mapped, Bye. dev_name: %s, size: 0x%zx, exp_name: %s\n",
			__func__, current->pid, dev_name(attachment->dev),
			attachment->dmabuf->size, attachment->dmabuf->exp_name);
		return;
	}

	a->mapped = false;
	ktime_get_real_ts64(&tv0);

#if USE_DMA_UNMAP_OPS
	if (a->uncached)
		attr = DMA_ATTR_SKIP_CPU_SYNC;
	dma_unmap_sgtable(attachment->dev, table, direction, attr);
#else
	mutex_lock(&(info->handler->handle_lock));
	info->handler->sg_map_count--;
	mutex_unlock(&(info->handler->handle_lock));
#endif

	ktime_get_real_ts64(&tv1);
	elapsed_time = (tv1.tv_sec - tv0.tv_sec) * USEC_PER_SEC +
			(tv1.tv_nsec - tv0.tv_nsec) / NSEC_PER_USEC;

	trace_mtk_iommu_dmaheap_dmabuf_unmap(
			TPS(__func__),
			dev_name(attachment->dev),
			attachment->dmabuf->size,
			attachment->dmabuf->exp_name,
			elapsed_time);
}

int mtk_dmaheap_buf_begin_cpu_access(struct dma_buf *dmabuf,
						enum dma_data_direction direction)
{
	struct mtk_dmaheap_buffer *buffer;
	struct mtk_dmaheap_attachment *a;
	struct mtk_dmaheap_buffer_info *info = NULL;
	struct timespec64 tv0 = {0}, tv1 = {0};
	u32 elapsed_time = 0;
	bool synced = false;

	if (!dmabuf || !dmabuf->priv)
		return -EINVAL;

	buffer = (struct mtk_dmaheap_buffer *)dmabuf->priv;

	info = to_dmaheap_info(buffer);
	if (IS_ERR_OR_NULL(info))
		pr_err("[IOMMU][%s] cannot get dmaheap_buffer_info\n", __func__);

	ktime_get_real_ts64(&tv0);

	mutex_lock(&buffer->lock);

	if (buffer->vmap_cnt)
		invalidate_kernel_vmap_range(buffer->vaddr, buffer->len);

	if (!buffer->uncached) {
		list_for_each_entry(a, &buffer->attachments, list) {
			if (!a->mapped)
				continue;
			dma_sync_sgtable_for_cpu(a->dev, a->table, direction);
			synced = true;
		}

		/*
		 * sync for user space while no kernel driver attached.
		 */
		if (!synced && !(current->flags & PF_KTHREAD))
			__internal_direct_begin_cpu_access(info->handle, direction);
	}
	mutex_unlock(&buffer->lock);

	ktime_get_real_ts64(&tv1);
	elapsed_time = (tv1.tv_sec - tv0.tv_sec) * USEC_PER_SEC +
			(tv1.tv_nsec - tv0.tv_nsec) / NSEC_PER_USEC;

	trace_mtk_iommu_dmaheap_dmabuf_sync_begin(
			dma_heap_get_name(buffer->heap), buffer->len, info->handle, elapsed_time);
	return 0;
}

int mtk_dmaheap_buf_end_cpu_access(struct dma_buf *dmabuf,
					      enum dma_data_direction direction)
{
	struct mtk_dmaheap_buffer *buffer;
	struct mtk_dmaheap_attachment *a;
	struct mtk_dmaheap_buffer_info *info = NULL;
	struct timespec64 tv0 = {0}, tv1 = {0};
	u32 elapsed_time = 0;
	bool synced = false;

	if (!dmabuf || !dmabuf->priv)
		return -EINVAL;

	buffer = (struct mtk_dmaheap_buffer *)dmabuf->priv;

	info = to_dmaheap_info(buffer);
	if (IS_ERR_OR_NULL(info))
		pr_err("[IOMMU][%s] cannot get dmaheap_buffer_info\n", __func__);

	ktime_get_real_ts64(&tv0);

	mutex_lock(&buffer->lock);

	if (buffer->vmap_cnt)
		flush_kernel_vmap_range(buffer->vaddr, buffer->len);

	if (!buffer->uncached) {
		list_for_each_entry(a, &buffer->attachments, list) {
			if (!a->mapped)
				continue;
			dma_sync_sgtable_for_device(a->dev, a->table, direction);
			synced = true;
		}

		/*
		 * sync for user space while no kernel driver attached.
		 */
		if (!synced && !(current->flags & PF_KTHREAD))
			__internal_direct_end_cpu_access(info->handle, direction);
	}
	mutex_unlock(&buffer->lock);

	ktime_get_real_ts64(&tv1);
	elapsed_time = (tv1.tv_sec - tv0.tv_sec) * USEC_PER_SEC +
			(tv1.tv_nsec - tv0.tv_nsec) / NSEC_PER_USEC;

	trace_mtk_iommu_dmaheap_dmabuf_sync_end(
			dma_heap_get_name(buffer->heap), buffer->len, info->handle, elapsed_time);
	return 0;
}

int mtk_dmaheap_buf_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	int ret;
	struct mtk_dmaheap_buffer *buffer;
	struct sg_table *table;
	unsigned long addr = vma->vm_start;
	struct sg_page_iter piter;

	if (!dmabuf || !dmabuf->priv)
		return -EINVAL;

	buffer = (struct mtk_dmaheap_buffer *)dmabuf->priv;
	table = &buffer->sg_table;

	if (buffer->uncached)
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	for_each_sgtable_page(table, &piter, vma->vm_pgoff) {
		struct page *page = sg_page_iter_page(&piter);

		ret = remap_pfn_range(vma, addr, page_to_pfn(page), PAGE_SIZE,
				      vma->vm_page_prot);
		if (ret)
			return ret;
		addr += PAGE_SIZE;
		if (addr >= vma->vm_end)
			return 0;
	}
	return 0;
}

static void *mtk_dmaheap_buf_do_vmap(struct mtk_dmaheap_buffer *buffer)
{
	struct sg_table *table = &buffer->sg_table;
	int npages = PAGE_ALIGN(buffer->len) / PAGE_SIZE;
	struct page **pages = vmalloc(sizeof(struct page *) * npages);
	struct page **tmp = pages;
	struct sg_page_iter piter;
	pgprot_t pgprot = PAGE_KERNEL;
	void *vaddr;

	if (!pages)
		return ERR_PTR(-ENOMEM);

	if (buffer->uncached)
		pgprot = pgprot_writecombine(PAGE_KERNEL);

	for_each_sgtable_page(table, &piter, 0) {
		WARN_ON(tmp - pages >= npages);
		*tmp++ = sg_page_iter_page(&piter);
	}

	vaddr = vmap(pages, npages, VM_MAP, pgprot);
	vfree(pages);

	if (!vaddr)
		return ERR_PTR(-ENOMEM);

	return vaddr;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
int mtk_dmaheap_buf_vmap(struct dma_buf *dmabuf, struct iosys_map *map)
#else
int mtk_dmaheap_buf_vmap(struct dma_buf *dmabuf, struct dma_buf_map *map)
#endif
{
	void *vaddr;
	struct mtk_dmaheap_buffer *buffer;
	int ret = 0;


	if (!dmabuf || !dmabuf->priv)
		return -EINVAL;

	buffer = (struct mtk_dmaheap_buffer *)dmabuf->priv;

	mutex_lock(&buffer->lock);
	if (buffer->vmap_cnt) {
		buffer->vmap_cnt++;
		vaddr = buffer->vaddr;
		goto out;
	}

	vaddr = mtk_dmaheap_buf_do_vmap(buffer);
	if (IS_ERR(vaddr)) {
		ret = PTR_ERR(vaddr);
		goto out;
	}

	dma_buf_map_set_vaddr(map, vaddr);
	buffer->vaddr = vaddr;
	buffer->vmap_cnt++;
out:
	mutex_unlock(&buffer->lock);

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
void mtk_dmaheap_buf_vunmap(struct dma_buf *dmabuf, struct iosys_map *map)
#else
void mtk_dmaheap_buf_vunmap(struct dma_buf *dmabuf, struct dma_buf_map *map)
#endif
{
	struct mtk_dmaheap_buffer *buffer;

	if (!dmabuf || !dmabuf->priv)
		return;

	buffer = (struct mtk_dmaheap_buffer *)dmabuf->priv;

	mutex_lock(&buffer->lock);
	if (!--buffer->vmap_cnt) {
		vunmap(buffer->vaddr);
		buffer->vaddr = NULL;
	}
	mutex_unlock(&buffer->lock);
}
