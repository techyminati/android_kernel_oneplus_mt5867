// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright (c) 2020 MediaTek Inc.
 * Author: Joe Liu <joe.liu@mediatek.com>
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/dma-map-ops.h>
#include <linux/dma-direct.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/buffer_head.h>
#include <linux/of_reserved_mem.h>
#include <linux/dma-buf.h>
#include <linux/of_address.h>
#include <linux/sched/signal.h>
#include <linux/version.h>

#include "mtk-cma.h"
#include "cma.h"
extern int miuprotect_deleteKRange(unsigned long buffer_start_pa, unsigned long buffer_length);
extern int miuprotect_addKRange(unsigned long buffer_start_pa, unsigned long buffer_length);

#if IS_ENABLED(CONFIG_ION)
#include <linux/ion.h>

#define to_mtkcma_heap(x) container_of(x, struct mtkcma_ion_cma_heap, heap)

struct mtkcma_ion_cma_heap {
	struct ion_heap heap;
	struct cma *cma;
	struct device *owner_device;
	struct list_head list;
};
#endif

#if IS_ENABLED(CONFIG_DMABUF_HEAPS_CMA) || IS_ENABLED(CONFIG_DMABUF_HEAPS)
#include <linux/dma-heap.h>
#include <uapi/linux/dma-heap.h>

struct cma_heap {
	struct dma_heap *heap;
	struct cma *cma;
};

struct mtkcma_dmaheap {
	struct cma_heap cma_heap;
	struct device *owner_device;
	struct list_head list;
};

struct cma_heap_buffer {
	struct cma_heap *heap;
	struct list_head attachments;
	struct mutex lock;
	unsigned long len;
	struct page *cma_pages;
	struct page **pages;
	pgoff_t pagecount;
	int vmap_cnt;
	void *vaddr;
};

struct dma_heap_attachment {
	struct device *dev;
	struct sg_table table;
	struct list_head list;
	bool mapped;
};
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)
MODULE_IMPORT_NS(DMA_BUF);
#endif

#define CMA_RETRY_TIMEOUT_MS 8000
#define NULL_MAPPING_ADDRESS 0x0

static LIST_HEAD(mtkcma_cma_heap_device_list);
static DEFINE_MUTEX(mtkcma_cma_heap_device_mutex);
static DEFINE_MUTEX(mtkcma_cpu_bus_base_mutex);

u32 mtkcma_cpu_bus_base = -1;
EXPORT_SYMBOL(mtkcma_cpu_bus_base);

static inline struct cma *dev_get_cma_off_area(struct device *dev)
{
	if (dev && dev->cma_area)
		return dev->cma_area;
	return NULL;
}

static int count_cma_area_free_page_num(struct cma *counted_cma)
{
	int count_cma_free_page_count       = 0;
	int count_cma_free_start			= 0;
	int count_cma_bitmap_start_zero		= 0;
	int count_cma_bitmap_end_zero		= 0;

	pr_debug("cma_area having ");
	for (;;) {
		count_cma_bitmap_start_zero = find_next_zero_bit(
			counted_cma->bitmap, counted_cma->count,
				count_cma_free_start);

		if (count_cma_bitmap_start_zero >= counted_cma->count)
			break;

		count_cma_free_start = count_cma_bitmap_start_zero + 1;
		count_cma_bitmap_end_zero = find_next_bit(
			counted_cma->bitmap, counted_cma->count,
				count_cma_free_start);

		if (count_cma_bitmap_end_zero >= counted_cma->count) {
			count_cma_free_page_count +=
			(counted_cma->count - count_cma_bitmap_start_zero);
			break;
		}

		count_cma_free_page_count +=
		(count_cma_bitmap_end_zero - count_cma_bitmap_start_zero);

		count_cma_free_start = count_cma_bitmap_end_zero + 1;

		if (count_cma_free_start >= counted_cma->count)
			break;
	}
	pr_debug("%d free pages\n", count_cma_free_page_count);

	return count_cma_free_page_count;
}

static unsigned long cma_bitmap_pages_to_bits(const struct cma *cma,
						unsigned long pages)
{
	return ALIGN(pages, 1UL << cma->order_per_bit) >> cma->order_per_bit;
}

static void cma_clear_bitmap(struct cma *cma, unsigned long pfn,
			unsigned int count)
{
	unsigned long bitmap_no, bitmap_count;
	unsigned long flags;

	bitmap_no = (pfn - cma->base_pfn) >> cma->order_per_bit;
	bitmap_count = cma_bitmap_pages_to_bits(cma, count);

	spin_lock_irqsave(&cma->lock, flags);
	bitmap_clear(cma->bitmap, bitmap_no, bitmap_count);
	spin_unlock_irqrestore(&cma->lock, flags);
}

struct page *dma_alloc_at_from_contiguous_new(struct cma *cma, unsigned long count,
					unsigned int align, phys_addr_t at_addr)
{
	unsigned long mask, pfn, pageno, start = 0;
	struct page *page = NULL;
	int ret;
	size_t i;
	unsigned long timeout;
	unsigned long start_pfn = __phys_to_pfn(at_addr);
	struct acr_info dummy_info;

	pr_info("start_pfn is 0x%lX, count is %lu  cma %lx cma->count %lu\n",
			start_pfn, count, cma, cma->count);

	if (!cma || !cma->count || !count || (count > cma->count))
		return NULL;

	if (align > CONFIG_CMA_ALIGNMENT)
		align = CONFIG_CMA_ALIGNMENT;

	mask = (1 << align) - 1;

	if (start_pfn && start_pfn < cma->base_pfn)
		return NULL;
	start = start_pfn ? start_pfn - cma->base_pfn : start;

	pr_debug("%s(alloc %lu pages, at_addr %pap, start pfn 0x%lX)\n",
		__func__, count, &at_addr, start_pfn);
	pr_debug("Function = %s, Line = %d, find bit_map from 0x%lX\n",
		__PRETTY_FUNCTION__, __LINE__, start);
	pr_debug("[%s] Before %s \033[m", current->comm,
		__PRETTY_FUNCTION__);
	spin_lock_irq(&cma->lock);
	count_cma_area_free_page_num(cma);
	spin_unlock_irq(&cma->lock);

	spin_lock_irq(&cma->lock);
	timeout = jiffies + msecs_to_jiffies(CMA_RETRY_TIMEOUT_MS);

	pageno = bitmap_find_next_zero_area(cma->bitmap, cma->count,
					    start, count, mask);

	/* we want to force the allocation start pfn */
	if (pageno >= cma->count || (start_pfn && start != pageno)) {
		spin_unlock_irq(&cma->lock);
		goto alloc_finished;
	}
	bitmap_set(cma->bitmap, pageno, count);
	/*
	 * It's safe to drop the lock here. We've marked this region for
	 * our exclusive use. If the migration fails we will take the
	 * lock again and unmark it.
	 */
	spin_unlock_irq(&cma->lock);

	pfn = cma->base_pfn + pageno;
retry:
	ret = alloc_contig_range(pfn, pfn + count,
					MIGRATE_CMA, GFP_KERNEL, &dummy_info);
	if (ret == 0) {
		page = pfn_to_page(pfn);
	} else if (fatal_signal_pending(current)) {
		pr_err("Function = %s, cannot get cma_memory, get fatal_signal_pending\n",
			__PRETTY_FUNCTION__);
		pr_err("Function = %s, ret is %d\n",
			__PRETTY_FUNCTION__, ret);
		cma_clear_bitmap(cma, pfn, count);
	} else if (start_pfn && time_before(jiffies, timeout)) {
		pr_err("Function = %s, cannot get cma_memory, step_1\n",
					__PRETTY_FUNCTION__);
		pr_err("Function = %s, start_pfn is 0x%lX\n",
					__PRETTY_FUNCTION__, start_pfn);
		cond_resched();
		invalidate_bh_lrus();
		goto retry;
	} else if (ret != -EBUSY || start_pfn) {
		pr_err("Function = %s, cannot get cma_memory, step_2\n",
					__PRETTY_FUNCTION__);
		pr_err("Function = %s, ret is %d\n",
					__PRETTY_FUNCTION__, ret);
		cma_clear_bitmap(cma, pfn, count);
	} else {
		pr_err("Function = %s, cannot get cma_memory, step_3\n",
					__PRETTY_FUNCTION__);
		pr_err("Function = %s, ret is %d\n",
					__PRETTY_FUNCTION__, ret);
		cma_clear_bitmap(cma, pfn, count);
	}
alloc_finished:
	/*
	 * CMA can allocate multiple page blocks, which results in different
	 * blocks being marked with different tags. Reset the tags to ignore
	 * those page blocks.
	 */
	if (page) {
		for (i = 0; i < count; i++)
			page_kasan_tag_reset(page + i);
	}

	pr_debug("%s(): returned %p\n", __func__, page);

	pr_debug("[%s] After %s ",
		current->comm, __PRETTY_FUNCTION__);
	spin_lock_irq(&cma->lock);
	count_cma_area_free_page_num(cma);
	spin_unlock_irq(&cma->lock);

	return page;
}
EXPORT_SYMBOL(dma_alloc_at_from_contiguous_new);

static void *mtkcma_dma_alloc(struct device *dev, size_t size,
			dma_addr_t *dma_handle,
			gfp_t flags, unsigned long attrs)
{
	struct page *pages;
	void *ret;
	phys_addr_t start_addr, end_addr;
	struct cma *cma;
	u64 map_pfn;
	pgprot_t pgprot;
	bool do_miu_protect;
	unsigned long nr_pages = PAGE_ALIGN(size) >> PAGE_SHIFT;
	struct page **map_pages, **tmp;
	int i = 0;
	unsigned long miup_miu_addr;
	unsigned long miup_miu_size;

	cma = dev_get_cma_off_area(dev);
	if (!cma) {
		pr_emerg("%s(%d): get cma failed!\n", __func__, __LINE__);
		return ERR_PTR(-EFAULT);
	}

	start_addr = cma->base_pfn + (*dma_handle >> PAGE_SHIFT);
	start_addr = start_addr << PAGE_SHIFT;
	end_addr = start_addr + (nr_pages << PAGE_SHIFT);

	pr_info("dma: allocation by device: %s\n", dev_name(dev));

	if (attrs & 1 << IOMMU_CMA_ALLOC_BIT ||
		strstr(cma_get_name(cma), "default_cma") != NULL) {
		pages = cma_alloc(cma, nr_pages, 0, 1);
		do_miu_protect = false;
	}
	else {
		pr_info("from %pap to %pap\n", &start_addr, &end_addr);
		pages = dma_alloc_at_from_contiguous_new(cma, nr_pages, 0, start_addr);
		do_miu_protect = true;
	}

	if (!pages) {
		pr_emerg("Function = %s, no page\n", __PRETTY_FUNCTION__);
		*dma_handle = 0;
		return ERR_PTR(-ENOMEM);
	}

	*dma_handle = phys_to_dma(dev, page_to_phys(pages));

	map_pages = vmalloc(sizeof(struct page *) * nr_pages);
	if (!map_pages)
		return NULL;
	tmp = map_pages;
	map_pfn = page_to_pfn(pages);

	for (i = 0; i < nr_pages; i++) {
		*(tmp++) = __pfn_to_page(map_pfn);
		map_pfn++;
	}

	// see: ion_heap_map_kernel()
	if (attrs & DMA_ATTR_NO_KERNEL_MAPPING) {
		/* does not need kernel mapping */
		ret = NULL_MAPPING_ADDRESS;
	} else {
		if (attrs & DMA_ATTR_WRITE_COMBINE) {
			/* need kernel non-cache mapping */
			pgprot = pgprot_writecombine(PAGE_KERNEL);

			ret = vmap(map_pages, nr_pages, VM_MAP, pgprot);
		} else {
			/* need kernel non-cache mapping,
			 * however, cma region is pfn_valid,
			 * non-cache mapping is not supported
			 */
			pgprot = PAGE_KERNEL;

			if (!PageHighMem(pages))
				ret = page_address(pages);
			else
				ret = vmap(map_pages, nr_pages, VM_MAP, pgprot);
		}
	}
	vfree(map_pages);

#ifdef CONFIG_ARCH_DMA_ADDR_T_64BIT
	pr_info("result: *dma_handle is 0x%llX\n", *dma_handle);
#else
	pr_info("result: *dma_handle is 0x%X\n", *dma_handle);
#endif
	pr_info("result: ret_va is %p\n", ret);

	/* remove miu protect with miu_address */
	if (do_miu_protect) {
		miup_miu_addr = (unsigned long)(page_to_phys(pages));
		miup_miu_size = (unsigned long)(nr_pages << PAGE_SHIFT);
		miuprotect_deleteKRange(miup_miu_addr, miup_miu_size);
		//mtk_miup_req_kprot(miup_miu_addr, miup_miu_size);
	}

	return ret;
}

static void mtkcma_dma_free(struct device *dev, size_t size,
			void *vaddr, dma_addr_t dma_handle,
			unsigned long attrs)
{
	unsigned long miup_miu_addr;
	unsigned long miup_miu_size;
	phys_addr_t cma_phys_addr;
	unsigned long pfn;
	struct cma *cma;
	struct page *pages;
	bool do_miu_protect;

	pr_info("dma: free by device: %s\n", dev_name(dev));
#ifdef CONFIG_ARCH_DMA_ADDR_T_64BIT
	pr_info("from 0x%llX to 0x%llX\n", dma_handle, (dma_handle + size));
#else
	pr_info("from 0x%X to 0x%X\n", dma_handle, (dma_handle + size));
#endif
	pr_info("va is %p\n", vaddr);

	if (is_vmalloc_addr(vaddr))
		vunmap(vaddr);

	cma_phys_addr = dma_to_phys(dev, dma_handle);
	pfn = __phys_to_pfn(cma_phys_addr);
	cma = dev_get_cma_off_area(dev);
	pages = virt_to_page(phys_to_virt(cma_phys_addr));

	if (!cma || !pages) {
		pr_emerg("can not get cma_area or can not get freed_page, do not free\n");
		return;
	}

	if (pfn < cma->base_pfn || pfn >= cma->base_pfn + cma->count)
		return;

	if (strstr(cma_get_name(cma), "default_cma") != NULL)
		do_miu_protect = false;
	else
		do_miu_protect = true;

	/* add miu protect with miu_address*/
	if (do_miu_protect) {
		miup_miu_addr = (unsigned long)(cma_phys_addr);
		miup_miu_size = (unsigned long)(PAGE_ALIGN(size));
		miuprotect_addKRange(miup_miu_addr, miup_miu_size);
		//mtk_miup_rel_kprot(miup_miu_addr, miup_miu_size);
	}

	cma_release(cma, pages, PAGE_ALIGN(size) >> PAGE_SHIFT);
}

static void mtkcma_dma_sync_single_for_cpu(struct device *dev, dma_addr_t bus_addr,
				size_t size, enum dma_data_direction dir)
{
/* This casue loop 
[    9.314549][    C0]  mtkcma_dma_sync_single_for_cpu+0x14/0x24 [mtk_memory]
[    9.314554][    C0]  dma_sync_single_for_cpu+0x70/0x178
[    9.314557][    C0]  mtkcma_dma_sync_single_for_cpu+0x14/0x24 [mtk_memory]
[    9.314562][    C0]  dma_sync_single_for_cpu+0x70/0x178
[    9.314565][    C0]  mtkcma_dma_sync_single_for_cpu+0x14/0x24 [mtk_memory]
[    9.314570][    C0]  dma_sync_single_for_cpu+0x70/0x178
[    9.314573][    C0]  mtk_mmap_device_driver_probe+0x224/0x2e0 [mtk_memory]
since cma use the memory cpu can access directly, we shouldn't need to sync
*/
//	dma_sync_single_for_cpu(dev, bus_addr, size, dir);
}

static void mtkcma_dma_sync_single_for_device(struct device *dev,
				dma_addr_t bus_addr, size_t size, enum dma_data_direction dir)
{
//	dma_sync_single_for_device(dev, bus_addr, size, dir);
}

static const struct dma_map_ops mtkcma_dma_ops = {
	.alloc = mtkcma_dma_alloc,
	.free = mtkcma_dma_free,
	.sync_single_for_cpu = mtkcma_dma_sync_single_for_cpu,
	.sync_single_for_device = mtkcma_dma_sync_single_for_device,
};

#if IS_ENABLED(CONFIG_ION)
static int mtkcma_ion_cma_allocate(struct ion_heap *heap,
			struct ion_buffer *buffer,
			unsigned long len, unsigned long flags)
{
	struct mtkcma_ion_cma_heap *cma_heap = to_mtkcma_heap(heap);
	struct sg_table *table;
	struct page *pages;
	phys_addr_t start_addr;
	int ret;
	phys_addr_t end_addr;
	bool do_miu_protect;
	unsigned long size = PAGE_ALIGN(len);
	unsigned long nr_pages = size >> PAGE_SHIFT;
	unsigned long align = get_order(size);
	unsigned long miup_miu_addr;
	unsigned long miup_miu_size;

	start_addr = cma_heap->cma->base_pfn + (flags >> PAGE_SHIFT);
	start_addr = start_addr << PAGE_SHIFT;
	end_addr = start_addr + (nr_pages << PAGE_SHIFT);

	if (align > CONFIG_CMA_ALIGNMENT)
		align = CONFIG_CMA_ALIGNMENT;

	if (strstr(cma_get_name(cma_heap->cma), "default_cma") != NULL) {
		pages = cma_alloc(cma_heap->cma, nr_pages, 0, 1);
		do_miu_protect = false;
	} else {
		pages = dma_alloc_at_from_contiguous_new(cma_heap->cma,
					nr_pages, 0, start_addr);
		do_miu_protect = true;
	}

	if (!pages) {
		pr_emerg("Function = %s, %s no page\n",
					__PRETTY_FUNCTION__, heap->name);
		return -ENOMEM;
	}

	if (PageHighMem(pages)) {
		unsigned long nr_clear_pages = nr_pages;
		struct page *page = pages;

		while (nr_clear_pages > 0) {
			void *vaddr = kmap_atomic(page);

			memset(vaddr, 0, PAGE_SIZE);
			kunmap_atomic(vaddr);
			page++;
			nr_clear_pages--;
		}
	} else {
		memset(page_address(pages), 0, size);
	}

	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		goto err;

	ret = sg_alloc_table(table, 1, GFP_KERNEL);
	if (ret)
		goto free_mem;

	sg_set_page(table->sgl, pages, size, 0);
	sg_dma_address(table->sgl) = page_to_phys(pages);
	sg_dma_len(table->sgl) = size;

	buffer->priv_virt = pages;
	buffer->sg_table = table;

	/* remove miu protect with miu_address*/
	if (do_miu_protect) {
		miup_miu_addr = (unsigned long)(page_to_phys(pages));
		miup_miu_size = (unsigned long)(nr_pages << PAGE_SHIFT);
		miuprotect_deleteKRange(miup_miu_addr, miup_miu_size);
		//mtk_miup_req_kprot(miup_miu_addr, miup_miu_size);
	}

	return 0;

free_mem:
	kfree(table);
err:
	cma_release(cma_heap->cma, pages, nr_pages);
	return -ENOMEM;
}

static void mtkcma_ion_cma_free(struct ion_buffer *buffer)
{
	unsigned long miup_miu_addr;
	unsigned long miup_miu_size;
	bool do_miu_protect;
	struct mtkcma_ion_cma_heap *cma_heap = to_mtkcma_heap(buffer->heap);
	struct page *pages = buffer->priv_virt;
	unsigned long nr_pages = PAGE_ALIGN(buffer->size) >> PAGE_SHIFT;

	if (strstr(cma_get_name(cma_heap->cma), "default_cma") != NULL)
		do_miu_protect = false;
	else
		do_miu_protect = true;

	/* add miu protect with miu_address*/
	if (do_miu_protect) {
		miup_miu_addr = (unsigned long)(page_to_phys(pages));
		miup_miu_size = ((unsigned long)nr_pages << PAGE_SHIFT);
		miuprotect_addKRange(miup_miu_addr, miup_miu_size);
		//mtk_miup_rel_kprot(miup_miu_addr, miup_miu_size);
	}

	cma_release(cma_heap->cma, pages, nr_pages);
	/* release sg table */
	sg_free_table(buffer->sg_table);
	kfree(buffer->sg_table);
}

static struct ion_heap_ops mtkcma_ion_cma_ops = {
	.allocate = mtkcma_ion_cma_allocate,
	.free = mtkcma_ion_cma_free,
};

#if IS_ENABLED(CONFIG_ION)
static int mtk_cma_device_initialize_ion(struct device *cma_device)
{
	struct ion_heap *heap;
	struct mtkcma_ion_cma_heap *cma_heap;
	struct cma *cma;

	if (!cma_device->cma_area) {
		pr_emerg("Function = %s, cma_device has no cma_area\n",
				__PRETTY_FUNCTION__);
		return -EINVAL;
	}

	pr_info("        for: device %s, cma: %s\n",
			dev_name(cma_device), cma_device->cma_area->name);
	cma = cma_device->cma_area;
	show_cma_info(cma);

	/* copy from __ion_add_cma_heaps(cma) */
	cma_heap = kzalloc(sizeof(*cma_heap), GFP_KERNEL);

	if (!cma_heap)
		return -ENOMEM;

	cma_heap->owner_device = cma_device;
	cma_heap->heap.ops = &mtkcma_ion_cma_ops;

	/*
	 * get device from private heaps data, later it will be
	 * used to make the link with reserved CMA memory
	 */
	cma_heap->cma = cma;
	cma_heap->heap.type = ION_HEAP_TYPE_CUSTOM;
	heap = &cma_heap->heap;

	heap->name = dev_name(cma_device);

	pr_info("        add mtkcma ion_heap with name %s\n", heap->name);
	ion_device_add_heap(heap);

	set_dma_ops(cma_device, &mtkcma_dma_ops);

	cma_device->coherent_dma_mask = (phys_addr_t)~0;

	mutex_lock(&mtkcma_cma_heap_device_mutex);
	list_add(&cma_heap->list, &mtkcma_cma_heap_device_list);
	mutex_unlock(&mtkcma_cma_heap_device_mutex);

	return 0;
}
#endif

unsigned long ion_get_mtkcma_buffer_info(int share_fd)
{
	struct dma_buf *show_info_dma_buf;
	struct ion_buffer *buffer;
	struct ion_heap *heap;
	unsigned long buffer_pfn;

	 // do fget, so file->f_count++
	show_info_dma_buf = dma_buf_get(share_fd);
	if (IS_ERR_OR_NULL(show_info_dma_buf)) {
		pr_emerg("Function = %s, no dma_buf\n",
			__PRETTY_FUNCTION__);

		return -EINVAL;
	}
	buffer = show_info_dma_buf->priv;
	heap = buffer->heap;

	if (heap->type != ION_HEAP_TYPE_CUSTOM) {
		pr_emerg("Function = %s, not mtk heap\n",
			__PRETTY_FUNCTION__);
		dma_buf_put(show_info_dma_buf);

		return -EINVAL;
	}

	buffer_pfn = page_to_pfn((struct page *)buffer->priv_virt);

	dma_buf_put(show_info_dma_buf); // release dma_buf, so file->f_count--

	return buffer_pfn;
}
EXPORT_SYMBOL(ion_get_mtkcma_buffer_info);
#endif

#if IS_ENABLED(CONFIG_DMABUF_HEAPS_CMA) || IS_ENABLED(CONFIG_DMABUF_HEAPS)
static int cma_heap_attach(struct dma_buf *dmabuf,
			   struct dma_buf_attachment *attachment)
{
	struct cma_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a;
	int ret;

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;

	ret = sg_alloc_table_from_pages(&a->table, buffer->pages,
					buffer->pagecount, 0,
					buffer->pagecount << PAGE_SHIFT,
					GFP_KERNEL);
	if (ret) {
		kfree(a);
		return ret;
	}

	a->dev = attachment->dev;
	INIT_LIST_HEAD(&a->list);
	a->mapped = false;

	attachment->priv = a;

	mutex_lock(&buffer->lock);
	list_add(&a->list, &buffer->attachments);
	mutex_unlock(&buffer->lock);

	return 0;
}

static void cma_heap_detach(struct dma_buf *dmabuf,
			    struct dma_buf_attachment *attachment)
{
	struct cma_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a = attachment->priv;

	mutex_lock(&buffer->lock);
	list_del(&a->list);
	mutex_unlock(&buffer->lock);

	sg_free_table(&a->table);
	kfree(a);
}

static struct sg_table *cma_heap_map_dma_buf(struct dma_buf_attachment *attachment,
					     enum dma_data_direction direction)
{
	struct dma_heap_attachment *a = attachment->priv;
	struct sg_table *table = &a->table;
	int attrs = attachment->dma_map_attrs;
	int ret;

	ret = dma_map_sgtable(attachment->dev, table, direction, attrs);
	if (ret)
		return ERR_PTR(-ENOMEM);
	a->mapped = true;
	return table;
}

static void cma_heap_unmap_dma_buf(struct dma_buf_attachment *attachment,
				   struct sg_table *table,
				   enum dma_data_direction direction)
{
	struct dma_heap_attachment *a = attachment->priv;
	int attrs = attachment->dma_map_attrs;

	a->mapped = false;
	dma_unmap_sgtable(attachment->dev, table, direction, attrs);
}

static int cma_heap_dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
					     enum dma_data_direction direction)
{
	struct cma_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a;

	mutex_lock(&buffer->lock);

	if (buffer->vmap_cnt)
		invalidate_kernel_vmap_range(buffer->vaddr, buffer->len);

	list_for_each_entry(a, &buffer->attachments, list) {
		if (!a->mapped)
			continue;
		dma_sync_sgtable_for_cpu(a->dev, &a->table, direction);
	}
	mutex_unlock(&buffer->lock);

	return 0;
}

static int cma_heap_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
					   enum dma_data_direction direction)
{
	struct cma_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a;

	mutex_lock(&buffer->lock);

	if (buffer->vmap_cnt)
		flush_kernel_vmap_range(buffer->vaddr, buffer->len);

	list_for_each_entry(a, &buffer->attachments, list) {
		if (!a->mapped)
			continue;
		dma_sync_sgtable_for_device(a->dev, &a->table, direction);
	}
	mutex_unlock(&buffer->lock);

	return 0;
}

static vm_fault_t cma_heap_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct cma_heap_buffer *buffer = vma->vm_private_data;

	if (vmf->pgoff > buffer->pagecount)
		return VM_FAULT_SIGBUS;

	vmf->page = buffer->pages[vmf->pgoff];
	get_page(vmf->page);

	return 0;
}

static const struct vm_operations_struct dma_heap_vm_ops = {
	.fault = cma_heap_vm_fault,
};

static int cma_heap_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct cma_heap_buffer *buffer = dmabuf->priv;

	if ((vma->vm_flags & (VM_SHARED | VM_MAYSHARE)) == 0)
		return -EINVAL;

	vma->vm_ops = &dma_heap_vm_ops;
	vma->vm_private_data = buffer;

	return 0;
}

static void *cma_heap_do_vmap(struct cma_heap_buffer *buffer)
{
	void *vaddr;

	vaddr = vmap(buffer->pages, buffer->pagecount, VM_MAP, PAGE_KERNEL);
	if (!vaddr)
		return ERR_PTR(-ENOMEM);

	return vaddr;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
static int cma_heap_vmap(struct dma_buf *dmabuf, struct iosys_map *map)
#else
static int cma_heap_vmap(struct dma_buf *dmabuf, struct dma_buf_map *map)
#endif
{
	struct cma_heap_buffer *buffer = dmabuf->priv;
	void *vaddr;
	int ret = 0;

	mutex_lock(&buffer->lock);
	if (buffer->vmap_cnt) {
		buffer->vmap_cnt++;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
		iosys_map_set_vaddr(map, buffer->vaddr);
#else
		dma_buf_map_set_vaddr(map, buffer->vaddr);
#endif
		goto out;
	}

	vaddr = cma_heap_do_vmap(buffer);
	if (IS_ERR(vaddr)) {
		ret = PTR_ERR(vaddr);
		goto out;
	}
	buffer->vaddr = vaddr;
	buffer->vmap_cnt++;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
	iosys_map_set_vaddr(map, buffer->vaddr);
#else
	dma_buf_map_set_vaddr(map, buffer->vaddr);
#endif
out:
	mutex_unlock(&buffer->lock);

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
static void cma_heap_vunmap(struct dma_buf *dmabuf, struct iosys_map *map)
#else
static void cma_heap_vunmap(struct dma_buf *dmabuf, struct dma_buf_map *map)
#endif
{
	struct cma_heap_buffer *buffer = dmabuf->priv;

	mutex_lock(&buffer->lock);
	if (!--buffer->vmap_cnt) {
		vunmap(buffer->vaddr);
		buffer->vaddr = NULL;
	}
	mutex_unlock(&buffer->lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
	iosys_map_clear(map);
#else
	dma_buf_map_clear(map);
#endif
}

static void cma_heap_dma_buf_release(struct dma_buf *dmabuf)
{
	struct cma_heap_buffer *buffer = dmabuf->priv;
	struct cma_heap *cma_heap = buffer->heap;

	if (buffer->vmap_cnt > 0) {
		WARN(1, "%s: buffer still mapped in the kernel\n", __func__);
		vunmap(buffer->vaddr);
		buffer->vaddr = NULL;
	}

	/* free page list */
	kfree(buffer->pages);
	/* release memory */
	cma_release(cma_heap->cma, buffer->cma_pages, buffer->pagecount);
	kfree(buffer);
}

static const struct dma_buf_ops cma_heap_buf_ops = {
	.attach = cma_heap_attach,
	.detach = cma_heap_detach,
	.map_dma_buf = cma_heap_map_dma_buf,
	.unmap_dma_buf = cma_heap_unmap_dma_buf,
	.begin_cpu_access = cma_heap_dma_buf_begin_cpu_access,
	.end_cpu_access = cma_heap_dma_buf_end_cpu_access,
	.mmap = cma_heap_mmap,
	.vmap = cma_heap_vmap,
	.vunmap = cma_heap_vunmap,
	.release = cma_heap_dma_buf_release,
};

static struct dma_buf *cma_heap_allocate(struct dma_heap *heap,
					 unsigned long len,
					 unsigned long fd_flags,
					 unsigned long heap_flags)
{
	struct cma_heap *cma_heap = dma_heap_get_drvdata(heap);
	struct cma_heap_buffer *buffer;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	size_t size = PAGE_ALIGN(len);
	pgoff_t pagecount = size >> PAGE_SHIFT;
	unsigned long align = get_order(size);
	struct page *cma_pages;
	struct dma_buf *dmabuf;
	int ret = -ENOMEM;
	pgoff_t pg;

	if (!cma_heap)
		return ERR_PTR(-EINVAL);

	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&buffer->attachments);
	mutex_init(&buffer->lock);
	buffer->len = size;

	if (align > CONFIG_CMA_ALIGNMENT)
		align = CONFIG_CMA_ALIGNMENT;

	cma_pages = cma_alloc(cma_heap->cma, pagecount, align, false);
	if (!cma_pages)
		goto free_buffer;

	/* Clear the cma pages */
	if (PageHighMem(cma_pages)) {
		unsigned long nr_clear_pages = pagecount;
		struct page *page = cma_pages;

		while (nr_clear_pages > 0) {
			void *vaddr = kmap_atomic(page);

			memset(vaddr, 0, PAGE_SIZE);
			kunmap_atomic(vaddr);
			/*
			 * Avoid wasting time zeroing memory if the process
			 * has been killed by SIGKILL
			 */
			if (fatal_signal_pending(current))
				goto free_cma;
			page++;
			nr_clear_pages--;
		}
	} else {
		memset(page_address(cma_pages), 0, size);
	}

	buffer->pages = kmalloc_array(pagecount, sizeof(*buffer->pages), GFP_KERNEL);
	if (!buffer->pages) {
		ret = -ENOMEM;
		goto free_cma;
	}

	for (pg = 0; pg < pagecount; pg++)
		buffer->pages[pg] = &cma_pages[pg];

	buffer->cma_pages = cma_pages;
	buffer->heap = cma_heap;
	buffer->pagecount = pagecount;

	/* create the dmabuf */
	exp_info.exp_name = dma_heap_get_name(heap);
	exp_info.ops = &cma_heap_buf_ops;
	exp_info.size = buffer->len;
	exp_info.flags = fd_flags;
	exp_info.priv = buffer;
	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto free_pages;
	}
	return dmabuf;

free_pages:
	kfree(buffer->pages);
free_cma:
	cma_release(cma_heap->cma, cma_pages, pagecount);
free_buffer:
	kfree(buffer);

	return ERR_PTR(ret);
}

static const struct dma_heap_ops cma_heap_ops = {
	.allocate = cma_heap_allocate,
};

#if !IS_ENABLED(CONFIG_ION)
static int mtk_cma_device_initialize_dmaheap(struct device *cma_device)
{
	struct cma *cma;
	struct mtkcma_dmaheap *mtkcma_heap;
	struct dma_heap_export_info exp_info;

	if (!cma_device->cma_area) {
		pr_emerg("Function = %s, cma_device has no cma_area\n",
				__PRETTY_FUNCTION__);
		return -EINVAL;
	}

	pr_info("        for: device %s, cma: %s\n",
			dev_name(cma_device), cma_device->cma_area->name);
	cma = cma_device->cma_area;
	show_cma_info(cma);

	/* copy from __add_cma_heap in drivers/dma-buf/heaps/cma_heap.c*/
	mtkcma_heap = kzalloc(sizeof(*mtkcma_heap), GFP_KERNEL);
	if (!mtkcma_heap)
		return -ENOMEM;
	mtkcma_heap->cma_heap.cma = cma;

	exp_info.name = dev_name(cma_device);	// dmaheap name should be unique
	exp_info.ops = &cma_heap_ops;
	exp_info.priv = &mtkcma_heap->cma_heap;

	pr_info("        add mtkcma dma_heap with name %s\n", exp_info.name);
	mtkcma_heap->cma_heap.heap = dma_heap_add(&exp_info);
	if (IS_ERR(mtkcma_heap->cma_heap.heap)) {
		int ret = PTR_ERR(mtkcma_heap->cma_heap.heap);

		kfree(mtkcma_heap);
		return ret;
	}
	mtkcma_heap->owner_device = cma_device;

	set_dma_ops(cma_device, &mtkcma_dma_ops);

	cma_device->coherent_dma_mask = (phys_addr_t)~0;

	mutex_lock(&mtkcma_cma_heap_device_mutex);
	list_add(&mtkcma_heap->list, &mtkcma_cma_heap_device_list);
	mutex_unlock(&mtkcma_cma_heap_device_mutex);

	return 0;
}
#endif

unsigned long dmaheap_get_mtkcma_buffer_info(int share_fd)
{
	struct dma_buf *show_info_dma_buf;
	struct cma_heap_buffer *buffer;
	unsigned long buffer_pfn;

	 // do fget, so file->f_count++
	show_info_dma_buf = dma_buf_get(share_fd);
	if (IS_ERR_OR_NULL(show_info_dma_buf)) {
		pr_emerg("Function = %s, no dma_buf\n",
			__PRETTY_FUNCTION__);

		return -EINVAL;
	}
	buffer = show_info_dma_buf->priv;

	buffer_pfn = page_to_pfn((struct page *)buffer->cma_pages);

	dma_buf_put(show_info_dma_buf); // release dma_buf, so file->f_count--

	return buffer_pfn;
}
EXPORT_SYMBOL(dmaheap_get_mtkcma_buffer_info);
#endif

static int mtkcma_get_bus_address_info(u32 *addr)
{
	struct device_node *target_memory_np = NULL;
	uint32_t len = 0;
	__be32 *p = NULL;

	target_memory_np = of_find_node_by_name(NULL, "memory_info");
	if (!target_memory_np)
		return -ENODEV;

	p = (__be32 *)of_get_property(target_memory_np, "cpu_emi0_base", &len);
	if (p != NULL) {
		*addr = be32_to_cpup(p);
		of_node_put(target_memory_np);
		p = NULL;
	} else {
		pr_err("can not find cpu_emi0_base info\n");
		of_node_put(target_memory_np);
		return -EINVAL;
	}
	return 0;
}

void show_cma_info(struct cma *show_cma)
{
	pr_info("        cma_base_pfn is 0x%lX\n",
			show_cma->base_pfn);
	pr_info("        cma_page_count is 0x%lX\n",
			show_cma->count);
	pr_info("        cma_name is %s\n",
			show_cma->name);

}
EXPORT_SYMBOL(show_cma_info);

int mtkcma_presetting(struct device *dev, int pool_index)
{
	pr_emerg("please use mtkcma_presetting_v2, instead");
	return 0;
}
EXPORT_SYMBOL(mtkcma_presetting);

int mtkcma_presetting_v2(struct device *dev, int pool_index)
{
	int ret;
#if IS_ENABLED(CONFIG_ION)
	struct mtkcma_ion_cma_heap *cma_heap, *tmp;
#else
	struct mtkcma_dmaheap *cma_heap, *tmp;
#endif

	mutex_lock(&mtkcma_cma_heap_device_mutex);
	list_for_each_entry_safe(cma_heap, tmp, &mtkcma_cma_heap_device_list, list) {
		if (cma_heap->owner_device == dev) {
			pr_emerg("%s is already registered, pass it\n", dev_name(dev));
			mutex_unlock(&mtkcma_cma_heap_device_mutex);
			return 0;
		}
	}
	mutex_unlock(&mtkcma_cma_heap_device_mutex);

	// this will set dev->cma_area
	ret = of_reserved_mem_device_init_by_idx(dev, dev->of_node, pool_index);
	if (ret) {
		pr_emerg("(sti) %s: of_reserved_mem_device_init_by_idx error!!\n",
			dev_name(dev));
		return ret;
	}

	pr_info("    Start mtk_cma_device_initialize\n");
#if IS_ENABLED(CONFIG_ION)
	ret = mtk_cma_device_initialize_ion(dev);
#else
	ret = mtk_cma_device_initialize_dmaheap(dev);
#endif
	mutex_lock(&mtkcma_cpu_bus_base_mutex);
	mtkcma_get_bus_address_info(&mtkcma_cpu_bus_base);
	mutex_unlock(&mtkcma_cpu_bus_base_mutex);
	pr_info("    End mtk_cma_device_initialize, ret is %d\n",
				ret);

	return ret;
}
EXPORT_SYMBOL(mtkcma_presetting_v2);

int mtkcma_presetting_utopia(struct device *dev, int pool_index)
{
	int ret;

	// this will set dev->cma_area
	ret = of_reserved_mem_device_init_by_idx(dev, dev->of_node, pool_index);
	if (ret) {
		pr_emerg("(utopia) %s: of_reserved_mem_device_init_by_idx error!!\n",
			dev_name(dev));
		return ret;
	}

	set_dma_ops(dev, &mtkcma_dma_ops);
	dev->coherent_dma_mask = (phys_addr_t)~0;

	return ret;
}

MODULE_AUTHOR("MTK");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("mtk-memory");
