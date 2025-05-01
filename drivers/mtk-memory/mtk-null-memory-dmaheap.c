// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright (c) 2022 MediaTek Inc.
 */

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/dma-direct.h>
#include <linux/dma-heap.h>
#include <linux/err.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/buffer_head.h>
#include <linux/dma-buf.h>
#include <linux/of_reserved_mem.h>
#include <linux/of_fdt.h>
#include <linux/of.h>
#include <linux/bitmap.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/arm-smccc.h>
#include <linux/vmalloc.h>

#include "mtk-cma.h"
#include "cma.h"
#include "mtk-null-memory-dmaheap.h"

#define NULL_MEMORY_SIZE 0x10000000
#define NULL_MEMORY_CNT 1

static struct mtk_nullmemory_heap *nullmemory_heap[NULL_MEMORY_CNT];

#define to_mtk_nullmemory_heap(x) container_of(x, struct mtk_nullmemory_heap, heap)

#define nullmem_mtk_smc(cmd, val, res) \
	arm_smccc_smc(MTK_SIP_NULLMEM_CONTROL, cmd, val, 0, 0, 0, 0, 0, &(res))

#define nullmem_mtk_riu_ctrl(res, set_bit) \
	nullmem_mtk_smc(NULLMEM_MTK_SIP_RIU_ERROR_MASK_CTRL, set_bit, res)

static bool is_nullheap_created;

struct mtk_nullmemory_heap {
	unsigned long start_bus_address;
	unsigned long buffer_size;
	unsigned long page_cnt;
	struct dma_heap *heap;
	unsigned long *bitmap;
	spinlock_t lock;
	int add_heap_result;
	unsigned long remain_size;
	char *heap_name;
};

static bool fake_bitmap_clear(struct mtk_nullmemory_heap *fake_heap, const struct page *pages,
			unsigned int count)
{
	unsigned long bus_address;
	unsigned long start_bus_address;
	unsigned long end_bus_address;
	unsigned long bitmap_no;

	start_bus_address = fake_heap->start_bus_address;
	end_bus_address = fake_heap->start_bus_address + fake_heap->buffer_size;
	bus_address = page_to_phys(pages);

	if (bus_address < start_bus_address)
		return false;

	if (bus_address >= end_bus_address)
		return false;

	VM_BUG_ON(bus_address + (count << PAGE_SHIFT) > end_bus_address);

	bitmap_no = (bus_address - start_bus_address) >> PAGE_SHIFT;

	spin_lock(&fake_heap->lock);
	bitmap_clear(fake_heap->bitmap, bitmap_no, count);
	spin_unlock(&fake_heap->lock);
	return true;
}

static void update_error_response_mask(struct mtk_nullmemory_heap *fake_heap)
{
	struct arm_smccc_res res;

	if (fake_heap->buffer_size > fake_heap->remain_size) {
		// set mask bit to be 1
		nullmem_mtk_riu_ctrl(res, 1);
	} else if (fake_heap->buffer_size == fake_heap->remain_size) {
		// set mask bit to be 0
		nullmem_mtk_riu_ctrl(res, 0);
	} else {
		pr_emerg("un-known case, panic\n");
		panic("nullmem: update error response mask error\n");
	}
}

static struct sg_table *dup_sg_table(struct sg_table *table)
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
		new_sg = sg_next(new_sg);
	}

	return new_table;
}

static int mtk_nullmem_dmabuf_ops_attach(struct dma_buf *dmabuf,
					struct dma_buf_attachment *attachment)
{
	struct mtk_nullmem_buffer *buffer;
	struct mtk_nullmem_attachment *a;
	struct sg_table *table;

	if (!dmabuf || !dmabuf->priv)
		return -EINVAL;

	buffer = (struct mtk_nullmem_buffer *)dmabuf->priv;

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;

	table = dup_sg_table(&buffer->sg_table);
	if (IS_ERR(table)) {
		kfree(a);
		return -ENOMEM;
	}

	a->table = table;
	a->dev = attachment->dev;
	INIT_LIST_HEAD(&a->list);
	a->mapped = false;
	a->uncached = buffer->uncached;
	attachment->priv = a;

	mutex_lock(&buffer->lock);
	list_add(&a->list, &buffer->attachments);
	mutex_unlock(&buffer->lock);

	return 0;
}

static void mtk_nullmem_dmabuf_ops_detach(struct dma_buf *dmabuf,
					struct dma_buf_attachment *attachment)
{
	struct mtk_nullmem_buffer *buffer;
	struct mtk_nullmem_attachment *a;

	if (!dmabuf || !dmabuf->priv || !attachment || !attachment->priv)
		return;

	buffer = (struct mtk_nullmem_buffer *)dmabuf->priv;
	a = (struct mtk_nullmem_attachment *)attachment->priv;

	mutex_lock(&buffer->lock);
	list_del(&a->list);
	mutex_unlock(&buffer->lock);

	sg_free_table(a->table);
	kfree(a->table);
	kfree(a);
}

static struct sg_table *mtk_nullmem_dmabuf_ops_map_dma_buf(struct dma_buf_attachment *attachment,
						enum dma_data_direction direction)
{
	struct mtk_nullmem_attachment *a = attachment->priv;
	struct sg_table *table = a->table;
	int attr = 0;
	int ret;

	if (a->uncached)
		attr = DMA_ATTR_SKIP_CPU_SYNC;

	ret = dma_map_sgtable(attachment->dev, table, direction, attr);
	if (ret)
		return ERR_PTR(ret);

	a->mapped = true;
	return table;
}

static void mtk_nullmem_dmabuf_ops_unmap_dma_buf(struct dma_buf_attachment *attachment,
				      struct sg_table *table,
				      enum dma_data_direction direction)
{
	struct mtk_nullmem_attachment *a = attachment->priv;
	int attr = 0;

	if (a->uncached)
		attr = DMA_ATTR_SKIP_CPU_SYNC;
	a->mapped = false;
	dma_unmap_sgtable(attachment->dev, table, direction, attr);
}

static int mtk_nullmem_dmabuf_ops_begin_cpu_access(struct dma_buf *dmabuf,
						enum dma_data_direction direction)
{
	struct mtk_nullmem_buffer *buffer;
	struct mtk_nullmem_attachment *a;

	if (!dmabuf || !dmabuf->priv)
		return -EINVAL;

	buffer = (struct mtk_nullmem_buffer *)dmabuf->priv;

	mutex_lock(&buffer->lock);

	if (buffer->vmap_cnt)
		invalidate_kernel_vmap_range(buffer->vaddr, buffer->len);

	if (!buffer->uncached) {
		list_for_each_entry(a, &buffer->attachments, list) {
			if (!a->mapped)
				continue;
			dma_sync_sgtable_for_cpu(a->dev, a->table, direction);
		}
	}
	mutex_unlock(&buffer->lock);

	return 0;
}

static int mtk_nullmem_dmabuf_ops_end_cpu_access(struct dma_buf *dmabuf,
					      enum dma_data_direction direction)
{
	struct mtk_nullmem_buffer *buffer;
	struct mtk_nullmem_attachment *a;

	if (!dmabuf || !dmabuf->priv)
		return -EINVAL;

	buffer = (struct mtk_nullmem_buffer *)dmabuf->priv;

	mutex_lock(&buffer->lock);

	if (buffer->vmap_cnt)
		flush_kernel_vmap_range(buffer->vaddr, buffer->len);

	if (!buffer->uncached) {
		list_for_each_entry(a, &buffer->attachments, list) {
			if (!a->mapped)
				continue;
			dma_sync_sgtable_for_device(a->dev, a->table, direction);
		}
	}
	mutex_unlock(&buffer->lock);

	return 0;
}

static int mtk_nullmem_dmabuf_ops_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct mtk_nullmem_buffer *buffer;
	struct sg_table *table;
	unsigned long addr = vma->vm_start;
	struct sg_page_iter piter;
	int ret;

	if (!dmabuf || !dmabuf->priv)
		return -EINVAL;

	buffer = (struct mtk_nullmem_buffer *)dmabuf->priv;
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

static void *mtk_nullmem_do_vmap(struct mtk_nullmem_buffer *buffer)
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
static int mtk_nullmem_dmabuf_ops_vmap(struct dma_buf *dmabuf, struct iosys_map *map)
#else
static int mtk_nullmem_dmabuf_ops_vmap(struct dma_buf *dmabuf, struct dma_buf_map *map)
#endif
{
	struct mtk_nullmem_buffer *buffer;
	void *vaddr;

	if (!dmabuf || !dmabuf->priv)
		return -EINVAL;

	buffer = (struct mtk_nullmem_buffer *) dmabuf->priv;

	mutex_lock(&buffer->lock);
	if (buffer->vmap_cnt) {
		buffer->vmap_cnt++;
		vaddr = buffer->vaddr;
		goto out;
	}

	vaddr = mtk_nullmem_do_vmap(buffer);
	if (IS_ERR(vaddr))
		goto out;

	map->vaddr = vaddr;
	buffer->vaddr = vaddr;
	buffer->vmap_cnt++;
out:
	mutex_unlock(&buffer->lock);

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
static void mtk_nullmem_dmabuf_ops_vunmap(struct dma_buf *dmabuf, struct iosys_map *map)
#else
static void mtk_nullmem_dmabuf_ops_vunmap(struct dma_buf *dmabuf, struct dma_buf_map *map)
#endif
{
	struct mtk_nullmem_buffer *buffer;

	if (!dmabuf || !dmabuf->priv)
		return;

	buffer = (struct mtk_nullmem_buffer *)dmabuf->priv;

	mutex_lock(&buffer->lock);
	if (!--buffer->vmap_cnt) {
		vunmap(buffer->vaddr);
		buffer->vaddr = NULL;
	}
	mutex_unlock(&buffer->lock);
}

static void mtk_nullmem_dmabuf_ops_release(struct dma_buf *dmabuf)
{
	struct mtk_nullmemory_heap *fake_heap;
	struct mtk_nullmem_buffer *buffer;
	struct dma_heap *heap;
	struct page *pages;
	struct scatterlist *sg;
	struct sg_table *table;
	unsigned long nr_pages = 0;

	if (!dmabuf || !dmabuf->priv)
		return;

	nr_pages = PAGE_ALIGN(dmabuf->size) >> PAGE_SHIFT;

	buffer = (struct mtk_nullmem_buffer *)dmabuf->priv;
	heap = buffer->heap;
	if (!heap) {
		pr_err("%s: dma_heap is NULL\n", __func__);
		return;
	}

	fake_heap = dma_heap_get_drvdata(heap);
	if (!fake_heap) {
		pr_err("%s: private data is NULL\n", __func__);
		return;
	}

	table = &buffer->sg_table;
	sg = table->sgl;
	pages = sg_page(sg);
	fake_bitmap_clear(fake_heap, pages, nr_pages);
	/* release sg table */
	sg_free_table(table);
	kfree(buffer);
	dmabuf->priv = NULL;

	spin_lock(&fake_heap->lock);
	fake_heap->remain_size += nr_pages << PAGE_SHIFT;
	update_error_response_mask(fake_heap);
	spin_unlock(&fake_heap->lock);
}

static const struct dma_buf_ops mtk_nullmem_dmabuf_ops = {
	.attach =  mtk_nullmem_dmabuf_ops_attach,
	.detach =  mtk_nullmem_dmabuf_ops_detach,
	.map_dma_buf =  mtk_nullmem_dmabuf_ops_map_dma_buf,
	.unmap_dma_buf =  mtk_nullmem_dmabuf_ops_unmap_dma_buf,
	.begin_cpu_access =  mtk_nullmem_dmabuf_ops_begin_cpu_access,
	.end_cpu_access =  mtk_nullmem_dmabuf_ops_end_cpu_access,
	.mmap =  mtk_nullmem_dmabuf_ops_mmap,
	.vmap =  mtk_nullmem_dmabuf_ops_vmap,
	.vunmap =  mtk_nullmem_dmabuf_ops_vunmap,
	.release = mtk_nullmem_dmabuf_ops_release
};


static struct dma_buf *mtk_nullmemory_allocate(struct dma_heap *heap,
				unsigned long len,
				unsigned long fd_flags,
				unsigned long heap_flags)
{
	struct mtk_nullmemory_heap *fake_heap;
	struct mtk_nullmem_buffer *buffer;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	unsigned long size = PAGE_ALIGN(len);
	struct dma_buf *dmabuf;
	struct sg_table *table;
	int ret;
	unsigned long nr_pages = size >> PAGE_SHIFT;
	unsigned long pageno;
	struct page *pages;

	fake_heap = dma_heap_get_drvdata(heap);
	if (!fake_heap)
		return ERR_PTR(-EINVAL);

	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&buffer->attachments);
	mutex_init(&buffer->lock);
	buffer->heap = heap;
	buffer->len = len;
	buffer->uncached = true;

	spin_lock(&fake_heap->lock);
	if (size > fake_heap->remain_size) {
		pr_emerg("Function = %s, no enough nullmem size\n",
				__PRETTY_FUNCTION__);
		spin_unlock(&fake_heap->lock);
		ret = -ENOMEM;
		goto free_buffer;
	}

	pageno = bitmap_find_next_zero_area_off(fake_heap->bitmap, fake_heap->page_cnt,
		0, nr_pages, 0, 0);

	if (pageno >= fake_heap->page_cnt) {
		spin_unlock(&fake_heap->lock);
		pr_emerg("Function = %s, no page\n",
				__PRETTY_FUNCTION__);
		ret = -ENOMEM;
		goto free_buffer;
	}
	bitmap_set(fake_heap->bitmap, pageno, nr_pages);
	spin_unlock(&fake_heap->lock);

	pages = pfn_to_page(__phys_to_pfn(fake_heap->start_bus_address) + pageno);

	table = &buffer->sg_table;
	ret = sg_alloc_table(table, 1, GFP_KERNEL);
	if (ret)
		goto err;

	sg_set_page(table->sgl, pages, size, 0);

	/* create the dmabuf */
	exp_info.exp_name = dma_heap_get_name(heap);
	exp_info.ops = &mtk_nullmem_dmabuf_ops;
	exp_info.size = len;
	exp_info.flags = fd_flags;
	exp_info.priv = buffer;
	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto free_mem;
	}

	spin_lock(&fake_heap->lock);
	fake_heap->remain_size -= size;
	update_error_response_mask(fake_heap);
	spin_unlock(&fake_heap->lock);

	return dmabuf;

free_mem:
	sg_free_table(table);
err:
	fake_bitmap_clear(fake_heap, pages, nr_pages);
free_buffer:
	kfree(buffer);

	return ERR_PTR(ret);
}

static struct dma_heap_ops mtk_nullmemory_ops = {
	.allocate = mtk_nullmemory_allocate,
};

int mtk_nullmemory_dmaheap_create(void)
{
	struct dma_heap_export_info exp_info;
	int i;
	unsigned long start_bus_address;
	unsigned long buffer_size;
	int ret;
	struct device_node *np = NULL;
	__be32 *p, *endp = NULL;
	uint32_t len = 0;

	/* we assume that each nullmemory is 256MB */
	int bitmap_size = BITS_TO_LONGS(NULL_MEMORY_SIZE >> PAGE_SHIFT) * sizeof(long);

	if (is_nullheap_created)
		return 0;

	for (i = 0; i < NULL_MEMORY_CNT; i++) {
		np = of_find_node_by_type(np, "mtk-nullmem");
		if (np == NULL) {
			pr_err("[%d] not find device node\033[m\n", i);
			return 0;
		}

		p = (__be32 *)of_get_property(np, "reg", &len);
		if (p != NULL) {
			endp = p + (len / sizeof(__be32));

			while ((endp - p) >=
				(root_addr_cells + root_size_cells)) {
				start_bus_address =
					mtk_mem_next_cell(root_addr_cells, (const __be32 **)&p);
				buffer_size =
					mtk_mem_next_cell(root_size_cells, (const __be32 **)&p);
			}
		} else {
			pr_err("can not find memory info reg, name is %s\n",
				np->name);
			of_node_put(np);
			ret = -EINVAL;
			goto nullmem_error_case;
		}
		of_node_put(np);
		nullmemory_heap[i] = kzalloc(sizeof(struct mtk_nullmemory_heap), GFP_KERNEL);

		if (IS_ERR(nullmemory_heap[i])) {
			pr_emerg("Function = %s, no nullmemory_heap\n", __PRETTY_FUNCTION__);
			ret = -ENOMEM;
			goto nullmem_error_case;
		}

		nullmemory_heap[i]->add_heap_result = -1;
		nullmemory_heap[i]->start_bus_address = start_bus_address;
		nullmemory_heap[i]->buffer_size = buffer_size;
		nullmemory_heap[i]->remain_size = buffer_size;
		nullmemory_heap[i]->bitmap = kzalloc(bitmap_size, GFP_KERNEL);
		nullmemory_heap[i]->page_cnt = NULL_MEMORY_SIZE >> PAGE_SHIFT;
		spin_lock_init(&nullmemory_heap[i]->lock);

		if (!nullmemory_heap[i]->bitmap) {
			pr_emerg("Function = %s, no bitmap\n", __PRETTY_FUNCTION__);
			ret = -ENOMEM;
			goto nullmem_error_case;
		}

		exp_info.ops = &mtk_nullmemory_ops;
		nullmemory_heap[i]->heap_name =
				kzalloc(sizeof(char) * MTK_NULLMEM_DMABUF_NAME_SIZE, GFP_KERNEL);
		if (!nullmemory_heap[i]->heap_name) {
			pr_emerg("Function = %s, heap_name alloc failed\n", __func__);
			ret = -ENOMEM;
			goto nullmem_error_case;
		}
		scnprintf(nullmemory_heap[i]->heap_name, MTK_NULLMEM_DMABUF_NAME_SIZE,
                          	"mtk_%s", np->name);
		exp_info.name = nullmemory_heap[i]->heap_name;
		exp_info.priv = nullmemory_heap[i];
		nullmemory_heap[i]->heap = dma_heap_add(&exp_info);
		if (IS_ERR(nullmemory_heap[i]->heap)) {
			ret = PTR_ERR(nullmemory_heap[i]->heap);
			goto nullmem_error_case;
		}
		dma_coerce_mask_and_coherent(dma_heap_get_dev(nullmemory_heap[i]->heap),
						DMA_BIT_MASK(MTK_NULLMEM_DMA_MASK));
		mb(); /* make sure we only set allocate after dma_mask is set */
		pr_emerg("add null memory dma_heap with name %s\n",
			exp_info.name);
		pr_emerg("    range from 0x%lX to 0x%lX\n\n\n",
			start_bus_address, (start_bus_address + buffer_size));
	}

	is_nullheap_created = true;
	return 0;

nullmem_error_case:
	pr_emerg("fail, do nullmem_error_case\n");
	for (i = 0; i < NULL_MEMORY_CNT; i++) {
		if (nullmemory_heap[i]) {
			kfree(nullmemory_heap[i]->bitmap);

			if (nullmemory_heap[i]->add_heap_result == 0)
				dma_heap_put(nullmemory_heap[i]->heap);
			kfree(nullmemory_heap[i]);
		}
	}
	return ret;
}
EXPORT_SYMBOL(mtk_nullmemory_dmaheap_create);

unsigned long dma_get_nullmem_buffer_info(int share_fd)
{
	struct dma_buf *dmabuf;
	struct mtk_nullmem_buffer *buffer;
	struct page *pages;
	struct sg_table *table;
	struct scatterlist *sg;
	unsigned long buffer_pfn;

	dmabuf = dma_buf_get(share_fd);
	if (!dmabuf || !dmabuf->priv) {
		pr_emerg("Function = %s, no dma_buf\n",
			__PRETTY_FUNCTION__);
		return -EINVAL;
	}

	buffer = (struct mtk_nullmem_buffer *)dmabuf->priv;

	table = &buffer->sg_table;
	sg = table->sgl;
	pages = sg_page(sg);
	buffer_pfn = page_to_pfn(pages);

	dma_buf_put(dmabuf);

	return buffer_pfn;
}
EXPORT_SYMBOL(dma_get_nullmem_buffer_info);

int is_nullmem_dma_heap(struct dma_buf *dmabuf)
{
	return dmabuf->ops == &mtk_nullmem_dmabuf_ops;
}
