// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright (c) 2020 MediaTek Inc.
 */
#include <linux/list.h>
#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/dma-heap.h>
#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/sched/signal.h>
#include <linux/dma-direct.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/of_reserved_mem.h>
#include <linux/of_address.h>
#include <linux/genalloc.h>
#include <linux/platform_device.h>
#include <linux/of_platform.h>
#include <linux/sizes.h>
#include <asm/page.h>

#include "mtk_iommu_page_pool.h"
#include "mtk_iommu_dmaheap.h"
#include "mtk_iommu_carveout_dmaheap.h"
#include "mtk_iommu_sys_dmaheap.h"
#include "mtk_iommu_dmaheap_ops.h"
#include "mtk_iommu_dmaheap_name.h"
#include "mtk_iommu_trace.h"
#include "mtk_iommu_internal.h"
#include "mtk_iommu_agile_dmaheap.h"

#define IOMMU_CARVEOUT_ALIGN	SZ_1M

static const unsigned int orders[NUM_ORDERS] = {8, 4, 0};
static struct device *carv_dev;

struct mtk_dma_carveout_heap {
	struct dma_heap *heap;
	struct dma_heap *uc_heap;
	struct gen_pool *pool;
	phys_addr_t pa;
	size_t size;
};

struct iommu_carveout_node {
	struct list_head list;
	struct page *page;
	unsigned long len;
};

unsigned int get_carv_size(void)
{
	struct mtk_dma_carveout_heap *carv;
	struct dma_heap *dmaheap;

	dmaheap = dma_heap_find(MTK_CARVEOUT_DMAHEAP_UC);
	if (!dmaheap) {
		pr_info("[IOMMU] find [%s] fail\n", MTK_CARVEOUT_DMAHEAP_UC);
		return 0;
	}
	carv = dma_heap_get_drvdata(dmaheap);
	dma_heap_put(dmaheap);
	if (!carv) {
		pr_info("[IOMMU] carv null private data\n");
		return 0;
	}

	return carv->size;

}

static inline bool is_carveout_range(unsigned long carv_base,
		unsigned long carv_len, struct page *page)
{
	unsigned long ba;

	WARN_ON(!carv_base || !page);

	ba = (unsigned long)page_to_phys(page);
	return (ba >= carv_base && ba < (carv_base + carv_len));
}

// free buffer immediately
static void carv_heap_dma_buf_release(struct dma_buf *dmabuf)
{
	int i, j;
	struct mtk_dmaheap_buffer_info *info;
	struct mtk_dmaheap_buffer *buffer;
	struct sg_table *table;
	struct scatterlist *sg;
	struct dma_heap *heap;
	struct mtk_dma_carveout_heap *carv;

	if (!dmabuf || !dmabuf->priv) {
		pr_err("%s: dmabuf get wrong\n", __func__);
		return;
	}

	buffer = (struct mtk_dmaheap_buffer *)dmabuf->priv;
	info = to_dmaheap_info(buffer);
	if (WARN_ON(info->magic != IOMMU_DMAHEAP_MAGIC)) {
		pr_err("%s: dmabuf is not from dma-heaps\n", __func__);
		return;
	}

	heap = buffer->heap;
	if (!heap) {
		pr_err("%s: dma_heap is NULL\n", __func__);
		return;
	}

	carv = dma_heap_get_drvdata(heap);
	if (!carv) {
		pr_err("%s: private data is gone\n", __func__);
		return;
	}

	table = &buffer->sg_table;
	for_each_sg(table->sgl, sg, table->orig_nents, i) {
		struct page *page = sg_page(sg);

		if (is_carveout_range(carv->pa, carv->size, page)) {
			if (!buffer->uncached) {
				dma_sync_single_for_device(carv_dev, page_to_phys(page),
						sg->length, DMA_BIDIRECTIONAL);
				dma_sync_single_for_cpu(carv_dev, page_to_phys(page),
						sg->length, DMA_BIDIRECTIONAL);
			}
			gen_pool_free(carv->pool, page_to_phys(page), sg->length);
		} else {
			for (j = 0; j < NUM_ORDERS; j++) {
				if (compound_order(page) == orders[j]) {
					mtk_iommu_dmabuf_page_pool_free(agile_pools[j],
							page, buffer->uncached);
					break;
				}
			}
		}
	}

	sg_free_table(table);
	kfree(info);
	dmabuf->priv = NULL;
}

static const struct dma_buf_ops carv_dmaheap_buf_ops = {
	.attach = mtk_dmaheap_buf_attach,
	.detach = mtk_dmaheap_buf_detach,
	.map_dma_buf = mtk_dmaheap_buf_map_dma_buf,
	.unmap_dma_buf = mtk_dmaheap_buf_unmap_dma_buf,
	.begin_cpu_access = mtk_dmaheap_buf_begin_cpu_access,
	.end_cpu_access = mtk_dmaheap_buf_end_cpu_access,
	.mmap = mtk_dmaheap_buf_mmap,
	.vmap = mtk_dmaheap_buf_vmap,
	.vunmap = mtk_dmaheap_buf_vunmap,
	.release = carv_heap_dma_buf_release,	// self impl
};

static struct page *alloc_largest_available(unsigned long size,
					    unsigned int max_order,
					    bool uncached)
{
	struct page *page;
	unsigned int i;

	for (i = 0; i < NUM_ORDERS; i++) {
		if (size <  (PAGE_SIZE << orders[i]))
			continue;

		if (max_order < orders[i])
			continue;
		page = mtk_iommu_dmabuf_page_pool_alloc(agile_pools[i], uncached);
		if (!page)
			continue;

		return page;
	}
	return NULL;
}

static int alloc_from_buddy(struct list_head *pages,
			size_t *remaining, unsigned long flags,
			unsigned int *max_order, bool uncached)
{
	int i = 0;
	struct page *page;
	int carv_sys = !!get_ratio();
	struct iommu_carveout_node *node;

	// FIXME: update gfp_mask as lowmem

	while (*remaining > 0) {
		page = alloc_largest_available(*remaining, *max_order, uncached);
		if (!page) {
			pr_err("%s: alloc_pages fail\n", __func__);
			return -ENOMEM;
		}
		*max_order = compound_order(page);
		if (carv_sys)
			list_add_tail(&page->lru, pages);
		else {
			node = kzalloc(sizeof(struct iommu_carveout_node),
				GFP_KERNEL);
			if (!node) {
				__free_pages(page, compound_order(page));
				pr_err("%s: kzalloc fail\n", __func__);
				return -ENOMEM;
			}
			node->len = page_size(page);
			node->page = page;
			INIT_LIST_HEAD(&node->list);
			list_add_tail(&node->list, pages);
		}
		*remaining -= page_size(page);
		i++;

		pr_debug("%s: alloc 0x%lx+%lx from buddy sys\n",
				__func__, (unsigned long)page_to_phys(page),
				(unsigned long)page_size(page));
	}

	return i;
}

static int alloc_from_resv_mem(struct gen_pool *pool, struct list_head *pages,
			size_t *remaining, bool uncached)
{
	int i = 0, j = 0;
	unsigned long pa;
	size_t len, len2, sys_total = 0;
	int ret;
	int current_times = 1;
	int carv_sys = !!get_ratio();
	struct iommu_carveout_node *node;
	struct page *page;
	unsigned int max_order = orders[0];

	// TODO: how to pre-determine the size from carv or sys
	while (*remaining && *remaining >= IOMMU_CARVEOUT_ALIGN * carv_sys) {
		len = min_t(size_t, *remaining, IOMMU_CARVEOUT_ALIGN);
		pa = gen_pool_alloc(pool, len);
		if (!pa) {
			pr_warn("%s: carveout mem not enough\n", __func__);
			break;
		}

		if (offset_in_page(pa)) {
			pr_err("%s: pa is not page aligned\n", __func__);
			gen_pool_free(pool, pa, len);
			return -EINVAL;
		}
		page = phys_to_page(pa);
		if (carv_sys)
			list_add_tail(&page->lru, pages);
		else {
			node = kzalloc(sizeof(struct iommu_carveout_node),
				GFP_KERNEL);
			if (!node) {
				gen_pool_free(pool, pa, len);
				return -ENOMEM;
			}
			node->len = len;
			node->page = page;
			INIT_LIST_HEAD(&node->list);
			list_add_tail(&node->list, pages);
		}
		*remaining -= len;
		i++;

		pr_debug("%s: alloc 0x%lx+%zx from carveout\n", __func__, pa, len);

		if (get_ratio() <= 0 || current_times - get_ratio() != 0) {
			current_times++;
			continue;
		} else
			current_times = 1;

		len = min_t(size_t, *remaining, IOMMU_CARVEOUT_ALIGN);
		len2 = len;
		ret = alloc_from_buddy(pages, &len2, 0, &max_order, uncached);
		if (ret < 0)
			return ret;
		*remaining -= len;
		sys_total += len;
		j += ret;
	}

	if (*remaining > 0) {
		sys_total += *remaining;
		ret = alloc_from_buddy(pages, remaining, 0, &max_order, uncached);
		if (ret < 0)
			return ret;
		j += ret;
	}

	IOMMU_DEBUG(E_LOG_CRIT,
			"ratio %d, alloc %d * 1M from carveout, %d sg_page from agile, total memory from system: %zu\n",
			get_ratio(), i, j, sys_total);

	return i + j;
}

static struct dma_buf *mtk_carv_heap_do_allocate(struct dma_heap *heap,
					       unsigned long len,
					       unsigned long fd_flags,
					       unsigned long heap_flags,
					       bool uncached)
{
	unsigned int nents = 0;
	struct mtk_dmaheap_buffer *buffer;
	struct mtk_dmaheap_buffer_info *info;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	size_t size_remaining = PAGE_ALIGN(len);
	struct dma_buf *dmabuf;
	struct sg_table *table;
	struct scatterlist *sg;
	struct list_head pages;
	struct page *page, *tmp_page;
	struct iommu_carveout_node *node, *tmp;
	int ret = -ENOMEM;
	struct mtk_dma_carveout_heap *carv;
	int carv_sys = !!get_ratio();
	struct timespec64 tv0 = {0}, tv1 = {0};
	u32 elapsed_time = 0;

	carv = dma_heap_get_drvdata(heap);
	if (!carv)
		return ERR_PTR(-EINVAL);

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return ERR_PTR(-ENOMEM);

	info->magic = IOMMU_DMAHEAP_MAGIC;
	buffer = &info->buffer;

	INIT_LIST_HEAD(&buffer->attachments);
	mutex_init(&buffer->lock);
	buffer->heap = heap;
	buffer->len = len;
	buffer->uncached = uncached;

	INIT_LIST_HEAD(&pages);

	ktime_get_real_ts64(&tv0);

	ret = alloc_from_resv_mem(carv->pool, &pages, &size_remaining, uncached);
	if (ret < 0)
		goto out;

	nents += ret;

	ktime_get_real_ts64(&tv1);
	elapsed_time = (tv1.tv_sec - tv0.tv_sec) * USEC_PER_SEC +
			(tv1.tv_nsec - tv0.tv_nsec) / NSEC_PER_USEC;
	trace_mtk_iommu_alloc(dma_heap_get_name(heap), TPS("system"), len, elapsed_time);

	table = &buffer->sg_table;
	if (sg_alloc_table(table, nents, GFP_KERNEL))
		goto out;

	sg = table->sgl;
	if (carv_sys) {
		list_for_each_entry_safe(page, tmp_page, &pages, lru) {
			if (is_carveout_range(carv->pa, carv->size, page)) {
				sg_set_page(sg, page, IOMMU_CARVEOUT_ALIGN, 0);
			} else
				sg_set_page(sg, page, page_size(page), 0);
			sg = sg_next(sg);
			list_del(&page->lru);
		}
	} else {
		list_for_each_entry_safe(node, tmp, &pages, list) {
			sg_set_page(sg, node->page, node->len, 0);
			sg = sg_next(sg);
			list_del(&node->list);
			kfree(node);
		}
	}

	/* create the dmabuf */
	exp_info.exp_name = dma_heap_get_name(heap);
	exp_info.ops = &carv_dmaheap_buf_ops;
	exp_info.size = len;
	exp_info.flags = fd_flags;
	exp_info.priv = &info->buffer;
	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto out;
	}
	return dmabuf;
out:
	if (nents == 0) {
		kfree(info);
		return ERR_PTR(ret);
	}

	if (carv_sys) {
		list_for_each_entry_safe(page, tmp_page, &pages, lru)
			if (is_carveout_range(carv->pa, carv->size, page))
				gen_pool_free(carv->pool, page_to_phys(page), IOMMU_CARVEOUT_ALIGN);
			else
				__free_pages(page, compound_order(page));
	} else {
		list_for_each_entry_safe(node, tmp, &pages, list) {
			if (is_carveout_range(carv->pa, carv->size, node->page))
				gen_pool_free(carv->pool, page_to_phys(node->page), node->len);
			else
				__free_pages(node->page, get_order(node->len));
			list_del(&node->list);
			kfree(node);
		}
	}
	kfree(info);

	return ERR_PTR(ret);
}

static struct dma_buf *carveout_heap_not_initialized(struct dma_heap *heap,
					    unsigned long len,
					    unsigned long fd_flags,
					    unsigned long heap_flags)
{
	return ERR_PTR(-EBUSY);
}

static struct dma_buf *carveout_heap_allocate(struct dma_heap *heap,
					    unsigned long len,
					    unsigned long fd_flags,
					    unsigned long heap_flags)
{
	return mtk_carv_heap_do_allocate(heap, len, fd_flags, heap_flags, false);
}

static struct dma_buf *carveout_heap_allocate_uncached(struct dma_heap *heap,
					    unsigned long len,
					    unsigned long fd_flags,
					    unsigned long heap_flags)
{
	return mtk_carv_heap_do_allocate(heap, len, fd_flags, heap_flags, true);
}

static const struct dma_heap_ops mtk_carv_heap_ops = {
	.allocate = carveout_heap_allocate,
};

static struct dma_heap_ops mtk_carv_uncached_heap_ops = {
	.allocate = carveout_heap_not_initialized,
};

static const struct of_device_id mtk_iommu_carveout_of_ids[] = {
	{.compatible = "mediatek,dtv-iommu-carveout",},
	{ }
};

static int iommu_carveout_probe(struct platform_device *pdev)
{
	int ret;
	struct device *dev = &pdev->dev;
	struct device_node *np;
	struct mtk_dma_carveout_heap *carv;
	struct resource r;
	struct dma_heap_export_info exp_info;

	np = of_parse_phandle(dev->of_node, "memory-region", 0);
	if (!np) {
		dev_err(dev, "No memory-region specified\n");
		return -ENODEV;
	}

	ret = of_address_to_resource(np, 0, &r);
	if (ret) {
		dev_err(dev, "No memory address assigned to the region\n");
		return -EINVAL;
	}

	dev->dma_mask = devm_kzalloc(dev,
				sizeof(*dev->dma_mask), GFP_KERNEL);
	if (!dev->dma_mask)
		return -ENOMEM;
	dma_set_mask(dev, DMA_BIT_MASK(IOMMU_DMA_MASK));

	carv = devm_kzalloc(dev, sizeof(struct mtk_dma_carveout_heap), GFP_KERNEL);
	if (!carv)
		return -ENOMEM;

	dev_info(dev, "reserved mem pa:%pa+%lx\n",
			&r.start, (unsigned long)resource_size(&r));

	carv->pa = r.start;
	carv->size = (size_t)resource_size(&r);
	carv->pool = gen_pool_create(PAGE_SHIFT, -1);
	if (!carv->pool) {
		dev_err(dev, "gen pool failed\n");
		return -ENOMEM;
	}

	ret = gen_pool_add(carv->pool, carv->pa, carv->size, -1);
	if (ret) {
		dev_err(dev, "gen_pool_add failed with %d\n", ret);
		goto out;
	}

	exp_info.name = MTK_CARVEOUT_DMAHEAP;
	exp_info.ops = &mtk_carv_heap_ops,
	exp_info.priv = carv;
	carv->heap = dma_heap_add(&exp_info);
	if (IS_ERR(carv->heap)) {
		ret = PTR_ERR(carv->heap);
		goto out;
	}

	exp_info.name = MTK_CARVEOUT_DMAHEAP_UC;
	exp_info.ops = &mtk_carv_uncached_heap_ops,
	exp_info.priv = carv;
	carv->uc_heap = dma_heap_add(&exp_info);
	if (IS_ERR(carv->uc_heap)) {
		ret = PTR_ERR(carv->uc_heap);
		goto out;
	}

	platform_set_drvdata(pdev, carv);

	dma_coerce_mask_and_coherent(dma_heap_get_dev(carv->uc_heap),
			DMA_BIT_MASK(IOMMU_DMAHEAP_MASK));
	mb(); /* make sure we only set allocate after dma_mask is set */
	mtk_carv_uncached_heap_ops.allocate = carveout_heap_allocate_uncached;

	return 0;
out:
	gen_pool_destroy(carv->pool);
	return ret;
}

static int iommu_carveout_remove(struct platform_device *pdev)
{
	struct mtk_dma_carveout_heap *carv =
		platform_get_drvdata(pdev);

	if (!carv)
		return -EINVAL;

	gen_pool_destroy(carv->pool);
	dma_heap_put(carv->heap);
	dma_heap_put(carv->uc_heap);

	return 0;
}

static struct platform_driver carveout_dmaheap_driver = {
	.probe = iommu_carveout_probe,
	.remove = iommu_carveout_remove,
	.driver = {
		.name = "mtk-iommu-carveout",
		.of_match_table = mtk_iommu_carveout_of_ids,
	}
};

int mtk_carveout_dmaheap_init(struct device *dev)
{
	carv_dev = dev;
	return platform_driver_register(&carveout_dmaheap_driver);
}

void mtk_carveout_dmaheap_exit(void)
{
	platform_driver_unregister(&carveout_dmaheap_driver);
}
