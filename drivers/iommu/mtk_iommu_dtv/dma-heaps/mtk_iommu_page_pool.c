// SPDX-License-Identifier: GPL-2.0
/*
 * DMA BUF page pool system
 *
 * Copyright (C) 2020 Linaro Ltd.
 *
 * Based on the ION page pool code
 * Copyright (C) 2011 Google, Inc.
 */

#include <linux/freezer.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/sched/signal.h>
#include <linux/atomic.h>
#include <linux/version.h>
#include "mtk_iommu_trace.h"
#include "mtk_iommu_page_pool.h"
#include "mtk_iommu_internal.h"

static LIST_HEAD(pool_list);
static DEFINE_MUTEX(pool_list_lock);
atomic_t total_pool_size;
atomic_t total_alloc_size;
static struct device *heap_dev;

static inline
struct page *mtk_iommu_dmabuf_page_pool_alloc_pages(struct mtk_iommu_dmabuf_page_pool *pool)
{
	struct mtk_iommu_dmabuf_page_pool *tmp_pool;
	gfp_t gfp = pool->gfp_mask;
	int i;
	bool has_small_page = false;
	int small_page_count = 0;

	if (fatal_signal_pending(current))
		return NULL;
	if (pool->order && pool->is_agile) {
		list_for_each_entry(tmp_pool, &pool_list, list) {
			if (!tmp_pool->is_agile)
				continue;
			if (tmp_pool->order < pool->order) {
				for (i = 0; i < POOL_TYPE_SIZE; i++)
					small_page_count += (tmp_pool->count[i] << tmp_pool->order);
			}
		}
		if (small_page_count >= (1 << pool->order))
			has_small_page = true;
	}

	return has_small_page ? NULL : alloc_pages(gfp, pool->order);
}

static inline void mtk_iommu_dmabuf_page_pool_free_pages(struct mtk_iommu_dmabuf_page_pool *pool,
					       struct page *page)
{
	if (pool->is_agile)
		atomic_sub(1 << pool->order, &total_alloc_size);
	__free_pages(page, pool->order);
}

static void mtk_iommu_dmabuf_page_pool_add(struct mtk_iommu_dmabuf_page_pool *pool,
		struct page *page)
{
	int index;

	if (PageHighMem(page))
		index = POOL_HIGHPAGE;
	else
		index = POOL_LOWPAGE;

	mutex_lock(&pool->mutex);
	list_add_tail(&page->lru, &pool->items[index]);
	pool->count[index]++;
	mutex_unlock(&pool->mutex);
	mod_node_page_state(page_pgdat(page), NR_KERNEL_MISC_RECLAIMABLE,
			    1 << pool->order);
	if (pool->is_agile)
		atomic_add(1 << pool->order, &total_pool_size);
}

static struct page *mtk_iommu_dmabuf_page_pool_remove(struct mtk_iommu_dmabuf_page_pool *pool,
		int index)
{
	struct page *page;

	mutex_lock(&pool->mutex);
	page = list_first_entry_or_null(&pool->items[index], struct page, lru);
	if (page) {
		pool->count[index]--;
		list_del(&page->lru);
		mod_node_page_state(page_pgdat(page), NR_KERNEL_MISC_RECLAIMABLE,
				    -(1 << pool->order));
		if (pool->is_agile)
			atomic_sub(1 << pool->order, &total_pool_size);
	}
	mutex_unlock(&pool->mutex);

	return page;
}

static struct page *mtk_iommu_dmabuf_page_pool_fetch(struct mtk_iommu_dmabuf_page_pool *pool)
{
	struct page *page = NULL;

	page = mtk_iommu_dmabuf_page_pool_remove(pool, POOL_HIGHPAGE);
	if (!page)
		page = mtk_iommu_dmabuf_page_pool_remove(pool, POOL_LOWPAGE);

	return page;
}

struct page *mtk_iommu_dmabuf_page_pool_alloc(struct mtk_iommu_dmabuf_page_pool *pool,
		bool uncached)
{
	struct page *page = NULL;

	if (WARN_ON(!pool))
		return NULL;

	page = mtk_iommu_dmabuf_page_pool_fetch(pool);

	if (!page) {
		page = mtk_iommu_dmabuf_page_pool_alloc_pages(pool);
		if (page) {
			if (pool->is_agile)
				atomic_add(1 << pool->order, &total_alloc_size);
			if (heap_dev && uncached) {
				dma_addr_t addr;

				addr = dma_map_page(heap_dev, page,
						0, page_size(page), DMA_BIDIRECTIONAL);
				dma_unmap_page(heap_dev, addr,
						page_size(page), DMA_BIDIRECTIONAL);
			}
		}
	}
	return page;
}
EXPORT_SYMBOL_GPL(mtk_iommu_dmabuf_page_pool_alloc);

void mtk_iommu_dmabuf_page_pool_free(struct mtk_iommu_dmabuf_page_pool *pool, struct page *page,
		bool uncached)
{
	if (WARN_ON(pool->order != compound_order(page)))
		return;
	if (heap_dev && !uncached) {
		dma_addr_t addr;

		addr = dma_map_page(heap_dev, page,
				0, page_size(page), DMA_BIDIRECTIONAL);
		dma_unmap_page(heap_dev, addr,
				page_size(page), DMA_BIDIRECTIONAL);
	}
	mtk_iommu_dmabuf_page_pool_add(pool, page);
}
EXPORT_SYMBOL_GPL(mtk_iommu_dmabuf_page_pool_free);

static int mtk_iommu_dmabuf_page_pool_total(struct mtk_iommu_dmabuf_page_pool *pool,
		bool high)
{
	int count = pool->count[POOL_LOWPAGE];

	if (high)
		count += pool->count[POOL_HIGHPAGE];

	return count << pool->order;
}

struct mtk_iommu_dmabuf_page_pool *mtk_iommu_dmabuf_page_pool_create(gfp_t gfp_mask,
		unsigned int order)
{
	struct mtk_iommu_dmabuf_page_pool *pool = kmalloc(sizeof(*pool), GFP_KERNEL);
	int i;

	if (!pool)
		return NULL;

	for (i = 0; i < POOL_TYPE_SIZE; i++) {
		pool->count[i] = 0;
		INIT_LIST_HEAD(&pool->items[i]);
	}
	pool->gfp_mask = gfp_mask | __GFP_COMP;
	pool->order = order;
	pool->is_agile = false;
	mutex_init(&pool->mutex);

	mutex_lock(&pool_list_lock);
	list_add(&pool->list, &pool_list);
	mutex_unlock(&pool_list_lock);

	return pool;
}
EXPORT_SYMBOL_GPL(mtk_iommu_dmabuf_page_pool_create);

void mtk_iommu_dmabuf_page_pool_destroy(struct mtk_iommu_dmabuf_page_pool *pool)
{
	struct page *page;
	int i;

	/* Remove us from the pool list */
	mutex_lock(&pool_list_lock);
	list_del(&pool->list);
	mutex_unlock(&pool_list_lock);

	/* Free any remaining pages in the pool */
	for (i = 0; i < POOL_TYPE_SIZE; i++) {
		while ((page = mtk_iommu_dmabuf_page_pool_remove(pool, i)))
			mtk_iommu_dmabuf_page_pool_free_pages(pool, page);
	}

	kfree(pool);
}
EXPORT_SYMBOL_GPL(mtk_iommu_dmabuf_page_pool_destroy);

static int mtk_iommu_dmabuf_page_pool_do_shrink(struct mtk_iommu_dmabuf_page_pool *pool,
		gfp_t gfp_mask, int nr_to_scan)
{
	int freed = 0;
	bool high;

	if (current_is_kswapd())
		high = true;
	else
		high = !!(gfp_mask & __GFP_HIGHMEM);

	if (nr_to_scan == 0)
		return (get_total_alloc_size() > get_pool_water_mark() >> PAGE_SHIFT)
			|| !pool->is_agile ?
			mtk_iommu_dmabuf_page_pool_total(pool, high) : 0;

	if (get_total_alloc_size() <= get_pool_water_mark() >> PAGE_SHIFT && pool->is_agile)
		return 0;

	while (freed < nr_to_scan) {
		struct page *page;

		/* Try to free low pages first */
		page = mtk_iommu_dmabuf_page_pool_remove(pool, POOL_LOWPAGE);
		if (!page)
			page = mtk_iommu_dmabuf_page_pool_remove(pool, POOL_HIGHPAGE);

		if (!page)
			break;

		mtk_iommu_dmabuf_page_pool_free_pages(pool, page);
		freed += (1 << pool->order);
	}

	if (pool->is_agile) {
		trace_mtk_iommu_pool_event(TPS("agile_pool_shrink"), pool->order, freed);
		trace_mtk_iommu_pool_event(TPS("agile shrinker current_allocated_size"),
						pool->order, get_total_alloc_size());
	} else
		trace_mtk_iommu_pool_event(TPS("pool_shrink"), pool->order, freed);

	return freed;
}

static int mtk_iommu_dmabuf_page_pool_shrink(gfp_t gfp_mask, int nr_to_scan)
{
	struct mtk_iommu_dmabuf_page_pool *pool;
	int nr_total = 0;
	int nr_freed;
	int only_scan = 0;

	if (!nr_to_scan)
		only_scan = 1;

	mutex_lock(&pool_list_lock);
	list_for_each_entry(pool, &pool_list, list) {
		if (only_scan) {
			nr_total += mtk_iommu_dmabuf_page_pool_do_shrink(pool,
							       gfp_mask,
							       nr_to_scan);
		} else {
			nr_freed = mtk_iommu_dmabuf_page_pool_do_shrink(pool,
							      gfp_mask,
							      nr_to_scan);
			nr_to_scan -= nr_freed;
			nr_total += nr_freed;
			if (nr_to_scan <= 0)
				break;
		}
	}
	mutex_unlock(&pool_list_lock);

	return nr_total;
}

static unsigned long mtk_iommu_dmabuf_page_pool_shrink_count(struct shrinker *shrinker,
						   struct shrink_control *sc)
{
	return mtk_iommu_dmabuf_page_pool_shrink(sc->gfp_mask, 0);
}

static unsigned long mtk_iommu_dmabuf_page_pool_shrink_scan(struct shrinker *shrinker,
						  struct shrink_control *sc)
{
	if (sc->nr_to_scan == 0)
		return 0;
	return mtk_iommu_dmabuf_page_pool_shrink(sc->gfp_mask, sc->nr_to_scan);
}

static struct shrinker pool_shrinker = {
	.count_objects = mtk_iommu_dmabuf_page_pool_shrink_count,
	.scan_objects = mtk_iommu_dmabuf_page_pool_shrink_scan,
	.seeks = DEFAULT_SEEKS,
	.batch = 0,
};

int mtk_iommu_dmabuf_page_pool_init_shrinker(struct device *dev)
{
	heap_dev = dev;
	atomic_set(&total_pool_size, 0);
	atomic_set(&total_alloc_size, 0);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
	return register_shrinker(&pool_shrinker);
#else
	return register_shrinker(&pool_shrinker, "mtk_iommu_dmabuf_page_pool");
#endif
}
