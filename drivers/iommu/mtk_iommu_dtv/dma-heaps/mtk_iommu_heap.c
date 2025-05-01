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
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/platform_device.h>

#include "mtk_iommu_of.h"
#include "mtk_iommu_dtv.h"
#include "mtk_iommu_internal.h"
#include "mtk_iommu_dmaheap.h"
#include "mtk_iommu_dmaheap_ops.h"
#include "mtk_iommu_sys_dmaheap.h"
#include "mtk_iommu_agile_dmaheap.h"
#include "mtk_iommu_cma_dmaheap.h"
#include "mtk_iommu_carveout_dmaheap.h"

#define NEED_CACHE_NONCACAHE_HEAPS	2
#define NEED_2XIOVA_HEAPS		2

enum cust_heap_type {
	E_NONCACHE,
	E_NONCACHE_2XIOVA,
	E_CACHE,
	E_CACHE_2XIOVA
};

static struct device *dmaheap_dev;
static struct device *direct_dev;

/* mem_cust_info */
static struct mem_cust_policy_info *info;

/* buf_tag to heaps */
static struct dma_heap **buf_tag_heaps;
static struct buf_tag_info **tags_info;
static int buf_tag_ns;

static int need_zero(unsigned int buf_tag_id)
{
	int i;

	for (i = 0; i < info->nr_need_zeropage; i++)
		if (buf_tag_id == info->need_zeropage[i])
			return 1;

	return 0;
}

static int need_2xiova(unsigned int buf_tag_id)
{
	int i;

	for (i = 0; i < info->nr_need_2xiova; i++)
		if (buf_tag_id == info->need_2xiova[i])
			return 1;

	return 0;
}

static void mtk_dmaheap_buf_destroy(struct mtk_dmaheap_buffer_info *info)
{
	struct sg_table *table;
	struct mtk_dmaheap_buffer *buffer = &info->buffer;

	if (!buffer->vaddr)
		buffer->vaddr = (void *)0xFFFFFFFF;

	/* release internal memory */
	dma_free_attrs(dmaheap_dev, buffer->len, buffer->vaddr,
				info->handle, info->attrs);

	/* release sg table */
	table = &buffer->sg_table;
	sg_free_table(table);
	kfree(info);
}

static void mtk_dmaheap_buf_release(struct dma_buf *dmabuf)
{
	struct mtk_dmaheap_buffer *buffer = dmabuf->priv;
	struct mtk_dmaheap_buffer_info *info = to_dmaheap_info(buffer);

	if (WARN_ON(info->magic != IOMMU_DMAHEAP_MAGIC))
		return;

	mtk_dmaheap_buf_destroy(info);
	dmabuf->priv = NULL;
}

static const struct dma_buf_ops mtk_dmaheap_buf_ops = {
	.attach = mtk_dmaheap_buf_attach,
	.detach = mtk_dmaheap_buf_detach,
	.map_dma_buf = mtk_dmaheap_buf_map_dma_buf,
	.unmap_dma_buf = mtk_dmaheap_buf_unmap_dma_buf,
	.begin_cpu_access = mtk_dmaheap_buf_begin_cpu_access,
	.end_cpu_access = mtk_dmaheap_buf_end_cpu_access,
	.mmap = mtk_dmaheap_buf_mmap,
	.vmap = mtk_dmaheap_buf_vmap,
	.vunmap = mtk_dmaheap_buf_vunmap,
	.release = mtk_dmaheap_buf_release,
};

int is_dmaheap_ops(struct dma_buf *db)
{
	return db->ops == &mtk_dmaheap_buf_ops;
}

static int __query_buf_tag_id(const char *heap_name)
{
	unsigned int id = 0;
	int i;

	for (i = 0; i < buf_tag_ns; i++) {
		if ((strlen(heap_name) == strlen(tags_info[i]->heap_name))
			&& strncmp(tags_info[i]->heap_name, heap_name, strlen(heap_name)) == 0) {
			id = tags_info[i]->id;
			break;
		}
	}
	return id;
}

static int _update_heap_attrs(struct dma_heap *heap, unsigned long *attrs, bool uncached)
{
	int buf_tag_id;

	*attrs |= DMA_ATTR_NO_KERNEL_MAPPING;

	buf_tag_id = __query_buf_tag_id(dma_heap_get_name(heap));
	*attrs |= buf_tag_id << BUFTAG_SHIFT;

	if (strstr(dma_heap_get_name(heap), "2xiova"))
		*attrs |= IOMMUMD_FLAG_2XIOVA;

	if (need_zero(buf_tag_id))
		*attrs |= IOMMUMD_FLAG_ZEROPAGE;

	if (uncached)
		*attrs |= DMA_ATTR_WRITE_COMBINE;

	return 0;
}

static struct mtk_dmaheap_buffer_info *mtk_dmaheap_buffer_alloc(struct dma_heap *heap,
							   unsigned long len,
							   unsigned long fd_flags,
							   unsigned long heap_flags,
							   bool uncached)
{
	struct mtk_dmaheap_buffer_info *info;
	unsigned long attrs = heap_flags & (~0xFF);
	int ret;

	if (dma_get_mask(dmaheap_dev) < DMA_BIT_MASK(IOMMU_DMAHEAP_MASK)) {
		dev_emerg(dmaheap_dev, "%s, check IOMMU client fail, mask=0x%llx\n",
			__func__, dma_get_mask(dmaheap_dev));
		return ERR_PTR(-EINVAL);
	}

	info = kzalloc(sizeof(struct mtk_dmaheap_buffer_info), GFP_KERNEL);
	if (!info)
		return ERR_PTR(-ENOMEM);

	ret = _update_heap_attrs(heap, &attrs, uncached);
	if (ret) {
		dev_emerg(dmaheap_dev, "%s, update heap attrs fail\n", __func__);
		return ERR_PTR(-EINVAL);
	}

	info->buffer.vaddr = dma_alloc_attrs(dmaheap_dev, len, &(info->handle),
					GFP_HIGHUSER, attrs);

	if (!(info->handle || info->buffer.vaddr)) {
		dev_err(dmaheap_dev, "%s, fail to allocate buffer\n", __func__);
		goto err;
	}

	if (dma_mapping_error(dmaheap_dev, info->handle) != 0) {
		dev_err(dmaheap_dev, "%s, fail to check dma_mapping.\n", __func__);
		goto err;
	}

	if (dma_get_sgtable_attrs(dmaheap_dev, &(info->buffer.sg_table), info->buffer.vaddr,
			info->handle, len, attrs)) {
		dev_err(dmaheap_dev, "%s, fail to get_sgtable.\n", __func__);
		goto free_mem;
	}

	info->buffer.len = len;
	info->buffer.uncached = uncached;
	info->buffer.heap = heap;
	info->magic = IOMMU_DMAHEAP_MAGIC;
	info->attrs = attrs;

	INIT_LIST_HEAD(&info->buffer.attachments);
	mutex_init(&info->buffer.lock);

	return info;

free_mem:
	dma_free_attrs(dmaheap_dev, len, info->buffer.vaddr, info->handle, attrs);
err:
	kfree(info);

	return ERR_PTR(-ENOMEM);
}

static struct dma_buf *mtk_dmaheap_do_allocate(struct dma_heap *heap,
					       unsigned long len,
					       unsigned long fd_flags,
					       unsigned long heap_flags,
					       bool uncached)
{
	struct mtk_dmaheap_buffer_info *info;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct dma_buf *dmabuf;
	struct mtk_iommu_buf_handle *buf_handle = NULL;
	struct mtk_dtv_iommu_data *data = NULL;
	int ret = -ENOMEM;

	ret = get_iommu_data(&data);
	if (ret)
		return ERR_PTR(ret);

	/* allocate dmaheap_buffer */
	info = mtk_dmaheap_buffer_alloc(heap, len, fd_flags, heap_flags, uncached);
	if (IS_ERR(info)) {
		dev_err(dmaheap_dev, "%s: heap [%s] len %lu create buffer fail\n",
			__func__, dma_heap_get_name(heap), len);
		return ERR_CAST(info);
	}

	/* create the dmabuf */
	exp_info.exp_name = dma_heap_get_name(heap);
	exp_info.ops = &mtk_dmaheap_buf_ops;
	exp_info.size = info->buffer.len;
	exp_info.flags = O_RDWR;
	exp_info.priv = &info->buffer;

	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto free_pages;
	}

	/* correlate ext_dmabuf and internal buf_handle */
	if (info->handle >= IOVA_START_ADDR)
		buf_handle = __mtk_iommu_find_buf_handle(info->handle, data);

	if (!buf_handle && info->attrs & IOMMUMD_FLAG_NOMAPIOVA)
		buf_handle = __mtk_iommu_find_name(info->handle, data);

	if (!IS_ERR_OR_NULL(buf_handle)) {
		info->handler = buf_handle;
		buf_handle->dmabuf = dmabuf;
	}

	return dmabuf;

free_pages:
	mtk_dmaheap_buf_destroy(info);
	return ERR_PTR(ret);
}

static struct dma_buf *mtk_dmaheap_allocate(struct dma_heap *heap,
					    unsigned long len,
					    unsigned long fd_flags,
					    unsigned long heap_flags)
{
	return mtk_dmaheap_do_allocate(heap, len, fd_flags, heap_flags, false);
}

static const struct dma_heap_ops mtk_dmaheap_ops = {
	.allocate = mtk_dmaheap_allocate,
};

static struct dma_buf *mtk_dmaheap_uncached_allocate(struct dma_heap *heap,
						     unsigned long len,
						     unsigned long fd_flags,
						     unsigned long heap_flags)
{
	return mtk_dmaheap_do_allocate(heap, len, fd_flags, heap_flags, true);
}

/* Dummy function to be used until we can call coerce_mask_and_coherent */
static struct dma_buf *mtk_dmaheap_uncached_not_initialized(struct dma_heap *heap,
							    unsigned long len,
							    unsigned long fd_flags,
							    unsigned long heap_flags)
{
	return ERR_PTR(-EBUSY);
}

static struct dma_heap_ops mtk_dmaheap_uncached_ops = {
	/* After mtk_iommu_dmaheap_create is complete, we will swap this */
	.allocate = mtk_dmaheap_uncached_not_initialized,
};

static int _create_cust_heap_tag_info(struct buf_tag_info *buf, int i, unsigned int cust_type)
{
	tags_info[i] = kzalloc(sizeof(struct buf_tag_info), GFP_KERNEL);
	if (!tags_info[i])
		return -EINVAL;

	tags_info[i]->id = buf->id;
	tags_info[i]->heap_type = buf->heap_type;
	tags_info[i]->miu = buf->miu;
	tags_info[i]->maxsize = buf->maxsize;
	tags_info[i]->zone = buf->zone;

	switch (cust_type) {
	case E_NONCACHE:
		tags_info[i]->cache = false;
		tags_info[i]->heap_name =
			kzalloc(sizeof(char) * MAX_DMAHEAP_UNCACHED_NAME_SIZE, GFP_KERNEL);
		scnprintf(tags_info[i]->heap_name, MAX_DMAHEAP_UNCACHED_NAME_SIZE,
			"mtk_%s_uncached", buf->name);
		break;
	case E_NONCACHE_2XIOVA:
		tags_info[i]->cache = false;
		tags_info[i]->heap_name =
			kzalloc(sizeof(char) * MAX_DMAHEAP_UNCACHED_2XIOVA_NAME_SIZE, GFP_KERNEL);
		scnprintf(tags_info[i]->heap_name, MAX_DMAHEAP_UNCACHED_2XIOVA_NAME_SIZE,
			"mtk_%s_2xiova_uncached", buf->name);
		break;
	case E_CACHE:
		tags_info[i]->cache = true;
		tags_info[i]->heap_name =
			kzalloc(sizeof(char) * MAX_DMAHEAP_CACHED_NAME_SIZE, GFP_KERNEL);
		scnprintf(tags_info[i]->heap_name, MAX_DMAHEAP_CACHED_NAME_SIZE,
			"mtk_%s", buf->name);
		break;
	case E_CACHE_2XIOVA:
		tags_info[i]->cache = true;
		tags_info[i]->heap_name =
			kzalloc(sizeof(char) * MAX_DMAHEAP_CACHED_2XIOVA_NAME_SIZE, GFP_KERNEL);
		scnprintf(tags_info[i]->heap_name, MAX_DMAHEAP_CACHED_2XIOVA_NAME_SIZE,
			"mtk_%s_2xiova", buf->name);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int _create_cust_heap_info(struct buf_tag_info *buf, int i)
{
	int ret, cnt = 0, idx = i;

	/*
	 * cache: 1 -> cache type
	 * cache: 2 -> cache and noncache type
	 */
	if (buf->cache) {
		ret = _create_cust_heap_tag_info(buf, idx, E_CACHE);
		if (ret)
			return -EINVAL;
		idx++;

		if (need_2xiova(buf->id)) {
			ret = _create_cust_heap_tag_info(buf, idx, E_CACHE_2XIOVA);
			if (ret)
				return -EINVAL;
			idx++;
		}
	}

	/*
	 * cache: 0 -> noncache type
	 */
	if (buf->cache != 1) {
		ret = _create_cust_heap_tag_info(buf, idx, E_NONCACHE);
		if (ret)
			return -EINVAL;
		idx++;

		if (need_2xiova(buf->id)) {
			ret = _create_cust_heap_tag_info(buf, idx, E_NONCACHE_2XIOVA);
			if (ret)
				return -EINVAL;
			idx++;
		}
	}

	return cnt += (idx - i);
}

static struct buf_tag_info **__query_buf_tag_names(int *buf_tag_ns)
{
	struct list_head *head = NULL;
	struct buf_tag_info *buf = NULL;
	int i, cnt = 0;
	int heap_nr = 1;

	if (buf_tag_heaps)
		goto out;

	head = mtk_iommu_get_buftags();
	if (!head || list_empty(head))
		goto out;

	list_for_each_entry(buf, head, list) {
		heap_nr = 1;
		/*
		 * cache: 0 -> noncache type
		 * cache: 1 -> cache type
		 * cache: 2 -> cache and noncache type
		 */
		if (buf->cache == NEED_CACHE_NONCACAHE_HEAPS)
			heap_nr *= NEED_CACHE_NONCACAHE_HEAPS;

		if (need_2xiova(buf->id))
			heap_nr *= NEED_2XIOVA_HEAPS;

		cnt += heap_nr;
	}

	*buf_tag_ns = cnt;

	tags_info = kcalloc(cnt, sizeof(struct buf_tag_info *), GFP_KERNEL);
	if (!tags_info)
		goto oom;

	i = 0;
	list_for_each_entry(buf, head, list) {
		heap_nr = _create_cust_heap_info(buf, i);
		if (heap_nr > 0)
			i += heap_nr;
		else {
			dev_emerg(dmaheap_dev,
				"%s, [%s] create cust heap info failed, heap_nr: %d\n",
				__func__, buf->name, heap_nr);
			return ERR_PTR(-EINVAL);
		}
	}

	return tags_info;
oom:
	return ERR_PTR(-ENOMEM);
out:
	return ERR_PTR(-EINVAL);
}

/*
 * ONE buf_tag -> ONE heaps: cached or non-cached specified by dts
 *
 * TODO: can use heap->priv to store data or debug callback
 */
int mtk_iommu_dmaheap_create(void)
{
	struct dma_heap_export_info exp_info;
	int ret = -1, i;

	if (buf_tag_heaps) {
		dev_err(dmaheap_dev, "%s: buf_tag_heaps already init\n", __func__);
		return 1;
	}

	/* query cust policy info */
	ret = get_mem_cust_policy_info(&info);
	if (ret) {
		dev_err(dmaheap_dev, "%s: get_policy_info failed, create heap abort\n", __func__);
		goto out;
	}

	/* query buf_tag_names list */
	tags_info = __query_buf_tag_names(&buf_tag_ns);
	if (!buf_tag_ns || !tags_info) {
		dev_err(dmaheap_dev, "%s: query buf tag name failed, create heap abort\n",
				__func__);
		goto out;
	}

	/* create heaps by buf_tag_names */
	buf_tag_heaps = kcalloc(buf_tag_ns, sizeof(struct dma_heap *), GFP_KERNEL);
	if (!buf_tag_heaps)
		goto out;

	for (i = 0; i < buf_tag_ns; i++) {
		/* create heap */
		exp_info.name = tags_info[i]->heap_name;
		exp_info.ops = tags_info[i]->cache ? &mtk_dmaheap_ops : &mtk_dmaheap_uncached_ops;
		exp_info.priv = NULL;

		buf_tag_heaps[i] = dma_heap_add(&exp_info);
		if (IS_ERR(buf_tag_heaps[i]))
			return PTR_ERR(buf_tag_heaps[i]);

		if (!tags_info[i]->cache)
			dma_coerce_mask_and_coherent(dma_heap_get_dev(buf_tag_heaps[i]),
					DMA_BIT_MASK(IOMMU_DMAHEAP_MASK));
	}

	mb(); /* make sure we only set allocate after dma_mask is set */
	mtk_dmaheap_uncached_ops.allocate = mtk_dmaheap_uncached_allocate;

	return 0;
out:
	if (tags_info) {
		for (i = 0; i < buf_tag_ns; i++)
			kfree(tags_info[i]);
		kfree(tags_info);
	}
	return ret;
}

static int mtk_iommu_dmaheap_probe(struct platform_device *pdev)
{
	int ret;

	dmaheap_dev = &(pdev->dev);

	ret = mtk_iommu_dmaheap_create();
	if (ret) {
		dev_err(dmaheap_dev, "mtk-iommu-dmaheap create failed\n");
		goto err;
	}

	ret = mtk_system_dmaheap_create(direct_dev);
	if (ret) {
		dev_err(dmaheap_dev, "sys dmaheap create failed with %d\n", ret);
		goto err;
	}

	ret = mtk_agile_dmaheap_create(direct_dev);
	if (ret) {
		dev_err(dmaheap_dev, "agile dmaheap create failed with %d\n", ret);
		goto err;
	}

	ret = mtk_cma_dmaheap_create();
	if (ret) {
		dev_err(dmaheap_dev, "cma dmaheap create failed with %d\n", ret);
		goto err;
	}

	ret = mtk_carveout_dmaheap_init(direct_dev);
	if (ret) {
		dev_err(dmaheap_dev, "carveout dmaheap create failed with %d\n", ret);
		goto err;
	}

	return 0;
err:
	return ret;
}

static int mtk_iommu_dmaheap_remove(struct platform_device *pdev)
{
	int i;

	mtk_carveout_dmaheap_exit();
	mtk_cma_dmaheap_destroy();
	mtk_agile_dmaheap_destroy();
	mtk_system_dmaheap_destroy();

	if (buf_tag_heaps) {
		for (i = 0; i < buf_tag_ns; i++)
			dma_heap_put(buf_tag_heaps[i]);
	}

	return 0;
}

static const struct of_device_id mtk_iommu_dmaheap_of_ids[] = {
	{.compatible = "mediatek,dtv-iommu-dmaheap",},
	{}
};

static struct platform_driver mtk_iommu_dmaheap_driver = {
	.probe = mtk_iommu_dmaheap_probe,
	.remove = mtk_iommu_dmaheap_remove,
	.driver = {
		.name = "mtk-iommu-dmaheap",
		.of_match_table = mtk_iommu_dmaheap_of_ids,
	}
};

int __init mtk_iommu_dmaheap_init(struct device *dev)
{
	direct_dev = dev;
	return platform_driver_register(&mtk_iommu_dmaheap_driver);
}

void __exit mtk_iommu_dmaheap_deinit(void)
{
	platform_driver_unregister(&mtk_iommu_dmaheap_driver);
}
