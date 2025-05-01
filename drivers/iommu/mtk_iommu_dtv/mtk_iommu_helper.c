// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright (c) 2020 MediaTek Inc.
 */
#include <linux/version.h>
#include <linux/bug.h>
#include <linux/device.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
#include <linux/dma-iommu.h>
#endif
#include <linux/err.h>
#include <linux/io.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <asm/barrier.h>
#include <linux/module.h>
#include <linux/dma-buf.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/syscalls.h>
#include <linux/dma-mapping.h>
#include <linux/dma-map-ops.h>
#include <linux/cache.h>
#include <asm/cacheflush.h>
#include <linux/memblock.h>
#include <linux/sizes.h>
#include <linux/spinlock.h>

#include "mtk_iommu_dtv.h"
#include "mtk_iommu_of.h"
#include "mtk_iommu_dmaheap.h"
#if IS_ENABLED(CONFIG_ION)
#include "mtk_iommu_ion.h"
#endif
#include "mtk_iommu_sysfs.h"
#include "mtk_iommu_common.h"
#include "mtk_iommu_tee_interface.h"
#include "mtk_iommu_test.h"
#include "mtk_iommu_internal.h"
#include "mtk_iommu_trace.h"
#include "mtk_iommu_mixed_mma.h"
#include "mtk_iommu_pool_collector.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
static int mtk_iommu_dma_buf_vmap(struct dma_buf *dmabuf, struct iosys_map *map)
#else
static int mtk_iommu_dma_buf_vmap(struct dma_buf *dmabuf, struct dma_buf_map *map)
#endif
{
	int ret = 0;
	struct mtk_iommu_buf_handle *handle = dmabuf->priv;
	struct mtk_dtv_iommu_data *data = NULL;
	struct dma_buf *internal_db;

	if (!handle)
		return -EINVAL;

	internal_db = handle->b.db_ion;
	if (IS_ERR_OR_NULL(handle->b.db_ion))
		return -EINVAL;

	if (get_iommu_data(&data))
		return -EINVAL;

	if (!internal_db->ops->vmap)
		return -EINVAL;

	ret = internal_db->ops->vmap(internal_db, map);

	trace_mtk_iommu(TPS(__func__), handle->buf_tag, handle->length, handle->addr);
	IOMMU_DEBUG(E_LOG_CRIT, "buf_tag=%s, size=0x%zx, addr=0x%llx,va=0x%lx\n",
		handle->buf_tag, handle->length, handle->addr, (unsigned long)map->vaddr);
	return ret;
}

static void mtk_iommu_dma_buf_vunmap(struct dma_buf *dmabuf,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
		struct iosys_map *map)
#else
		struct dma_buf_map *map)
#endif
{
	struct mtk_iommu_buf_handle *handle = dmabuf->priv;
	struct mtk_dtv_iommu_data *data = NULL;
	struct dma_buf *internal_db;

	if (!handle)
		return;

	internal_db = handle->b.db_ion;
	if (IS_ERR_OR_NULL(handle->b.db_ion))
		return;

	if (get_iommu_data(&data))
		return;

	if (!internal_db->ops->vunmap)
		return;

	internal_db->ops->vunmap(internal_db, map);

	trace_mtk_iommu(TPS(__func__), handle->buf_tag, handle->length, handle->addr);
	IOMMU_DEBUG(E_LOG_CRIT, "buf_tag=%s, size=0x%zx, addr=0x%llx, va=0x%lx\n",
		handle->buf_tag, handle->length, handle->addr, (unsigned long)map->vaddr);
}

static int mtk_iommu_dma_buf_mmap(struct dma_buf *dmabuf,
		struct vm_area_struct *vma)
{
	int ret;
	struct mtk_iommu_buf_handle *handle = dmabuf->priv;
	struct dma_buf *db_ion;
	struct mtk_dtv_iommu_data *data = NULL;

	if (!handle)
		return -EINVAL;

	db_ion = handle->b.db_ion;
	ret = get_iommu_data(&data);
	if (ret)
		return ret;

	trace_mtk_iommu(TPS(__func__), handle->buf_tag, handle->length, handle->addr);
	IOMMU_DEBUG(E_LOG_CRIT, "map user buf_tag=%s, size=0x%zx, addr=0x%llx,va=0x%lx\n",
		handle->buf_tag, handle->length, handle->addr, (unsigned long)vma->vm_start);

	// update map pid
	handle->map_pid = current->pid;

	return dma_buf_mmap(db_ion, vma, vma->vm_pgoff);
}

static void mtk_iommu_dma_buf_release(struct dma_buf *dmabuf)
{
	struct mtk_iommu_buf_handle *buf_handle = NULL;
	struct mtk_dtv_iommu_data *data = NULL;

	mutex_lock(&dmabuf->lock);
	buf_handle = dmabuf->priv;
	dmabuf->priv = NULL;
	mutex_unlock(&dmabuf->lock);

	if (!buf_handle)
		return;

	if (get_iommu_data(&data))
		return;

	if (!has_buf_handle(buf_handle, data, true)) {
		pr_err("[%s][%d] %s cannot find buf_handle in buf_handle list\n",
				current->comm, current->pid, buf_handle->buf_tag);
		return;
	}

	if (buf_handle->attach) {
		/* Skipping unmap_attachment is OK*/
		buf_handle->sg_map_count--;
		buf_handle->attach->sgt = NULL;
		dma_buf_detach(buf_handle->b.db_ion, buf_handle->attach);
		buf_handle->internal_sgt = NULL;
		buf_handle->attach = NULL;
	}

	__free_internal(buf_handle);

	kfree(buf_handle);
}

static struct sg_table *mtk_iommu_map_dma_buf(struct dma_buf_attachment *attachment,
				enum dma_data_direction direction)
{
	struct dma_buf_attachment *db_attach;
	struct dma_buf *dmabuf = attachment->dmabuf;
	struct mtk_iommu_buf_handle *handle = dmabuf->priv;
	struct dma_buf *internal_db;
	struct sg_table *sgt;

	if (!handle)
		return NULL;

	internal_db = handle->b.db_ion;
	if (IS_ERR_OR_NULL(handle->b.db_ion)) {
		pr_err("[IOMMU][%s] internal db is null\n", __func__);
		return NULL;
	}

	db_attach = (struct dma_buf_attachment *)attachment->priv;
	if (IS_ERR_OR_NULL(db_attach)) {
		pr_err("%s(%d) db_attachment is NULL\n", __func__, __LINE__);
		return NULL;
	}

	if (!internal_db->ops->map_dma_buf)
		return NULL;

	sgt = internal_db->ops->map_dma_buf(db_attach, direction);
	if (IS_ERR_OR_NULL(sgt)) {
		pr_err("[IOMMU][%s] sgt is NULL\n", __func__);
		return NULL;
	}

	return sgt;
}

static void mtk_iommu_unmap_dma_buf(struct dma_buf_attachment *attachment,
		struct sg_table *sgt, enum dma_data_direction direction)
{
	struct dma_buf_attachment *db_attach;
	struct dma_buf *dmabuf = attachment->dmabuf;
	struct mtk_iommu_buf_handle *handle = dmabuf->priv;
	struct dma_buf *internal_db;

	if (!handle)
		return;

	internal_db = handle->b.db_ion;
	if (IS_ERR_OR_NULL(handle->b.db_ion)) {
		pr_err("[IOMMU][%s] internal db is null\n", __func__);
		return;
	}

	db_attach = (struct dma_buf_attachment *)attachment->priv;
	if (IS_ERR_OR_NULL(db_attach)) {
		pr_err("%s(%d) db_attachment is NULL\n", __func__, __LINE__);
		return;
	}

	if (!internal_db->ops->unmap_dma_buf)
		return;

	internal_db->ops->unmap_dma_buf(db_attach, sgt, direction);
}

static int mtk_iommu_dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
					      enum dma_data_direction direction)
{
	struct mtk_iommu_buf_handle *handle = dmabuf->priv;

	if (!handle)
		return -EINVAL;

	if (IS_ERR_OR_NULL(handle->b.db_ion))
		return -EINVAL;

	return dma_buf_begin_cpu_access(handle->b.db_ion, direction);
}

static int mtk_iommu_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
					    enum dma_data_direction direction)
{
	struct mtk_iommu_buf_handle *handle = dmabuf->priv;

	if (!handle)
		return -EINVAL;

	if (handle->b.db_ion)
		dma_buf_end_cpu_access(handle->b.db_ion, direction);

	return 0;
}

static int mtk_iommu_dma_attach(struct dma_buf *dmabuf,
		struct dma_buf_attachment *attach)
{
	int ret;
	struct mtk_iommu_buf_handle *handle = dmabuf->priv;
	struct mtk_dtv_iommu_data *data = NULL;
	struct dma_buf_attachment *db_attach;
	struct dma_buf *internal_db;

	if (!handle)
		return -EINVAL;

	internal_db = handle->b.db_ion;
	if (IS_ERR_OR_NULL(handle->b.db_ion))
		return -EINVAL;

	ret = get_iommu_data(&data);
	if (ret)
		return ret;

	if (!internal_db->ops->attach)
		return -EINVAL;

	db_attach = kmemdup(attach, sizeof(*db_attach), GFP_KERNEL);
	if (!db_attach)
		return -ENOMEM;

	db_attach->dmabuf = internal_db;
	ret = internal_db->ops->attach(internal_db, db_attach);
	if (ret)
		return ret;

	attach->priv = (void *)db_attach;

	trace_mtk_iommu(TPS(__func__), handle->buf_tag, handle->length, handle->addr);
	IOMMU_DEBUG(E_LOG_DEBUG, "buf_tag=%s, size=0x%zx, addr=0x%llx\n",
		handle->buf_tag, handle->length, handle->addr);

	return ret;
}

static void mtk_iommu_dma_detach(struct dma_buf *dmabuf,
		struct dma_buf_attachment *attach)
{
	struct mtk_iommu_buf_handle *handle = dmabuf->priv;
	struct mtk_dtv_iommu_data *data = NULL;
	struct dma_buf_attachment *db_attach;
	struct dma_buf *internal_db;

	if (!handle)
		return;

	internal_db = handle->b.db_ion;
	if (IS_ERR_OR_NULL(handle->b.db_ion))
		return;

	if (get_iommu_data(&data))
		return;

	db_attach = (struct dma_buf_attachment *)attach->priv;
	if (IS_ERR_OR_NULL(db_attach)) {
		pr_err("%s(%d) db_attachment is NULL\n", __func__, __LINE__);
		return;
	}
	if (!internal_db->ops->detach)
		return;

	internal_db->ops->detach(internal_db, db_attach);
	kfree(db_attach);

	trace_mtk_iommu(TPS(__func__), handle->buf_tag, handle->length, handle->addr);
	IOMMU_DEBUG(E_LOG_DEBUG, "buf_tag=%s, size=0x%zx, addr=0x%llx\n",
		handle->buf_tag, handle->length, handle->addr);
}

static struct dma_buf_ops mtk_iommud_dma_buf_ops = {
	.attach = mtk_iommu_dma_attach,
	.detach = mtk_iommu_dma_detach,
	.map_dma_buf = mtk_iommu_map_dma_buf,
	.unmap_dma_buf = mtk_iommu_unmap_dma_buf,
	.release = mtk_iommu_dma_buf_release,
	.mmap = mtk_iommu_dma_buf_mmap,
	.begin_cpu_access = mtk_iommu_dma_buf_begin_cpu_access,
	.end_cpu_access = mtk_iommu_dma_buf_end_cpu_access,
	.vmap = mtk_iommu_dma_buf_vmap,
	.vunmap = mtk_iommu_dma_buf_vunmap,
};

static int mtkd_iommu_supported(void)
{
	int ret;
	struct mtk_dtv_iommu_data *data = NULL;

	ret = get_iommu_data(&data);
	if (ret)
		return 0;

	return data->iommu_status;
}

int mtkd_iommu_query_id(char *name, unsigned int *id, unsigned int *max_size)
{
	struct list_head *tag_list;
	struct buf_tag_info *buf;

	if (strlen(name) > MAX_NAME_SIZE)
		return -EINVAL;

	tag_list = mtk_iommu_get_buftags();
	if (!tag_list) {
		pr_err("%s: get buftags list failed!\n", __func__);
		return -ENODEV;
	}

	// this list should be constant, lock free
	list_for_each_entry(buf, tag_list, list) {
		if (!strncmp(name, buf->name, MAX_NAME_SIZE)) {
			*id = buf->id;
			*max_size = (unsigned int)buf->maxsize;
			return 0;
		}
	}

	return -ENODEV;
}
EXPORT_SYMBOL(mtkd_iommu_query_id);

int mtkd_iommu_query_buftag(unsigned int buf_tag, unsigned int *max_size)
{
	int ret;
	struct mtk_dtv_iommu_data *data = NULL;
	struct buf_tag_info tag_info = {
		.id = buf_tag >> BUFTAG_SHIFT,
	};

	if (!max_size)
		return -EINVAL;

	ret = get_iommu_data(&data);
	if (ret)
		return ret;

	ret = mtk_iommu_get_buftag_info(&tag_info);
	if (ret)
		return ret;

	*max_size = (unsigned int)tag_info.maxsize;
	return 0;
}
EXPORT_SYMBOL(mtkd_iommu_query_buftag);

int mtkd_iommu_query_buftag_usage(unsigned int *buf_tag_array,
		unsigned int *len_array, unsigned int buf_tag_num)
{
	int ret, i;
	struct mtk_dtv_iommu_data *data = NULL;
	struct buf_tag_info tag_info = { 0 };

	if (!len_array || !buf_tag_array || !buf_tag_num)
		return -EINVAL;

	if (buf_tag_num > MAX_TAG_NUM)
		return -EINVAL;

	ret = get_iommu_data(&data);
	if (ret)
		return ret;

	for (i = 0; i < buf_tag_num; i++) {
		memset(&tag_info, 0, sizeof(tag_info));
		tag_info.id = buf_tag_array[i] >> BUFTAG_SHIFT;
		ret = mtk_iommu_get_buftag_info(&tag_info);
		if (ret)
			return ret;

		ret = get_curr_buftag_size(tag_info.name, len_array + i);
	}

	return ret;
}
EXPORT_SYMBOL(mtkd_iommu_query_buftag_usage);

int mtkd_iommu_reserve_iova(char *space_tag, unsigned int *buf_tag_array,
			    unsigned long long *addr, unsigned int size,
			    unsigned int buf_tag_num)
{
	int ret = 0, i;
	struct mtk_iommu_space_handle *handle = NULL;
	struct mtk_dtv_iommu_data *mtk_iommu_data = NULL;
	unsigned long long iova;
	struct timespec64 tv0, tv1;
	unsigned int time;
	unsigned long flags = 0;

	if (!space_tag || !buf_tag_array || !addr)
		return -EINVAL;

	if (buf_tag_num > MAX_TAG_NUM)
		return -EINVAL;

	ret = get_iommu_data(&mtk_iommu_data);
	if (ret)
		return ret;

	ktime_get_real_ts64(&tv0);

	handle = __mtk_iommu_find_space_handle(space_tag, mtk_iommu_data);
	if (handle)
		*addr = handle->data.base_addr;
	else {
		ret = mtk_iommu_tee_reserve_space(MTK_IOMMU_ADDR_TYPE_IOVA,
				space_tag, size, &iova);
		if (ret < 0) {
			pr_err("%s(%d): tee reserved space failed with %d\n",
					__func__, __LINE__, ret);
			return ret;
		}

		handle = kzalloc(sizeof(*handle), GFP_KERNEL);
		if (!handle) {
			mtk_iommu_tee_free_space(MTK_IOMMU_ADDR_TYPE_IOVA,
					space_tag);
			return -ENOMEM;
		}
		handle->data.buf_tag_num = buf_tag_num;
		handle->data.size = size;
		strncpy(handle->data.space_tag, space_tag, MAX_NAME_SIZE);
		handle->data.space_tag[MAX_NAME_SIZE - 1] = '\0';
		handle->data.base_addr = iova;
		for (i = 0; i < buf_tag_num; i++)
			handle->data.buf_tag_array[i] = buf_tag_array[i];
		spin_lock_irqsave(&(mtk_iommu_data->buf_lock), flags);
		list_add(&handle->list_node,
				&(mtk_iommu_data->space_list_head));
		spin_unlock_irqrestore(&(mtk_iommu_data->buf_lock), flags);
		*addr = handle->data.base_addr;
	}

	ktime_get_real_ts64(&tv1);
	time = (tv1.tv_sec - tv0.tv_sec) * USEC_PER_SEC +
			(tv1.tv_nsec - tv0.tv_nsec) / NSEC_PER_USEC;

	IOMMU_DEBUG(E_LOG_DEBUG, "reserve iova space_tag=%s, addr=0x%llx,time=%d\n",
			space_tag, *addr, time);

	return 0;
}
EXPORT_SYMBOL(mtkd_iommu_reserve_iova);

static int __mtk_iommu_create_dmabuf(struct mtk_iommu_buf_handle *handle, int *fd)
{
	int dmafd;
	DEFINE_DMA_BUF_EXPORT_INFO(info);

	info.ops = &mtk_iommud_dma_buf_ops;
	info.size = handle->length;
	info.flags = O_RDWR;
	info.priv = handle;
	handle->dmabuf = dma_buf_export(&info);

	if (IS_ERR(handle->dmabuf)) {
		pr_err("%s %d, dma_buf_export fail!\n", __func__, __LINE__);
		return -EFAULT;
	}

	dmafd = dma_buf_fd(handle->dmabuf, O_CLOEXEC);
	if (dmafd < 0) {
		pr_err("%s %d, dma_buf_fd fail!\n", __func__, __LINE__);
		dma_buf_put(handle->dmabuf);
		return -EFAULT;
	}
	*fd = dmafd;

	return 0;
}

int mtkd_iommu_buffer_alloc(unsigned int flag, unsigned int size,
		unsigned long long *addr, int *fd)
{
	dma_addr_t iova = 0;
	void *va = NULL;
	struct mtk_iommu_buf_handle *buf_handle = NULL;
	struct mtk_dtv_iommu_data *data = NULL;
	int dmafd = 0, ret;

	if (!addr || !fd)
		return -EINVAL;

	ret = get_iommu_data(&data);
	if (ret)
		return ret;

	if ((flag & IOMMUMD_FLAG_2XIOVA) && !IS_ALIGNED(size, SZ_4K))  {
		pr_err("%s(%d): size should be 4KB alignment\n",
				__func__, __LINE__);
		return -EINVAL;
	}

	size = PAGE_ALIGN(size);
#if IS_ENABLED(CONFIG_ION)
	if (!(flag & ION_FLAG_CACHED))
		flag |= DMA_ATTR_WRITE_COMBINE;
#endif

	flag |= DMA_ATTR_NO_KERNEL_MAPPING;
	va = __mtk_iommu_alloc_attrs(data->dev, size, addr, 0, flag);

	iova = *addr;
	if (iova == DMA_MAPPING_ERROR) {
		pr_err("%s(%d) alloc iommu buffer failed!\n",
			__func__, __LINE__);
		return -ENOMEM;
	}

	if (iova >= IOVA_START_ADDR)
		buf_handle = __mtk_iommu_find_buf_handle(iova, data);

	if (!buf_handle && flag & IOMMUMD_FLAG_NOMAPIOVA)
		buf_handle = __mtk_iommu_find_name(iova, data);

	if (!buf_handle) {
		pr_err("%s(%d) iova: 0x%llx, cannot find buf_handle\n",
				__func__, __LINE__, iova);
		goto out;
	}

	ret = __mtk_iommu_create_dmabuf(buf_handle, &dmafd);
	if (ret)
		goto out;

	*fd = dmafd;

	return 0;
out:
	__mtk_iommu_free_attrs(data->dev, size, va, iova, flag);
	return -EFAULT;
}
EXPORT_SYMBOL(mtkd_iommu_buffer_alloc);

int mtkd_iommu_get_carv_size(unsigned int flag, unsigned int *size)
{
	struct buf_tag_info tag_info = {0};
	int ret;

	tag_info.id = (flag & BUFTAGMASK) >> BUFTAG_SHIFT;
	ret = mtk_iommu_get_buftag_info(&tag_info);
	if (ret) {
		pr_err("%s(%d): %x get bufinfo failed\n",
			__func__, __LINE__, flag);
		return -EINVAL;
	}

	if (tag_info.heap_type != HEAP_TYPE_CARVEOUT) {
		pr_info("%x is not carveout heap\n", flag);
		*size = 0;
		return 0;
	}

	*size = get_carv_size();
	*size = *size > PAGE_SIZE ? *size : 0;

	return 0;
}
EXPORT_SYMBOL(mtkd_iommu_get_carv_size);

int mtkd_iommu_en_lv2_carv(int status)
{
	en_lv2_carv = status;
	return 0;
}
EXPORT_SYMBOL(mtkd_iommu_en_lv2_carv);

int mtkd_iommu_pool_collector_prior(int status)
{
	switch (status) {
	case MTK_IOMMU_PRIO_HIGH:
		renice_pool_collector(-IOMMU_SCHED_PRIOR);
		break;
	case MTK_IOMMU_PRIO_LOW:
		renice_pool_collector(IOMMU_SCHED_PRIOR);
		break;
	default:
		pr_err("[IOMMU][%s] collector not support this priority\n", __func__);
		return -EINVAL;
	}
	return 0;
}
EXPORT_SYMBOL(mtkd_iommu_pool_collector_prior);

int mtkd_iommu_free_iova(char *space_tag)
{
	int ret = 0;
	struct mtk_iommu_space_handle *handle = NULL;
	struct mtk_dtv_iommu_data *mtk_iommu_data = NULL;
	unsigned long flags = 0;

	if (!space_tag)
		return -EINVAL;

	ret = get_iommu_data(&mtk_iommu_data);
	if (ret)
		return ret;

	handle = __mtk_iommu_find_space_handle(space_tag, mtk_iommu_data);
	if (!handle) {
		pr_err("%s(%d): find space handle failed!\n",
			__func__, __LINE__);
		return -ENOENT;
	}

	ret = mtk_iommu_tee_free_space(MTK_IOMMU_ADDR_TYPE_IOVA, space_tag);
	if (ret) {
		pr_err("%s(%d): free space failed!\n", __func__, __LINE__);
		return ret;
	}

	IOMMU_DEBUG(E_LOG_DEBUG, "free iova space_tag=%s, addr=0x%llx\n",
			space_tag, handle->data.base_addr);

	spin_lock_irqsave(&(mtk_iommu_data->buf_lock), flags);
	list_del(&handle->list_node);
	spin_unlock_irqrestore(&(mtk_iommu_data->buf_lock), flags);
	kfree(handle);
	return 0;
}
EXPORT_SYMBOL(mtkd_iommu_free_iova);

int mtkd_iommu_allocpipelineid(unsigned int *pipelineid)
{
	int ret;
	unsigned int id;
	struct mtk_dtv_iommu_data *data = NULL;

	if (!pipelineid)
		return -EINVAL;

	ret = get_iommu_data(&data);
	if (ret)
		return ret;

	ret = mtk_iommu_tee_get_pipelineid(&id);
	if (ret) {
		pr_err("%s(%d): tee get pipeline id failed\n",
				__func__, __LINE__);
		return ret;
	}

	*pipelineid = id;

	IOMMU_DEBUG(E_LOG_CRIT, "pipelineid = %u\n", id);

	return 0;
}
EXPORT_SYMBOL(mtkd_iommu_allocpipelineid);

int mtkd_iommu_freepipelineid(unsigned int pipelineid)
{
	int ret;
	struct mtk_dtv_iommu_data *data = NULL;

	ret = get_iommu_data(&data);
	if (ret)
		return ret;

	return mtk_iommu_tee_free_pipelineid(pipelineid);
}
EXPORT_SYMBOL(mtkd_iommu_freepipelineid);

static struct mtk_iommu_buf_handle *__mtk_iommu_find_physical_buf_handle(
			dma_addr_t addr)
{
	struct mtk_iommu_buf_handle *buf_handle = NULL;
	struct mtk_dtv_iommu_data *data = NULL;
	int ret;

	ret = get_iommu_data(&data);
	if (ret)
		return NULL;

	mutex_lock(&data->physical_buf_lock);
	list_for_each_entry(buf_handle, &data->physical_buf_list_head,
				buf_list_node) {
		if (buf_handle->addr == addr) {
			mutex_unlock(&data->physical_buf_lock);
			return buf_handle;
		}
	}
	mutex_unlock(&data->physical_buf_lock);
	return NULL;
}

int mtkd_iommu_buffer_authorize(unsigned int buf_tag, unsigned long long addr,
				size_t size, unsigned int pipeline_id)
{
	int ret;
	unsigned int time;
	struct timespec64 tv0, tv1;
	struct mtk_dtv_iommu_data *data = NULL;
	struct mtk_iommu_buf_handle *buf_handle = NULL;

	ret = get_iommu_data(&data);
	if (ret)
		return ret;

	ktime_get_real_ts64(&tv0);
	if (addr >= IOVA_START_ADDR) {
		buf_handle = __mtk_iommu_find_buf_handle(addr, data);
		if (!buf_handle) {
			pr_err("%s(%d): find buf handle failed!\n", __func__, __LINE__);
			return -ENOENT;
		}
	} else {
		buf_handle = __mtk_iommu_find_physical_buf_handle(addr);
		if (!buf_handle) {
			struct buf_tag_info tag_info = {
				.id = buf_tag >> BUFTAG_SHIFT,
			};

			ret = mtk_iommu_get_buftag_info(&tag_info);
			if (ret)
				return ret;

			buf_handle = kzalloc(sizeof(*buf_handle), GFP_KERNEL);
			if (!buf_handle)
				return -ENOMEM;

			buf_handle->auth_count = 0;
			buf_handle->addr = addr;
			buf_handle->length = size;
			strncpy(buf_handle->buf_tag, tag_info.name,
					MAX_NAME_SIZE);
			buf_handle->buf_tag[MAX_NAME_SIZE - 1] = '\0';
			mutex_lock(&data->physical_buf_lock);
			list_add(&buf_handle->buf_list_node,
					&data->physical_buf_list_head);
			mutex_unlock(&data->physical_buf_lock);
		}
	}

	/* already authorized */
	if (buf_handle->auth_count == 1)
		return 0;

	ret = mtk_iommu_tee_authorize(buf_handle->addr,
			buf_handle->length, buf_handle->buf_tag,
			pipeline_id);
	if (ret) {
		pr_err("%s(%d): tee auth failed with %d\n",
			__func__, __LINE__, ret);
		return ret;
	}
	buf_handle->pipe_id = pipeline_id;
	buf_handle->auth_count = 1;
	buf_handle->is_secure = true;

	ktime_get_real_ts64(&tv1);
	time = (tv1.tv_sec - tv0.tv_sec) * USEC_PER_SEC +
			(tv1.tv_nsec - tv0.tv_nsec) / NSEC_PER_USEC;

	trace_mtk_iommu(TPS(__func__), buf_handle->buf_tag, buf_handle->length, buf_handle->addr);
	IOMMU_DEBUG(E_LOG_CRIT, "buf_tag=%s,size=0x%zx,addr=0x%llx,pid=%u,time =%d\n",
		    buf_handle->buf_tag, buf_handle->length,
		    buf_handle->addr, pipeline_id, time);
	return 0;
}
EXPORT_SYMBOL(mtkd_iommu_buffer_authorize);

int mtkd_iommu_buffer_unauthorize(unsigned long long addr)
{
	int ret;
	struct mtk_iommu_buf_handle *buf_handle = NULL;
	struct mtk_iommu_range_t range_out;
	struct timespec64 tv0, tv1;
	unsigned int time;
	size_t sz;
	dma_addr_t iova;
	char buf_tag[MAX_NAME_SIZE];
	struct mtk_dtv_iommu_data *data = NULL;

	ret = get_iommu_data(&data);
	if (ret)
		return ret;

	ktime_get_real_ts64(&tv0);

	if (addr >= IOVA_START_ADDR)
		buf_handle = __mtk_iommu_find_buf_handle(addr, data);
	else
		buf_handle = __mtk_iommu_find_physical_buf_handle(addr);

	if (!buf_handle) {
		pr_err("%s(%d): find buf handle failed!\n", __func__, __LINE__);
		return -ENOENT;
	}

	scnprintf(buf_tag, sizeof(buf_tag), "%s", buf_handle->buf_tag);
	sz = buf_handle->length;
	iova = buf_handle->addr;

	if (buf_handle->auth_count == 1) {
		ret = mtk_iommu_tee_unauthorize(buf_handle->addr,
				buf_handle->length, buf_handle->buf_tag,
				buf_handle->pipe_id, &range_out);
		if (ret) {
			pr_err("%s(%d): tee auth failed with %d\n",
				__func__, __LINE__, ret);
			return ret;
		}
		buf_handle->auth_count = 0;
		buf_handle->is_secure = false;
		if (addr < IOVA_START_ADDR) {
			mutex_lock(&data->physical_buf_lock);
			list_del(&buf_handle->buf_list_node);
			mutex_unlock(&data->physical_buf_lock);
			kfree(buf_handle);
		}
	} else {
		pr_err("%s,%d,authorize count == 0,addr=0x%llx,buftag=%s\n",
		       __func__, __LINE__,
		       buf_handle->addr, buf_handle->buf_tag);
		return -EINVAL;
	}

	ktime_get_real_ts64(&tv1);
	time = (tv1.tv_sec - tv0.tv_sec) * USEC_PER_SEC +
			(tv1.tv_nsec - tv0.tv_nsec) / NSEC_PER_USEC;

	trace_mtk_iommu(TPS(__func__), buf_tag, sz, iova);
	IOMMU_DEBUG(E_LOG_CRIT, "buf_tag=%s, size=0x%zx, addr=0x%llx, time =%d\n",
			buf_tag, sz, iova, time);
	return 0;
}
EXPORT_SYMBOL(mtkd_iommu_buffer_unauthorize);

extern int is_dmaheap_ops(struct dma_buf *db);
static int _get_info_from_dmabuf(struct dma_buf *db, dma_addr_t *dma_address,
		void **kvaddr, unsigned long *attrs)
{
	int magic;
	struct mtk_dmaheap_buffer *buffer;
	struct mtk_dmaheap_buffer_info *info;
#if IS_ENABLED(CONFIG_ION)
	struct ion_buffer *ion_buf;
#endif

	if (!db || !db->priv || !dma_address || !kvaddr || !attrs)
		return -EINVAL;
	if (is_dmaheap_ops(db)) {
		buffer = (struct mtk_dmaheap_buffer *)db->priv;
		if (IS_ERR_OR_NULL(buffer)) {
			pr_err("%s(%d): got error dmaheap magic\n", __func__, __LINE__);
			return -EINVAL;
		}
		info = to_dmaheap_info(buffer);
		if (IS_ERR_OR_NULL(info)) {
			pr_err("%s(%d): got error dmaheap magic\n", __func__, __LINE__);
			return -EINVAL;
		}
		magic = info->magic;
		if (WARN_ON(magic != IOMMU_DMAHEAP_MAGIC)) {
			pr_err("%s(%d): got error dmaheap magic\n", __func__, __LINE__);
			return -EINVAL;
		}
		*dma_address = info->handle;
		*kvaddr = buffer->vaddr;
		*attrs = info->attrs;
	}
#if IS_ENABLED(CONFIG_ION)
	else {
		ion_buf = (struct ion_buffer *)db->priv;
		if (IS_ERR_OR_NULL(ion_buf->priv_virt)) {
			pr_err("%s(%d): error ion_fd\n", __func__, __LINE__);
			return -EINVAL;
		}
		if (!is_ion_iommu_heap(ion_buf->heap)) {
			pr_err("not allocate from iommu heap");
			return -EINVAL;
		}
		magic = ((struct ion_iommu_buffer_info *)(ion_buf->priv_virt))->magic;
		if (magic != ION_IOMMU_MAGIC) {
			pr_err("%s(%d): error ion iommu magic\n", __func__, __LINE__);
			return -EINVAL;
		}

		*dma_address = ((struct ion_iommu_buffer_info *)
					(ion_buf->priv_virt))->handle;
		*kvaddr = ((struct ion_iommu_buffer_info *)
					(ion_buf->priv_virt))->cpu_addr;
		*attrs = (unsigned int)((struct ion_iommu_buffer_info *)
					(ion_buf->priv_virt))->attrs;
	}
#endif

	return 0;
}

int mtkd_iommu_getiova_kernel(struct dma_buf *db, unsigned long long *addr, unsigned int *size)
{
	int ret;
	int tee_map;
	unsigned long attrs = 0;
	void *kvaddr = NULL;
	dma_addr_t dma_address;
	struct mtk_iommu_buf_handle *buf_handle = NULL;
	struct mtk_dtv_iommu_data *data = NULL;
	struct dma_buf_ops *iommu_dma = &mtk_iommud_dma_buf_ops;

	if (!addr || !size)
		return -EINVAL;

	ret = get_iommu_data(&data);
	if (ret)
		return ret;

	if (IS_ERR_OR_NULL(db)) {
		pr_err("%s(%d): invalid db\n", __func__, __LINE__);
		return -EINVAL;
	}

	if (db->ops == iommu_dma) {
		buf_handle = (struct mtk_iommu_buf_handle *)db->priv;
		if (IS_ERR_OR_NULL(buf_handle))
			goto out;
		mutex_lock(&buf_handle->handle_lock);
		tee_map = buf_handle->tee_map;
		mutex_unlock(&buf_handle->handle_lock);
		if (tee_map == TEE_MAP_NON)
			__do_TEEMap_internal(buf_handle);
		*addr = buf_handle->addr;
		*size = buf_handle->length;
		if (!*addr) {
			pr_err("no addr exist!\n");
			return -EINVAL;
		}

		trace_mtk_iommu(TPS(__func__), buf_handle->buf_tag,
				buf_handle->length, buf_handle->addr);
		IOMMU_DEBUG(E_LOG_CRIT, "[mtkd] buf_tag=%s, addr=0x%llx,size=0x%x\n",
			buf_handle->buf_tag, *addr, *size);
		return 0;
	}

	ret = _get_info_from_dmabuf(db, &dma_address, &kvaddr, &attrs);
	if (ret)
		goto out;

	if (dma_address >= IOVA_START_ADDR && dma_address < IOVA_END_ADDR)
		buf_handle = __mtk_iommu_find_buf_handle(dma_address, data);
	else if (dma_address && (attrs & IOMMUMD_FLAG_NOMAPIOVA))
		buf_handle = __mtk_iommu_find_name(dma_address, data);
	else if (kvaddr > 0)
		buf_handle = __mtk_iommu_find_kva(kvaddr, data);
	else {
		pr_err("%s(%d): error ion dmabuf\n", __func__, __LINE__);
		goto out;
	}
	if (IS_ERR_OR_NULL(buf_handle)) {
		pr_err("%s(%d): error ion buf_handle not found\n",
				__func__, __LINE__);
		goto out;
	}

	mutex_lock(&buf_handle->handle_lock);
	tee_map = buf_handle->tee_map;
	mutex_unlock(&buf_handle->handle_lock);
	if (tee_map == TEE_MAP_NON)
		__do_TEEMap_internal(buf_handle);
	*addr = buf_handle->addr;
	*size = buf_handle->length;

	trace_mtk_iommu(TPS(__func__), buf_handle->buf_tag, buf_handle->length, buf_handle->addr);
	IOMMU_DEBUG(E_LOG_CRIT, "buf_tag=%s, addr=0x%llx,size=0x%x\n",
			buf_handle->buf_tag, *addr, *size);
	if (!*addr)
		goto out;
	return 0;
out:
	pr_err("[%s][%d] failed, db->ops %s from ion\n",
		__func__, __LINE__, (db->ops == iommu_dma) ? "is not" : "is");
	*addr = 0;
	*size = 0;
	return -EINVAL;
}
EXPORT_SYMBOL(mtkd_iommu_getiova_kernel);

int mtkd_iommu_getiova(int fd, unsigned long long *addr, unsigned int *size)
{
	int ret;
	struct dma_buf *db;
	struct mtk_dtv_iommu_data *data = NULL;

	if (!addr || !size || fd < 0) {
		pr_err("[%s] [%d] invalid input\n",  __func__, __LINE__);
		return -EINVAL;
	}

	ret = get_iommu_data(&data);
	if (ret) {
		pr_err("[%s] [%d] get iommu data fail\n",  __func__, __LINE__);
		return ret;
	}

	db = dma_buf_get(fd);
	if (IS_ERR_OR_NULL(db)) {
		pr_err("[%s] [%d] invalid fd: %d\n",  __func__, __LINE__, fd);
		return -EINVAL;
	}

	ret = mtkd_iommu_getiova_kernel(db, addr, size);
	if (ret)
		pr_err("[%s] [%d] invalid db\n", __func__, __LINE__);

	dma_buf_put(db);
	return ret;
}
EXPORT_SYMBOL(mtkd_iommu_getiova);

int mtkd_iommu_buffer_resize(int fd, unsigned int size,
		unsigned long long *addr, unsigned int flag)
{
	struct mtk_iommu_buf_handle *buf_handle, *buf_handle_t;
	struct dma_buf *db;
	size_t ori_size;
	dma_addr_t iova = 0;
	void *va = NULL;
	unsigned int attrs = 0, orig_attrs = 0;
	int ret;
	struct mtk_dtv_iommu_data *data = NULL;
	struct dma_buf_ops *iommu_dma = &mtk_iommud_dma_buf_ops;

	if (!addr || size == 0)
		return -EINVAL;

	ret = get_iommu_data(&data);
	if (ret)
		return ret;

	if ((flag & IOMMUMD_FLAG_2XIOVA) && !IS_ALIGNED(size, SZ_4K)) {
		pr_err("%s(%d): size should be 4KB alignment\n",
					__func__, __LINE__);
		return -EINVAL;
	}

	db = dma_buf_get(fd);
	if (IS_ERR_OR_NULL(db)) {
		pr_err("%s(%d): no dma buf\n", __func__, __LINE__);
		return -EINVAL;
	}

	// resize only support iommu buffer alloc via mtk_iommud
	if (db->ops != iommu_dma) {
		pr_err("%s %d,fd=%d not IOMMU buffer\n", __func__, __LINE__, fd);
		dma_buf_put(db);
		return -EINVAL;
	}

	mutex_lock(&db->lock);
	ori_size = db->size;
	buf_handle = (struct mtk_iommu_buf_handle *)db->priv;
	if (IS_ERR_OR_NULL(buf_handle)) {
		pr_err("%s(%d): no buf handle\n", __func__, __LINE__);
		mutex_unlock(&db->lock);
		goto out;
	}

	orig_attrs = buf_handle->attrs;
	if ((flag & BUFTAGMASK) && (flag & BUFTAGMASK) != (orig_attrs & BUFTAGMASK)) {
		pr_err("%s %d, not allow to resize buf_tag_id from %d to %d\n",
			__func__, __LINE__,
			(orig_attrs & BUFTAGMASK) >> BUFTAG_SHIFT,
			(flag & BUFTAGMASK) >> BUFTAG_SHIFT);
		*addr = 0;
		mutex_unlock(&db->lock);
		goto out;
	} else
		attrs = orig_attrs;

	db->priv = NULL;
	mutex_unlock(&db->lock);

	if (!has_buf_handle(buf_handle, data, true)) {
		pr_err("[%s][%d] %s cannot find buf_handle in buf_handle list\n",
				current->comm, current->pid, buf_handle->buf_tag);
		goto out;
	}

	if (buf_handle->attach) {
		/* Skipping unmap_attachment is OK*/
		buf_handle->sg_map_count--;
		buf_handle->attach->sgt = NULL;
		dma_buf_detach(buf_handle->b.db_ion, buf_handle->attach);
		buf_handle->internal_sgt = NULL;
		buf_handle->attach = NULL;
	}

	db->size = 0;

	__free_internal(buf_handle);

	kfree(buf_handle);

	ret = 0;
recovery:
	size = PAGE_ALIGN(size);
	attrs |= DMA_ATTR_NO_KERNEL_MAPPING;
	attrs &= ~IOMMUMD_FLAG_NOMAPIOVA;

	va = __mtk_iommu_alloc_attrs(data->dev, size, addr, 0, attrs);
	iova = *addr;
	if (iova == DMA_MAPPING_ERROR && !va) {
		ret = -ENOMEM;
		if (size != ori_size) {
			pr_info("%s %d, %x alloc fail, recovery original size %zx!\n",
					__func__, __LINE__, size, ori_size);
			size = ori_size;
			goto recovery;
		}
		pr_err("%s %d, alloc fail!\n", __func__, __LINE__);
		goto out;
	}

	buf_handle_t = __mtk_iommu_find_buf_handle(iova, data);
	if (IS_ERR_OR_NULL(buf_handle_t)) {
		pr_err("%s(%d): no iommu buf handle\n", __func__, __LINE__);
		goto out;
	}

	db->size = size;
	db->priv = buf_handle_t;


	trace_mtk_iommu_resize(TPS(__func__),
			buf_handle_t->buf_tag, buf_handle_t->length, buf_handle_t->addr);
	IOMMU_DEBUG_INFO(E_LOG_CRIT, "buf_tag=%s, size=0x%zx, addr=0x%llx\n",
		    buf_handle_t->buf_tag, buf_handle_t->length, buf_handle_t->addr);
	dma_buf_put(db);
	return ret;
out:
	dma_buf_put(db);
	return -EINVAL;

}
EXPORT_SYMBOL(mtkd_iommu_buffer_resize);

int mtkd_iommu_flush(unsigned long va, unsigned int size)
{
	int i, ret;
	unsigned long pfn;
	struct vm_area_struct *vma;
	struct page **pages;
	struct mm_struct *mm = current->mm;
	unsigned long end = (va + size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	unsigned long start = va >> PAGE_SHIFT;
	const int nr_pages = end - start;

	if (!mm)
		return -EINVAL;
	/* sanity check */
	if (va == 0 || size == 0)
		return -EINVAL;

	/* User attempted Overflow! */
	if ((va + size) < va)
		return -EINVAL;

	/* only support va from user */
	if (va > min(PAGE_OFFSET, VMALLOC_START))
		return -EINVAL;

	pages = kcalloc(nr_pages, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	for (i = 0; i < nr_pages; ++i)
		pages[i] = NULL;

	down_read(&mm->mmap_lock);
	vma = find_vma(mm, va);
	if (!vma) {
		pr_err("%s: get vma failed\n", __func__);
		up_read(&mm->mmap_lock);
		ret = -ENOMEM;
		goto out;
	}

	// from mmap
	if (vma->vm_flags & (VM_IO | VM_PFNMAP)) {
		for (start = va, i = 0;
			start + PAGE_SIZE <= vma->vm_end && i < nr_pages;
			start += PAGE_SIZE, i++) {
			ret = follow_pfn(vma, start, &pfn);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
			if (ret || !pfn_is_map_memory(pfn)) {
#else
			if (ret || !pfn_valid(pfn)) {
#endif
				up_read(&mm->mmap_lock);
				pr_err("%s: get invalid pfn\n", __func__);
				goto out;
			}
			pages[i] = pfn_to_page(pfn);
			get_page(pages[i]);
		}
		up_read(&mm->mmap_lock);
		if (i != nr_pages) {
			pr_err("%s: wrong nr_pages %d, expect %d\n",
				__func__, i, nr_pages);
			goto out;
		}
	} else {	// from user alloc
		up_read(&mm->mmap_lock);
		ret = get_user_pages_fast(va, nr_pages, FOLL_WRITE, pages);
		if (ret < nr_pages) {
			pr_crit("%s: get_user_pages failed with %d\n", __func__, ret);
			ret = -EINVAL;
			goto out;
		}
		ret = 0;
	}

	// flush it
	for (i = 0; i < nr_pages; ++i)
		flush_dcache_page(pages[i]);
out:
	for (i = 0; i < nr_pages; ++i) {
		if (pages[i])
			put_page(pages[i]);
	}
	kfree(pages);

	return ret;
}
EXPORT_SYMBOL(mtkd_iommu_flush);

static int mtkd_iommu_get_dmabuf_id(int fd, u32 *dmabuf_id)
{
	int ret;
	struct mtk_dtv_iommu_data *data = NULL;
	struct mtk_iommu_buf_handle *buf_handle = NULL;
	struct dma_buf *db;
	dma_addr_t dma_address;
	void *kvaddr = NULL;
	unsigned long attrs = 0;
	struct dma_buf_ops *iommu_dma = &mtk_iommud_dma_buf_ops;

	if (!dmabuf_id)
		return -EINVAL;

	ret = get_iommu_data(&data);
	if (ret)
		return ret;

	db = dma_buf_get(fd);
	if (IS_ERR_OR_NULL(db)) {
		pr_err("%s, fd=%d, pid=%d, get dmabuf fail\n",
				__func__, fd, current->tgid);
		return -EINVAL;
	}

	//IOMMUD fd
	if (db->ops == iommu_dma) {
		buf_handle = (struct mtk_iommu_buf_handle *)db->priv;
		if (IS_ERR_OR_NULL(buf_handle))
			goto out;

		*dmabuf_id = buf_handle->serial;
		if (!*dmabuf_id)
			goto out;

		dma_buf_put(db);
		IOMMU_DEBUG(E_LOG_CRIT,
			"fd=%d, buf_tag=%s, dmabuf_id=%d\n",
			fd, buf_handle->buf_tag, *dmabuf_id);
		return 0;
	}

	// dmaheap or ion
	ret = _get_info_from_dmabuf(db, &dma_address, &kvaddr, &attrs);
	if (ret)
		goto out;

	if (dma_address >= IOVA_START_ADDR && dma_address < IOVA_END_ADDR)
		buf_handle = __mtk_iommu_find_buf_handle(dma_address, data);
	else if (dma_address && (attrs & IOMMUMD_FLAG_NOMAPIOVA))
		buf_handle = __mtk_iommu_find_name(dma_address, data);
	else if (kvaddr > 0)
		buf_handle = __mtk_iommu_find_kva(kvaddr, data);
	else {
		pr_err("%s(%d): error ion_fd\n", __func__, __LINE__);
		goto out;
	}
	if (IS_ERR_OR_NULL(buf_handle)) {
		pr_err("%s(%d): error ion_fd buf_handle not found\n",
				__func__, __LINE__);
		goto out;
	}
	*dmabuf_id = buf_handle->serial;
	if (!*dmabuf_id)
		goto out;

	dma_buf_put(db);
	IOMMU_DEBUG(E_LOG_CRIT, "fd=%d, buf_tag=%s, dmabuf_id=%d\n",
			fd, buf_handle->buf_tag, *dmabuf_id);
	return 0;
out:
	dma_buf_put(db);
	*dmabuf_id = 0;

	return -EFAULT;
}

int mtkd_iommu_share(int fd, u32 *db_id)
{
	struct dma_buf *db;
	struct mtk_dtv_iommu_data *data = NULL;
	int ret;
	u32 dmabuf_id;
	unsigned long long addr;
	unsigned int size;
	struct mtk_iommu_share *share;

	if (fd < 0)
		return -EINVAL;

	ret = get_iommu_data(&data);
	if (ret)
		return ret;

	db = dma_buf_get(fd);
	if (IS_ERR_OR_NULL(db))
		return -EINVAL;

	ret = mtkd_iommu_getiova_kernel(db, &addr, &size);
	if (ret) {
		dma_buf_put(db);
		return -EINVAL;
	}

	ret = mtkd_iommu_get_dmabuf_id(fd, &dmabuf_id);
	if (ret) {
		dma_buf_put(db);
		return -EINVAL;
	}

	share = kzalloc(sizeof(*share), GFP_KERNEL);
	if (!share) {
		dma_buf_put(db);
		return -ENOMEM;
	}

	share->db = db;
	share->addr = addr;
	share->size = size;
	share->dmabuf_id = dmabuf_id;
	*db_id = dmabuf_id;

	mutex_lock(&(data->share_lock));
	list_add(&share->list, &data->share_list_head);
	mutex_unlock(&(data->share_lock));
	IOMMU_DEBUG(E_LOG_CRIT, "addr=0x%llx, size=0x%x, dmabuf_id=%d\n",
			addr, size, dmabuf_id);

	return 0;
}
EXPORT_SYMBOL(mtkd_iommu_share);

int mtkd_query_dmabuf_id_by_iova(unsigned long long iova,
		u32 *db_id, unsigned long long *buf_start)
{
	struct mtk_dtv_iommu_data *data = NULL;
	struct mtk_iommu_buf_handle *buf_handle = NULL;
	int ret;

	ret = get_iommu_data(&data);
	if (ret)
		return ret;

	buf_handle = __mtk_iommu_find_buf_handle(iova, data);
	if (!buf_handle)
		return -EINVAL;

	*db_id = buf_handle->serial;
	*buf_start = buf_handle->addr;

	IOMMU_DEBUG(E_LOG_CRIT,
		"iova=0x%llx, buf_start=0x%llx, size=0x%zx, dmabuf_id=%d\n",
		iova, *buf_start, buf_handle->length, *db_id);

	return 0;
}
EXPORT_SYMBOL(mtkd_query_dmabuf_id_by_iova);

int mtkd_iommu_getfd(int *fd, unsigned int *len, u32 db_id)
{
	struct dma_buf *db;
	struct mtk_dtv_iommu_data *data = NULL;
	int ret;
	struct mtk_iommu_share *share;
	int dmafd;

	if (!fd || !len)
		return -EINVAL;

	ret = get_iommu_data(&data);
	if (ret)
		return ret;

	mutex_lock(&data->share_lock);
	list_for_each_entry(share, &data->share_list_head, list) {
		if (share->dmabuf_id == db_id) {
			dmafd = dma_buf_fd(share->db, O_CLOEXEC);
			if (dmafd < 0) {
				pr_err("%s, alloc fd fail, %d\n", __func__, dmafd);
				mutex_unlock(&data->share_lock);
				return -EINVAL;
			}

			db = dma_buf_get(dmafd);
			if (IS_ERR(db)) {
				pr_err("%s, get db fail, %x\n", __func__, dmafd);
				mutex_unlock(&data->share_lock);
				return -EINVAL;
			}

			*fd = dmafd;
			*len = share->size;
			IOMMU_DEBUG(E_LOG_CRIT, "fd=%d, dmabuf_id=%d\n",
							dmafd, db_id);
			mutex_unlock(&data->share_lock);
			return 0;
		}
	}
	mutex_unlock(&data->share_lock);
	*fd = -1;
	return -EINVAL;
}
EXPORT_SYMBOL(mtkd_iommu_getfd);

int mtkd_iommu_delete(u32 db_id)
{
	struct mtk_dtv_iommu_data *data = NULL;
	int ret;
	struct mtk_iommu_share *share, *tmp;

	ret = get_iommu_data(&data);
	if (ret)
		return ret;

	mutex_lock(&data->share_lock);
	list_for_each_entry_safe(share, tmp, &data->share_list_head, list) {
		if (share->dmabuf_id == db_id) {
			dma_buf_put(share->db);
			list_del(&share->list);
			kfree(share);
			mutex_unlock(&data->share_lock);
			IOMMU_DEBUG(E_LOG_CRIT, "dmabuf_id = %d\n", db_id);
			return 0;
		}
	}
	mutex_unlock(&data->share_lock);

	return -EINVAL;
}
EXPORT_SYMBOL(mtkd_iommu_delete);

int mma_callback_register(struct mma_callback *mma_cb)
{
	return __mma_callback_register(mma_cb);
}
EXPORT_SYMBOL(mma_callback_register);

static long mdiommu_userdev_ioctl(struct file *file,
			unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	int dir = _IOC_DIR(cmd);
	int cleanup_auth = 0;
	unsigned int cleanup_reserve = 0;
	unsigned int cleanup_pipelineid = 0;
	union ioctl_data {
		struct mdiommu_buftag_data buftags;
		struct mdiommu_reserve_iova reservation;
		struct mdiommu_ioc_data data;
		struct mdseal_ioc_data seal_data;
		struct mdiommu_buf_tag query_buftag;
		unsigned int pipelineid;
		int status;
	} data = { };

	if (arg == 0)
		return -EINVAL;

	if (_IOC_SIZE(cmd) > sizeof(data)) {
		ret = -EFAULT;
		goto exit;
	}

	if (dir & _IOC_WRITE) {
		if (!access_ok((void __user *)arg, _IOC_SIZE(cmd))) {
			pr_emerg("[IOMMU] user ptr is illegal\n");
			ret = -EFAULT;
			goto exit;
		} else if (copy_from_user(&data, (void __user *)arg, _IOC_SIZE(cmd))) {
			ret = -EFAULT;
			goto exit;
		}
	}

	switch (cmd) {
	case MDIOMMU_IOC_SUPPORT:
		data.status = mtkd_iommu_supported();
		break;
	case MDIOMMU_IOC_QUERY_BUFTAG:
		ret = mtkd_iommu_query_buftag(data.data.flag,
					&data.data.len);
		if (ret)
			goto exit;
		data.data.status = 1;
		break;
	case MDIOMMU_IOC_QUERY_BUFTAG_ID:
		ret = mtkd_iommu_query_id(data.query_buftag.buf_tag,
			&data.query_buftag.id, &data.query_buftag.max_size);
		if (ret)
			goto exit;
		break;
	case MDIOMMU_IOC_QUERY_BUFTAG_USAGE:
		ret = mtkd_iommu_query_buftag_usage(data.buftags.buf_tag_array,
					data.buftags.len_array, data.buftags.buf_tag_num);
		if (ret)
			goto exit;
		data.buftags.status = 1;
		break;
	case MDIOMMU_IOC_RESERVE_IOVA:
		ret = mtkd_iommu_reserve_iova(data.reservation.space_tag,
			data.reservation.buf_tag_array, &data.reservation.base_addr,
			data.reservation.size, data.reservation.buf_tag_num);
		if (ret) {
			ret = -ENOMEM;
			goto exit;
		}
		cleanup_reserve = 1;
		break;
	case MDIOMMU_IOC_FREE_IOVA:
		ret = mtkd_iommu_free_iova(data.reservation.space_tag);
		if (ret)
			goto exit;
		break;
	case MDIOMMU_IOC_ALLOC:
		ret = mtkd_iommu_buffer_alloc(data.data.flag,
				data.data.len,
				&data.data.addr, &data.data.fd);
		if (ret)
			goto exit;
		break;
	case MDIOMMU_IOC_GET_CARVOUT_SIZE:
		ret = mtkd_iommu_get_carv_size(data.data.flag,
				&data.data.len);
		if (ret)
			goto exit;
		break;
	case MDIOMMU_IOC_EN_LV2_CARV:
		ret = mtkd_iommu_en_lv2_carv(data.data.status);
		if (ret)
			goto exit;
		break;
	case MDIOMMU_IOC_COLLECTOR_PRIOR:
		ret = mtkd_iommu_pool_collector_prior(data.data.status);
		if (ret)
			goto exit;
		break;
	case MDIOMMU_IOC_ALLOCPIPELINEID:
		ret = mtkd_iommu_allocpipelineid(&data.pipelineid);
		if (ret)
			goto exit;
		cleanup_pipelineid = data.pipelineid;
		break;
	case MDIOMMU_IOC_FREEPIPELINEID:
		ret = mtkd_iommu_freepipelineid(data.pipelineid);
		if (ret)
			goto exit;
		break;
	case MDIOMMU_IOC_AUTHORIZE:
		ret = mtkd_iommu_buffer_authorize(data.data.flag,
				data.data.addr, data.data.len,
				data.data.pipelineid);
		if (ret)
			goto exit;
		cleanup_auth = 1;
		break;
	case MDIOMMU_IOC_UNAUTHORIZE:
		ret = mtkd_iommu_buffer_unauthorize(data.data.addr);
		if (ret)
			goto exit;
		break;
	case MDIOMMU_IOC_GETIOVA:
		ret = mtkd_iommu_getiova(data.data.fd,
				&data.data.addr, &data.data.len);
		if (ret)
			goto exit;
		break;
	case MDIOMMU_IOC_RESIZE:
		ret = mtkd_iommu_buffer_resize(data.data.fd,
				data.data.len, &data.data.addr,
				data.data.flag);
		if (ret)
			goto exit;
		break;
	case MDIOMMU_IOC_FLUSH:
		ret = mtkd_iommu_flush((unsigned long)data.data.va,
				data.data.len);
		if (ret)
			goto exit;
		break;
	case MDIOMMU_IOC_TEST:
		ret = mtk_iommu_test_tee();
		if (ret)
			goto exit;
		break;
	case MDIOMMU_IOC_SHARE:
		ret = mtkd_iommu_share(data.data.fd, &data.data.dmabuf_id);
		if (ret)
			goto exit;
		break;
	case MDIOMMU_IOC_GETFD:
		ret = mtkd_iommu_getfd(&data.data.fd,
				&data.data.len, data.data.dmabuf_id);
		if (ret)
			goto exit;
		break;
	case MDIOMMU_IOC_QUERY_ID:
		ret = mtkd_query_dmabuf_id_by_iova(data.data.addr,
			&data.data.dmabuf_id, &data.data.va);
		if (ret)
			goto exit;
		break;
	case MDIOMMU_IOC_DELETE:
		ret = mtkd_iommu_delete(data.data.dmabuf_id);
		if (ret)
			goto exit;
		break;
	case MDSEAL_IOC_GETAIDTYPE:
		ret = mtkd_seal_getaidtype(&data.seal_data);
		if (ret)
			goto exit;
		break;
	default:
		ret = -ENOTTY;
		goto exit;
	}

	if (dir & _IOC_READ) {
		if (!access_ok((void __user *)arg, _IOC_SIZE(cmd))) {
			pr_emerg("[IOMMU] user ptr is illegal\n");
			ret = -EFAULT;
			goto exit;
		} else if (copy_to_user((void __user *)arg, &data, _IOC_SIZE(cmd))) {
			if (cleanup_pipelineid) {
				ret = mtkd_iommu_freepipelineid(cleanup_pipelineid);
				if (ret)
					goto exit;
			}
			if (cleanup_reserve)
				mtkd_iommu_free_iova(
				data.reservation.space_tag);
			if (cleanup_auth)
				mtkd_iommu_buffer_unauthorize(data.data.addr);
			pr_err("IOMMU copy_to_user failed\n");
			ret = -EFAULT;
		}
	}
exit:
	return ret;
}

static int mdiommu_userdev_open(struct inode *inode, struct file *file)
{
	/* do nothing */
	return 0;
}

static int mdiommu_userdev_release(struct inode *inode, struct file *file)
{
	/* do nothing */
	return 0;
}

static const struct file_operations mdiommu_userdev_fops = {
	.owner = THIS_MODULE,
	.open = mdiommu_userdev_open,
	.release = mdiommu_userdev_release,
	.unlocked_ioctl = mdiommu_userdev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = mdiommu_userdev_ioctl,
#endif
};

int iommud_misc_register(struct mtk_dtv_iommu_data *data)
{
	data->misc_dev.minor = MISC_DYNAMIC_MINOR;
	data->misc_dev.name = "iommu_mtkd";
	data->misc_dev.fops = &mdiommu_userdev_fops;

	return misc_register(&data->misc_dev);
}
