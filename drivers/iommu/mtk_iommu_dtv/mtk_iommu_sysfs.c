// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright (c) 2020 MediaTek Inc.
 * Author: Benson liang <benson.liang@mediatek.com>
 */
#include <linux/seq_file.h>
#include <linux/file.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/spinlock.h>

#include "mtk_iommu_common.h"
#include "mtk_iommu_dtv.h"
#include "mtk_iommu_of.h"
#include "mtk_iommu_tee_interface.h"
#include "mtk_iommu_ta.h"
#include "mtk_iommu_sysfs.h"
#include "mtk_iommu_statist.h"
#include "mtk_iommu_internal.h"
#include "mtk_iommu_trace.h"
#include "dma-heaps/mtk_iommu_page_pool.h"
#include "dma-heaps/mtk_iommu_agile_dmaheap.h"
#include "mtk_iommu_pool_collector.h"

#define MEMINFO_LEVEL_3 3
#define MEMINFO_LEVEL_2 2
#define MEMINFO_LEVEL_1 1
#define ASCII_0 48
#define LINEMAX 45
#define INIT_RATIO 0
#define LEAK_THRESHOLD 1000

#define HIGH_ORDER_GFP  (((GFP_HIGHUSER | __GFP_NOWARN \
				| __GFP_NORETRY) & ~__GFP_RECLAIM) \
				| __GFP_COMP)
#define LOW_ORDER_GFP (GFP_HIGHUSER | __GFP_COMP)
static gfp_t order_flags[] = {HIGH_ORDER_GFP,	// order 8
		HIGH_ORDER_GFP,	// order 4
		HIGH_ORDER_GFP, // order 2
		LOW_ORDER_GFP,	// order 1
		LOW_ORDER_GFP}; // order 0

u32 dbg_level;
u32 ratio_x_100 = INIT_RATIO;
u32 pool_water_mark;
static struct mtk_dtv_iommu_data *iommu_data_fs;
static const unsigned int orders[] = {8, 4, 0};
static bool interrupt_init;
static char meminfo[MAX_NAME_SIZE];
static char trace_buf_tag[MAX_NAME_SIZE];
static char alloc_buf_tag[MAX_NAME_SIZE];
static struct mem_statistics **statis;
static int nr_buf_tags;

static bool _is_num_entry_leak(unsigned long long num)
{
	if (unlikely(num >= LEAK_THRESHOLD))
		return true;

	return false;
}

void show_statistics(void)
{
	int i;

	for (i = 0; i < nr_buf_tags; i++) {
		unsigned long long total_sz;
#ifdef CONFIG_HIGHMEM
		unsigned long long low_size = atomic64_read(&statis[i]->low_size);
#endif
		if (IS_ERR_OR_NULL(statis[i]) ||
			atomic64_read(&statis[i]->total_sz) == 0)
			continue;
		total_sz = atomic64_read(&statis[i]->total_sz);
		pr_info("[IOMMU] %16.s total_size: %10llx entries: %9llx\n",
			statis[i]->buftag,
			total_sz,
			atomic64_read(&statis[i]->num_entry));
#ifdef CONFIG_HIGHMEM
		pr_info("[IOMMU] %16.s low_mem: %10llx high_mem: %9llx\n",
			statis[i]->buftag,
			low_size,
			total_sz - low_size);
#endif

		if (_is_num_entry_leak(atomic64_read(&statis[i]->num_entry))) {
			pr_crit("[IOMMU][Leak]\n");
			panic("[Leak] %s entries:%llx size:%llx\n", statis[i]->buftag,
				atomic64_read(&statis[i]->num_entry),
				total_sz);
		}
	}
}

static int meminfo_show_level_3(struct mtk_iommu_buf_handle *handle, u64 *total,
		char *buf, ssize_t *linemax, ssize_t *count)
{
	struct file *file = NULL;

	pr_emerg(
	"IOMMU: %10s %9s %16s %10s %9s %5s %5s %5s %16s %6s %6s %10s %10s %10s %16s\n",
			"serial", "buftag_id", "buf_tag", "addr",
			"size", "pid", "tgid", "mpid", "comm",
			"secure", "2XIOVA", "a_time(us)", "m_time(us)",
			"inode", "add_time");
	list_for_each_entry(handle, &iommu_data_fs->buf_list_head, buf_list_node) {
		if (handle->b.db_ion && handle->b.db_ion->file)
			file = handle->b.db_ion->file;
		pr_emerg(
		"IOMMU: %10d %9d %16.s %10llx %9x %5d %5d %5d %16.s %6d %6d %10u %10u %10lu %16s\n",
		handle->serial, handle->buf_tag_id, handle->buf_tag, handle->addr,
		(u32)handle->length, handle->pid, handle->tgid, handle->map_pid,
		handle->comm,
		handle->is_secure, handle->iova2x, handle->alloc_time, handle->map_time,
		file ? file_inode(file)->i_ino : 0, handle->buf_alloc_time);
		*total += handle->length;
	}
	return 0;
}

static int meminfo_show_level_2(struct mtk_iommu_buf_handle *handle, u64 *total,
		char *buf, ssize_t *linemax, ssize_t *count)
{
	int over_size = 0;
	int i;

	*count += scnprintf(buf, PAGE_SIZE, "%16.s %10.s %9.s\n",
			"buf_tag", "size", "#entries");
	*linemax += *count;
	if (IS_ERR_OR_NULL(statis))
		goto out;
	for (i = 0; i < nr_buf_tags; i++) {
		if (*count > PAGE_SIZE - *linemax)
			over_size = 1;

		if (IS_ERR_OR_NULL(statis[i]) ||
				atomic64_read(&statis[i]->total_sz) == 0)
			continue;
		if (!over_size) {
			*count += scnprintf(buf + *count, PAGE_SIZE - *count,
					"%16.s %10llx %9llx\n",
					statis[i]->buftag,
					atomic64_read(&statis[i]->total_sz),
					atomic64_read(&statis[i]->num_entry));
		}

		if (_is_num_entry_leak(atomic64_read(&statis[i]->num_entry))) {
			pr_crit("[IOMMU][Leak]\n");
			panic("[Leak] %s entries:%llx size:%llx\n", statis[i]->buftag,
				atomic64_read(&statis[i]->num_entry),
				atomic64_read(&statis[i]->total_sz));
		}

		*total += atomic64_read(&statis[i]->total_sz);
	}
out:
	return over_size;
}

static int meminfo_show_level_1(struct mtk_iommu_buf_handle *handle, u64 *total,
		char *buf, ssize_t *linemax, ssize_t *count)
{
	int over_size = 0;
	struct file *file = NULL;

	*count += scnprintf(buf, PAGE_SIZE,
			"%16.s %10.s %9.s %5.s %5.s %5.s %16.s %10s %6.s %10.s %16.s\n",
			"buf_tag", "addr", "size", "pid", "tgid", "mpid",
			"comm", "heap_type", "secure", "inode", "add_time");
	*linemax += *count;
	list_for_each_entry(handle, &iommu_data_fs->buf_list_head, buf_list_node) {
		if (*count > PAGE_SIZE - *linemax)
			over_size = 1;

		if (handle->b.db_ion && handle->b.db_ion->file)
			file = handle->b.db_ion->file;
		if (!over_size) {
			*count += scnprintf(buf + *count, PAGE_SIZE - *count,
				"%16.s %10llx %9x %5d %5d %5d %16.s %10d %6d %10lu %16s\n",
				handle->buf_tag, handle->addr, (u32)handle->length, handle->pid,
				handle->tgid, handle->map_pid, handle->comm, handle->heap_type,
				handle->is_secure, file ? file_inode(file)->i_ino : 0,
				handle->buf_alloc_time);
		}
		*total += handle->length;
	}
	return over_size;

}

static int meminfo_show_level_0(struct mtk_iommu_buf_handle *handle, u64 *total,
		char *buf, ssize_t *linemax, ssize_t *count)
{
	int over_size = 0;

	*count += scnprintf(buf, PAGE_SIZE, "%16.s %10.s %9.s\n",
			"buf_tag", "addr", "size");
	*linemax += *count;
	list_for_each_entry(handle, &iommu_data_fs->buf_list_head, buf_list_node) {
		if (*count > PAGE_SIZE - *linemax)
			over_size = 1;

		if (!over_size) {
			*count += scnprintf(buf + *count, PAGE_SIZE - *count, "%16.s %10llx %9x\n",
				handle->buf_tag, handle->addr,
				(u32)handle->length);
		}
		*total += handle->length;
	}
	return over_size;

}
static int meminfo_show_level_buftag(struct mtk_iommu_buf_handle *handle, u64 *total,
		char *buf, ssize_t *linemax, ssize_t *count)
{
	int over_size = 0;
	struct file *file = NULL;
	int i;
	struct scatterlist *sg = NULL;
	int wide = 0, narrow = 0;

	*count += scnprintf(buf, PAGE_SIZE,
	"IOMMU: %9s %9s %16s %10s %10s %9s %5s %5s %16s %10s\n",
			"serial", "buftag_id", "buf_tag", "addr",
			"wide/narr", "size", "pid", "tgid", "comm",
			"inode");

	*linemax += *count;
	list_for_each_entry(handle, &iommu_data_fs->buf_list_head, buf_list_node) {
		if (*count > PAGE_SIZE - *linemax)
			over_size = 1;

		if (strncmp(meminfo, handle->buf_tag, MAX_NAME_SIZE))
			continue;

		if (handle->b.db_ion && handle->b.db_ion->file)
			file = handle->b.db_ion->file;
		for_each_sg(handle->sgt->sgl, sg, handle->sgt->orig_nents, i) {
			if (page_to_phys(sg_page(sg)) < iommu_data_fs->asym_addr_start)
				wide++;
			else
				narrow++;
		}
		if (!over_size) {
			*count += scnprintf(buf + *count, PAGE_SIZE - *count,
				"IOMMU: %9d %9d %16.s %10llx %6d/%3d %9x %5d %5d %16.s %10lu\n",
				handle->serial, handle->buf_tag_id, handle->buf_tag,
				handle->addr, wide, narrow,
				(u32)handle->length, handle->pid, handle->tgid,
				handle->comm, file ? file_inode(file)->i_ino : 0);
		}
		wide = 0;
		narrow = 0;
		*total += handle->length;
	}
	return over_size;
}

static ssize_t meminfo_show(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	struct mtk_iommu_buf_handle *handle = NULL;
	ssize_t count = 0, linemax = LINEMAX;
	u64 total = 0;
	int over_size = 0;
	int info_type = -1;
	unsigned long flags = 0;

	if (!iommu_data_fs)
		return -ENODEV;
	info_type = meminfo[0] - ASCII_0;

	spin_lock_irqsave(&(iommu_data_fs->buf_lock), flags);

	if (info_type == MEMINFO_LEVEL_3) {
		over_size = meminfo_show_level_3(handle, &total, buf, &linemax, &count);
		pr_emerg("IOMMU: total size 0x%llx\n", total);
	} else if (info_type == MEMINFO_LEVEL_2) {
		over_size = meminfo_show_level_2(handle, &total, buf, &linemax, &count);
	} else if (info_type == MEMINFO_LEVEL_1) {
		over_size = meminfo_show_level_1(handle, &total, buf, &linemax, &count);
	} else if (info_type > MEMINFO_LEVEL_3) {
		over_size = meminfo_show_level_buftag(handle, &total, buf, &linemax, &count);
	} else {
		over_size = meminfo_show_level_0(handle, &total, buf, &linemax, &count);
	}

	count += scnprintf(buf + count, linemax, "Total size: 0x%llx\n", total);
	spin_unlock_irqrestore(&(iommu_data_fs->buf_lock), flags);
	if (over_size == 1)
		count += scnprintf(buf + count, linemax, "more buffer not show\n");

	return count;
}

static ssize_t meminfo_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int ret;
	unsigned int len;

	if (!iommu_data_fs)
		return -ENODEV;

	len = strlen(buf);
	if (len >= MAX_NAME_SIZE || len == 0) {
		pr_err("[IOMMU] buf_tag incompatible length\n");
		return count;
	}

	ret = scnprintf(meminfo, MAX_NAME_SIZE, "%s", buf);
	meminfo[len - 1] = '\0';
	return ret;
}

static ssize_t calltrace_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	if (!iommu_data_fs)
		return scnprintf(buf, PAGE_SIZE,
			"MTK DTV iommu driver is not supported\n");

	return scnprintf(buf, PAGE_SIZE, "calltrace = %d\n",
				iommu_data_fs->calltrace_enable);
}

static ssize_t calltrace_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int err;
	unsigned long val;

	if (!iommu_data_fs)
		return -ENODEV;

	err = kstrtoul(buf, 10, &val);
	if (err)
		return err;

	if (val > 255)
		return -EINVAL;

	iommu_data_fs->calltrace_enable = val;
	return count;
}

static ssize_t log_level_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	if (!iommu_data_fs)
		return scnprintf(buf, PAGE_SIZE,
			"MTK DTV iommu driver is not supported\n");

	return scnprintf(buf, PAGE_SIZE, "log_level = %d\n", iommu_data_fs->log_level);
}

static ssize_t log_level_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned long val;
	int err;

	if (!iommu_data_fs)
		return -ENODEV;

	err = kstrtoul(buf, 10, &val);
	if (err)
		return err;

	if (val > 255)
		return -EINVAL;

	iommu_data_fs->log_level = val;
	dbg_level = val;
	return count;
}

static ssize_t ratio_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	if (!iommu_data_fs)
		return scnprintf(buf, PAGE_SIZE,
			"MTK DTV iommu driver is not supported\n");

	return scnprintf(buf, PAGE_SIZE, "ratio = %d\n", ratio_x_100);
}

static ssize_t ratio_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned long val;
	int err;

	if (!iommu_data_fs)
		return -ENODEV;

	err = kstrtoul(buf, 10, &val);
	if (err)
		return err;

	ratio_x_100 = val;
	return count;
}

static ssize_t recordtime_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	if (!iommu_data_fs)
		return scnprintf(buf, PAGE_SIZE,
			"MTK DTV iommu driver is not supported\n");

	return scnprintf(buf, PAGE_SIZE, "recordtime = %d\n",
		iommu_data_fs->record_alloc_time);
}

static ssize_t recordtime_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned long val;
	int err;

	if (!iommu_data_fs)
		return -ENODEV;

	err = kstrtoul(buf, 10, &val);
	if (err)
		return err;

	if (val > 255)
		return -EINVAL;

	iommu_data_fs->record_alloc_time = val;
	return count;
}

static ssize_t asym_start_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	if (!iommu_data_fs)
		return scnprintf(buf, PAGE_SIZE,
			"MTK DTV iommu driver is not supported\n");
	return scnprintf(buf, PAGE_SIZE, "asym_addr_start = %lu\n",
		iommu_data_fs->asym_addr_start);
}

static ssize_t asym_start_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned long val;
	int err;

	if (!iommu_data_fs)
		return -ENODEV;
	err = kstrtoul(buf, 0, &val);
	if (err)
		return err;
	iommu_data_fs->asym_addr_start = val;
	return count;
}

static irqreturn_t _irq_top(int eIntNum, void *dev_id)
{
	// TODO: try to detect irq coming reason
	return IRQ_WAKE_THREAD;
}

static irqreturn_t mtk_iommu_secure_isr(int irq, void *devid)
{
#define ITEM_0		0
#define ITEM_1		1
#define ITEM_2		2
#define NR_SMC_BUF	3
	int ret;
	uint8_t buf[NR_SMC_BUF] = { };
	struct device *dev = ((struct mtk_dtv_iommu_data *)devid)->dev;

	ret = mtk_iommu_tee_debug(E_MMA_IOMMU_DEBUG_INFO,
				&buf[ITEM_0], sizeof(uint8_t),
				&buf[ITEM_1], sizeof(uint8_t),
				&buf[ITEM_2], sizeof(uint8_t));
	if (ret)
		dev_err(dev, "%s: return error 0x%x from tee\n",
			__func__, ret);

	return IRQ_HANDLED;
}

static ssize_t interrupt_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	if (!iommu_data_fs)
		return scnprintf(buf, PAGE_SIZE,
			"MTK DTV iommu driver is not supported\n");

	return scnprintf(buf, PAGE_SIZE, "debug interrupt %s\n",
		interrupt_init ? "enable" : "disable");
}

static ssize_t interrupt_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int irq, err;
	unsigned long val;

	if (!iommu_data_fs)
		return -ENODEV;

	irq = iommu_data_fs->irq;
	if (!irq) {
		dev_err(iommu_data_fs->dev, "missing irq number!\n");
		return -EINVAL;
	}

	err = kstrtoul(buf, 10, &val);
	if (err)
		return err;

	switch (val) {
	case 0:
		if (!interrupt_init)
			break;

		devm_free_irq(iommu_data_fs->dev, irq, iommu_data_fs);
		interrupt_init = false;
		dev_info(iommu_data_fs->dev, "free debug irq @%d\n", irq);

		break;
	case 1:
		if (interrupt_init)
			break;

		err = devm_request_threaded_irq(iommu_data_fs->dev, irq,
					_irq_top, mtk_iommu_secure_isr,
					IRQF_TRIGGER_HIGH | IRQF_SHARED | IRQF_ONESHOT,
					"iommu-dbg", iommu_data_fs);
		if (err) {
			dev_err(iommu_data_fs->dev,
				"register iommu debug irq @%d but failed with %d\n",
				irq, err);
			return err;
		}
		interrupt_init = true;
		dev_info(iommu_data_fs->dev, "register debug irq @%d\n", irq);

		break;
	default:
		return -EINVAL;
	}

	return count;
}

static ssize_t lock_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int ret;
	char *tmp;
	char *start, *end;
	size_t size, i;
	struct tee_map_lock lock = { };

	if (!iommu_data_fs)
		return -ENODEV;

	tmp = devm_kzalloc(iommu_data_fs->dev, count, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	strncpy(tmp, buf, count);
	tmp[count - 1] = '\0';

	start = tmp;
	end = strchr(start, ',');
	if (end) {
		size = (size_t)(end - start);
		if (size > (MAX_NAME_SIZE - 1)) {
			dev_err(iommu_data_fs->dev, "%s: invalid buftag size\n",
				__func__);
			goto out;
		}
		strncpy(lock.buffer_tag, tmp, size);
		lock.buffer_tag[size] = '\0';
	} else {
		dev_err(iommu_data_fs->dev, "%s: invalid input buf tag\n", __func__);
		goto out;
	}

	start = end + 1;
	end = strchr(start, ',');
	if (end)
		*end = '\0';
	else
		goto out;

	ret = kstrtou32(start, 10, &lock.aid_num);
	if (ret) {
		dev_err(iommu_data_fs->dev, "%s: aid_num kstrtou32 failed with %d\n",
				__func__, ret);
		goto out;
	}
	if (lock.aid_num > 8) {
		dev_err(iommu_data_fs->dev, "%s: aid_num(%d) > 8\n",
				__func__, lock.aid_num);
		goto out;
	}
	if (lock.aid_num > 0) {
		for (i = 0; i < lock.aid_num; i++) {
			start = end + 1;
			end = strchr(start, ',');
			if (end) {
				*end = '\0';
				ret = kstrtou32(start, 10, &lock.aid[i]);
				if (ret) {
					dev_err(iommu_data_fs->dev,
						"%s: aid kstrtou32 failed with %d\n",
						__func__, ret);
					goto out;
				}
			} else {
				dev_err(iommu_data_fs->dev, "%s: aid error\n", __func__);
				goto out;
			}
		}
	}

	ret = mtk_iommu_tee_lockdebug(&lock);
	if (ret)
		dev_err(iommu_data_fs->dev, "%s: failed with 0x%x\n", __func__, ret);

out:
	devm_kfree(iommu_data_fs->dev, tmp);
	return count;
}

int _statis_init(void)
{
	struct list_head *head = NULL, *pos = NULL;
	struct buf_tag_info *buf = NULL;
	int i, j, count = 0;

	if (statis)
		return 0;

	head = mtk_iommu_get_buftags();
	if (!head || list_empty(head))
		return -EINVAL;

	list_for_each(pos, head)
		count++;
	nr_buf_tags = count;

	statis = kcalloc(count, sizeof(struct mem_statistics *), GFP_KERNEL);
	if (IS_ERR_OR_NULL(statis))
		return -ENOMEM;

	i = 0;
	list_for_each_entry(buf, head, list) {
		statis[i] = kzalloc(sizeof(struct mem_statistics), GFP_KERNEL);
		if (IS_ERR_OR_NULL(statis[i])) {
			for (j = i - 1; j >= 0; j--)
				kfree(statis[j]);
			kfree(statis);
			return -ENOMEM;
		}

		strncpy(statis[i]->buftag, buf->name, MAX_NAME_SIZE);
		statis[i]->buftag[MAX_NAME_SIZE - 1] = '\0';
		atomic64_set(&statis[i]->total_sz, 0);
		atomic64_set(&statis[i]->dma_sz, 0);
		atomic64_set(&statis[i]->others_sz, 0);
		atomic64_set(&statis[i]->num_entry, 0);
#ifdef CONFIG_HIGHMEM
		atomic64_set(&statis[i]->low_size, 0);
#endif
		i++;
	}
	return 0;
}

struct mem_statistics *get_buf_tag_statistics(const char *buf_tag)
{
	int i, ret;

	if (IS_ERR_OR_NULL(buf_tag))
		goto out;

	ret = _statis_init();
	if (ret) {
		pr_err("[IOMMU][%s] statis init failed with %d\n", __func__, ret);
		goto out;
	}

	for (i = 0; i < nr_buf_tags; i++) {
		if (strncmp(statis[i]->buftag, buf_tag, MAX_NAME_SIZE) == 0)
			return statis[i];
	}

out:
	return ERR_PTR(-EINVAL);
}

static inline unsigned long _get_memusage_by_buftag(const char *buf_tag,
			struct mtk_dtv_iommu_data *data)
{
	unsigned long total_size = 0;
	struct mtk_iommu_buf_handle *buf_handle = NULL;
	unsigned long flags = 0;

	if (!buf_tag || !data)
		return 0;

	spin_lock_irqsave(&(data->buf_lock), flags);
	list_for_each_entry(buf_handle, &(data->buf_list_head), buf_list_node) {
		if (strncmp(buf_tag, buf_handle->buf_tag,
				MAX_NAME_SIZE) == 0)
			total_size += buf_handle->length;
	}
	spin_unlock_irqrestore(&(data->buf_lock), flags);

	return total_size;
}

static ssize_t statistics_show(struct device *dev,
			 struct device_attribute *attr,
			 char *buf)
{
	struct mem_statistics *stat = NULL;

	if (!iommu_data_fs)
		return 0;

	if (trace_buf_tag[0] == '\0')
		return scnprintf(buf, PAGE_SIZE, "please set target buftag first\n");

	stat = get_buf_tag_statistics(trace_buf_tag);
	if (IS_ERR_OR_NULL(stat))
		return 0;

	return scnprintf(buf, PAGE_SIZE, "Buf_tag: %s, memory cost: 0x%llx bytes\n",
			stat->buftag, atomic64_read(&stat->total_sz));
}

static ssize_t statistics_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct mem_statistics *stat = NULL;
	unsigned int len;

	if (!iommu_data_fs)
		return count;

	if (strstr(buf, "clear")) {
		memset(trace_buf_tag, '\0', MAX_NAME_SIZE);
		return count;
	}

	len = strlen(buf) - 1;
	if (len >= MAX_NAME_SIZE) {
		pr_err("[IOMMU] buf_tag length %u too long\n", len);
		return count;
	}

	memcpy(trace_buf_tag, buf, len);
	trace_buf_tag[len] = '\0';

	stat = get_buf_tag_statistics(trace_buf_tag);
	if (IS_ERR_OR_NULL(stat)) {
		pr_err("[IOMMU] [%s] buf_tag_stat not exist\n", trace_buf_tag);
		return count;
	}

	pr_emerg("counting the meminfo for %s, current mem usage: 0x%llx bytes\n",
			stat->buftag, atomic64_read(&stat->total_sz));

	return count;
}

struct alloc_data {
	int ret;
	char *buf;
};

static struct page *alloc_largest_available(unsigned long size,
					    unsigned int *max_order_index)
{
	struct page *page;
	unsigned int i;

	for (i = 0; i < NUM_ORDERS; i++) {
		if (size <  (PAGE_SIZE << orders[i]))
			continue;

		if (orders[*max_order_index] < orders[i])
			continue;
		page = alloc_pages(order_flags[i], orders[i]);
		if (!page)
			continue;
		*max_order_index = i;
		return page;
	}
	return NULL;
}

static void alloc_free(void *data)
{
	struct alloc_data *a_data = data;
	struct page *page;
	char *cur = a_data->buf;
	int err;
	unsigned long size = 0;
	long real_allocate_size = 0;
	u32 prev_water_mark = 0;
	unsigned int max_order_index = 0;
	struct timespec64 tv0 = {0}, tv1 = {0};
	u32 elapsed_time = 0;

	if (!iommu_data_fs) {
		a_data->ret = -ENODEV;
		goto out;
	}

	err = kstrtoul(cur, 0, &size);
	if (err) {
		a_data->ret = err;
		goto out;
	}

	prev_water_mark = pool_water_mark;
	pool_water_mark = size;
	if (size <= prev_water_mark || size >= SZ_1G)
		goto out;

	real_allocate_size = size - max((get_total_alloc_size() << PAGE_SHIFT), prev_water_mark);
	size = real_allocate_size;
	ktime_get_real_ts64(&tv0);
	while (real_allocate_size > 0
			&& get_total_alloc_size() < (get_pool_water_mark() >> PAGE_SHIFT)) {
		page = alloc_largest_available(real_allocate_size, &max_order_index);
		if (!page) {
			ktime_get_real_ts64(&tv1);
			goto out;
		}
		atomic_add(1 << orders[max_order_index], &total_alloc_size);
		mtk_iommu_dmabuf_page_pool_free(agile_pools[max_order_index], page, false);
		real_allocate_size -= page_size(page);
	}
	ktime_get_real_ts64(&tv1);
out:
	elapsed_time = (tv1.tv_sec - tv0.tv_sec) * USEC_PER_SEC +
			(tv1.tv_nsec - tv0.tv_nsec) / NSEC_PER_USEC;
	trace_mtk_iommu_alloc(TPS("sysfs agile"), TPS("alloc_free"),
			size - real_allocate_size, elapsed_time);
	pr_info("watermark from 0x%x to 0x%x alloc 0x%lx success, total_size=0x%0x000 a_times=%u\n",
			prev_water_mark, pool_water_mark, size - real_allocate_size,
			get_total_alloc_size(), elapsed_time);
	kfree(cur);
	kfree(a_data);
	return;
}

static ssize_t agile_pool_size_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct alloc_data *a_data;
	unsigned int len;

	a_data = kzalloc(sizeof(*a_data), GFP_KERNEL);
	len = strlen(buf) + 1;
	a_data->buf = kzalloc(len, GFP_KERNEL);
	memcpy(a_data->buf, buf, len);
	add_collector(alloc_free, a_data);

	return count;
}

static ssize_t agile_pool_size_show(struct device *dev,
			 struct device_attribute *attr,
			 char *buf)
{
	int at = 0, i;

	for (i = 0; i < NUM_ORDERS; i++) {
		at += sysfs_emit_at(buf, at, "agile pool [%d], order %d, count %d\n",
				i, orders[i],
				agile_pools[i]->count[0] + agile_pools[i]->count[1]);
	}
	at += sysfs_emit_at(buf, at,
			"agile_water_mark: 0x%x, pool size: 0x%x000, alloc from system: 0x%x000\n",
			pool_water_mark, get_total_pool_size(), get_total_alloc_size());
	at += sysfs_emit_at(buf, at,
			"out_of_pool_times: %u\n", out_of_pool_times);
	return at;
}

static ssize_t heap_type_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct list_head *tag_list;
	struct buf_tag_info *buf_info;
	char *input;
	char *cur;
	int i = 0;
	int err;
	unsigned int len;
	unsigned long type = HEAP_TYPE_MAX;
	char buf_tag[MAX_NAME_SIZE];

	tag_list = mtk_iommu_get_buftags();
	if (!tag_list) {
		pr_err("%s: get buftags list failed!\n", __func__);
		return -ENODEV;
	}

	cur = kstrdup(buf, GFP_KERNEL);
	if (!cur)
		return -ENOMEM;
	while ((input = strsep(&cur, ","))) {
		switch (i) {
		case 0:
			len = strscpy(buf_tag, input, MAX_NAME_SIZE);
			if (len >= MAX_NAME_SIZE) {
				pr_err("[IOMMU] buf_tag length %u too long\n", len);
				kfree(cur);
				return -EINVAL;
			}
			break;
		case 1:
			err = kstrtoul(input, 10, &type);
			if (err) {
				kfree(cur);
				return err;
			}
			break;
		default:
			break;
		}
		i++;
	}

	list_for_each_entry(buf_info, tag_list, list) {
		if (!strncmp(buf_tag, buf_info->name, MAX_NAME_SIZE)) {
			buf_info->heap_type = type;
			pr_crit("input %s: buf_tag %s change to heap_type %u\n",
				buf_tag, buf_info->name, buf_info->heap_type);
			break;
		}
	}

	kfree(cur);
	return count;
}

static ssize_t alloc_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
#define MAX_LOOP 64
	struct list_head *tag_list;
	struct buf_tag_info *buf_info;
	char *input;
	char *cur;
	int i = 0;
	int err;
	unsigned int len;
	unsigned long attrs = 0;
	unsigned long size = 0x1000000;
	unsigned long times = 32;
	void *va[MAX_LOOP];
	dma_addr_t iova[MAX_LOOP] = {0};

	if (!iommu_data_fs)
		return count;

	tag_list = mtk_iommu_get_buftags();
	if (!tag_list) {
		pr_err("%s: get buftags list failed!\n", __func__);
		return -ENODEV;
	}

	cur = kstrdup(buf, GFP_KERNEL);
	if (!cur)
		return -ENOMEM;
	while ((input = strsep(&cur, ","))) {
		switch (i) {
		case 0:
			len = strlen(input) - 1;
			if (len >= MAX_NAME_SIZE) {
				pr_err("[IOMMU] buf_tag length %u too long\n", len);
				kfree(cur);
				return count;
			}
			memcpy(alloc_buf_tag, input, len);
			alloc_buf_tag[len] = '\0';
			break;
		case 1:
			err = kstrtoul(input, 10, &times);
			if (err) {
				kfree(cur);
				return err;
			}
			break;
		case 2:
			err = kstrtoul(input, 0, &size);
			if (err) {
				kfree(cur);
				return err;
			}
			break;
		default:
			break;
		}
		i++;
	}

	list_for_each_entry(buf_info, tag_list, list) {
		if (!strncmp(alloc_buf_tag, buf_info->name, MAX_NAME_SIZE)) {
			attrs = buf_info->id << 24;
			goto found;
		}
	}
	pr_err("%s not found\n", alloc_buf_tag);
	kfree(cur);
	return -EINVAL;
found:
	attrs |= DMA_ATTR_WRITE_COMBINE;
	for (i = 0; i < times; i++) {
		va[i] = __mtk_iommu_alloc_attrs(iommu_data_fs->dev, size, &iova[i],
					GFP_HIGHUSER, attrs);
		if (dma_mapping_error(dev, iova[i]) != 0)
			pr_err("dma_alloc_attrs fail\n");
	}

	if (i == times)
		pr_emerg("alloc success\n");
	i--;

	for (; i >= 0; i--) {
		//  free IOMMU buffer
		__mtk_iommu_free_attrs(iommu_data_fs->dev, size, va[i], iova[i], attrs);
		va[i] = 0;
		iova[i] = 0;
	}

	kfree(cur);
	return count;
}

static ssize_t help_show(struct device *dev,
			 struct device_attribute *attr,
			 char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "Debug Help:\n"
		       "- log_level <RW>: To control debug log level.\n"
		       "                  Read log_level value.\n"
		       "- meminfo <RW>: To control read buffer information.\n"
		       "                value:0,1,2,3 means different level information\n"
		       "                Read IOMMU buffer information.\n"
		       "- calltrace <RW>: To dump allocate calltrace.\n"
		       "                1:enable, 0:disable.\n"
		       "                Read calltrace value.\n"
		       "- recordtime <RW>:To control printf how much time it take.\n"
		       "                1:enable, 0:disable.\n"
		       "                Read recordtime value.\n"
		       "- interrupt <RW>:To control security interrupt.\n"
		       "                1:enable, 0:disable.\n"
		       "                Read interrupt value.\n"
		       "- lock      <RO>:For IOMMU memory debug.\n"
		       "- statistics <RW>: To statistic memory usage via buftag\n");
}

static DEVICE_ATTR_RO(help);
static DEVICE_ATTR_RW(log_level);
static DEVICE_ATTR_RW(ratio);
static DEVICE_ATTR_RW(meminfo);
static DEVICE_ATTR_RW(calltrace);
static DEVICE_ATTR_RW(recordtime);
static DEVICE_ATTR_RW(interrupt);
static DEVICE_ATTR_WO(lock);
static DEVICE_ATTR_WO(alloc);
static DEVICE_ATTR_WO(heap_type);
static DEVICE_ATTR_RW(agile_pool_size);
static DEVICE_ATTR_RW(statistics);
static DEVICE_ATTR_RW(asym_start);

static struct attribute *mtk_iommu_attrs[] = {
	&dev_attr_meminfo.attr,
	&dev_attr_calltrace.attr,
	&dev_attr_recordtime.attr,
	&dev_attr_interrupt.attr,
	&dev_attr_lock.attr,
	&dev_attr_help.attr,
	&dev_attr_log_level.attr,
	&dev_attr_ratio.attr,
	&dev_attr_statistics.attr,
	&dev_attr_asym_start.attr,
	&dev_attr_alloc.attr,
	&dev_attr_heap_type.attr,
	&dev_attr_agile_pool_size.attr,
	NULL,
};

static const struct attribute_group mtk_iommu_attr_group = {
	.name = "mtk_dbg",
	.attrs = mtk_iommu_attrs,
};

static const struct attribute_group *mtk_iommu_attr_groups[] = {
	&mtk_iommu_attr_group,
	NULL,
};

int mtk_iommu_sysfs_init(struct device *dev, struct mtk_dtv_iommu_data *data)
{
	int ret;

	if (!dev || !data)
		return -EINVAL;

	iommu_data_fs = data;

	ret = mtk_iommu_pool_collector_init(dev);
	if (ret)
		dev_err(data->dev, "failed to create pool collector thread");

	ret = sysfs_create_groups(&dev->kobj, mtk_iommu_attr_groups);
	if (ret) {
		dev_err(data->dev, "%s failed with %d\n", __func__, ret);
		return ret;
	}

	ret = _statis_init();
	if (ret) {
		dev_err(data->dev, "%s statis init failed with %d\n", __func__, ret);
		return ret;
	}

	return 0;
}

int mtk_iommu_sysfs_destroy(struct device *dev)
{
	if (interrupt_init && iommu_data_fs) {
		devm_free_irq(iommu_data_fs->dev,
				iommu_data_fs->irq, iommu_data_fs);
		interrupt_init = false;
	}

	sysfs_remove_groups(&dev->kobj, mtk_iommu_attr_groups);
	mtk_iommu_pool_collector_exit();
	return 0;
}
