/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright (c) 2020 MediaTek Inc.
 * Author: Benson liang <benson.liang@mediatek.com>
 */

#ifndef _MTK_IOMMU_OF_H_
#define _MTK_IOMMU_OF_H_

#include <linux/list.h>
#include <linux/types.h>
#include <linux/errno.h>

#include "mtk_iommu_common.h"

struct buf_tag_info {
	uint32_t id;
	uint32_t heap_type;
	uint32_t miu;
	uint32_t zone;
	uint32_t cache;
	uint64_t maxsize;
	char name[MAX_NAME_SIZE];
	char *heap_name;
	struct list_head list;
};

struct reserved_info {
	struct list_head list;
	struct mdiommu_reserve_iova reservation;
};

struct lx_range_node {
	struct list_head list;
	uint64_t start;
	uint64_t length;
};

struct mem_cust_policy_info {
	uint64_t cma_region_maxsize;
	uint32_t mali_threshold;
	uint32_t mali_reduce_migration;
	uint32_t nr_need_2xiova;
	uint32_t *need_2xiova;
	uint32_t nr_need_zeropage;
	uint32_t *need_zeropage;
};

int mtk_iommu_get_buftag_info(struct buf_tag_info *info);
struct list_head *mtk_iommu_get_buftags(void);
int mtk_iommu_buftag_check(unsigned long buf_tag_id);
int mtk_iommu_get_reserved(struct list_head *head);
int mtk_iommu_get_memoryinfo(uint64_t *addr0, uint64_t *size0,
		uint64_t *addr1, uint64_t *size1);
int mtk_iommu_get_mem_cust_info(struct mem_cust_policy_info *info);
int mtk_iommu_get_dummy(void);

#define READ_REG(offset)	readl_relaxed(base + (offset))
#define READ_REG_16(offset)   readw_relaxed(base + (offset))
#define WRITE_REG_16(val, offset)   writew_relaxed((val), base + (offset))
#define DUMMY_ADDR_REG 1
#define DUMMY_SIZE_REG 3
#define CPU_DUMMY 0x1c4012C0
#define CPU_DUMMY_0 0
#define CPU_DUMMY_1 4
#define DUMMY_SIZE 0x200000

#endif
