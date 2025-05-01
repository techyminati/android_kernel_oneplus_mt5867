/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright (c) 2020 MediaTek Inc.
 * Author: Joe Liu <joe.liu@mediatek.com>
 */

#include "deferred-free-helper.h"

/*
 * SiP commands
 */
#define NULLMEM_MTK_SIP_RIU_ERROR_MASK_CTRL            BIT(0)
#define MTK_SIP_NULLMEM_CONTROL                0x8200000e
#define MTK_NULLMEM_DMABUF_NAME_SIZE	30
#define MTK_NULLMEM_DMA_MASK 35

// should be aligned with struct system_heap_buffer
struct mtk_nullmem_buffer {
	struct dma_heap *heap;
	struct list_head attachments;
	struct mutex lock;
	unsigned long len;
	struct sg_table sg_table;
	int vmap_cnt;
	void *vaddr;
	struct deferred_freelist_item deferred_free;

	bool uncached;
};

struct mtk_nullmem_attachment {
	struct device *dev;
	struct sg_table *table;
	struct list_head list;
	bool mapped;
	bool uncached;
};

extern u64 mtk_mem_next_cell(int s, const __be32 **cellp);
extern int root_addr_cells;
extern int root_size_cells;
unsigned long dma_get_nullmem_buffer_info(int share_fd);
int is_nullmem_dma_heap(struct dma_buf *dmabuf);
