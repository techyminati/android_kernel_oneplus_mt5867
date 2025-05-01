/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2022 Mediatek Inc.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM mtk_iommu

#if !defined(_MTK_IOMMU_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _MTK_IOMMU_TRACE_H

#include <linux/tracepoint.h>
#include "mtk_iommu_dtv.h"

#define MAX_HEAP_NAME_SIZE 40
#define TPS(x)  tracepoint_string(x)

/* mtk_iommu general tracepoint */
TRACE_EVENT(mtk_iommu,
	TP_PROTO(
		const char *action,
		const char *buf_tag,
		size_t size,
		unsigned long long addr
	),

	TP_ARGS(action, buf_tag, size, addr),

	TP_STRUCT__entry(
		__field(const char *, action)
		__array(char, buf_tag, MAX_NAME_SIZE)
		__field(size_t, size)
		__field(unsigned long long, addr)
	),

	TP_fast_assign(
		__entry->action = action;
		strscpy(__entry->buf_tag, buf_tag, MAX_NAME_SIZE);
		__entry->size = size;
		__entry->addr = addr;
	),

	TP_printk("[%s] buf_tag: %s, size: 0x%zx, addr: 0x%llx",
		__entry->action, __entry->buf_tag, __entry->size, __entry->addr
	)
);

TRACE_EVENT(mtk_buf_handle,
	TP_PROTO(
		const char *action,
		struct mtk_iommu_buf_handle *buf_handle
	),

	TP_ARGS(action, buf_handle),

	TP_STRUCT__entry(
		__field(const char *, action)
		__field(struct mtk_iommu_buf_handle *, buf_handle)
	),

	TP_fast_assign(
		__entry->action = action;
		__entry->buf_handle = buf_handle;
	),

	TP_printk("[%s] buf_tag: %s, size: 0x%zx, addr: 0x%llx",
		__entry->action, __entry->buf_handle->buf_tag,
		__entry->buf_handle->length, __entry->buf_handle->addr
	)
);

/* mtk_iommu_resize tracepoint */
TRACE_EVENT(mtk_iommu_resize,
	TP_PROTO(
		const char *action,
		const char *buf_tag,
		size_t size,
		unsigned long long addr
	),

	TP_ARGS(action, buf_tag, size, addr),

	TP_STRUCT__entry(
		__field(const char *, action)
		__array(char, buf_tag, MAX_NAME_SIZE)
		__field(size_t, size)
		__field(unsigned long long, addr)
	),

	TP_fast_assign(
		__entry->action = action;
		strscpy(__entry->buf_tag, buf_tag, MAX_NAME_SIZE);
		__entry->size = size;
		__entry->addr = addr;
	),

	TP_printk("[%s] buf_tag: %s, size: 0x%zx, addr: 0x%llx",
		__entry->action, __entry->buf_tag, __entry->size, __entry->addr
	)
);

/* mtk_iommu_sg tracepoint */
TRACE_EVENT(mtk_iommu_sg,
	TP_PROTO(
		const char *action,
		const char *buf_tag,
		size_t size,
		unsigned long long addr,
		int found,
		u32 elapsed_time
	),

	TP_ARGS(action, buf_tag, size, addr, found, elapsed_time),

	TP_STRUCT__entry(
		__field(const char *, action)
		__array(char, buf_tag, MAX_NAME_SIZE)
		__field(size_t, size)
		__field(unsigned long long, addr)
		__field(int, found)
		__field(u32, elapsed_time)
	),

	TP_fast_assign(
		__entry->action = action;
		strscpy(__entry->buf_tag, buf_tag, MAX_NAME_SIZE);
		__entry->size = size;
		__entry->addr = addr;
		__entry->found = found;
		__entry->elapsed_time = elapsed_time;
	),

	TP_printk("[%s] buf_tag: %s, size: 0x%zx, addr: 0x%llx, found: %d, elapsed_time: %u",
		__entry->action, __entry->buf_tag, __entry->size,
		__entry->addr, __entry->found, __entry->elapsed_time
	)
);

/* dma_heap: pool_shrink */
TRACE_EVENT(mtk_iommu_pool_event,
	TP_PROTO(
		const char *pool,
		u32 order,
		int freed
	),

	TP_ARGS(pool, order, freed),

	TP_STRUCT__entry(
		__field(const char *, pool)
		__field(u32, order)
		__field(int, freed)
	),

	TP_fast_assign(
		__entry->pool = pool;
		__entry->order = order;
		__entry->freed = freed;
	),

	TP_printk("[%s] order: %d, size: %d",
		__entry->pool, __entry->order, __entry->freed
	)
);

/* dma_heap: allocate buffer */
TRACE_EVENT(mtk_iommu_alloc,
	TP_PROTO(
		const char *heap_name,
		const char *pool,
		size_t size,
		u32 time
	),

	TP_ARGS(heap_name, pool, size, time),

	TP_STRUCT__entry(
		__array(char, heap_name, MAX_HEAP_NAME_SIZE)
		__field(const char *, pool)
		__field(size_t, size)
		__field(u32, time)
	),

	TP_fast_assign(
		strscpy(__entry->heap_name, heap_name, MAX_HEAP_NAME_SIZE);
		__entry->pool = pool;
		__entry->size = size;
		__entry->time = time;
	),

	TP_printk("heap_name: %s, from: %s, size: 0x%zx, elapsed_time: %d us",
		__entry->heap_name, __entry->pool, __entry->size, __entry->time
	)
);

/* dma_heap: allocate uncached buffer sync */
TRACE_EVENT(mtk_iommu_alloc_sync,
	TP_PROTO(const char *heap_name, size_t size, u32 time),

	TP_ARGS(heap_name, size, time),

	TP_STRUCT__entry(
		__array(char, heap_name, MAX_HEAP_NAME_SIZE)
		__field(size_t, size)
		__field(u32, time)
	),

	TP_fast_assign(
		strscpy(__entry->heap_name, heap_name, MAX_HEAP_NAME_SIZE);
		__entry->size = size;
		__entry->time = time;
	),

	TP_printk("heap_name: %s, size: 0x%zx, elapsed_time: %d us",
		__entry->heap_name, __entry->size, __entry->time)
);

/* dma_heap's dmabuf map/unmap */
DECLARE_EVENT_CLASS(mtk_iommu_dmaheap_dmabuf,
	TP_PROTO(
		const char *func,
		const char *dev_name,
		size_t size,
		const char *exp_name,
		u32 time
	),

	TP_ARGS(func, dev_name, size, exp_name, time),

	TP_STRUCT__entry(
		__field(const char *, func)
		__array(char, dev_name, MAX_HEAP_NAME_SIZE)
		__field(size_t, size)
		__array(char, exp_name, MAX_HEAP_NAME_SIZE)
		__field(u32, time)
	),

	TP_fast_assign(
		__entry->func = func;
		strscpy(__entry->dev_name, dev_name, MAX_HEAP_NAME_SIZE);
		__entry->size = size;
		strscpy(__entry->exp_name, exp_name, MAX_HEAP_NAME_SIZE);
		__entry->time = time;
	),

	TP_printk("[%s] exp_name: %s, size: 0x%zx, dev_name: %s, elapsed_time: %d us",
		__entry->func, __entry->exp_name, __entry->size, __entry->dev_name, __entry->time
	)
);

DEFINE_EVENT(mtk_iommu_dmaheap_dmabuf, mtk_iommu_dmaheap_dmabuf_map,
	TP_PROTO(
		const char *func,
		const char *dev_name,
		size_t size,
		const char *exp_name,
		u32 time),
	TP_ARGS(func, dev_name, size, exp_name, time));

DEFINE_EVENT(mtk_iommu_dmaheap_dmabuf, mtk_iommu_dmaheap_dmabuf_unmap,
	TP_PROTO(
		const char *func,
		const char *dev_name,
		size_t size,
		const char *exp_name,
		u32 time),
	TP_ARGS(func, dev_name, size, exp_name, time));

/* dma_heap's dmabuf begin/end */
DECLARE_EVENT_CLASS(mtk_iommu_dmaheap_dmabuf_sync,
	TP_PROTO(
		const char *heap_name,
		size_t size,
		unsigned long long addr,
		u32 time
	),

	TP_ARGS(heap_name, size, addr, time),

	TP_STRUCT__entry(
		__array(char, heap_name, MAX_HEAP_NAME_SIZE)
		__field(size_t, size)
		__field(unsigned long long, addr)
		__field(u32, time)
	),

	TP_fast_assign(
		strscpy(__entry->heap_name, heap_name, MAX_HEAP_NAME_SIZE);
		__entry->size = size;
		__entry->addr = addr;
		__entry->time = time;
	),

	TP_printk("heap_name: %s, size: 0x%zx, addr: 0x%llx, elapsed_time: %d us",
		__entry->heap_name, __entry->size, __entry->addr, __entry->time
	)
);

DEFINE_EVENT(mtk_iommu_dmaheap_dmabuf_sync, mtk_iommu_dmaheap_dmabuf_sync_begin,
	TP_PROTO(const char *heap_name, size_t size, unsigned long long addr, u32 time),
	TP_ARGS(heap_name, size, addr, time));

DEFINE_EVENT(mtk_iommu_dmaheap_dmabuf_sync, mtk_iommu_dmaheap_dmabuf_sync_end,
	TP_PROTO(const char *heap_name, size_t size, unsigned long long addr, u32 time),
	TP_ARGS(heap_name, size, addr, time));

#endif /* _MTK_IOMMU_TRACE_H */

/* This part must be outside protection */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE mtk_iommu_trace

#include <trace/define_trace.h>
