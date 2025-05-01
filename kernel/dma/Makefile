# SPDX-License-Identifier: GPL-2.0
ifeq ($(CONFIG_MP_CMA_PATCH_CMA_MSTAR_DRIVER_BUFFER),y)
EXTRA_CFLAGS      +=  -Idrivers/mstar2/include
EXTRA_CFLAGS      +=  -I$(srctree)/mm
endif

obj-$(CONFIG_HAS_DMA)			+= mapping.o direct.o
obj-$(CONFIG_DMA_OPS)			+= ops_helpers.o
obj-$(CONFIG_DMA_OPS)			+= dummy.o
obj-$(CONFIG_DMA_CMA)			+= contiguous.o
obj-$(CONFIG_DMA_DECLARE_COHERENT)	+= coherent.o
obj-$(CONFIG_DMA_API_DEBUG)		+= debug.o
obj-$(CONFIG_SWIOTLB)			+= swiotlb.o
obj-$(CONFIG_DMA_COHERENT_POOL)		+= pool.o
obj-$(CONFIG_DMA_REMAP)			+= remap.o
obj-$(CONFIG_DMA_MAP_BENCHMARK)		+= map_benchmark.o
