#
# Makefile for MStar NAND device drivers.
#
CONFIG_MSTAR_CHIP_NAME := $(subst ",,$(CONFIG_MSTAR_CHIP_NAME))

# general options

EXTRA_CFLAGS    += -I$(srctree)/drivers/mstar2/include
#EXTRA_CFLAGS      += -I$(srctree)/drivers/mstar/drv/nand/
EXTRA_CFLAGS    += -I$(srctree)/drivers/mstar2/drv/nand/inc/api
EXTRA_CFLAGS    += -I$(srctree)/drivers/mstar2/drv/nand/inc/common
EXTRA_CFLAGS    += -I$(srctree)/drivers/mstar2/drv/nand/inc/config
EXTRA_CFLAGS    += -I$(srctree)/drivers/mstar2/hal/$(CONFIG_MSTAR_CHIP_NAME)/nand

# specific options

obj-y           += mdrv_nand.o mdrv_nand_io.o
obj-y           += unfdblk.o
obj-y           += src/common/drvNAND_utl.o
obj-y           += src/common/drvNAND_hal.o
obj-y           += src/common/drvNAND_ReadRetry.o
obj-y           += src/common/drvNAND_hal_v5.o
obj-y           += src/common/drvNAND_ReadRetry_v5.o
obj-y           += src/common/drvNAND_ftl.o
obj-y           += src/common/drvNAND_task.o
obj-y           += ../../hal/$(CONFIG_MSTAR_CHIP_NAME)/nand/drvNAND_platform.o
obj-$(CONFIG_MSTAR_FTL) += msftl/
