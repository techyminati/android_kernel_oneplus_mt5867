#
# Makefile for MStar EMAC device drivers.
#
CONFIG_MSTAR_CHIP_NAME := $(subst ",,$(CONFIG_MSTAR_CHIP_NAME))
ifdef CONFIG_MSTAR_PROJECT_NAME
    CONFIG_MSTAR_PROJECT_NAME := $(subst ",,$(CONFIG_MSTAR_PROJECT_NAME))
endif

# general options
EXTRA_CFLAGS      +=  -I$(srctree)/kernel/power
EXTRA_CFLAGS      +=  -I$(srctree)/drivers/mstar2/include
EXTRA_CFLAGS      +=  -I$(srctree)/drivers/mstar2/drv/gpio
EXTRA_CFLAGS      +=  -I$(srctree)/drivers/mstar2/drv/pm
EXTRA_CFLAGS      +=  -I$(srctree)/drivers/mstar2/hal/$(CONFIG_MSTAR_CHIP_NAME)/pm
EXTRA_CFLAGS      +=  -I$(srctree)/include/linux
EXTRA_CFLAGS      +=  -I$(srctree)/drivers/mstar2/hal/$(CONFIG_MSTAR_CHIP_NAME)/gpio

# specific options
EXTRA_CFLAGS      +=  -DRED_LION
# files

obj-y   := mdrv_pm.o
obj-y   += mdrv_pm_io.o
obj-y    += ../../hal/$(CONFIG_MSTAR_CHIP_NAME)/pm/mhal_pm.o
