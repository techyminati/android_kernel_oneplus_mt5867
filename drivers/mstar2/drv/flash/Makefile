#
# Makefile for MStar NAND device drivers.
#
ifdef CONFIG_MSTAR_PROJECT_NAME
    CONFIG_MSTAR_PROJECT_NAME := $(subst ",,$(CONFIG_MSTAR_PROJECT_NAME))
endif

# general options
EXTRA_CFLAGS      +=  -Idrivers/mstar2/include
EXTRA_CFLAGS      +=  -Idrivers/mstar2/include/sys/common
EXTRA_CFLAGS      +=  -Idrivers/mstar2/include/sys/drv
EXTRA_CFLAGS      +=  -Idrivers/mstar2/drv/flash
EXTRA_CFLAGS      +=  -Idrivers/mstar2/hal/common/flash
# specific options
#EXTRA_CFLAGS      +=  -O0
EXTRA_CFLAGS      +=  -DTITANIA
EXTRA_CFLAGS      +=  -DMSOS_TYPE_LINUX

# files

obj-$(CONFIG_MSTAR_SPI_FLASH)   += drvSERFLASH.o
obj-$(CONFIG_MSTAR_SPI_FLASH)	+= mtd_serflash.o
obj-$(CONFIG_MSTAR_SPI_FLASH)   += ../../hal/common/flash/halSERFLASH.o

