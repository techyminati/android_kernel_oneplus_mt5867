#
# Makefile for MStar Malloc device drivers.
#

# general options
EXTRA_CFLAGS      +=  -Idrivers/mstar2/common
EXTRA_CFLAGS      +=  -Idrivers/mstar2/include
EXTRA_CFLAGS      +=  -Idrivers/mstar2/drv/iomap
#EXTRA_CFLAGS      +=  -Idrivers/mstar/iomap/$(CONFIG_MSTAR_CHIP_NAME)

# specific options
EXTRA_CFLAGS      +=

# files
obj-$(CONFIG_MSTAR_IOMAP)	+= mdrv-iomap.o
mdrv-iomap-objs			+= mdrv_iomap.o
