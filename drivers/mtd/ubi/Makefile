# SPDX-License-Identifier: GPL-2.0

# compatiblity with mstar
EXTRA_CFLAGS      +=  -Idrivers/mstar/nand/fcie3/inc/api

# compatiblity with mstar2
EXTRA_CFLAGS      +=  -Idrivers/mstar2/drv/nand/inc/api

obj-$(CONFIG_MTD_UBI) += ubi.o

ubi-y += vtbl.o vmt.o upd.o build.o cdev.o kapi.o eba.o io.o wl.o attach.o
ubi-y += misc.o debug.o
ubi-$(CONFIG_MTD_UBI_FASTMAP) += fastmap.o
ubi-$(CONFIG_MTD_UBI_BLOCK) += block.o

obj-$(CONFIG_MTD_UBI_GLUEBI) += gluebi.o
