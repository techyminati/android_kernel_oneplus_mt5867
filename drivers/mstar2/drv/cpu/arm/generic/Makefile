#
# Carsten Langgaard, carstenl@mips.com
# Copyright (C) 1999,2000 MIPS Technologies, Inc.  All rights reserved.
#
# This program is free software; you can distribute it and/or modify it
# under the terms of the GNU General Public License (Version 2) as
# published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
#
# Makefile for the MIPS boards generic routines under Linux.
#

#obj-y				:= reset.o display.o init.o memory.o
obj-y				:= memory.o \

#obj-$(CONFIG_MIPS_CMP)	+= amon.o
#
#obj-$(CONFIG_EARLY_PRINTK)	+= console.o
#obj-$(CONFIG_PCI)		+= pci.o
#obj-$(CONFIG_KGDB)		+= gdb_hook.o

ifndef CONFIG_ARM_LPAE
EXTRA_CFLAGS += -Werror
endif

CONFIG_MSTAR_CHIP_NAME := $(subst ",,$(CONFIG_MSTAR_CHIP_NAME))
ifdef CONFIG_MSTAR_PROJECT_NAME
    CONFIG_MSTAR_PROJECT_NAME := $(subst ",,$(CONFIG_MSTAR_PROJECT_NAME))
endif

ifdef CONFIG_MSTAR_PROJECT_NAME
    EXTRA_CFLAGS      +=  -Iarch/arm/arm-boards/$(CONFIG_MSTAR_CHIP_NAME)/$(CONFIG_MSTAR_PROJECT_NAME)
    EXTRA_CFLAGS      +=  -Iarch/arm/arm-boards/$(CONFIG_MSTAR_CHIP_NAME)/$(CONFIG_MSTAR_PROJECT_NAME)/board
endif
EXTRA_CFLAGS      +=  -Idrivers/mstar2/hal/$(CONFIG_MSTAR_CHIP_NAME)/cpu/board/
EXTRA_CFLAGS      +=  -Idrivers/mstar2/hal/$(CONFIG_MSTAR_CHIP_NAME)/cpu/arm/board/
EXTRA_CFLAGS      +=  -Iarch/arm/arm-boards/$(CONFIG_MSTAR_CHIP_NAME)
EXTRA_CFLAGS      +=  -Iarch/arm/arm-boards/$(CONFIG_MSTAR_CHIP_NAME)/board
EXTRA_CFLAGS      +=  -Idrivers/mstar2/include
