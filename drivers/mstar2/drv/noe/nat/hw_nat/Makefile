CONFIG_MSTAR_CHIP_NAME := $(subst ",,$(CONFIG_MSTAR_CHIP_NAME))
ifdef CONFIG_MSTAR_PROJECT_NAME
    CONFIG_MSTAR_PROJECT_NAME := $(subst ",,$(CONFIG_MSTAR_PROJECT_NAME))
endif


# general options
EXTRA_CFLAGS      +=  -Idrivers/mstar2/include/sys/common
EXTRA_CFLAGS      +=  -Idrivers/mstar2/include
EXTRA_CFLAGS      +=  -Idrivers/mstar2/drv/noe
EXTRA_CFLAGS      +=  -Idrivers/mstar2/hal/$(CONFIG_MSTAR_CHIP_NAME)/noe
EXTRA_CFLAGS      +=  -Iinclude/linux
EXTRA_CFLAGS      +=  -Idrivers/mstar2/drv/noe/eth
EXTRA_CFLAGS      +=  -Idrivers/mstar2/drv/noe/nat/hw_nat


ifeq ($(CONFIG_NOE_QDMA),y)
EXTRA_CFLAGS      +=  -DCONFIG_RAETH_QDMA
endif

ifeq ($(CONFIG_NOE_GMAC2),y)
EXTRA_CFLAGS      +=  -DCONFIG_RAETH_GMAC2
EXTRA_CFLAGS      +=  -DCONFIG_PSEUDO_SUPPORT
endif
EXTRA_CFLAGS      +=  -DCONFIG_RA_NAT_HW


obj-$(CONFIG_NOE_HW_NAT) += hw_nat.o
hw_nat-objs := mdrv_hwnat.o
hw_nat-objs += mdrv_hwnat_foe.o
hw_nat-objs += mdrv_hwnat_util.o
hw_nat-objs += mdrv_hwnat_ioctl.o
hw_nat-objs += mdrv_hwnat_log.o
hw_nat-objs += mdrv_hwnat_api.o


hw_nat-objs += mdrv_hwnat_mcast.o
hw_nat-objs += ../../../../hal/$(CONFIG_MSTAR_CHIP_NAME)/noe/mhal_hwnat.o

