# SPDX-License-Identifier: GPL-2.0

# The link order is important here. ufshcd-core must initialize
# before vendor drivers.
obj-$(CONFIG_SCSI_UFSHCD)	+= core/ host/
ifeq ($(CONFIG_MSTAR_UFS),y)
EXTRA_CFLAGS    += -Idrivers/mstar2/drv/ufs
EXTRA_CFLAGS    += -Idrivers/mstar2/hal/$(CONFIG_MSTAR_CHIP_NAME)/ufs
endif
