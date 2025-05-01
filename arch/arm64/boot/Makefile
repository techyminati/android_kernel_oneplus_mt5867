#
# arch/arm64/boot/Makefile
#
# This file is included by the global makefile so that you can add your own
# architecture-specific flags and dependencies.
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Copyright (C) 2012, ARM Ltd.
# Author: Will Deacon <will.deacon@arm.com>
#
# Based on the ia64 boot/Makefile.
#

ifeq ($(CONFIG_MSTAR_CHIP),y)
ifneq ($(MACHINE),)
include $(srctree)/$(MACHINE)/Makefile.boot
endif
endif

ZRELADDR    := $(zreladdr-y)

export ZRELADDR

OBJCOPYFLAGS_Image :=-O binary -R .note -R .note.gnu.build-id -R .comment -S

targets := Image Image.bz2 Image.gz Image.lz4 Image.lzma Image.lzo uImage uImage-dtb
UIMAGE_COMPRESSION = gzip
$(obj)/Image: vmlinux FORCE
	$(call if_changed,objcopy)

$(obj)/Image.bz2: $(obj)/Image FORCE
	$(call if_changed,bzip2)

$(obj)/Image.gz: $(obj)/Image FORCE
	$(call if_changed,gzip)

$(obj)/Image.lz4: $(obj)/Image FORCE
	$(call if_changed,lz4)

$(obj)/Image.lzma: $(obj)/Image FORCE
	$(call if_changed,lzma)

$(obj)/Image.lzo: $(obj)/Image FORCE
	$(call if_changed,lzo)
$(obj)/Image.gz-dtb: $(obj)/Image.gz $(DTB_OBJS) FORCE
	$(call if_changed,cat)

ifneq ($(LOADADDR),)
  UIMAGE_LOADADDR=$(LOADADDR)
else
  ifeq ($(CONFIG_ZBOOT_ROM),y)
    UIMAGE_LOADADDR=$(CONFIG_ZBOOT_ROM_TEXT)
  else
    UIMAGE_LOADADDR=$(ZRELADDR)
  endif
endif

$(obj)/zImage: $(obj)/Image.gz FORCE
	$(call if_changed,uimage)

ifneq ($(CONFIG_MSTAR_UIMAGE_UC),y)
$(obj)/uImage: $(obj)/zImage FORCE
else
$(obj)/uImage: $(obj)/Image FORCE
endif
	$(call if_changed,uimage)
	@echo '  Image $@ is ready'

ifeq ($(CONFIG_MSTAR_CHIP),y)
MAIN_DTB_OBJS := $(subst ",,$(CONFIG_MSTAR_CHIP_NAME)_an).main_dtb
MAIN_DTB := $(addprefix $(obj)/dts/mediatek-dtv/,$(MAIN_DTB_OBJS))

ifeq ($(CONFIG_MSTAR_CHIP),y)
# cat
# ---------------------------------------------------------------------------
# Concatentate multiple files together
quiet_cmd_catbin = CAT     $@
cmd_catbin = (cat $(filter-out FORCE,$^) > $@) || (rm -f $@; false)
endif

$(obj)/uImage-dtb: $(obj)/uImage $(MAIN_DTB) FORCE
	$(call if_changed,catbin)
	@echo ' uImage $@ is ready'
endif
