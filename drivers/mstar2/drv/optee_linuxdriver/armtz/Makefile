
#########################################################################
# Set Internal Variables                                                #
# May be modified to match your setup                                   #
#########################################################################
CFG_TEE_DRV_DEBUGFS?=0
CFG_TEE_CORE_LOG_LEVEL?=2
CFG_TEE_TA_LOG_LEVEL?=2

ccflags-y+=-Werror
ccflags-y+=-Idrivers/mstar2/drv/optee_linuxdriver/include/arm_common
ccflags-y+=-Idrivers/mstar2/drv/optee_linuxdriver/include/linux
ccflags-y+=-Idrivers/mstar2/drv/optee_linuxdriver/include
ccflags-y+=-Idrivers/mstar2/drv/optee_linuxdriver/core
#Mstar
ccflags-y+=-Idrivers/mstar2/hal/$(CONFIG_MSTAR_CHIP_NAME)/optee_linuxdriver
ccflags-y+=-Idrivers/mstar2/include

ccflags-y+=-DCFG_TEE_DRV_DEBUGFS=${CFG_TEE_DRV_DEBUGFS}
ccflags-y+=-DCFG_TEE_CORE_LOG_LEVEL=${CFG_TEE_CORE_LOG_LEVEL}
ccflags-y+=-DCFG_TEE_TA_LOG_LEVEL=${CFG_TEE_TA_LOG_LEVEL}

obj-y += optee_armtz.o

optee_armtz-objs:=   \
		tee_tz_drv.o \
		tee_mem.o \
		tee_common.o \
		handle.o

#Mstar

ifeq ($(CONFIG_ARM),y)
# "smc" assembly intruction requires dedicated "armv7 secure extension"
secext := $(call as-instr,.arch_extension sec,+sec)
AFLAGS_tee_smc-arm.o := -Wa,-march=armv7-a$(secext)
optee_armtz-objs += \
	tee_smc-arm.o
endif

ifeq ($(CONFIG_ARM64),y)
optee_armtz-objs += \
	tee_smc-arm64.o
endif

