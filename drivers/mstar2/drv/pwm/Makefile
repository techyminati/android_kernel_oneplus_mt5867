#
# Makefile for MStar PWM device drivers.
#
ifdef CONFIG_MSTAR_PROJECT_NAME
    CONFIG_MSTAR_PROJECT_NAME := $(subst ",,$(CONFIG_MSTAR_PROJECT_NAME))
endif

# general options
EXTRA_CFLAGS      +=  -Idrivers/mstar2/include
EXTRA_CFLAGS      +=  -Idrivers/mstar2/drv/pwm
EXTRA_CFLAGS      +=  -Idrivers/mstar2/hal/common/pwm
EXTRA_CFLAGS      +=  -Idrivers/mstar2/include/sys/common
EXTRA_CFLAGS      +=  -Iinclude/linux

# specific options
EXTRA_CFLAGS      +=  -DRED_LION
# files
obj-$(CONFIG_MSTAR_PWM)             := mdrv-pwm.o


mdrv-pwm-objs    := mdrv_pwm_io.o mdrv_pwm.o ../../hal/common/pwm/mhal_pwm.o
# mdrv-pwm-objs  := mdrv_pwm_io.o
