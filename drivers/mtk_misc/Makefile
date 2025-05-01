obj-$(CONFIG_FUNCTION_TRACER) += met/
#obj-y += mtk_perf/
obj-y += timestamp/
obj-y += cb2/
#obj-y += mtk-fusion/
obj-m += devnode/
obj-y += early_suspend/
obj-y += log2usb/
obj-y += export_symbol/
#obj-y += mm_debug/
#obj-y += hang_debug/
$(info TARGET_BUILD_VARIANT=$(TARGET_BUILD_VARIANT))
ifneq "$(TARGET_BUILD_VARIANT)" "user"
ifneq "$(KERNEL_VER)" "linux-5.15_14"
#obj-y += mtk_debug/
#obj-y += mtk_perf/
endif
endif
