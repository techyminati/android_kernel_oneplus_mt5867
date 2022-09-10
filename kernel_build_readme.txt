cd fusion/4.19/
export PATH=/linaro-4.9.3-2014.11-arm-linux-gnueabihf/bin:$PATH
cp .config_mt5867_SMP_arm_android_emmc_nand_utopia2k_iommu .config
cp .config_mt5867_SMP_arm_android_emmc_nand_utopia2k_iommu arch/arm/configs/mstar_config

make menuconfig ->kernel hacking->Comlipe-time checks and complier options->warn for statck frame larger than ->2048
make defconfig KBUILD_DEFCONFIG=mstar_config
make -j32 