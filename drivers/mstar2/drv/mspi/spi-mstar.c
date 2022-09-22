/* SPDX-License-Identifier: GPL-2.0-only OR BSD-3-Clause */
/******************************************************************************
 *
 * This file is provided under a dual license.  When you use or
 * distribute this software, you may choose to be licensed under
 * version 2 of the GNU General Public License ("GPLv2 License")
 * or BSD License.
 *
 * GPLv2 License
 *
 * Copyright(C) 2019 MediaTek Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See http://www.gnu.org/licenses/gpl-2.0.html for more details.
 *
 * BSD LICENSE
 *
 * Copyright(C) 2019 MediaTek Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/

/* dts example for maxim 107B */
/* 
	    spi@0x153A {
			compatible = "mstar,mstar-mspi";
			reg = <0 0 0x2A7400 0x1000>;
            interrupts = <43>;
            mspi_channel = <0>;
			#address-cells = <1>;
			#size-cells = <0>;
			status = "okay";
				spidev@1{
					compatible = "spidev";
					reg = <0x0>;
					spi-max-frequency = <2000000>;
				};
	    };
 
 */ 

#include <linux/clk.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_device.h>
#include <linux/spi/spi.h>
#include <linux/version.h>
#include "mdrv_mspi.h"

/*
 * CONFIG_DEBUG_MSPI: 
 *      1:map MAXIM pins of mspi to  reg_ld_spi3_config
 *      0:require pins mapping at sboot/mboot stage.
 */ 
#define CONFIG_DEBUG_MSPI 0

/* SPI register offsets */
#define MSPI_WD0_1                      0x40
#define MSPI_WD2_3                      0x41
#define MSPI_WD4_5                      0x42
#define MSPI_WD6_7                      0x43
#define MSPI_RD0_1                      0x78
#define MSPI_RD2_3                      0x79
#define MSPI_RD4_5                      0x7a
#define MSPI_RD6_7                      0x7b
#define MSPI_WBF_RBF_SIZE               0x48
#define MSPI_WBF_RBF_SIZE_MAX           8
#define MSPI_CTRL_CLOCK_RATE            0x49
#define MSPI_ENABLE_BIT                 BIT(0)
#define MSPI_RESET_BIT                  BIT(1)
#define MSPI_ENABLE_INT_BIT             BIT(2)
#define MSPI_3WARE_MODE_BIT             BIT(4)
#define MSPI_CPHA_BIT                   BIT(6)
#define MSPI_CPOL_BIT                   BIT(7)
#define MSPI_TR_START_END_TIME          0x4a
#define MSPI_TBYTE_INTERVAL_AROUND_TIME 0x4b
#define MSPI_WD0_3_BIT_SEL              0x4c
#define MSPI_WD4_7_BIT_SEL              0x4d
#define MSPI_RD0_3_BIT_SEL              0x4e
#define MSPI_RD4_7_BIT_SEL              0x4f
#define MSPI_LSB_FIRST                  0x50
#define MSPI_LSB_FIRST_BIT              BIT(0)
#define MSPI_TRIGGER                    0x5a
#define MSPI_TRIGGER_BIT                BIT(0)
#define MSPI_DONE_FLAG                  0x5b
#define MSPI_CLEAR_DONE_FLAG            0x5c
#define MSPI_CLEAR_DONE_FLAG_BIT        BIT(0)
#define MSPI_CHIP_SELECT                0x5f
#define MSPI_CHIP_SELECT_BIT            BIT(0)

#define WB16_INDEX                     0x4
#define WB8_INDEX                      0x3
#define MSPI_WRITE_BUF_OFFSET          0x40
#define MSPI_WRITE_EXT_BUF_OFFSET      0x00
#define MAX_TX_BUF_SIZE                0x20
#define MSPI_READ_EXT_BUF_OFFSET       0x10
#define MSPI_READ_BUF_OFFSET           0x44


#define MSTAR_SPI_TIMEOUT_MS	1000
#define MSTAR_SPI_MODE_BITS	(SPI_CPOL | SPI_CPHA | SPI_CS_HIGH | SPI_NO_CS | SPI_LSB_FIRST)

#define DRV_NAME	"mspi-mstar"

struct mstar_spi {
	u64 regs;
    u32 mspi_channel;
	struct clk *clk;
	int irq;
	struct completion done;
	const u8 *tx_buf;
	u8 *rx_buf;
	int len;
    int current_trans_len;
};

struct mstar_spi_data {
	u32 regs;
	u32 irq;
    u32 mspi_channel;
};
extern ptrdiff_t mstar_pm_base;
#define REG_ADDR(addr)  (*((volatile u16 *)((mstar_pm_base + (addr )))))
#define BASEREG_ADDR(addr)  ((mstar_pm_base + (addr )))

// read 2 byte
#define MSPI_READ(_reg_)          (REG_ADDR(bs->regs + ((_reg_)<<2)))

// write 2 byte
#define MSPI_WRITE(_reg_, _val_)    \
        do{ REG_ADDR(bs->regs + ((_reg_)<<2)) =(_val_) ; }while(0)

static inline u16 mstar_rd(struct mstar_spi *bs, u32 reg)
{
	return MSPI_READ(reg);
}
static inline u8 mstar_rdh(struct mstar_spi *bs, u32 reg)
{
	return mstar_rd(bs,reg)>>8;
}
static inline u8 mstar_rdl(struct mstar_spi *bs, u16 reg)
{
	return mstar_rd(bs,reg)&0xff;
}
static inline void mstar_wr(struct mstar_spi *bs, u16 reg, u32 val)
{
	MSPI_WRITE(reg,val);
}
static inline void mstar_wrh(struct mstar_spi *bs, u16 reg, u8 val)
{
    u16 val16 = mstar_rd(bs,reg)&0xff;
    val16 |= ((u16)val)<<8;
	mstar_wr(bs,reg,val16);
}
static inline void mstar_wrl(struct mstar_spi *bs, u16 reg, u8 val)
{
    u16 val16 = mstar_rd(bs,reg)&0xff00;
    val16 |= val;
	mstar_wr(bs,reg,val16);
}

static const u16 mspi_txfifoaddr[] = { 
    MSPI_WD0_1,
    MSPI_WD2_3,
    MSPI_WD4_5,
    MSPI_WD6_7,
};
static const u16 mspi_rxfifoaddr[] = { 
    MSPI_RD0_1,
    MSPI_RD2_3,
    MSPI_RD4_5,
    MSPI_RD6_7,
};


static void mstar_hw_set_clock(struct mstar_spi *bs,struct spi_device *spi,struct spi_transfer *tfr)
{
   /*
    * FIXME: 
    *   Setup mspi clock from clock tree. 
    */ 
    extern u8 HAL_MSPI_LD_CLK_Config(u8 u8Chanel,u32 u32MspiClk);
    HAL_MSPI_LD_CLK_Config(bs->mspi_channel,tfr->speed_hz);

}
#if CONFIG_DEBUG_MSPI
static void mstar_hw_set_pin_mode(struct mstar_spi *bs,struct spi_device *spi)
{
   /*
    * FIXME: 
    *   Setup mspi pin mode from pinctrl. 
    */ 
    u64 PINCTL_REG = 0x101E<<9;
    u64 PM_SLEEP_REG = 0x0E<<9;
    REG_ADDR(PM_SLEEP_REG + (0x72<<2)) = BIT(15);
    REG_ADDR(PINCTL_REG + (0x4e<<2)) = BIT(5);

}
#endif
static void mstar_hw_enable_interrupt(struct mstar_spi *bs,bool enable)
{
    u8 val = mstar_rdl(bs,MSPI_CTRL_CLOCK_RATE);
    if (enable){
        val |= MSPI_ENABLE_INT_BIT;
    }
    else{
        val &= ~MSPI_ENABLE_INT_BIT;
    }
    mstar_wrl(bs,MSPI_CTRL_CLOCK_RATE,val);
}
static void mstar_hw_set_bits(struct mstar_spi *bs,struct spi_device *spi)
{
    int bits = spi->bits_per_word - 1;
    bits = bits|(bits<<3)|(bits<<6)|(bits<<9);
    mstar_wr(bs,MSPI_WD0_3_BIT_SEL,bits);
    mstar_wr(bs,MSPI_WD4_7_BIT_SEL,bits);
    mstar_wr(bs,MSPI_RD0_3_BIT_SEL,bits);
    mstar_wr(bs,MSPI_RD4_7_BIT_SEL,bits);
}
static void mstar_hw_set_mode(struct mstar_spi *bs,struct spi_device *spi)
{
    u8 val = mstar_rdl(bs,MSPI_CTRL_CLOCK_RATE);
    if(spi->mode&SPI_CPOL){
        val|= MSPI_CPOL_BIT;
    }else{
        val&= ~MSPI_CPOL_BIT;
    }
    if(spi->mode&SPI_CPHA){
        val|= MSPI_CPHA_BIT;
    }else{
        val&= ~MSPI_CPHA_BIT;
    }
    mstar_wrl(bs,MSPI_CTRL_CLOCK_RATE,val);
    val = mstar_rdl(bs,MSPI_LSB_FIRST);
    if (spi->mode&SPI_LSB_FIRST){
        val |= MSPI_LSB_FIRST_BIT;  
    }else{
        val &= ~MSPI_LSB_FIRST_BIT; 
    }
    mstar_wrl(bs,MSPI_LSB_FIRST,val);
}
static inline void mstar_hw_chip_select(struct mstar_spi *bs,struct spi_device *spi,bool enable)
{
    u8 val;
    if (spi->mode&SPI_NO_CS){
        return ;
    }
    val = mstar_rdl(bs, MSPI_CHIP_SELECT);
    if (enable != (!!(spi->mode&SPI_CS_HIGH))){
        val &= ~MSPI_CHIP_SELECT_BIT;
    }else{
        val |= MSPI_CHIP_SELECT_BIT;
    }
    mstar_wrl(bs,MSPI_CHIP_SELECT,val);
}
static inline void mstar_hw_clear_done(struct mstar_spi *bs)
{
    mstar_wrl(bs,MSPI_CLEAR_DONE_FLAG,MSPI_CLEAR_DONE_FLAG_BIT);
}
static inline void mstar_hw_enable(struct mstar_spi *bs,bool enable)
{
    u8 val;
    val = mstar_rdl(bs,MSPI_CTRL_CLOCK_RATE);
    if (enable){
        val |= MSPI_ENABLE_BIT;
        val |= MSPI_RESET_BIT;
    }else{
        val &= ~MSPI_ENABLE_BIT;
        val &= ~MSPI_RESET_BIT;
    }
    mstar_wrl(bs,MSPI_CTRL_CLOCK_RATE,val);
}
static inline void mstar_hw_transfer_trigger(struct mstar_spi *bs)
{
    mstar_wr(bs,MSPI_TRIGGER,MSPI_TRIGGER_BIT);
}
static void mstar_hw_txdummy(struct mstar_spi *bs,u8 len)
{
    int cnt;
    for (cnt = 0; cnt < len>>1;cnt++)
    {
        mstar_wr(bs,mspi_txfifoaddr[cnt],0xffff);
    }
    if (len&1)
    {
        mstar_wrl(bs,mspi_txfifoaddr[cnt],0xff);
    }
    mstar_wrl(bs,MSPI_WBF_RBF_SIZE,len);
}
static void mstar_hw_txfillfifo(struct mstar_spi *bs,const u8*buffer,u8 len)
{
    int cnt;
    for (cnt = 0; cnt < len>>1;cnt++)
    {
        mstar_wr(bs,mspi_txfifoaddr[cnt],buffer[cnt<<1]|(buffer[(cnt<<1)+1]<<8));
    }
    if (len&1)
    {
        mstar_wrl(bs,mspi_txfifoaddr[cnt],buffer[cnt<<1]);
    }
    mstar_wrl(bs,MSPI_WBF_RBF_SIZE,len);
}
static void mstar_hw_rxgetfifo(struct mstar_spi *bs,u8*buffer,u8 len)
{
    int cnt;
    for (cnt = 0; cnt < (len>>1);cnt++)
    {
        u16 val = mstar_rd(bs,mspi_rxfifoaddr[cnt]);
        buffer[cnt<<1] = val &0xff;
        buffer[(cnt<<1)+1] = val>>8;
    }
    if (len&1)
    {
        buffer[cnt<<1] = mstar_rdl(bs,mspi_rxfifoaddr[cnt]);
    }
}

static void mstar_spi_hw_receive(struct mstar_spi *bs)
{
    if (bs->rx_buf != NULL)
    {
        mstar_hw_rxgetfifo(bs, bs->rx_buf, bs->current_trans_len);
        bs->rx_buf += bs->current_trans_len;
    }
}
static void mstar_spi_hw_transfer(struct mstar_spi *bs)
{
    int len = bs->len;
    if (len >= 8){
        len = 8;
    }
    if (bs->tx_buf != NULL){
        mstar_hw_txfillfifo(bs, bs->tx_buf, len);
        bs->tx_buf += len;
    }else{
        mstar_hw_txdummy(bs,len);
    }
    bs->current_trans_len = len;
    bs->len -= len;
    mstar_hw_transfer_trigger(bs);
}

static void mstar_spi_hw_rx_ext(struct mstar_spi *bs)
{
    int  u8Index = 0;
    int  u16TempBuf = 0;
    int  addr_tmp = 0;
    int  j = 0;

    j =  bs->current_trans_len;
    if (bs->rx_buf != NULL)
    {
        for(u8Index = 0; u8Index < j; u8Index++)
        {
            if(u8Index & 1)
            {
                u16TempBuf = ((bs->tx_buf)[u8Index] << 8) | ((bs->tx_buf)[u8Index-1]);
                if(u8Index >>WB16_INDEX)
                {
                   addr_tmp = MSPI_READ_EXT_BUF_OFFSET+WB16_INDEX+((u8Index&(~(1<<WB16_INDEX)))>> 1);
                }
                else if(u8Index >>WB8_INDEX)
                {
                   addr_tmp = MSPI_READ_EXT_BUF_OFFSET+((u8Index&(~(1<<WB8_INDEX)))>> 1);
                }
                else
                {
                   addr_tmp = (MSPI_READ_BUF_OFFSET + (u8Index >> 1));
                }
                u16TempBuf =  mstar_rd(bs,addr_tmp);
                (bs->rx_buf)[u8Index] = u16TempBuf >> 8;
                (bs->rx_buf)[u8Index-1] = u16TempBuf & 0xFF;
            }
            else if(u8Index == (j -1))
            {
                if(u8Index >>WB16_INDEX)
                {
                   addr_tmp = MSPI_READ_EXT_BUF_OFFSET+WB16_INDEX+((u8Index&(~(1<<WB16_INDEX)))>> 1);
                }
                else if(u8Index >>WB8_INDEX)
                {
                   addr_tmp = MSPI_READ_EXT_BUF_OFFSET+((u8Index&(~(1<<WB8_INDEX)))>> 1);
                }
                else
                {
                   addr_tmp = (MSPI_READ_BUF_OFFSET + (u8Index >> 1));
                }
                u16TempBuf =  mstar_rd(bs,addr_tmp);
                (bs->rx_buf)[u8Index] = u16TempBuf >> 8;
            }
        }
        (bs->rx_buf) += j;
    }
}

static void mstar_spi_hw_xfer_ext(struct mstar_spi *bs)
{
    int  u8Index = 0;
    int  u16TempBuf = 0;
    int  addr_tmp = 0;
    int  j = 0;

    j = bs->len;
    if (j >= MAX_TX_BUF_SIZE){
        j = MAX_TX_BUF_SIZE;
    }

    if (bs->tx_buf != NULL)
    {
        for(u8Index = 0; u8Index < j; u8Index++)
        {
            if(u8Index & 1)
            {
                u16TempBuf = ((bs->tx_buf)[u8Index] << 8) | ((bs->tx_buf)[u8Index-1]);
                if(u8Index >>WB16_INDEX)
                {
                   addr_tmp = MSPI_WRITE_EXT_BUF_OFFSET+WB16_INDEX+((u8Index&(~(1<<WB16_INDEX)))>> 1);
                }
                else if(u8Index >>WB8_INDEX)
                {
                   addr_tmp = MSPI_WRITE_EXT_BUF_OFFSET+((u8Index&(~(1<<WB8_INDEX)))>> 1);
                }
                else
                {
                   addr_tmp = (MSPI_WRITE_BUF_OFFSET + (u8Index >> 1));
                }
                mstar_wr(bs,addr_tmp,u16TempBuf);
            }
            else if(u8Index == (j -1))
            {
                if(u8Index >>WB16_INDEX)
                {
                   addr_tmp = MSPI_WRITE_EXT_BUF_OFFSET+WB16_INDEX+((u8Index&(~(1<<WB16_INDEX)))>> 1);
                }
                else if(u8Index >>WB8_INDEX)
                {
                   addr_tmp = MSPI_WRITE_EXT_BUF_OFFSET+((u8Index&(~(1<<WB8_INDEX)))>> 1);
                }
                else
                {
                   addr_tmp = (MSPI_WRITE_BUF_OFFSET + (u8Index >> 1));
                }
                mstar_wr(bs,addr_tmp,(bs->tx_buf)[u8Index]);
            }
        }
        (bs->tx_buf) += j;
        mstar_wrl(bs,MSPI_WBF_RBF_SIZE,j);
        mstar_wrh(bs,MSPI_WBF_RBF_SIZE,0);
    }
    else
    {
        if (bs->rx_buf != NULL)
        {
           mstar_wrh(bs,MSPI_WBF_RBF_SIZE,(j));
           mstar_wrl(bs,MSPI_WBF_RBF_SIZE,0);
        }
    }
    bs->len -= j;
    bs->current_trans_len = j;
    mstar_hw_transfer_trigger(bs);
}

static irqreturn_t mstar_spi_interrupt(int irq, void *dev_id)
{
	struct spi_master *master = dev_id;
	struct mstar_spi *bs = spi_master_get_devdata(master);
    if(mstar_rd(bs,MSPI_DONE_FLAG)){
        mstar_hw_clear_done(bs);
        if (bs->current_trans_len != 0){
#if 0
            mstar_spi_hw_receive(bs);
#else
            mstar_spi_hw_rx_ext(bs);
#endif
        }else{
            return IRQ_NONE;
        }
        if (bs->len != 0){
#if 0
           mstar_spi_hw_transfer(bs);
#else
            mstar_spi_hw_xfer_ext(bs);
#endif
        }
        else{
            bs->current_trans_len = 0;
            complete(&bs->done);
        }
		return IRQ_HANDLED;
	}
    dev_err(&master->dev, "Error:incorrect irq num!\n");
    mstar_hw_clear_done(bs);
	return IRQ_NONE;
}

static int mstar_spi_start_transfer(struct spi_device *spi,
		struct spi_transfer *tfr)
{
	struct mstar_spi *bs = spi_master_get_devdata(spi->master);
#if CONFIG_DEBUG_MSPI
    mstar_hw_set_pin_mode(bs,spi);
#endif
    /* 
    *   Setup mspi clock for this transfer. 
    */ 
    mstar_hw_set_clock(bs,spi,tfr);

    /*
    *   Setup mspi cpol & cpha for this transfer. 
    */ 
    mstar_hw_set_mode(bs,spi);
    
    /*
    *   Setup mspi transfer bits for this transfer. 
    */ 
    mstar_hw_set_bits(bs,spi);
    
    /*
    * Enable SPI master controller&&Interrupt. 
    */
    mstar_hw_enable(bs,true);
    mstar_hw_clear_done(bs);
    mstar_hw_enable_interrupt(bs,true);
    
    /*
    *   Setup mspi chip select for this transfer. 
    */ 
    mstar_hw_chip_select(bs,spi,true);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 1)
	INIT_COMPLETION(bs->done);
#else
	reinit_completion(&bs->done);
#endif
	bs->tx_buf = tfr->tx_buf;
	bs->rx_buf = tfr->rx_buf;
	bs->len = tfr->len;
   /*
    *   Start transfer loop. 
    */ 
#if 0
    mstar_spi_hw_transfer(bs);
#else
    mstar_spi_hw_xfer_ext(bs);
#endif

	return 0;
}

static int mstar_spi_finish_transfer(struct spi_device *spi,
		struct spi_transfer *tfr, bool cs_change)
{
	struct mstar_spi *bs = spi_master_get_devdata(spi->master);

	if (tfr->delay_usecs)
		udelay(tfr->delay_usecs);

	if (cs_change){
		/*
        * Cancel chip select. 
        */ 
        mstar_hw_chip_select(bs,spi,false);
    }

	return 0;
}

static int mstar_spi_transfer_one(struct spi_master *master,
		struct spi_message *mesg)
{
	struct mstar_spi *bs = spi_master_get_devdata(master);
	struct spi_transfer *tfr;
	struct spi_device *spi = mesg->spi;
	int err = 0;
	unsigned int timeout;
	bool cs_change;

	list_for_each_entry(tfr, &mesg->transfers, transfer_list) {
    		err = mstar_spi_start_transfer(spi, tfr);
		if (err)
			goto out;

		timeout = wait_for_completion_timeout(&bs->done,
				msecs_to_jiffies(MSTAR_SPI_TIMEOUT_MS));
		if (!timeout) {
			err = -ETIMEDOUT;
			goto out;
		}

		cs_change = tfr->cs_change ||
			list_is_last(&tfr->transfer_list, &mesg->transfers);

		err = mstar_spi_finish_transfer(spi, tfr, cs_change);
		if (err)
			goto out;

		mesg->actual_length += (tfr->len - bs->len);
	}

out:

	mesg->status = err;
	spi_finalize_current_message(master);

	return 0;
}
static const struct of_device_id mstar_mspi_match[] = {
	{ .compatible = "mstar,mstar-mspi", },
	{}
};
MODULE_DEVICE_TABLE(of, mstar_mspi_match);

static int mstar_spi_probe(struct platform_device *pdev)
{
	struct spi_master *master;
	struct mstar_spi *bs;
	int err = -ENODEV;

	master = spi_alloc_master(&pdev->dev, sizeof(*bs));
	if (!master) {
		dev_err(&pdev->dev, "spi_alloc_master() failed\n");
		return -ENOMEM;
	}

	platform_set_drvdata(pdev, master);

	master->mode_bits = MSTAR_SPI_MODE_BITS;
	master->bits_per_word_mask = BIT(8 - 1)|BIT(7 - 1)
                                |BIT(6 - 1)|BIT(5 - 1)
                                |BIT(4 - 1)|BIT(3 - 1)
                                |BIT(2 - 1)|BIT(1 - 1);
	master->bus_num = -1;
	master->num_chipselect = 1;
	master->transfer_one_message = mstar_spi_transfer_one;
	master->dev.of_node = pdev->dev.of_node;

	bs = spi_master_get_devdata(master);

	init_completion(&bs->done);

	if(of_match_device(mstar_mspi_match,&pdev->dev)){
        u32 reg = 0;

    	err = of_property_read_u32_index(pdev->dev.of_node, "reg",2,&reg);
        if (err){
            dev_err(&pdev->dev, "could not get resource\n");
            return -EINVAL;
        }
        bs->regs = reg;
 
        err = of_property_read_u32(pdev->dev.of_node, "interrupts",&bs->irq);
        if (err){
            dev_err(&pdev->dev, "could not get resource\n");
            return -EINVAL;
        }
        err = of_property_read_u32(pdev->dev.of_node, "mspi_channel",&bs->mspi_channel);
        if (err){
            dev_err(&pdev->dev, "could not get resource\n");
            return -EINVAL;
        }
	}else{
        struct mstar_spi_data *data = dev_get_platdata(&pdev->dev);
        if (!data){
            dev_err(&pdev->dev, "could not get resource\n");
            return -EINVAL;
        }
        bs->regs = data->regs;
        bs->irq = data->irq;
        bs->mspi_channel = data->mspi_channel;
    }
    if (!bs->regs || !bs->irq) {
        dev_err(&pdev->dev, "could not get resource\n");
        return -EINVAL;
    }

	err = devm_request_irq(&pdev->dev,bs->irq, mstar_spi_interrupt, 0,
			dev_name(&pdev->dev), master);
	if (err) {
		dev_err(&pdev->dev, "could not request IRQ: %d:%d\n", bs->irq,err);
		return err;
	}


   /*
    * FIXME: 
    *   Setup mspi clock from clock tree. 
    */ 
    {

    }


	err = spi_register_master(master);
	if (err) {
		dev_err(&pdev->dev, "could not register SPI master: %d\n", err);
		return err;
	}

	return 0;
}

static int mstar_spi_remove(struct platform_device *pdev)
{
	struct spi_master *master = platform_get_drvdata(pdev);
	struct mstar_spi *bs = spi_master_get_devdata(master);

	devm_free_irq(&pdev->dev,bs->irq, master);
	spi_unregister_master(master);

	spi_master_put(master);

	return 0;
}


static struct platform_driver mstar_spi_driver = {
	.driver		= {
		.name		= DRV_NAME,
		.owner		= THIS_MODULE,
		.of_match_table	= mstar_mspi_match,
	},
	.probe		= mstar_spi_probe,
	.remove		= mstar_spi_remove,
};

module_platform_driver(mstar_spi_driver);

MODULE_DESCRIPTION("MSPI controller driver for MSTAR");
MODULE_AUTHOR("Vick Sun <vick.sun@mstarsemi.com>");
MODULE_LICENSE("GPL v2");
