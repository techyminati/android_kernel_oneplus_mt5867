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

#include <linux/err.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include "chip_int.h"
#include <trace/events/irq.h>

//#include "internals.h"
extern void irq_enable(struct irq_desc *desc);
extern void irq_disable(struct irq_desc *desc);
extern ptrdiff_t mstar_pm_base;

struct irq_stat
{
	unsigned int count[NR_IRQS];
	ktime_t	interval_stamp[NR_IRQS];
	ktime_t entry_stamp;
};

#ifdef CONFIG_MP_POTENTIAL_BUG
static bool __read_mostly dbg_irq_enabled = true;
#else
static bool __read_mostly dbg_irq_enabled = false;
#endif
static unsigned int __read_mostly threshold_cnt = 30000;
static unsigned int __read_mostly threshold_interval = 1000;
static unsigned int __read_mostly threshold_latency = 1000;

static struct irq_stat *pirq_stat;
static struct dentry *dbg_irq_dir;

static spinlock_t irq_hacking_lock;

static int __init dbg_irq_setup(char *str)
{
	char *temp;
	char *p;
	int index = 0;

	if (*str++ != '=' || !*str)
		return -EINVAL;

	p = str;
	while((temp = strstr(p, ",")) != NULL)
	{
		p = temp + 1;
		index++;
	}

	if(index == 2)
		sscanf(str, "%u,%u,%u", &threshold_cnt, &threshold_interval, &threshold_latency);

	dbg_irq_enabled = true;

	return 1;
}
__setup("dbg_irq", dbg_irq_setup);

static irqreturn_t irq_hacking(int irq, void *dev_id)
{
	unsigned long flags;
	static int i = 3000;

	spin_lock_irqsave(&irq_hacking_lock,flags);
	while (i > 0)
	{
		mdelay(1);
		i--;
	}
	spin_unlock_irqrestore(&irq_hacking_lock, flags);

	return IRQ_HANDLED;
}

static int irq_hack_show(struct seq_file *s, void *data)
{
	seq_printf(s, "\n");
	seq_printf(s,	"####### Abnormal Interrupt Detector #######\n"
			"----------------- Setting -----------------\n"
			"1. Using default threshold values\n"
			"   ac dbg_irq 1 @ mboot \n"
			"2. Using self-defining threshold values\n"
			"   ac dbg_irq threshold_cnt,threshold_interval,threshold_latency, Ex. ac dbg_irq 30000,500,1000\n"
			"   - Panic if interrupt frequency is over threshold_cnt (Times)/threshold_interval (milliseconds)\n"
			"   - Dump warning message if interrupt latency is over threshold_latency (milliseconds)\n"
			"---------------- Self-test ----------------\n"
			"echo test > /sys/kernel/debug/dbg_irq/irq_hack\n");
	seq_printf(s, "\n");
	return 0;
}

static int irq_hack_open(struct inode *inode, struct file *file)
{
	return single_open(file, irq_hack_show, NULL);
}

static ssize_t irq_hack_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char buffer[32];
	volatile void __iomem *reg = (volatile void __iomem *) (REG_IRQ_MASK_L - (4 << 2));

	if (!count || count > 16)// out of bound
		return count;

	if (copy_from_user(buffer, buf, count))
		return -EFAULT;

	buffer[count] = '\0';

	if (!strncmp(buffer,"test",4)) {
		pr_err("Abnormal Interrupt detector is testing irq\n");

		if(irq_to_desc(34)->action)
			free_irq(34, NULL);

		spin_lock_init(&irq_hacking_lock);
		request_irq(34, irq_hacking, SA_INTERRUPT, "irq_hack_test", NULL);

		__raw_writeb(0, reg);
		irq_enable(irq_to_desc(34));
		__raw_writeb(4, reg);
	}

	return count;
}

static const struct file_operations irq_hack_fops = {
    .owner      = THIS_MODULE,
    .open       = irq_hack_open,
    .read       = seq_read,
    .write      = irq_hack_write,
    .llseek     = seq_lseek,
    .release    = single_release,
};

static inline void irq_handler_entry_probe(void *data, int irq, struct irqaction *action)
{
	struct irq_stat *irq_stat;
	unsigned long delta_ms;

	if (action && (action->flags & IRQF_PERCPU))//do not check ppi
		return;

	if (irq >= NR_IRQS) {
		WARN_ONCE(irq >= NR_IRQS, "IRQ%d is enlarged NR_IRQS (%d), can not trace\n", irq, NR_IRQS);
		return;
	}

	irq_stat = this_cpu_ptr(data);
	irq_stat->entry_stamp = ktime_get();

	if (unlikely(irq_stat->count[irq] > threshold_cnt)) {
		delta_ms =  ktime_to_ms(ktime_sub(ktime_get(), irq_stat->interval_stamp[irq]));

		if (delta_ms < threshold_interval) {
			pr_emerg("Abnormal interrupt detected!!! over %u interrupts within %lu ms. IRQ%d, %s @ CPU%d\n", 
				irq_stat->count[irq], delta_ms, irq, irq_to_desc(irq)->action->name, smp_processor_id());
			pr_emerg("Try to disable IRQ%d to ease the system\n", irq);

			irq_disable(irq_to_desc(irq));
/* You can dump related registers befor panic.
			if (irq == 39)
			pr_emerg("@@ Bank:0x1024, [8bit] 0x14[0x%x]\n",
					 *(volatile unsigned short *)(mstar_pm_base + (0x102400+0x14)*2));
*/
			panic("MTK panic, Interrupt Overload @ IRQ%d, %s", irq, irq_to_desc(irq)->action->name);
		}

		irq_stat->count[irq] = 0;
		irq_stat->interval_stamp[irq] = ktime_get();
	}
	irq_stat->count[irq]++;
}

static void irq_handler_exit_probe(void *data, int irq, struct irqaction *action, int res)
{
	struct irq_stat *irq_stat;
	unsigned long latency_ms;

	if (action && (action->flags & IRQF_PERCPU))//do not check ppi
		return;

	if (irq >= NR_IRQS) {
		WARN_ONCE(irq >= NR_IRQS, "IRQ%d is enlarged NR_IRQS (%d), can not trace\n", irq, NR_IRQS);
		return;
	}

	irq_stat = this_cpu_ptr(data);
	latency_ms = ktime_to_ms(ktime_sub(ktime_get(), irq_stat->entry_stamp));

	if (unlikely(latency_ms >= threshold_latency)) {
		pr_emerg("\nAbnormal interrupt behavior detected!!! IRQ%d, %s @ CPU%d took %lu ms\n\n",
			irq, irq_to_desc(irq)->action->name, smp_processor_id(), latency_ms);
#ifdef CONFIG_MP_POTENTIAL_BUG
		panic("MTK panic, Interrupt took too long @ IRQ%d, %s", irq, irq_to_desc(irq)->action->name);
#endif
	}
}

static int __init mdrv_dbg_irq_init(void)
{
	struct dentry *dentry;
	int ret = 0;

	if (!dbg_irq_enabled)
		return ret;

	pirq_stat = alloc_percpu(struct irq_stat);

	if (!pirq_stat) {
		ret = -ENOMEM;
		goto fail;
	}

	ret = register_trace_irq_handler_entry(irq_handler_entry_probe, pirq_stat);
	if(ret) {
		free_percpu(pirq_stat);
		goto fail;
	}

	ret = register_trace_irq_handler_exit(irq_handler_exit_probe,pirq_stat);
	if(ret) {
		free_percpu(pirq_stat);
		goto fail;
	}

	dbg_irq_dir = debugfs_create_dir("dbg_irq", NULL);
	if(!dbg_irq_dir) {
		ret = -ENOMEM;
		goto fail;
	}

	dentry = debugfs_create_file("irq_hack", S_IRUGO | S_IWUGO, dbg_irq_dir, NULL, &irq_hack_fops);
	if(IS_ERR(dentry)) {
		ret = -ENOMEM;
		goto fail;
	}

	dentry = debugfs_create_u32("threshold_cnt", S_IRUGO | S_IWUGO, dbg_irq_dir, &threshold_cnt);
	if(IS_ERR(dentry)) {
		ret = -ENOMEM;
		goto fail;
	}

	dentry = debugfs_create_u32("threshold_interval", S_IRUGO | S_IWUGO, dbg_irq_dir, &threshold_interval);
	if(IS_ERR(dentry)) {
		ret = -ENOMEM;
		goto fail;
	}

	dentry = debugfs_create_u32("threshold_latency", S_IRUGO | S_IWUGO, dbg_irq_dir, &threshold_latency);
	if(IS_ERR(dentry)) {
		ret = -ENOMEM;
		goto fail;
	}

	pr_info("Abnomal interrupt detector initialized, frequency threshold is %u/%u (times/ms) and latency threshold is %u (ms)\n",
		threshold_cnt, threshold_interval, threshold_latency);
	return ret;

fail:
	pr_err("[%s] init fail, error code %d\n", __func__, ret);
	return ret;

}

static void __exit mdrv_dbg_irq_exit(void)
{
	if (!dbg_irq_enabled)
		return;

	debugfs_remove_recursive(dbg_irq_dir);
	unregister_trace_irq_handler_entry(irq_handler_entry_probe,pirq_stat);
	unregister_trace_irq_handler_exit(irq_handler_exit_probe,pirq_stat);
	free_percpu(pirq_stat);
}

pure_initcall(mdrv_dbg_irq_init);
module_exit(mdrv_dbg_irq_exit);

MODULE_AUTHOR("MTK");
MODULE_DESCRIPTION("Abnormal Interrupt Detector");
MODULE_LICENSE("GPL");
