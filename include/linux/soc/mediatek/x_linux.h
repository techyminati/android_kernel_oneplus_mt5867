/*
 * linux/arch/arm/mach-mt53xx/include/x_linux.h
 *
 * Debugging macro include header
 *
 * Copyright (c) 2008-2012 MediaTek Inc.
 * $Author: xiaojun.zhu $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 *
 */


#ifndef X_LINUX_H
#define X_LINUX_H


#include <linux/module.h>
#include <linux/poll.h>
#include <linux/ioport.h>
#include <linux/mm.h>
#include <asm/io.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#if defined(CONFIG_COMPAT)
#include <linux/compat.h>
#endif
#include "x_os.h"

#undef MODULE_NODE_NAME
#undef MODULE_FOPS
#undef MODULE_INIT_FUNC
#undef MODULE_EXIT_FUNC
#undef MODULE_IO_ADDR
#undef MODULE_IO_LEN


#define DECLARE_MODULE_FOPS(mod)                                            \
                                                                            \
static struct fasync_struct *async_queue = NULL;                            \
int mod##_ioctl(struct inode *inode, struct file *file, unsigned int cmd,   \
              unsigned long arg);                                           \
                                                                            \
static int mod##_fasync(int fd, struct file *filp, int mode)                \
{                                                                           \
	return fasync_helper(fd, filp, mode, &async_queue);                     \
}                                                                           \
                                                                            \
static int mod##_release(struct inode *inode, struct file *filp)            \
{                                                                           \
	mod##_fasync(-1, filp, 0);                                              \
	return 0;                                                               \
}                                                                           \
                                                                            \
struct file_operations mod##_fops = {                                       \
    .owner   = THIS_MODULE,                                                 \
    .ioctl   = mod##_ioctl,                                                 \
	.release = mod##_release,                                               \
	.fasync  = mod##_fasync,                                                \
};

extern UINT64 u8Div6432(UINT64 u8Dividend, UINT64 u8Divider,
			UINT64 * pu8Remainder);
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,20,0)
#define ACCESS_CHECK(addr,size) access_ok(addr,size)
#define get_fs() (mm_segment_t){}
#define set_fs(fs) 

#define MOD_VFS_WRITE  __kernel_write
#define MOD_VFS_READ  kernel_read
#else
#define ACCESS_CHECK(addr,size) access_ok(VERIFY_WRITE,addr,size)
#define MOD_VFS_WRITE  vfs_write
#define MOD_VFS_READ  vfs_read
#endif
#endif				//X_LINUX_H
