/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASM_TIMEX_H
#define __ASM_TIMEX_H

#include <asm/arch_timer.h>
#include <mstar/mpatch_macro.h>

/*
 * Use the current timer as a cycle counter since this is what we use for
 * the delay loop.
 */
#if (MP_PLATFORM_ARM_64bit_PORTING == 1)
#define get_cycles()    __arch_counter_get_cntpct_stable()
#else
#define get_cycles()	arch_timer_read_counter()
#endif

#include <asm-generic/timex.h>

#endif
