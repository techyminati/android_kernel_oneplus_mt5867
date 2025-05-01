// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
/*
 * Copyright (c) 2020 MediaTek Inc.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/swap.h>
#include <linux/wait.h>
#include <linux/cgroup.h>
#include <linux/oom.h>
#include <linux/rcupdate.h>
#include <linux/cgroup-defs.h>
#include <linux/pid_namespace.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/vmstat.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/firmware.h>
#include <linux/swap.h>

//for magic number
#define DF_3 3
#define DF_10 10
#define DF_50 50
#define DF_100 100
#define DF_200 200
#define DF_1000 1000
#define DF_90 90

int low_ram = 0;
#define CONFIG_ON 1
#define CONFIG_OFF 0
#define	NAP_TIME DF_3 //HZ*NAP_TIME
#define	MAX_EPOLL_EVENTS DF_10
#define	PATH_MAX DF_50
#define	MEM_FREE_FILE_SIZE DF_100
#define	SWAP_FILE_SIZE DF_200
#define	OOM_SCORE_ADJ_MAX	DF_1000
#define	OOM_SCORE_ADJ_MIN	-DF_1000
#define	OOM_SCORE_ADJ_DEF	600
#define	SWAP_THRESHOLD_DEF DF_90
#define	ONE_HUNDRED	DF_100
#define	TEN	10
#define	ONE_K	1024

struct task_struct *mtk_lmkd;
static int mtk_lmkd_func(void *);
static void	mtk_kill_all(void);
static void	mtk_kill_one(void);
static int mtk_show_zram_stat(void);
static void	mtk_privilege_list_init(void);
static int mtk_query_free_mem_threshold(void);
static int mtk_query_swap_threshold(void);
static int mtk_query_zram_kill_timer(void);
static bool	mtk_query_zram_kill(void);
struct task_struct *mtk_find_lock_task_mm(struct task_struct *p);
unsigned long	total_kill_size; //KB
int	oom_score_adj_threshold	=	OOM_SCORE_ADJ_DEF; //kill	>	this value
int	swap_threshold = SWAP_THRESHOLD_DEF; //Percentage
int	zram_kill_timer;
int	free_mem_threshold;	//KB
long totalswap;
bool zram_pressure_high;
int	zram_pressure_high_counter;
bool zram_kill;
#define	DECIMAL	10
#define	PERCENTAGE	100
#define	DROP_CACHES_LEVEL_1	1
#define	DROP_CACHES_LEVEL_2	2
#define	DROP_CACHES_LEVEL_3	3

spinlock_t privilege_list_lock;
spinlock_t free_mem_threshold_lock;
spinlock_t swap_threshold_lock;
spinlock_t zram_kill_timer_lock;
spinlock_t zram_kill_lock;
struct privilege_node {
	char name[PATH_MAX];
	struct list_head list;
};

struct list_head privilege_list	=	LIST_HEAD_INIT(privilege_list);

wait_queue_head_t	mtk_lmkd_wait;
EXPORT_SYMBOL(mtk_lmkd_wait);
atomic_t should_wait;
EXPORT_SYMBOL(should_wait);
void mtk_wakeup_lmkd(void)
{
	atomic_set(&should_wait, 0);
	//only wakeup while mtk_lmkd is sleeping
	if (waitqueue_active(&mtk_lmkd_wait)) {
		pr_alert("[mtklmkd]	wake up	from main	kernel\n");
		wake_up_interruptible(&mtk_lmkd_wait);
	}
}
EXPORT_SYMBOL(mtk_wakeup_lmkd);
void mtk_hypnotize_lmkd(void)
{
	pr_alert("[mtklmkd]	go sleep\n");
	atomic_set(&should_wait, 1);
}
EXPORT_SYMBOL(mtk_hypnotize_lmkd);

static ssize_t lmkd_privilege_list_read
(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	spin_lock(&privilege_list_lock);
	struct list_head *now;
	struct privilege_node	*now_node;
	int	len;
	char sbuf[PAGE_SIZE];

	list_for_each(now, &privilege_list)	{
		now_node = list_entry(now, struct	privilege_node,	list);
		pr_alert("%s\n", now_node->name);
	}
	spin_unlock(&privilege_list_lock);
	return 0;

}

static ssize_t lmkd_privilege_list_write
(struct	file *file,	const char __user *buf, size_t count, loff_t *ppos)
{
	struct privilege_node *new_node	= kmalloc(sizeof(struct	privilege_node), GFP_KERNEL);

	memset(new_node, 0,	sizeof(struct privilege_node));
	if (!count || count	> TASK_COMM_LEN) {
		kfree(new_node);
		return 0;
	}
	if (new_node) {
		copy_from_user(new_node->name, buf,	count);
		spin_lock(&privilege_list_lock);
		list_add(&new_node->list, &privilege_list);
		spin_unlock(&privilege_list_lock);
		return count;
	}

	else
		return -EINVAL;
}


static int lmkd_privilege_list_open(struct inode *inode, struct	file *file)
{
		return 0;
}

static int lmkd_privilege_list_release(struct inode	*inode,	struct file	*file)
{
		return 0;
}


static const struct	proc_ops lmkd_privilege_list_fops	=	{
				.proc_read = lmkd_privilege_list_read,
				.proc_write = lmkd_privilege_list_write,
				.proc_open = lmkd_privilege_list_open,
				.proc_release = lmkd_privilege_list_release,
};

static ssize_t free_mem_threshold_read(struct file *file, char __user *buf, size_t count,
loff_t *ppos)
{
	pr_alert("[mtklmkd]	free mem threshold = %d	KB\n",	mtk_query_free_mem_threshold());
	return 0;
}

static ssize_t free_mem_threshold_write
(struct file	*file, const char __user *buf, size_t count, loff_t *ppos)
{
	char threshold[TASK_COMM_LEN+1]	= {0};
	char *target;

	if (count	== 0 ||	count >	TASK_COMM_LEN)
		return 0;
	if (copy_from_user(threshold,	buf, count))
		return 0;

	spin_lock(&free_mem_threshold_lock);
	threshold[count] = '\0';
	target = strstrip(threshold);
	if (target) {
		kstrtoint(target, DECIMAL,	&free_mem_threshold);
		if (free_mem_threshold < 0)
			free_mem_threshold = 0;
		pr_alert("[mtklmkd]	set	free mem threshold = %d	KB\n", free_mem_threshold);
	}
	spin_unlock(&free_mem_threshold_lock);
	return count;
}

static int free_mem_threshold_open(struct inode	*inode,	struct file	*file)
{
	return 0;
}

static int free_mem_threshold_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct	proc_ops free_mem_threshold_fops = {
				.proc_read	= free_mem_threshold_read,
				.proc_write	= free_mem_threshold_write,
				.proc_open	= free_mem_threshold_open,
				.proc_release = free_mem_threshold_release,
};



static ssize_t low_ram_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	if (count == 0 || count > TASK_COMM_LEN)
		return -EINVAL;

	char buffer[TASK_COMM_LEN+1] = {0};
	char *temp;
	long low_ram_enable;
	if (copy_from_user(buffer, buf, count))
		return -EINVAL;
	low_ram_enable = simple_strtol(buffer, &temp, DECIMAL);
	if (low_ram_enable > CONFIG_ON || low_ram_enable < CONFIG_OFF)
		return -EINVAL;
	low_ram = low_ram_enable;
	return count;
}

static ssize_t low_ram_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	printk(KERN_ALERT"low ram %d \n", low_ram);
	return 0;
}
static int low_ram_open(struct inode *inode, struct file *file){
	return 0;
}
static int low_ram_release(struct inode *inode, struct file *file){
	return 0;
}

static struct proc_ops const low_ram_fops = {
        .proc_read           = low_ram_read,
        .proc_write          = low_ram_write,
        .proc_open           = low_ram_open,
        .proc_release        = low_ram_release,
};

static int mtk_query_free_mem_threshold(void)
{
	int	threshold	=	0;

	spin_lock(&free_mem_threshold_lock);
	threshold	=	free_mem_threshold;
	spin_unlock(&free_mem_threshold_lock);

	return threshold;
}

static ssize_t swap_threshold_read
(struct file *file,	char __user	*buf, size_t count, loff_t *ppos)
{
	pr_alert("[mtklmkd]	zram use %d\n",	mtk_show_zram_stat());
	pr_alert("[mtklmkd]	swap threshold = %d\n",	mtk_query_swap_threshold());
	return 0;
}

static ssize_t swap_threshold_write
(struct file *file, const char	__user *buf, size_t	count, loff_t *ppos)
{
	char threshold[TASK_COMM_LEN+1]	=	{0};
	char *target;

	if (count	== 0 ||	count	>	TASK_COMM_LEN)
		return 0;
	if (copy_from_user(threshold,	buf, count))
		return 0;

	spin_lock(&swap_threshold_lock);
	threshold[count] = '\0';
	target = strstrip(threshold);
	if (target) {
		kstrtoint(target, DECIMAL,	&swap_threshold);
		if (swap_threshold < 0)
			swap_threshold = 0;
		if (swap_threshold > PERCENTAGE)
			swap_threshold = PERCENTAGE;
		pr_alert("[mtklmkd]	set	swap threshold = %d	percentage\n",
			swap_threshold);
	}
	spin_unlock(&swap_threshold_lock);

	return count;
}

static int swap_threshold_open(struct	inode	*inode,	struct file	*file)
{
	return 0;
}

static int swap_threshold_release(struct inode *inode, struct	file *file)
{
	return 0;
}

static const struct	proc_ops swap_threshold_fops = {
				.proc_read	= swap_threshold_read,
				.proc_write	= swap_threshold_write,
				.proc_open	= swap_threshold_open,
				.proc_release = swap_threshold_release,
};

static int mtk_query_swap_threshold(void)
{
	int	threshold	=	0;

	spin_lock(&swap_threshold_lock);
	threshold	=	swap_threshold;
	spin_unlock(&swap_threshold_lock);

	return threshold;
}

static ssize_t zram_kill_timer_read
(struct file *file, char	__user *buf, size_t	count, loff_t *ppos)
{
	pr_alert("[mtklmkd]	zram kill timer	= %d\n",
	mtk_query_zram_kill_timer());
	return 0;
}

static ssize_t zram_kill_timer_write
(struct	file *file,	const char __user *buf, size_t count, loff_t *ppos)
{
	char timer[TASK_COMM_LEN+1]	=	{0};
	char *target;

	if (count	== 0 ||	count	>	TASK_COMM_LEN)
		return 0;
	if (copy_from_user(timer,	buf, count))
		return 0;

	spin_lock(&zram_kill_timer_lock);
	timer[count] = '\0';
	target = strstrip(timer);
	if (target) {
		kstrtoint(target, DECIMAL,	&zram_kill_timer);
		if (zram_kill_timer	<	0)
			zram_kill_timer	=	0;
		pr_alert("[mtklmkd]	set	zram kill timer	= %d\n",
		zram_kill_timer);
	}
	spin_unlock(&zram_kill_timer_lock);
	return count;
}

static int zram_kill_timer_open(struct inode *inode, struct	file *file)
{
	return 0;
}

static int zram_kill_timer_release(struct	inode	*inode,	struct file	*file)
{
	return 0;
}

static const struct	proc_ops zram_kill_timer_fops	=	{
				.proc_read = zram_kill_timer_read,
				.proc_write	= zram_kill_timer_write,
				.proc_open = zram_kill_timer_open,
				.proc_release = zram_kill_timer_release,
};

static int mtk_query_zram_kill_timer(void)
{
	int	timer	=	0;

	spin_lock(&zram_kill_timer_lock);
	timer	=	zram_kill_timer;
	spin_unlock(&zram_kill_timer_lock);

	return timer;
}

static bool	mtk_query_zram_kill(void)
{
	bool status	=	false;

	spin_lock(&zram_kill_lock);
	status = zram_kill;
	spin_unlock(&zram_kill_lock);

	return status;
}

static void	mtk_set_zram_kill(bool status)
{
	spin_lock(&zram_kill_lock);
	zram_kill	=	status;
	spin_unlock(&zram_kill_lock);
}

static ssize_t lmkd_killed_size_write
(struct file *file, const char	__user *buf, size_t	count, loff_t *ppos)
{
	return 0;
}
static ssize_t lmkd_killed_size_read
(struct	file *file,	char __user	*buf, size_t count, loff_t *ppos)
{
	pr_alert("[mtklmkd]	total	killed szie	%d Kb\n", total_kill_size);
		return 0;
}
static int lmkd_killed_size_open(struct	inode	*inode,	struct file	*file)
{
		return 0;
}
static int lmkd_killed_size_release(struct inode *inode, struct	file *file)
{
		return 0;
}
static const struct	proc_ops lmkd_killed_size_fops = {
				.proc_read	= lmkd_killed_size_read,
				.proc_write	= lmkd_killed_size_write,
				.proc_open	= lmkd_killed_size_open,
				.proc_release	= lmkd_killed_size_release,
};
static ssize_t oom_score_adj_threshold_write
(struct	file *file,	const char __user *buf, size_t count, loff_t *ppos)
{
	char buffer[TEN] = {0};
	long oom_score_adj;
	int err;

	if (copy_from_user(buffer, buf,	count))
		return -EINVAL;
	err = kstrtol(buffer, TEN, &oom_score_adj);
	if (err)
		return -EINVAL;
	if (oom_score_adj > OOM_SCORE_ADJ_MAX || oom_score_adj < OOM_SCORE_ADJ_MIN)
		return -EINVAL;
	oom_score_adj_threshold	= oom_score_adj;
	return count;
}
static ssize_t oom_score_adj_threshold_read
(struct file *file, char __user *buf, size_t count, loff_t	*ppos)
{
	pr_alert("oom	score	adj	threshold	%d\n",	oom_score_adj_threshold);
	return 0;
}
static int oom_score_adj_threshold_open(struct inode *inode, struct	file *file)
{
		return 0;
}
static int oom_score_adj_threshold_release(struct inode	*inode,	struct file	*file)
{
		return 0;
}
static unsigned	int	oom_score_adj_threshold_poll
(struct	file *file,	struct poll_table_struct *pts)
{
	pr_alert("start	poll\n");
	pr_alert("after	poll\n");
	int	poll_flags = POLLIN	| POLLRDNORM;
	return poll_flags;
}
static const struct	proc_ops oom_score_adj_threshold_fops	=	{
				.proc_read	= oom_score_adj_threshold_read,
				.proc_write	 = oom_score_adj_threshold_write,
				.proc_open	 = oom_score_adj_threshold_open,
				.proc_release = oom_score_adj_threshold_release,
				.proc_poll = oom_score_adj_threshold_poll,
};
static ssize_t mtk_wakeup_lmkd_write
(struct	file *file,	const char __user *buf, size_t count, loff_t *ppos)
{
	return 0;
}
static ssize_t mtk_wakeup_lmkd_read
(struct file *file, char __user *buf, size_t count, loff_t	*ppos)
{
	pr_alert("[mtklmkd]	should wait	%d\n",	atomic_read(&should_wait));
	return 0;
}
static int mtk_wakeup_lmkd_open(struct inode *inode, struct	file *file)
{
	mtk_wakeup_lmkd();
	return 0;
}
static int mtk_wakeup_lmkd_read_release(struct inode *inode, struct	file *file)
{
	mtk_hypnotize_lmkd();
	return 0;
}
static const struct	proc_ops mtk_wakeup_lmkd_fops	=	{
				.proc_read		= mtk_wakeup_lmkd_read,
				.proc_write		= mtk_wakeup_lmkd_write,
				.proc_open		= mtk_wakeup_lmkd_open,
				.proc_release	= mtk_wakeup_lmkd_read_release,
};
static ssize_t mtk_hypnotize_lmkd_write
(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	return 0;
}
static ssize_t mtk_hypnotize_lmkd_read
(struct	file *file,	char __user	*buf, size_t count, loff_t *ppos)
{
	pr_alert("[mtklmkd]	should wait	%d\n",	atomic_read(&should_wait));
	return 0;
}
static int mtk_hypnotize_lmkd_open(struct	inode	*inode,	struct file	*file)
{
	return 0;
}
static int mtk_hypnotize_lmkd_release(struct inode *inode, struct	file *file)
{
	return 0;
}
static const struct	proc_ops mtk_hypnotize_lmkd_fops = {
				.proc_read		= mtk_hypnotize_lmkd_read,
				.proc_write		= mtk_hypnotize_lmkd_write,
				.proc_open		= mtk_hypnotize_lmkd_open,
				.proc_release	= mtk_hypnotize_lmkd_release,
};


static ssize_t mtk_lmkd_totalswap_write
(struct file *file, const char	__user *buf, size_t	count, loff_t *ppos)
{
	char buffer[TEN] = {0};
	int err;

	if (copy_from_user(buffer, buf,	count))
		return -EINVAL;
	err	=	kstrtol(buffer,	TEN, &totalswap);
	if (err)
		return -EINVAL;

	return count;
}
static ssize_t mtk_lmkd_totalswap_read
(struct	file *file,	char __user	*buf, size_t count, loff_t *ppos)
{
	pr_alert("total	swap %d\n", totalswap);
	return 0;
}
static int mtk_lmkd_totalswap_open(struct inode	*inode,	struct file	*file)
{
		return 0;
}
static int mtk_lmkd_totalswap_release(struct inode *inode, struct	file *file)
{
		return 0;
}
static const struct	proc_ops mtk_lmkd_totalswap_fops = {
				.proc_read		= mtk_lmkd_totalswap_read,
				.proc_write		= mtk_lmkd_totalswap_write,
				.proc_open		= mtk_lmkd_totalswap_open,
				.proc_release	= mtk_lmkd_totalswap_release,
};

#define LMKD_UID 2948
#define LMKD_GID 2948

int __init mtk_lmkd_init(void)
{
	struct proc_dir_entry *mtk_lmkd_dir;
	struct proc_dir_entry *entry;

	mtk_privilege_list_init();


	spin_lock_init(&privilege_list_lock);
	spin_lock_init(&free_mem_threshold_lock);
	spin_lock_init(&swap_threshold_lock);
	spin_lock_init(&zram_kill_timer_lock);
	spin_lock_init(&zram_kill_lock);
	init_waitqueue_head(&mtk_lmkd_wait);
	mtk_lmkd_dir = proc_mkdir("mtk_lmkd", NULL);
	entry = proc_create("total_killed_size",
		0640,	mtk_lmkd_dir, &lmkd_killed_size_fops);
	if (!entry) {
		pr_alert("mtklmkd	fail !!\n");
		return -1;
	}
	proc_set_user(entry, KUIDT_INIT(LMKD_UID), KGIDT_INIT(LMKD_GID));

	entry = proc_create("oom_score_adj_threshold",
		0640, mtk_lmkd_dir,	&oom_score_adj_threshold_fops);
	if (!entry)	{
		pr_alert("mtklmkd	fail !!\n");
			return -1;
	}
	proc_set_user(entry, KUIDT_INIT(LMKD_UID), KGIDT_INIT(LMKD_GID));

	entry = proc_create("mtk_hypnotize_lmkd",
		0640, mtk_lmkd_dir, &mtk_hypnotize_lmkd_fops);
	if (!entry)	{
		pr_alert("mtklmkd	fail !!\n");
			return -1;
	}
	proc_set_user(entry, KUIDT_INIT(LMKD_UID), KGIDT_INIT(LMKD_GID));

	entry = proc_create("mtk_wakeup_lmkd",
		0640, mtk_lmkd_dir,	&mtk_wakeup_lmkd_fops);
	if (!entry)	{
		pr_alert("mtklmkd	fail !!\n");
			return -1;
	}
	proc_set_user(entry, KUIDT_INIT(LMKD_UID), KGIDT_INIT(LMKD_GID));

	entry = proc_create("privilege_list",
		0640, mtk_lmkd_dir, &lmkd_privilege_list_fops);
	if (!entry) {
		pr_alert("mtklmkd	fail !!\n");
			return -1;
	}
	proc_set_user(entry, KUIDT_INIT(LMKD_UID), KGIDT_INIT(LMKD_GID));

	entry = proc_create("free_mem_threshold",
		0640, mtk_lmkd_dir, &free_mem_threshold_fops);
	if (!entry)	{
		pr_alert("mtklmkd	fail !!\n");
		return -1;
	}
	proc_set_user(entry, KUIDT_INIT(LMKD_UID), KGIDT_INIT(LMKD_GID));

	entry = proc_create("swap_threshold",
		0640, mtk_lmkd_dir, &swap_threshold_fops);
	if (!entry)	{
		pr_alert("mtklmkd	fail !!\n");
		return -1;
	}
	proc_set_user(entry, KUIDT_INIT(LMKD_UID), KGIDT_INIT(LMKD_GID));

	entry = proc_create("zram_kill_timer",
		0640,	mtk_lmkd_dir,	&zram_kill_timer_fops);
	if (!entry)	{
		pr_alert("mtklmkd	fail !!\n");
		return -1;
	}
	proc_set_user(entry, KUIDT_INIT(LMKD_UID), KGIDT_INIT(LMKD_GID));

	entry = proc_create("mtk_lmkd_totalswap",
		0640, mtk_lmkd_dir, &mtk_lmkd_totalswap_fops);
	if (!entry)	{
		pr_alert("mtklmkd	fail !!\n");
		return -1;
	}
	proc_set_user(entry, KUIDT_INIT(LMKD_UID), KGIDT_INIT(LMKD_GID));
	
	entry =  proc_create("low_ram", 0640, mtk_lmkd_dir, &low_ram_fops);
	
	if (!entry)	{
		pr_alert("mtklmkd	fail !!\n");
		return -1;
	}
	proc_set_user(entry, KUIDT_INIT(LMKD_UID), KGIDT_INIT(LMKD_GID));

	atomic_set(&should_wait, 1);
	mtk_lmkd = kthread_run(mtk_lmkd_func,	NULL,	"mtk_lmkd");
	if (IS_ERR(mtk_lmkd))
		return -1;
	return 0;
}


#ifdef CONFIG_CPUSETS
struct fmeter	{
	int	cnt;		/* unprocessed events	count	*/
	int	val;		/* most	recent output	value	*/
	time64_t time;		/* clock (secs)	when val computed	*/
	spinlock_t lock;	/* guards	read or	write	of above */
};
struct cpuset	{
	struct cgroup_subsys_state css;
	unsigned long	flags;		/* "unsigned long" so	bitops work	*/
	cpumask_var_t	cpus_allowed;
	cpumask_var_t	cpus_requested;
	nodemask_t mems_allowed;
	cpumask_var_t	effective_cpus;
	nodemask_t effective_mems;
	nodemask_t old_mems_allowed;
	struct fmeter	fmeter;		/* memory_pressure filter	*/
	int	attach_in_progress;
	int	pn;
	int	relax_domain_level;
#ifdef CONFIG_MP_ASYM_UMA_ALLOCATION
	/* for memory	region idx */
	int	memalloc_idx;
#endif
};

static struct	cgroup_subsys_state	*mtk_task_cs(struct	task_struct	*tsk)
{
	struct cgroup_subsys_state *ptr	=	task_css(tsk,	cpuset_cgrp_id);

	if (ptr)
		return ptr;
	else
		return NULL;
}

#endif

static int mtk_show_zram_stat(void)	//return usage
{
	if (totalswap) {
		pr_alert("[mtklmkd]	total %d use %lld free ratio %d\n",
		totalswap, atomic_long_read(&nr_swap_pages)	+	1,
		(((atomic_long_read(&nr_swap_pages)	+	1) * ONE_HUNDRED)/(totalswap)));
	} else
		pr_alert("[mtklmkd]	total %d use	%lld ratio %d\n",
		totalswap,	atomic_long_read(&nr_swap_pages));
	return 0;
}

static int mtk_show_free_mem(void)
{
	struct sysinfo i;

	si_meminfo(&i);
	pr_alert("Free Memory =	%d KB\n",
	(i.freeram <<	(PAGE_SHIFT	-	TEN)));
	return 0;
}

static bool netflix_running(void)
{
	struct task_struct *tsk;
	bool found = false;

	if (low_ram)
		found = true;
	else {
		rcu_read_lock();
		for_each_process(tsk) {
			struct task_struct *p;
			p = mtk_find_lock_task_mm(tsk);
			if (!p)
				continue;
			if ((strstr(p->comm, "netflix.ninja") || strstr(p->comm, "youtube.tv")) && (p->signal->oom_score_adj <= 0)) {
				found = true;
				task_unlock(p);
				break;
			}
			task_unlock(p);
		}
		rcu_read_unlock();
	}
	return found;
}

static bool	swap_full(void)
{
	if (totalswap) {
		if	((((atomic_long_read(&nr_swap_pages) + 1) *	ONE_HUNDRED)/(totalswap))
			 <= (ONE_HUNDRED - swap_threshold))
			return true;
		else
			return false;
	}
	return false;
}

static int mtk_lmkd_func(void	*data)
{
	DEFINE_WAIT(wait);
	bool should_kill = false;

	while	(1) {
		if (kthread_should_stop())
			break;
		if (atomic_read(&should_wait)) {//no video play	go sleep
			should_kill	=	false;
			prepare_to_wait(&mtk_lmkd_wait,	&wait, TASK_INTERRUPTIBLE);
			schedule();
			finish_wait(&mtk_lmkd_wait,	&wait);
			should_kill	=	true;	//wake-up	lets kill
		}
		if (!atomic_read(&should_wait))	{
			if (!netflix_running())
				should_kill = false;
			if (should_kill) {
				pr_info("[mtklmkd] lets	go first time	kill!\n");
				goto start_kill;
			} else {
				set_current_state(TASK_INTERRUPTIBLE);
				schedule_timeout(HZ*NAP_TIME);
				set_current_state(TASK_RUNNING);
				if (swap_full() && netflix_running()) {//check	threshold
					pr_info("[mtklmkd] kill	because	of full	swap-space\n");
					goto start_kill;
				}	else {
					pr_info("[mtklmkd] swap-space	free take	nap\n");
					continue;
				}
			}
		}	else { //no	video	play lets	goto sleep
			continue;
		}


start_kill:
		mtk_kill_all();
		should_kill	=	false;
		continue;
	}
	return 0;
}

struct task_struct *mtk_find_lock_task_mm(struct task_struct *p)
{
	struct task_struct *t;

	rcu_read_lock();
	for_each_thread(p, t)	{
		task_lock(t);
		if (likely(t->mm))
			goto found;
		task_unlock(t);
	}
	t	=	NULL;
found:
	rcu_read_unlock();
	return t;
}

static bool	mtk_should_kill(struct task_struct *p, int last_kill_pid)
{
#ifdef CONFIG_CPUSETS
	struct cgroup_subsys_state *cpuset_ptr;

	cpuset_ptr = mtk_task_cs(p);
	if (cpuset_ptr &&
		cpuset_ptr->cgroup &&
		cpuset_ptr->cgroup->kn &&
		cpuset_ptr->cgroup->kn->name) {
		if (strstr(cpuset_ptr->cgroup->kn->name, "app"))
			return false;
	}
#endif
	struct list_head *now;
	struct privilege_node	*now_node;
	int	nr_free	=	global_zone_page_state(NR_FREE_PAGES);

	spin_lock(&privilege_list_lock);
	list_for_each(now, &privilege_list)	{
		now_node = list_entry(now, struct	privilege_node,	list);
		if (strstr(now_node->name, p->comm)) {
			spin_unlock(&privilege_list_lock);
			return false;
		}
	}
	spin_unlock(&privilege_list_lock);

	if (p->signal->oom_score_adj <=	oom_score_adj_threshold)
		return false;
	if (p->pid ==	last_kill_pid)
		return false;
	else
		return true;
}

static void	mtk_kill_all(void)
{
	struct task_struct *tsk;
	static int last_kill_pid = -1;
	int	tasksize = 0;
	struct task_struct *p;

	rcu_read_lock();
	for_each_process(tsk)	{
		if (atomic_read(&should_wait)	&& !mtk_query_zram_kill())
			break;
		p	=	mtk_find_lock_task_mm(tsk);
		if (!p)
			continue;
		if (!mtk_should_kill(p,	last_kill_pid))	{
			task_unlock(p);
			continue;
		}
		tasksize = get_mm_rss(p->mm);
		last_kill_pid	=	p->pid;
		send_sig(SIGKILL,	p, 0);
		pr_alert("[mtklmkd]	start to kill pid %d ! %s size %d kB\n",
			last_kill_pid, p->comm, (tasksize * (long)(PAGE_SIZE / ONE_K)));
		task_unlock(p);
		total_kill_size	+= (tasksize * (long)(PAGE_SIZE	/	ONE_K));
	}
end:
	rcu_read_unlock();
}

static void	mtk_privilege_list_init(void)
{
	struct privilege_node	*new_node;

	new_node = kmalloc(sizeof(struct privilege_node), GFP_KERNEL);
	memset(new_node, 0,	sizeof(struct	privilege_node));
	strncpy(new_node->name, ".katniss:search", TASK_COMM_LEN);
	list_add(&new_node->list, &privilege_list);

	new_node = kmalloc(sizeof(struct privilege_node), GFP_KERNEL);
	memset(new_node, 0,	sizeof(struct	privilege_node));
	strncpy(new_node->name, "niss:interactor", TASK_COMM_LEN);
	list_add(&new_node->list, &privilege_list);

	new_node = kmalloc(sizeof(struct privilege_node), GFP_KERNEL);
	memset(new_node, 0,	sizeof(struct	privilege_node));
	strncpy(new_node->name, ".remote.service", TASK_COMM_LEN);
	list_add(&new_node->list, &privilege_list);

	new_node = kmalloc(sizeof(struct privilege_node), GFP_KERNEL);
	memset(new_node, 0,	sizeof(struct	privilege_node));
	strncpy(new_node->name, "apps.mediashell", TASK_COMM_LEN);
	list_add(&new_node->list, &privilege_list);

}

static void	mtk_drop_caches(void)
{
	pr_alert("no CONFIG_SET_FS setting cant	read\n");
}

static void	__exit mtk_lmkd_exit(void)
{
	send_sig(SIGKILL,	mtk_lmkd,	0);
}
module_init(mtk_lmkd_init);
module_exit(mtk_lmkd_exit);
MODULE_LICENSE("GPL");

