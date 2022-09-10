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

#define NAP_TIME 1 //HZ*NAP_TIME
#define KILL_PENDING_TIME 2 // HZ*KILL_PENDING_TIME
#define MAX_EPOLL_EVENTS 10
#define PATH_MAX 100
#define OOM_SCORE_ADJ_MAX 1000
#define OOM_SCORE_ADJ_MIN -1000
struct task_struct *mtk_lmkd;
static int mtk_lmkd_func(void*);
static void mtk_kill_all(void);
static void mtk_kill_one(void);
static int mtk_show_zram_stat(void);
static void mtk_adjust_swappiness(unsigned int);
static void custom_drop_cache(void);
static void custom_upadte_urgent_state(unsigned int);
static void mtk_privilege_list_init(void);
unsigned long total_kill_size = 0; //KB
int oom_score_adj_threshold = 700; //kill > this value
int swap_threshold = 50;
bool zram_kill = false;
#define TRIGER_BY_VDEC 1

DEFINE_MUTEX(privilege_list_lock);
struct privilege_node
{
	char name[TASK_COMM_LEN];
	struct list_head list;
};

struct list_head privilege_list = LIST_HEAD_INIT(privilege_list);
struct list_head privilege_urgent_list = LIST_HEAD_INIT(privilege_urgent_list);

#ifdef TRIGER_BY_QOS
extern void mtk_wakeup_lmkd(void);
extern void mtk_hypnotize_lmkd(void);
extern wait_queue_head_t mtk_lmkd_wait;
extern bool should_wait;
#endif

#if TRIGER_BY_VDEC
wait_queue_head_t mtk_lmkd_wait;
EXPORT_SYMBOL(mtk_lmkd_wait);
bool should_wait = true;
EXPORT_SYMBOL(should_wait);
void mtk_wakeup_lmkd(void)
{
	if (waitqueue_active(&mtk_lmkd_wait)) {
		should_wait = false;
		printk(KERN_ALERT"[mktlmkd] wake up \n");
		wake_up_interruptible(&mtk_lmkd_wait);
	}
}
EXPORT_SYMBOL(mtk_wakeup_lmkd);
void mtk_hypnotize_lmkd(void)
{
	printk(KERN_ALERT"[mktlmkd] go sleep \n");
	should_wait = true;
}
EXPORT_SYMBOL(mtk_hypnotize_lmkd);
#endif

static ssize_t lmkd_privilege_list_read(struct file *file, char __user *buf, size_t count,
                             loff_t *ppos)
{
	mutex_lock(&privilege_list_lock);
	struct list_head *now;
	struct privilege_node *now_node;
	int len;
	char sbuf[4096];
	list_for_each(now, &privilege_list) {
		now_node = list_entry(now, struct privilege_node, list);
		printk(KERN_ALERT"%s\n", now_node->name);
	}
	mutex_unlock(&privilege_list_lock);
	return 0;

}

static ssize_t lmkd_privilege_list_write(struct file *file, const char __user *buf, size_t count,
                             loff_t *ppos)
{
	struct privilege_node *new_node = kmalloc(sizeof(struct privilege_node),GFP_KERNEL);
	memset(new_node, 0, sizeof(struct privilege_node));
	if (!count || count > TASK_COMM_LEN)
		return 0;
	if (new_node) {
		mutex_lock(&privilege_list_lock);
		copy_from_user(new_node->name, buf, count);
		list_add(&new_node->list,&privilege_list);
		mutex_unlock(&privilege_list_lock);
		return count;
	}

	else
		return -EINVAL;
}


static int lmkd_privilege_list_open(struct inode *inode, struct file *file){
    return 0;
}

static int lmkd_privilege_list_release(struct inode *inode, struct file *file){
    return 0;
}


static struct file_operations const lmkd_privilege_list_fops = {
        .owner          = THIS_MODULE,
        .read           = lmkd_privilege_list_read,
        .write          = lmkd_privilege_list_write,
        .open           = lmkd_privilege_list_open,
        .release        = lmkd_privilege_list_release,
};
static ssize_t lmkd_killed_size_write(struct file *file, const char __user *buf, size_t count,
                             loff_t *ppos)
{
	return 0;
}
static ssize_t lmkd_killed_size_read(struct file *file, char __user *buf, size_t count,
                             loff_t *ppos)
{
	printk(KERN_ALERT"total killed szie %d Kb \n", total_kill_size);
    return 0;
}
static int lmkd_killed_size_open(struct inode *inode, struct file *file){
    return 0;
}
static int lmkd_killed_size_release(struct inode *inode, struct file *file){
    return 0;
}
static struct file_operations const lmkd_killed_size_fops = {
        .owner          = THIS_MODULE,
        .read           = lmkd_killed_size_read,
        .write          = lmkd_killed_size_write,
        .open           = lmkd_killed_size_open,
        .release        = lmkd_killed_size_release,
};
static ssize_t oom_score_adj_threshold_write(struct file *file, const char __user *buf, size_t count,
                             loff_t *ppos)
{
	char buffer[8];
	char *temp;
	long oom_score_adj;
    if (copy_from_user(buffer, buf, count)) {
		return -EINVAL;
    }
    oom_score_adj = simple_strtol(buffer, &temp, 10);
	if (oom_score_adj > OOM_SCORE_ADJ_MAX || oom_score_adj < OOM_SCORE_ADJ_MIN)
		return -EINVAL;
	oom_score_adj_threshold = oom_score_adj;
	return count;
}
static ssize_t oom_score_adj_threshold_read(struct file *file, char __user *buf, size_t count,
                             loff_t *ppos)
{
	printk(KERN_ALERT"oom score adj threshold %d \n", oom_score_adj_threshold);
    return 0;
}
static int oom_score_adj_threshold_open(struct inode *inode, struct file *file){
    return 0;
}
static int oom_score_adj_threshold_release(struct inode *inode, struct file *file){
    return 0;
}
static unsigned int oom_score_adj_threshold_poll(struct file *file, struct poll_table_struct *pts)
{
	printk(KERN_ALERT"start poll \n");
	printk(KERN_ALERT"after poll \n");
	int	poll_flags = POLLIN | POLLRDNORM;
	return poll_flags;
}
static struct file_operations const oom_score_adj_threshold_fops = {
        .owner          = THIS_MODULE,
        .read           = oom_score_adj_threshold_read,
        .write          = oom_score_adj_threshold_write,
        .open           = oom_score_adj_threshold_open,
        .release        = oom_score_adj_threshold_release,
        .poll        	= oom_score_adj_threshold_poll,
};
static ssize_t mtk_wakeup_lmkd_write(struct file *file, const char __user *buf, size_t count,
                             loff_t *ppos)
{
	return 0;
}
static ssize_t mtk_wakeup_lmkd_read(struct file *file, char __user *buf, size_t count,
                             loff_t *ppos)
{
	printk(KERN_ALERT" should wait %d \n", should_wait);
    return 0;
}
static int mtk_wakeup_lmkd_open(struct inode *inode, struct file *file){
	mtk_wakeup_lmkd();
    return 0;
}
static int mtk_wakeup_lmkd_read_release(struct inode *inode, struct file *file){
    return 0;
}
static struct file_operations const mtk_wakeup_lmkd_fops = {
        .owner          = THIS_MODULE,
        .read           = mtk_wakeup_lmkd_read,
        .write          = mtk_wakeup_lmkd_write,
        .open           = mtk_wakeup_lmkd_open,
        .release        = mtk_wakeup_lmkd_read_release,
};
static ssize_t mtk_hypnotize_lmkd_write(struct file *file, const char __user *buf, size_t count,
                             loff_t *ppos)
{
	return 0;
}
static ssize_t mtk_hypnotize_lmkd_read(struct file *file, char __user *buf, size_t count,
                             loff_t *ppos)
{
	printk(KERN_ALERT" should wait %d \n", should_wait);
    return 0;
}
static int mtk_hypnotize_lmkd_open(struct inode *inode, struct file *file){
	mtk_hypnotize_lmkd();
    return 0;
}
static int mtk_hypnotize_lmkd_release(struct inode *inode, struct file *file){
    return 0;
}
static struct file_operations const mtk_hypnotize_lmkd_fops = {
        .owner          = THIS_MODULE,
        .read           = mtk_hypnotize_lmkd_read,
        .write          = mtk_hypnotize_lmkd_write,
        .open           = mtk_hypnotize_lmkd_open,
        .release        = mtk_hypnotize_lmkd_release,
};
static ssize_t mtk_swap_threshold_write(struct file *file, const char __user *buf, size_t count,
                             loff_t *ppos)
{
	char buffer[8];
	int threshold;
    if (copy_from_user(buffer, buf, count)) {
		return -EINVAL;
    }
    kstrtoint(strstrip(buffer), 0, &threshold);
	if (threshold > 100 || threshold < 0)
		return -EINVAL;
	swap_threshold = threshold;
	return count;
	return 0;
}
static ssize_t mtk_swap_threshold_read(struct file *file, char __user *buf, size_t count,
                             loff_t *ppos)
{
    //printk(KERN_ALERT" threshold %d \n", swap_threshold);
    ssize_t retval;
    char *kernel_buf;
    size_t size = 64;
    size_t len = 0;
    kernel_buf = kzalloc(size, GFP_KERNEL);
    if(!kernel_buf)
        return -ENOMEM;
    if(count >= 64)
        return -EPERM;
    len = sprintf(kernel_buf, "%d", swap_threshold);
    retval = simple_read_from_buffer(buf, count, ppos, kernel_buf, len);
    kfree(kernel_buf);
    return retval;
}
static int mtk_swap_threshold_open(struct inode *inode, struct file *file){
    return 0;
}
static int mtk_swap_threshold_release(struct inode *inode, struct file *file){
    return 0;
}
static struct file_operations const mtk_swap_threshold_fops = {
        .owner          = THIS_MODULE,
        .read           = mtk_swap_threshold_read,
        .write          = mtk_swap_threshold_write,
        .open           = mtk_swap_threshold_open,
        .release        = mtk_swap_threshold_release,
};

static int __init mtk_lmkd_init(void)
{
	mtk_privilege_list_init();
#ifdef TRIGER_BY_VDEC
	init_waitqueue_head(&mtk_lmkd_wait);
#endif
    static struct proc_dir_entry *mtk_lmkd_dir;
    mtk_lmkd_dir = proc_mkdir("mtk_lmkd", NULL);
    if (!proc_create("total_killed_size", 0644, mtk_lmkd_dir, &lmkd_killed_size_fops)) {
    	printk(KERN_ALERT"mtklmkd fail !!\n");
      	return -1;
    }
    if (!proc_create("oom_score_adj_threshold", 0644, mtk_lmkd_dir, &oom_score_adj_threshold_fops)) {
    	printk(KERN_ALERT"mtklmkd fail !!\n");
      	return -1;
    }
    if (!proc_create("mtk_hypnotize_lmkd", 0644, mtk_lmkd_dir, &mtk_hypnotize_lmkd_fops)) {
    	printk(KERN_ALERT"mtklmkd fail !!\n");
      	return -1;
    }
    if (!proc_create("mtk_wakeup_lmkd", 0644, mtk_lmkd_dir, &mtk_wakeup_lmkd_fops)) {
    	printk(KERN_ALERT"mtklmkd fail !!\n");
      	return -1;
    }
    if (!proc_create("swap_threshold", 0644, mtk_lmkd_dir, &mtk_swap_threshold_fops)) {
    	printk(KERN_ALERT"mtklmkd fail !!\n");
      	return -1;
    }
    if (!proc_create("privilege_list", 0644, mtk_lmkd_dir, &lmkd_privilege_list_fops)) {
    	printk(KERN_ALERT"mtklmkd fail !!\n");
      	return -1;
    }
    mtk_lmkd = kthread_run(mtk_lmkd_func, NULL, "mtk_lmkd");
	if (IS_ERR(mtk_lmkd)) {
		return -1;
	}
	return 0;
}


#ifdef CONFIG_CPUSETS
struct fmeter {
	int cnt;		/* unprocessed events count */
	int val;		/* most recent output value */
	time64_t time;		/* clock (secs) when val computed */
	spinlock_t lock;	/* guards read or write of above */
};
struct cpuset {
	struct cgroup_subsys_state css;
	unsigned long flags;		/* "unsigned long" so bitops work */
	cpumask_var_t cpus_allowed;
	cpumask_var_t cpus_requested;
	nodemask_t mems_allowed;
	cpumask_var_t effective_cpus;
	nodemask_t effective_mems;
	nodemask_t old_mems_allowed;
	struct fmeter fmeter;		/* memory_pressure filter */
	int attach_in_progress;
	int pn;
	int relax_domain_level;
#ifdef CONFIG_MP_ASYM_UMA_ALLOCATION
	/* for memory region idx */
	int memalloc_idx;
#endif
};

static struct cgroup_subsys_state *mtk_task_cs(struct task_struct *tsk)
{
	struct cgroup_subsys_state *ptr = task_css(tsk, cpuset_cgrp_id);
	if (ptr)
		return ptr;
	else
		return NULL;
}

#endif

static int mtk_show_zram_stat(void) //return usage
{
	unsigned char buf[1024];
	unsigned char *temp;
	char path[PATH_MAX+1];
	snprintf(path, PATH_MAX, "/proc/swaps");
	struct file  *f = filp_open(path, O_RDONLY, 0);
	if(IS_ERR_OR_NULL(f)) {
		//printk(KERN_ALERT" open fail \n");
		return -1;
	}
	mm_segment_t fs;
 	fs = get_fs();
    set_fs(get_ds());
    if (f->f_op->read)
    	f->f_op->read(f,buf,1024,&f->f_pos);
    set_fs(fs);
    filp_close(f,NULL);
    int total_size;
    int used;
    unsigned char *pos = strstr(buf, "on");
    if (pos) {
    	int i,k;
    	int i_start = 0;
    	int i_end = 0;
    	int k_start = 0;
    	int k_end = 0;
    	for (i = 0; i < (1024 - (pos - buf)); i++) 
    	{
    		if (isdigit(pos[i]) && !i_start)
    			i_start = i;
    		if (i_start && !isdigit(pos[i])) {
    			i_end = i - 1;
    			break;
    		}
    	}
    	if (!i_start)
			return -1;
		temp = kzalloc((i_end - i_start + 2), GFP_KERNEL);
    	strncpy(temp, pos + i_start, (i_end - i_start + 1));
    	temp[i_end - i_start + 1] = '\0';
    	kstrtoint((temp), 10, &total_size);
    	kfree(temp);
    	for (k = 0; k < 1024 - (pos + i - buf); k ++) // 
    	{
    		if (isdigit(pos[i + k]) && !k_start)
    			k_start = k;
    		if (k_start && !isdigit(pos[i + k])) {
    			k_end = k - 1;
    			break;
    		}
    	}
    	if (!k_start)
			return -1;
		temp = kzalloc((k_end - k_start + 2), GFP_KERNEL);
		strncpy(temp, pos + i + k_start, (k_end - k_start + 1));
    	temp[k_end - k_start + 1] = '\0';
    	kstrtoint((temp), 10, &used);
    	kfree(temp);
		return ((used * 100) / total_size);
    } else
      return 0;
}

static int mtk_lmkd_func(void *data)
{
    long remaining = 0;
    unsigned int usage = 0;
    DEFINE_WAIT(wait);
    while (1)
    {
       if (kthread_should_stop())
           break;
take_nap:
        if (should_wait) {
            prepare_to_wait(&mtk_lmkd_wait, &wait, TASK_INTERRUPTIBLE);
            remaining = schedule_timeout(HZ*NAP_TIME);
            usage = mtk_show_zram_stat();
            mtk_adjust_swappiness(usage);
            finish_wait(&mtk_lmkd_wait, &wait);
        } else
            remaining = 1;
        if (remaining) {
            goto start_kill;
        }
#if 1 // should disable selinux or add selinux rule
        swap_threshold = usage;
        if (usage >= 60) {
            zram_kill = true;
            goto start_kill;
        }
#endif
        /* do other things...*/
        goto take_nap;
start_kill:
        mtk_kill_all();
        prepare_to_wait(&mtk_lmkd_wait, &wait, TASK_INTERRUPTIBLE);
        schedule_timeout(HZ * KILL_PENDING_TIME);
        finish_wait(&mtk_lmkd_wait, &wait);
        should_wait = true;
        remaining = 0;
    }
    return 0;
}
struct task_struct *mtk_find_lock_task_mm(struct task_struct *p)
{
	struct task_struct *t;
	rcu_read_lock();
	for_each_thread(p, t) {
		task_lock(t);
		if (likely(t->mm))
			goto found;
		task_unlock(t);
	}
	t = NULL;
found:
	rcu_read_unlock();
	return t;
}

static bool mtk_should_kill(struct task_struct *p, int last_kill_pid)
{
#ifdef CONFIG_CPUSETS
	struct cgroup_subsys_state *cpuset_ptr;
	cpuset_ptr = mtk_task_cs(p);
	if (strstr(cpuset_ptr->cgroup->kn->name, "app")) {
		return false;
	}
#endif
	struct list_head *now;
	struct privilege_node *now_node;
	mutex_lock(&privilege_list_lock);
	list_for_each(now, &privilege_list) {
		now_node = list_entry(now, struct privilege_node, list);
		if (strstr(now_node->name, p->comm)) {
			mutex_unlock(&privilege_list_lock);
			return false;
        }
	}
	mutex_unlock(&privilege_list_lock);
    if(swap_threshold < 90){
        list_for_each(now, &privilege_urgent_list) {
            now_node = list_entry(now, struct privilege_node, list);
            if (strstr(now_node->name, p->comm)) {
                mutex_unlock(&privilege_list_lock);
                return false;
            }
        }
    }
	int nr_free = global_zone_page_state(NR_FREE_PAGES);
	if (p->signal->oom_score_adj <= oom_score_adj_threshold) {
		return false;
	}
	if (p->pid == last_kill_pid) {
		return false;
	}
	return true;
}
static void mtk_kill_one(void)
{
    struct task_struct *tsk;
    static int last_kill_pid = -1;
    static int last_kill_size = 0;
    static int last_kill_adj = 0;
    int tasksize = 0;
    static int retry_count = 0;
    int find = 0;
    struct task_struct *victim;
    if (last_kill_pid > 0 && retry_count < 10) {
        rcu_read_lock();
        victim = pid_task(find_pid_ns(last_kill_pid, task_active_pid_ns(current)), PIDTYPE_PID);
        if (!victim || (victim->exit_state && thread_group_empty(victim))) {
            printk(KERN_ALERT"[mtk_lmkd] pid %d already been killed! \n", last_kill_pid);
            total_kill_size += (last_kill_size * (long)(PAGE_SIZE / 1024));
            last_kill_pid = -1;
            last_kill_size = 0;
        } else {
            retry_count ++;
            goto end;
        }
        rcu_read_unlock();
    }
    rcu_read_lock();
    for_each_process(tsk) {
         if (should_wait && !zram_kill)
             break;
         struct task_struct *p;
         p = mtk_find_lock_task_mm(tsk);
         if (!p)
              continue;
         if (!mtk_should_kill(p, last_kill_pid)) {
            task_unlock(p);
            continue;
         }
         tasksize = get_mm_rss(p->mm);
         last_kill_adj = p->signal->oom_score_adj;
         if (tasksize > last_kill_size) {
             last_kill_size = tasksize;
             last_kill_pid = p->pid;
             find = 1;
         }
         task_unlock(p);
    }
    if (find) {
        victim = pid_task(find_pid_ns(last_kill_pid, task_active_pid_ns(current)), PIDTYPE_PID);
        if (victim) {
            task_lock(victim);
            retry_count = 0;
            send_sig(SIGKILL, victim, 0);
            printk(KERN_ALERT"[mtk_lmkd] start to kill pid %d adj %d ! %s  size %d kB \n",
                                        last_kill_pid, last_kill_adj, victim->comm, (last_kill_size * (long)(PAGE_SIZE / 1024)));
            task_unlock(victim);
        }
    }
    if (zram_kill)
        zram_kill = false;
end:
	rcu_read_unlock();
}

static void mtk_kill_all(void)
{
 	struct task_struct *tsk;
	static int last_kill_pid = -1;
    static int last_kill_adj = 0;
	int tasksize = 0;

	rcu_read_lock();
    for_each_process(tsk) {
		if (should_wait && !zram_kill)
		break;
		struct task_struct *p;
		p = mtk_find_lock_task_mm(tsk);
		if (!p)
			continue;
		if (!mtk_should_kill(p, last_kill_pid)) {
			task_unlock(p);
			continue;
		}
		tasksize = get_mm_rss(p->mm);
		last_kill_pid = p->pid;
        last_kill_adj = p->signal->oom_score_adj;
		send_sig(SIGKILL, p, 0);
		printk(KERN_ALERT"[mtk_lmkd] start to kill pid %d adj %d ! %s  size %d kB \n",
										last_kill_pid, last_kill_adj, p->comm, (tasksize * (long)(PAGE_SIZE / 1024)));
		task_unlock(p);
		total_kill_size += (tasksize * (long)(PAGE_SIZE / 1024));
	}
	if (zram_kill)
		zram_kill = false;

end:
	rcu_read_unlock();
}

static void custom_drop_cache(void)
{
    unsigned char input[3];
    unsigned char path[PATH_MAX+1];
    struct file  *f;
    mm_segment_t fs;
    loff_t pos;
    snprintf(path, PATH_MAX, "/proc/sys/vm/drop_caches");
    f = filp_open(path, O_RDWR, 0);
    if(f == NULL){
        return;
    }
    fs = get_fs();
    set_fs(get_ds());
    input[0] = '1';
    input[1] = '\0';
    pos = 0;
    //vfs_write(f,input,1,&pos);
    printk(KERN_ALERT"[mtk_lmkd] custom_drop_cache! \n");
    set_fs(fs);
    filp_close(f,NULL);
}

static void custom_upadte_urgent_state(unsigned int usage){
    unsigned char path[PATH_MAX+1];
    struct file  *f;
    snprintf(path, PATH_MAX, "/data/swap_urgent");
    if(usage > 90){
        f = filp_open(path, O_CREAT|O_RDWR, 0644);
    } else {
        //f = filp_open(path, O_CREAT|O_RDWR, 0600);
    }
    filp_close(f,NULL);
}

static void mtk_adjust_swappiness(unsigned int usage)
{
    unsigned char input[4];
    unsigned char path[PATH_MAX+1];
    struct file  *f;
    mm_segment_t fs;
    loff_t pos;
    snprintf(path, PATH_MAX, "/proc/sys/vm/swappiness");
    f = filp_open(path, O_RDWR, 0);
    fs = get_fs();
    set_fs(get_ds());
    if (usage >= 90) {/*if condition here */
        input[0] = '1';
    } else if (usage > 70 && usage < 90) {
        input[0] = '4';
    } else {
        input[0] = '6';
    }
    input[1] = '0';
    input[2] = '\0';
    pos = 0;
    vfs_write(f,input,3,&pos);
    set_fs(fs);
    filp_close(f,NULL);
}
static void mtk_privilege_list_init(void)
{
	struct privilege_node *new_node;

	new_node = kmalloc(sizeof(struct privilege_node),GFP_KERNEL);
	memset(new_node, 0, sizeof(struct privilege_node));
	strcpy(new_node->name, ".katniss:search");
	list_add(&new_node->list,&privilege_list);

	new_node = kmalloc(sizeof(struct privilege_node),GFP_KERNEL);
	memset(new_node, 0, sizeof(struct privilege_node));
	strcpy(new_node->name, "niss:interactor");
	list_add(&new_node->list,&privilege_list);

	new_node = kmalloc(sizeof(struct privilege_node),GFP_KERNEL);
	memset(new_node, 0, sizeof(struct privilege_node));
	strcpy(new_node->name, ".remote.service");
	list_add(&new_node->list,&privilege_list);

	new_node = kmalloc(sizeof(struct privilege_node),GFP_KERNEL);
	memset(new_node, 0, sizeof(struct privilege_node));
	strcpy(new_node->name, "apps.mediashell");
	list_add(&new_node->list,&privilege_list);

    new_node = kmalloc(sizeof(struct privilege_node),GFP_KERNEL);
    memset(new_node, 0, sizeof(struct privilege_node));
    strcpy(new_node->name, "recommendations");
    list_add(&new_node->list,&privilege_urgent_list);

    new_node = kmalloc(sizeof(struct privilege_node),GFP_KERNEL);
    memset(new_node, 0, sizeof(struct privilege_node));
    strcpy(new_node->name, "m.netflix.ninja");
    list_add(&new_node->list,&privilege_urgent_list);

    new_node = kmalloc(sizeof(struct privilege_node),GFP_KERNEL);
    memset(new_node, 0, sizeof(struct privilege_node));
    strcpy(new_node->name, "roid.youtube.tv");
    list_add(&new_node->list,&privilege_urgent_list);

    new_node = kmalloc(sizeof(struct privilege_node),GFP_KERNEL);
    memset(new_node, 0, sizeof(struct privilege_node));
    strcpy(new_node->name, "ideo.livingroom");
    list_add(&new_node->list,&privilege_urgent_list);

    new_node = kmalloc(sizeof(struct privilege_node),GFP_KERNEL);
    memset(new_node, 0, sizeof(struct privilege_node));
    strcpy(new_node->name, ".startv.hotstar");
    list_add(&new_node->list,&privilege_urgent_list);

    new_node = kmalloc(sizeof(struct privilege_node),GFP_KERNEL);
    memset(new_node, 0, sizeof(struct privilege_node));
    strcpy(new_node->name, "ngama.movies.tv");
    list_add(&new_node->list,&privilege_urgent_list);


}

static void __exit mtk_lmkd_exit(void)
{
	send_sig(SIGKILL, mtk_lmkd, 0);
}
module_init(mtk_lmkd_init);
module_exit(mtk_lmkd_exit);
MODULE_LICENSE("GPL");
