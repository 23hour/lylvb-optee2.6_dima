//整个hack_kernal_module需放至optee/linux/drivers/char下
//添加设备dev/hack,与用户态的ioctl配合（switch命令）通信获取用户端的pid号，模块化集成到内核中
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/file.h>
#include <linux/capability.h>
#include <linux/uaccess.h>

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/oom.h>

#include <linux/init.h>
#include <linux/pid.h>
#include <linux/mm_types.h>
#include "hack.h"

static int hack_lock = 1;


static int hack_release(struct inode *nodp, struct file *filp)
{
    printk("---------close-dev----------");
	return 0;
}

static int hack_open(struct inode *nodp, struct file *filp)
{   	
	printk("---------open-dev----------");
	return 0;
}

static long hack_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret;
    void __user *argp = (void __user *) arg;

    printk("---------ioctl--match--cmd----------");

    /* This cmd（命令） is match with the client's register imformation */
    switch (cmd) {

        case GAT_PROCESS_HACK_CMD:
        {
            int pid;
            if(hack_lock) break;

            /* get pid of the user transfer */
            if (copy_from_user(&pid, argp, sizeof(pid))) {
				ret = -EFAULT;
				break;
			}

            printk("ioctl output: %d\n", pid);
            ret = get_process_hack(pid);
            break;
        }

        case DIMA_SET_MEASUREMENT_LOCK_MODE_CMD:
		{
			hack_lock = 1;
			break;
		}

	case DIMA_SET_MEASUREMENT_UNLOCK_MODE_CMD:
		{
			hack_lock = 0;
			break;
		}

    }

    return ret;
}

/* I can use this way 设备注册*/
static const struct file_operations hack_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = hack_ioctl,
	.open = hack_open,
	.release = hack_release,
};

static struct miscdevice hack_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "hack",     //设备名
        //.name = "fack_hack",
	.fops = &hack_fops
};


static int __init init_hack(void)
{
    int error = 0;

    /* register the miscdev, all action is in the it */
    error = misc_register(&hack_miscdev);
    if (unlikely(error)) {
    }

    /* netlink初始化 */
    t_netlink_init();
    
    return 0;

}

static void release_hack(void) {
    misc_deregister(&hack_miscdev);
    test_netlink_exit();
    printk("---------release--zx----------");
}

/* This is the delay trigger, May be I need to change it. */
late_initcall(init_hack);
module_exit(release_hack);

/* This Identity imformation could important for the kernal */
/* I can't omit it */
MODULE_DESCRIPTION("Get process hack from kernal");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("lxq");
