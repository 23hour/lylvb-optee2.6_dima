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
#include "get_ktext.h"

static int ktext_lock = 1;


static int ktext_release(struct inode *nodp, struct file *filp)
{
    printk("---------close-dev----------");
	return 0;
}

static int ktext_open(struct inode *nodp, struct file *filp)
{   	
	printk("---------open-dev----------");
	return 0;
}

static long ktext_read(struct file *filp, char __user *buf, size_t count, loff_t *offset)
{
    int ret = 0;

    printk("---------read------------");

    /* This cmd（命令） is match with the client's register imformation */
    unsigned char msg[200];
    ret = lkm_init(msg);
    printk("-------read---lkm_init--------");
    copy_to_user(buf,msg,count);//目标地址（用户）、源地址（内核）、拷贝字节数
    printk("-------read---over--------");
    return ret;
}

static long ktext_ioctl(struct file *filp, unsigned int cmd,unsigned long arg)
{
    printk("---------ioctl--match--cmd----------");

    /* This cmd（命令） is match with the client's register imformation */
    switch (cmd) {

        case DIMA_SET_MEASUREMENT_LOCK_MODE_CMD:
		{
			ktext_lock = 1;
			break;
		}

	case DIMA_SET_MEASUREMENT_UNLOCK_MODE_CMD:
		{
			ktext_lock = 0;
			break;
		}

    }

    return 0;
}

/* I can use this way 设备注册*/
static const struct file_operations ktext_fops = {
	.owner = THIS_MODULE,
        .read = ktext_read,
	.unlocked_ioctl = ktext_ioctl,
	.open = ktext_open,
	.release = ktext_release,
};

static struct miscdevice ktext_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ktext",     //设备名
        //.name = "fack_hack",
	.fops = &ktext_fops
};


static int __init init_ktext(void)
{
    int error = 0;

    /* register the miscdev, all action is in the it */
    error = misc_register(&ktext_miscdev);
    if (unlikely(error)) {
    }

    /* netlink初始化 */
    t_netlink_init();
    
    return 0;

}

static void release_ktext(void) {
    misc_deregister(&ktext_miscdev);
    test_netlink_exit();
    printk("---------release--zx----------");
}

/* This is the delay trigger, May be I need to change it. */
late_initcall(init_ktext);
module_exit(release_ktext);

/* This Identity imformation could important for the kernal */
/* I can't omit it */
MODULE_DESCRIPTION("Get ktext from kernal");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("lxq");
