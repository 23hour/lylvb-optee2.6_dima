
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/file.h>
#include <linux/capability.h>
#include <linux/uaccess.h>

#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/oom.h>


#include <linux/init.h>
#include <linux/pid.h>
#include <linux/mm_types.h>


#include "dima.h"


char* dima_hash = "sm3";
// int dima_hash_digest_size = SM3_DIGEST_SIZE;
int dima_hash_digest_size = 20;

static int dima_lock = 1;


static int dima_release(struct inode *nodp, struct file *filp)
{
    printk("---------close--zx----------");
	return 0;
}

static int dima_open(struct inode *nodp, struct file *filp)
{
    printk("---------open--zx----------");
	return 0;
}

static long dima_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret;
    void __user *argp = (void __user *) arg; //char modulename[100]= "dima,pid"



    printk("---------ioctl--zx----------");

    /* This cmd is match with the client's register imformation */
    switch (cmd) {

		case DIMA_SET_MEASUREMENT_MODE_CMD:
		{
			int mode;
			if (copy_from_user(&mode, argp, sizeof(mode))) {
				ret = -EFAULT;
				break;
			}
			ret = dima_set_measurement_mode_cmd(mode);
			break;
		}

        case DIMA_MEASUREMENT_MODULE_CMD://使用的该模块
		{
            char name[MODULE_NAME_LEN] = {0};
			if(dima_lock) break;
			
			if (copy_from_user(name, argp, sizeof(name))) {
				ret = -EFAULT;
				break;
			}

			char *p = name;

			char * moduleName = strsep(&p, ",");
			char * modulePid = strsep(&p, ",");//strsep作用为分解字符串

            printk("ioctl module moduleName output: %s\n", moduleName);
			printk("ioctl module modulePid output: %s\n", modulePid);

			u8 digest1[DIMA_DIGEST_SIZE] = {0};
			// 进程度量
			printk("process measurement start");
			ret = dima_measurement_process_cmd(charToInt(modulePid), digest1);

			int i;
			for (i = 0; i < dima_hash_digest_size; i++) {
				pr_info("%02x", *(digest1 + i));
			}

			printk("process measurement end");
			printk(" ");
			
			u8 digest2[DIMA_DIGEST_SIZE] = {0};
			// 模块度量
			printk("module measurement start");
			ret = dima_measurement_module_cmd(moduleName, digest2);

			for (i = 0; i < dima_hash_digest_size; i++) {
				pr_info("%02x", *(digest2 + i));
			}
			
			printk("module measurement end");
			printk(" ");

			u8 digest[DIMA_DIGEST_SIZE] = {0};
			for (i = 0; i < DIMA_DIGEST_SIZE; i++) {
				digest[i] = digest1[i] ^ digest2[i];
			}

			send_usrmsg(digest, 20);
			
			break;
		}

        case DIMA_MEASUREMENT_PROCESS_CMD:
        {
            int pid;
            if(dima_lock) break;

            /* get pid of the user transfer */
            if (copy_from_user(&pid, argp, sizeof(pid))) {
				ret = -EFAULT;
				break;
			}

            printk("ioctl output: %d\n", pid);

            // ret = dima_measurement_process_cmd(pid);          /* take measurements */

            break;
        }

        case DIMA_SET_MEASUREMENT_LOCK_MODE_CMD:
		{
			dima_lock = 1;
			break;
		}

		case DIMA_SET_MEASUREMENT_UNLOCK_MODE_CMD:
		{
			dima_lock = 0;
			break;
		}

    }

    return ret;
}

/* I can use this way */
static const struct file_operations dima_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = dima_ioctl,
	.open = dima_open,
	.release = dima_release,
};

static struct miscdevice dima_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "dima",
	.fops = &dima_fops
};


static int __init init_dima(void)
{
    int error = 0;

    /* 1th:  init crypto hash cal */
    error = dima_init_crypto();

    /* 2th: register the miscdev, all action is in the it */
    error = misc_register(&dima_miscdev);
    if (unlikely(error)) {
    }

    /* netlink初始化 */
    test_netlink_init();
    
    /* end: init fs */
    return dima_fs_init();
    // return 0;
}

static void release_dima(void) {
    misc_deregister(&dima_miscdev);
    dima_fs_release();
    test_netlink_exit();
    printk("---------release--zx----------");
}

/* This is the delay trigger, May be I need to change it. */
late_initcall(init_dima);
module_exit(release_dima);

/* This Identity imformation could important for the kernal */
/* I can't omit it */
MODULE_DESCRIPTION("Dynamic Integrity Measurement Architecture");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("zhangxiang");
