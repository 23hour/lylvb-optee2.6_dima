#include<linux/init.h>
#include<linux/module.h>
#include<linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
static int hello_init(void)
{
        struct task_struct *p;
        printk(KERN_ALERT"名 称 \t 进程号 \t 状态 \t 优先级\t");
        for_each_process(p)
        {
                if(p->mm == NULL)//内核线程的mm成员为空
                  printk(KERN_ALERT"%s\t%d\t%d\t%d\n",p->comm,p->pid, p->state,p->normal_prio);
        }
        return 0;
}
static void hello_exit(void)
{
        printk(KERN_ALERT "list over !\n");
}
module_init(hello_init);//加载函数
module_exit(hello_exit);                //卸载函数
MODULE_LICENSE("GPL");  //许可证申明
MODULE_DESCRIPTION("list module");
MODULE_AUTHOR("fade");
