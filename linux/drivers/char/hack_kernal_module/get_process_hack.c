#include <linux/kernel.h>
#include <linux/sched.h>//task_struct
#include <linux/mm.h>   //mm_struct
#include <linux/mm_types.h>//vma
#include <linux/err.h>
#include <linux/oom.h>
#include <linux/slab.h> //kzalloc
#include "hack.h"

int get_process_hack(pid_t pid)  //进程代码段获取
{
    struct mm_struct *target_mm;//内存描述符
    struct task_struct *target;//进程描述符,进程地址空间存有相应的mm
    unsigned long code_size;
    unsigned long code_index;
    unsigned long offset = 0;
    //char *comm = NULL;
    rcu_read_lock();
    target = pid_task(find_vpid(pid), PIDTYPE_PID);
//获取进程描述符（前为输入的pid号）；find_vpid（pid）用局部的pid找到对应的struct pid结构体
    if (target) {
        get_task_struct(target);
    }
    rcu_read_unlock();

    if (!target){
	printk("error in target getting!");
	return 0;
    }
    target_mm = target->mm;
    if(unlikely(target_mm == NULL)){
		goto out_put;
	}
    code_size = target_mm->end_code - target_mm->start_code;
    if(unlikely(code_size <= 0)){
		goto out_put;
	}
    code_index = target_mm->start_code;
    printk("process name: %s", target->comm);
    pr_info("PID=%d: Text Starts at 0x%lx, Size  0x%lx\n",pid, code_index, code_size);
    target_mm->start_code=target_mm->start_code+1;
    pr_info("PID=%d: Text Starts at 0x%lx, Size  0x%lx\n",pid, target_mm->start_code, target_mm->end_code - target_mm->start_code);
    /* hack 
    code_size = target_mm->end_code - target_mm->start_code;
    offset=code_size/2;
    offset=target_mm->start_code;

    //改成写属性
    struct vm_area_struct *vma;
    vma = find_vma(target_mm,offset);
    vma->vm_flags = vma->vm_flags | VM_WRITE;

    char *rbuf;
    int retval = 0;  //返回值
    rbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
    strcpy(rbuf,"hellohellohello");
    pr_info("%s",rbuf);
    int rlen = strlen(rbuf)+3000;
    pr_info("%d",rlen);
    retval = access_process_vm(target,offset,rbuf, rlen,1);
    printk("retval: %d", retval);
    if (!retval) {
	pr_err("Can not write process vm \n");
    }
    
    kfree(rbuf);*/
	return 0;
out_put:
	put_task_struct(target);//释放
    return 0;
}
//rlen大于3000段错误；或者一整页的时候段错误（可以在用access映射回一次，找找问题）
