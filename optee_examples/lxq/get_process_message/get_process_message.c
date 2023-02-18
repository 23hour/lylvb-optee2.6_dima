#include <linux/kernel.h>
#include <linux/sched.h>//task_struct
#include <linux/mm.h>   //mm_struct
#include <linux/err.h>
#include <linux/oom.h>
#include <linux/slab.h> //kzalloc
#include "message.h"

int get_process_message(pid_t pid)  //进程代码段获取
{
    struct mm_struct *target_mm;//内存描述符
    struct task_struct *target;//进程描述符,进程地址空间存有相应的mm
    unsigned long code_size;
    unsigned long code_index;
    unsigned long offset = 0;
    char *rbuf;
    int rc;
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
       
    // target_mm = get_task_mm(target);
    target_mm = target->mm;
    if(unlikely(target_mm == NULL)){
		goto out_put;
	}
	// dump_stack();
    code_size = target_mm->end_code - target_mm->start_code;
    if(unlikely(code_size <= 0)){
		// mmput(target_mm);清除内存mm的一些状态、并将其从list中移除
		goto out_put;
	}
    code_index = target_mm->start_code;
    printk("process name: %s", target->comm);
    pr_info("PID=%d Text Starts at 0x%lx, Size  0x%lx\n",pid, code_index, code_size);
    /* comm save the process name */
    //strncpy(comm, target->comm, TASK_COMM_LEN);

    //printk("process name: %s", comm);//获取到了代码段的起始地址和截止地址、进程名字等

//获取代码段内容
	rbuf = kzalloc(PAGE_SIZE, GFP_KERNEL); //分配进程空间
	if (unlikely(!rbuf)) { //rbuf为1的可能性较大
		rc = -ENOMEM;  //ENOMEM为内存溢出错误
		goto out;
	}

	while (offset < code_size) {
		int rlen;
		int retval = 0;  //返回值

		if((code_size-offset) > PAGE_SIZE){
			rlen = PAGE_SIZE;
		}else{
			rlen = (code_size-offset);
		}

		retval = access_process_vm(target,code_index+offset,rbuf, rlen,0);//access_process_vm函数应该是加载数据至进程空间（将当前进程的一段内存内容拷贝到另一个进程的内存中）；retval应该是个地址
		printk("retval: %d", retval);
		
		if (!retval) {
			pr_err("Can not read process vm \n");
			rc = -EIO;
			break;
		}

		offset += retval;
//返回给用户态进程
	register unsigned int i = 0 ;
	char *toclient;
	for (; i < retval ; i++){ 
		printk("%d: %c",i,(unsigned char)rbuf[i]);//有问题（i变量类型还是rbuf访问？）可尝试设置一个buffer【】
		toclient[i]=(unsigned char)rbuf[i];
		}
	send_usrmsg(toclient,retval);//dima_netlink中

	}//while

	kfree(rbuf);
	return 0;
out_put:
	put_task_struct(target);//释放
out:
	return rc;
}

