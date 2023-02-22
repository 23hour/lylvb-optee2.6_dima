#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/oom.h>
#include <crypto/skcipher.h>
#include "dima.h"
#include "sha1.h"


// /*------zx------*/
// LIST_HEAD(dima_list);
// /*------zx------*/

static int dima_measurement_mode = 0;

static struct crypto_shash *dima_shash_tfm;//context descriptor structure and its size

/* need to achieve   */
int dima_init_crypto(void) 
{
    long rc;
    
    dima_shash_tfm = crypto_alloc_shash(dima_hash, 0, 0);//sm3
    if (IS_ERR(dima_shash_tfm)) {
        pr_err("Can not allocate dima hash");
    } else {
        printk("Hash init success");
    }
    return 0;
}

void printListNumber()
{
	struct dima_struct *_dima;
	int val =0 ;
    char tmpbuf[10];

    rcu_read_lock();
    list_for_each_entry_rcu(_dima, &dima_list, dimas) {
        val++;
    }
    rcu_read_unlock();

    printk(" List number is %d.\n", val);
}


static int cmp_dima_list(pid_t pid, const char* name, int mode, const char* comm, const u8* digest)
{
	struct dima_struct *_dima;
	struct dima_struct *a;
	struct timex txc;
	struct task_struct *target;

    rcu_read_lock();
	list_for_each_entry_rcu(_dima, &dima_list, dimas)
	    /* 对比链表中, 我所有需要对比的进程名称和度量模式 */
		if (strncmp(_dima->comm, comm, DIMA_NAME_LEN) == 0 && _dima->mode == mode)
		{
			_dima->count++;
			/* Linux中可以使用函数do_gettimeofday()函数来得到精确时间 */
			do_gettimeofday(&(txc.time));
			txc.time.tv_sec += 8*60*60;
			/* rtc_time_to_tm换算，根据系统 timezone换算成当前时区时间 */
			rtc_time_to_tm(txc.time.tv_sec, &_dima->lasttm);

            /* 进行 digest 和链表的对比 */
            /* 如果digest匹配失败 */
			if(memcmp(_dima->digest, digest, DIMA_DIGEST_SIZE)){
				// dima_integrity_audit_msg(AUDIT_INTEGRITY_DATA, NULL, 
                //         comm,"measurement_dima","invalid-hash", 0, 0);

                // if(mode == DIMA_MODE_PROCESS){
                //     target = find_task_by_vpid(pid);
                //     if (target && !(target->flags & PF_KTHREAD) && !test_tsk_thread_flag(target, TIF_MEMDIE))
                //     {
                //         send_sig(SIGKILL, target, 0);
                //         set_tsk_thread_flag(target, TIF_MEMDIE);

                //         pr_info("kill process %s %d \n",target->comm,pid);
                //     }
                // }

				// _dima->fails++;
				// rcu_read_unlock();

				printListNumber();
				printk("The Code Mathc Fail!!!");

				return CMD_ERR_FAILMEASURE;
			}

			/* 如果digest匹配成功 */
			rcu_read_unlock();

			printListNumber();
			printk("The Code Match Success!!!");

			return CMD_ERR_OK;
		}
	rcu_read_unlock();

    /* 未匹配, 制作新的节点, 插入链表 */
	a = kzalloc(sizeof(struct dima_struct), GFP_KERNEL);
	if (unlikely(a == NULL)) {
		return -ENOMEM;
	}

	strncpy(a->comm, comm, DIMA_NAME_LEN);
	memcpy(a->digest,digest, DIMA_DIGEST_SIZE);
	a->count = 1;
	a->fails  = 0;
	a->mode = mode;
	do_gettimeofday(&(txc.time));
	txc.time.tv_sec += 8*60*60;
	rtc_time_to_tm(txc.time.tv_sec, &a->lasttm);

	INIT_LIST_HEAD(&a->dimas);
	list_add_tail_rcu(&a->dimas, &dima_list);

	printk("The Process Name Mathc Fail!!!");/**/
	printListNumber();
	printk("Insert New Node !!!");

	// dima_pcr_extend(digest);
	return CMD_ERR_OK;
}



void get_ebp(void)
{
	// unsigned long ebp = 0;
    //     __asm__ __volatile__("movl %%ebp, %0;\r\n"
    //              :"=m"(ebp)
    //              ::"memory");
	// printk("ebp = %p", ebp);

	// void *stack_addr[10];
	// int layer = 0;
	// int size = 10;
	// int i;
    // while(layer < size && ebp != 0 && *(unsigned long*)ebp != 0 && *(unsigned long *)ebp != ebp)
    // {
    //         stack_addr[layer++] = *(unsigned long *)(ebp+4);
    //         ebp = *(unsigned long*)ebp;
    // }

	// for(i = 0; i < layer; i++) {
	// 	printk("\nmy: %p\n", stack_addr[i]);
	// }

 
}

static int dima_calc_buffer_hash(char * data, unsigned long len, u8 *digest)
{
	struct {
		/*
		tfm: a pointer to the underlying shash algorithm's transform object
		flags: a set of flags that control the behavior of the shash algorithm, such as whether to use hardware acceleration
		ctx: a pointer to the context data structure used to store the state of the shash algorithm during the hash computation
		*/
		struct shash_desc shash; //tfm, flags, ctx
		char ctx[crypto_shash_descsize(dima_shash_tfm)];
	} desc;

	desc.shash.tfm = dima_shash_tfm;
	desc.shash.flags = 0;

	return crypto_shash_digest(&desc.shash, data, len, digest);
}

static int dima_calc_task_buffer_hash(struct task_struct *tsk, unsigned long index, unsigned long len, u8 *digest)
{


	/*--------------zx----------------*/
	// SHA1Schedule ctx;
	// sha1_init(&ctx);
	// sha1_update(&ctx, message, len);
	// sha1_final(&ctx, digest);
	// const char table[]="0123456789abcdef";
	// register uint32_t value;
	// char*p_md5_2char=(out-2);
	// int j;
	// for(j=0;j<20;j++){
	// 	value=( (uint8_t)(digest[j])&0xff );//计算出10进制数
	// 	p_md5_2char+=2;
	// 	*(p_md5_2char+1)=table[value&0xf];
	// 	value=(value>>4);//value/=16;
	// 	*p_md5_2char=table[value&0xf];
	// }
	/*--------------zx-----------------*/






	unsigned long offset = 0;
	char *rbuf;
	int rc;
	// struct {
	// 	struct shash_desc shash;
	// 	char ctx[crypto_shash_descsize(dima_shash_tfm)];
	// } desc;

	// printk("crypto_shash_descsize(dima_shash_tfm) len = %d", crypto_shash_descsize(dima_shash_tfm));

	// desc.shash.tfm = dima_shash_tfm;
	// desc.shash.flags = 0;

	// rc = crypto_shash_init(&desc.shash);    //why not use???
	// if (rc != 0)
	// 	return rc;
	SHA1Schedule ctx;
	sha1_init(&ctx);

	rbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (unlikely(!rbuf)) {
		rc = -ENOMEM;
		goto out;
	}

	while (offset < len) {
		int rlen;
		int retval = 0;

		if((len-offset) > PAGE_SIZE){
			rlen = PAGE_SIZE;
		}else{
			rlen = (len-offset);
		}

		retval = access_process_vm(tsk,index+offset,rbuf, rlen,0);
		printk("retval: %d", retval);/**/
		
		if (!retval) {
			pr_err("Can not read process vm \n");
			rc = -EIO;
			break;
		}

		offset += retval;

		// rc = crypto_shash_update(&desc.shash, rbuf, retval);
		sha1_update(&ctx, rbuf, retval);
		// if (rc){
		// 	pr_err("Can not hash data err %d \n",rc);
		// 	break;
		// }
	}

	kfree(rbuf);

	// if (!rc)
	// rc = crypto_shash_final(&desc.shash, digest);   /* Return: 0 if the message digest creation was successful; < 0 if an error occured */
	sha1_final(&ctx, digest);


    // int i;
    // for (i = 0; i < dima_hash_digest_size; i++)
	// 	pr_info("%02x", *(digest + i));


out:
	return rc;
}


// static int getPhyAddress(struct mm_struct *mm)
// {
// 	int i = 1;              
// 	//得到了一个虚拟地址
// 	unsigned long addr = (unsigned long)(&i);
// 	unsigned long real_addr;
// 	unsigned long *pte_addr;
	
// 	struct pgd_t *pgd = pgd_offset(mm,addr);
// 	if(!pgd)
// 	{
// 		printk("pgd error!\n");
// 		return 0;
// 	}
// 	struct pud_t *pud = pud_offset(pgd,addr);
// 	struct pmd_t *pmd = pmd_offset(pud,addr);
// 	if(!pmd)
// 	{
// 		printk("pmd error!\n");
// 		return 0;     }                                                       
// 	//得到页表项地址    
// 	unsigned long pte = pte_offset(pmd,addr);           

// 	if(!pte)
// 	{
// 		printk("pte error\n");
// 		return 0;
// 	}
// 	//得到页内偏移量（线性地址的后12位）
// 	real_addr = addr&0x00000fff;        

// 	pte_addr = pte;
// 	//页表表项内容后20位填充的是页框起始地址
// 	real_addr += (*pte_addr)&0x000fffff;               


// 	printk("\t虚拟地址为%ld\n",addr);
// 	printk("\t物理地址为%ld\n",real_addr);
// 	return 0;
// }




// void getEBP2(pid_t pid)
// {
// 	ptrace(PTRACE_ATTACH, pid, NULL, NULL);
// 	long ebp; 


// 	wait(NULL);
// 	long ebp = ptrace(PTRACE_PEEKUSER, pid, 8*EBP, NULL);//获取子进程停止时，rip的值
// 	printf("tracee:ebp:0x%lx \n", ebp);
// 	ptrace(PTRACE_CONT,tracee,NULL,NULL);
// }



static int dima_calc_task_code_by_pid(pid_t pid, char* comm, u8* digest)
{
    int ret = CMD_ERR_OK;
    struct mm_struct *target_mm;
    struct task_struct *target;
    unsigned long code_size;
    unsigned long code_index;
    
    rcu_read_lock();
    /* I change an other way to get the task_struct, */
    /* because of this way(target = find_task_by_vpid(pid);) never effecive again */
	// target = find_task_by_vpid(pid);
    target = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (target) {
        get_task_struct(target);
    }
    rcu_read_unlock();

    if (!target)
        return CMD_ERR_NOSEACH;
    
    // target_mm = get_task_mm(target);
    target_mm = target->mm;
    if(unlikely(target_mm == NULL)){
		ret = CMD_ERR_NOSEACH;
		goto out_put;
	}
	// dump_stack();
    code_size = target_mm->end_code - target_mm->start_code;
    if(unlikely(code_size <= 0)){
		ret = CMD_ERR_NOSEACH;
		// mmput(target_mm);
		goto out_put;
	}

    code_index = target_mm->start_code;
    // mmput(target_mm);

    pr_info("PID=%d Text Starts at 0x%lx, Size  0x%lx\n",pid, code_index, code_size);
    
    /* do shash cacluate , digest save the hash code of process*/
    // if((ret = dima_calc_task_buffer_hash(target,code_index,code_size,digest))){
	// 	pr_err("dima process calc hash err = %d \n",ret);
	// 	goto out_put;
	// }

	dima_calc_task_buffer_hash(target,code_index,code_size,digest);


	// getEBP2(pid);


    /* comm save the process name */
    strncpy(comm, target->comm, TASK_COMM_LEN);

    printk("process name: %s", comm);/**/

 out_put:
	put_task_struct(target);
	return ret;

}

static int dima_calc_module_by_name(const char* name, char* comm, u8* digest)
{
	struct module *mod;
	int ret = CMD_ERR_OK;

	mod = find_module(name);
	if(!mod) {
		printk("mod get failure\n");
		return CMD_ERR_NOSEACH;
	}


	printk("ioctl module : %d\n", mod->core_layout.size);


	preempt_disable();
	
	if(strlen(mod->name) == 0){
		ret =  CMD_ERR_NOSEACH;
		goto out_put;
	}

	if(mod->core_layout.size <= 0){
		ret =  CMD_ERR_NOSEACH;
		goto out_put;
	}

	if((ret = dima_calc_buffer_hash(mod->core_layout.base, mod->core_layout.size, digest))){
		pr_err("dima module calc hash err = %d \n",ret);
		goto out_put;
	}


    // int i;
    // for (i = 0; i < dima_hash_digest_size; i++)
	// 	pr_info("b %02x", *(digest + i));


	strncpy(comm,mod->name,MODULE_NAME_LEN);
out_put:
	preempt_enable();
	return ret;
}


int dima_measurement_process_cmd(int pid, u8* digest)
{
    char comm[DIMA_NAME_LEN] = {0};
    // u8 digest[DIMA_DIGEST_SIZE] = {0};
    int ret = CMD_ERR_OK;

    /* calculate the hash of code */
    ret = dima_calc_task_code_by_pid(pid,comm,digest);
	if(ret == CMD_ERR_NOSEACH){
		return ret;
	} else if(ret != CMD_ERR_OK){
		
	}

	// send_usrmsg(digest, 20);
    
    return cmp_dima_list(pid,NULL,DIMA_MODE_PROCESS,comm,digest);
}

// 设置度量模块
int dima_set_measurement_mode_cmd(int mode)
{
	dima_measurement_mode = mode;
	return CMD_ERR_OK;
}

// 模块度量
int dima_measurement_module_cmd(const char* name, u8* digest)
{
	char comm[DIMA_NAME_LEN]={0};
	// u8 digest[DIMA_DIGEST_SIZE]={0};
	int ret = CMD_ERR_OK;

	ret = dima_calc_module_by_name(name,comm,digest);
	if(ret == CMD_ERR_NOSEACH){
		return ret;
	} else if(ret != CMD_ERR_OK){

	}


	// return cmp_dima_list(-1,name,DIMA_MODE_MODULE,comm,digest);
	return 1;
}


int charToInt(const char *s)
{
	int n;
	unsigned char sign = 0;

	//   while (isspace(*s))
	//   {
	//     s++;
	//   }

	if (*s == '-')
	{
	sign = 1;
	s++;
	}
	else if (*s == '+')
	{
	s++;
	}

	n=0;

//   while (isdigit(*s))
	while (*s)
	{
	n = n * 10 + *s++ - '0';
	}

	return sign ? -n : n;
}
