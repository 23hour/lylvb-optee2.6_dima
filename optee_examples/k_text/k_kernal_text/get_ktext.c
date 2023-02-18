#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include "get_ktext.h"


int lkm_init(unsigned char data[])
{
    char *sym_name = "lkm_init";//获取该模块的代码段
    unsigned long sym_addr = kallsyms_lookup_name(sym_name);
    int i=0;
    unsigned char *s = sym_addr;
    //printk(KERN_INFO "[%s] %s (0x%lx): %x\n", __this_module.name, sym_name, sym_addr, filename);
    for(i=0;i<88;i+=4)//22*4
    {
        data[i] = s[i];data[i+1] = s[i+1];data[i+2] = s[i+2];data[i+3] = s[i+3];
	printk(KERN_INFO "%x %x %x %x\n", data[i],data[i+1],data[i+2],data[i+3]);
    }
    //sym_name = "dima_calc_task_buffer_hash";
    char *sym_name2 = "get_process_hack";
    sym_addr = kallsyms_lookup_name(sym_name2);
    s = sym_addr;
    for(i=0;i<88;i+=4)//22*4
    {
        data[i+88] = s[i];data[i+89] = s[i+1];data[i+90] = s[i+2];data[i+91] = s[i+3];
	printk(KERN_INFO "%x %x %x %x\n", data[i+88],data[i+89],data[i+90],data[i+91]);
    }
    return 0;
    
}

