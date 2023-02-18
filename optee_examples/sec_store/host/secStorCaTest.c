
/****************************************************************************************/
/*                          COPYRIGHT INFORMATION                                       */
/*    All rights reserved:shuaifengyun@126.com.                                         */
/****************************************************************************************/
/*
 ****************************************************************************************
 *
 *               secStorCaTest.c
 *
 * Filename      : secStorCaTest.c
 * Author        : Shuai Fengyun
 * Mail          : shuai.fengyun@126.cn
 * Create Time   : Mon 19 Jun 2017 10:33:32 AM CST
 ****************************************************************************************
 */

#define MOUDLE_SST_TEST_CA_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "secStorCaType.h"
#include "secStorCaDebug.h"
#include "secStorCaTest.h"
#include "secStorCaHandle.h"
#include "stdio.h"



#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/ioctl.h> 
#include <sys/types.h> 
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <errno.h>

#define DIMA_MEASUREMENT_PROCESS_CMD    _IOW('d', 2, int)
#define DIMA_SET_MEASUREMENT_LOCK_MODE_CMD        _IO('d', 4)
#define DIMA_SET_MEASUREMENT_UNLOCK_MODE_CMD    _IO('d', 5)
#define DIMA_MEASUREMENT_MODULE_CMD	   _IOW('d', 3, char[MODULE_NAME_LEN])




#define NETLINK_TEST    30   
/*在include/linux/netlink.h中增加一个新类型的 netlink 协议定义即可,(如 #define NETLINK_TEST 20 然后，内核和用户态应用就可以立即通过 socket API 使用该 netlink 协议类型进行数据交换)*/

#define MSG_LEN            12500
#define MAX_PLOAD        125

#define DIMA_NAME_LEN 100
#define MODULE_NAME_LEN (64 - sizeof(unsigned long))

typedef struct _user_msg_info
{
    struct nlmsghdr hdr;
    unsigned char msg[MSG_LEN];
} user_msg_info;


/*
 *******************************************************************************
 *                         FUNCTIONS SUPPLIED BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                          VARIABLES SUPPLIED BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                          FUNCTIONS USED ONLY BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                          VARIABLES USED ONLY BY THIS MODULE
 *******************************************************************************
*/

CHAR oldFileName[] = "secureFile.txt";
CHAR newFileName[] = "changeSecureFile.txt";

CHAR readBuf[256] = {0};
CHAR writeBuf[] = "This is the test data which need be wrote into secure file";



/*
 *******************************************************************************
 *                               FUNCTIONS IMPLEMENT
 *******************************************************************************
*/


int toTA(unsigned char *msg) {

    int l_Ret = FAIL;
    UINT32 l_FileLen = 0U;
    
    TF("create operation!\n");
    /** 2) Read data from secure file */
    l_Ret = g_SecStorCa_CreateFile(sizeof(oldFileName), oldFileName);//文件名为oldFileName,可以改
    if(FAIL == l_Ret)
    {
        TF("Create secure file fail\n");
        return 0;
    }

    TF("write operation!\n");
    /** 3) Write data into secure file */
    l_Ret = g_SecStorCa_WiteFile(sizeof(oldFileName), oldFileName, 20, msg);
    if(FAIL == l_Ret)
    {
        TF("Write secure file fail\n");
        return 0;
    }

}


int determine(unsigned char *msg) {
    int l_Ret = FAIL;
    UINT32 l_FileLen = 0U;

    TF("read operation!\n");
    /** 2) Read data from secure file */
    l_Ret = g_SecStorCa_ReadFile(sizeof(oldFileName), oldFileName, 20, readBuf);
    if(FAIL == l_Ret)
    {
        TF("Read secure file fail\n");
        return 0;
    }
    else
    {
        g_CA_PrintfBuffer(readBuf, 20);
        TF("The read data is:\n");
        int i;
        for (i = 0; i < 20; i++)
            printf("%02x", *(readBuf + i));
        printf("\n");
    }

    if (memcmp(msg, readBuf, 20) == 0) {//比较msg和readBuf的前20个字节
        printf("ok\n");
    } else {
        printf("not ok\n");
        return 0;
    }
    
    return 1;
}




int func(char *p_pid) {

    int skfd;
    int ret;
    user_msg_info u_info;
    socklen_t len; //unsigned int
    struct nlmsghdr *nlh = NULL;//消息头
    struct sockaddr_nl saddr, daddr;//源地址、目的地址
    char *umsg = "hello netlink!!";
    int count = 0;
    int fd, err;


    int pid = atoi(p_pid);//把字符串转换为整数

    printf("pid = %d\n", pid);
    // func(a);

    fd = open("/dev/dima",O_RDWR);//读取内核模块二进制文件
    if (fd < 0) {
        printf("error open");
        return -1;
    }


    /* ----------------zx---------------- */


    /* 创建NETLINK socket */
    skfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_TEST);
    if(skfd == -1)
    {
        perror("create socket error\n");
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.nl_family = AF_NETLINK; //AF_NETLINK
    saddr.nl_pid = 100;  //端口号(port ID) 
    saddr.nl_groups = 0;
    if(bind(skfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0)
    {
        perror("bind() error\n");
        close(skfd);
        return -1;
    }

    memset(&daddr, 0, sizeof(daddr));
    daddr.nl_family = AF_NETLINK;
    daddr.nl_pid = 0; // to kernel 
    daddr.nl_groups = 0;
    /* ----------------zx---------------- */

    int flag = 0;

    char modulename[DIMA_NAME_LEN] = {'d','i','m','a'};
    strcat(modulename, ",");
    strcat(modulename, p_pid);//dima,pid

    

    while (1)
    {   
        printf("count = %d\n", count++);

        //度量内核模块和用户态模块
        /* May be I need to add the lock, we can go to the measure_process branch statement */
        ioctl(fd,DIMA_SET_MEASUREMENT_UNLOCK_MODE_CMD);
        /* Now I jast can translate the pid to the kernal state */
        /* Next I will translate more imformation to kernal state */
        //ioctl(fd,DIMA_MEASUREMENT_PROCESS_CMD,(unsigned long)&pid);
        ioctl(fd,DIMA_MEASUREMENT_MODULE_CMD,(unsigned long)modulename);
        ioctl(fd,DIMA_SET_MEASUREMENT_LOCK_MODE_CMD);
        
        memset(&u_info, 0, sizeof(u_info));
        len = sizeof(struct sockaddr_nl);
        ret = recvfrom(skfd, &u_info, sizeof(user_msg_info), 0, (struct sockaddr *)&daddr, &len); //read from kernel
        if(!ret) //ret==-1
        {
            perror("recv form kernel error\n");
            close(skfd);
            exit(-1);
        }

        printf("Get hash value.\n");
        int i;
        for (i = 0; i < 20; i++)
            printf("%02x", *(u_info.msg + i)); ////
        printf("\n");


        if (flag == 0) {
            // 创建文件并且写入文件
            toTA(u_info.msg);
            flag = 1;
        } else {
            // 对比
            int tmp = determine(u_info.msg);
            if (tmp == 0) {
                kill(pid, SIGTERM);
                break;
            }
        }
        sleep(25);
        //sleep(120);//1是1秒
    }
    
    close(skfd);

    free((void *)nlh);
    close(fd);

    return 0;


}




/** @ingroup MOUDLE_NAME_C_
 *- #Description  This function for handle command.
 * @param   pMsg           [IN] The received request message
 *                               - Type: MBX_Msg *
 *                               - Range: N/A.
 *
 * @return     void
 * @retval     void
 *
 *
 */
int main(int argc, char *argv[])
{
    if (argc < 1) {
        printf("error input\n");
    }

    UINT32 fd = 0xFFFF;
    int l_Ret = FAIL;
    UINT32 l_FileLen = 0U;


    func(argv[1]);















    // TF("create operation!\n");
    // /** 2) Read data from secure file */
    // l_Ret = g_SecStorCa_CreateFile(sizeof(oldFileName), oldFileName);
    // if(FAIL == l_Ret)
    // {
    //     TF("Read secure file fail\n");
    //     return 0;
    // }

    // TF("write operation!\n");
    // /** 3) Write data into secure file */
    // l_Ret = g_SecStorCa_WiteFile(sizeof(oldFileName), oldFileName, sizeof(writeBuf), writeBuf);
    // if(FAIL == l_Ret)
    // {
    //     TF("Write secure file fail\n");
    //     return 0;
    // }

    // TF("read operation!\n");
    // /** 2) Read data from secure file */
    // l_Ret = g_SecStorCa_ReadFile(sizeof(oldFileName), oldFileName, 60U, readBuf);
    // if(FAIL == l_Ret)
    // {
    //     TF("Read secure file fail\n");
    //     return 0;
    // }
    // else
    // {
    //     g_CA_PrintfBuffer(readBuf, 60U);
    //     TF("The read data is:\n");
    //     TF("%s\n", readBuf);
    // }


    // TF("rename operation!\n");
    // l_Ret = g_SecStorCa_RenameFile(sizeof(oldFileName), oldFileName, sizeof(newFileName), newFileName);
    // if(FAIL == l_Ret)
    // {
    //     TF("Read secure file fail\n");
    //     return 0;
    // }


    // TF("read operation!\n");
    // memset(readBuf, 0, 256);
    // /** 2) Read data from secure file */
    // l_Ret = g_SecStorCa_ReadFile(sizeof(newFileName), newFileName, 60U, readBuf);
    // if(FAIL == l_Ret)
    // {
    //     TF("Read secure file fail\n");
    //     return 0;
    // }
    // else
    // {
    //     g_CA_PrintfBuffer(readBuf, 60U);
    //     TF("The read data is:\n");
    //     TF("%s\n", readBuf);
    // }



    // TF("truncate operation!\n");
    // /** 6) Truncate the secure file */
    // l_Ret = g_SecStorCa_TrunCatFile(sizeof(newFileName), newFileName, 20);
    // if(FAIL == l_Ret)
    // {
    //     TF("Write secure file fail\n");
    //     return 0;
    // }


    // TF("read3 operation!\n");
    // memset(readBuf, 0, 256);
    // l_Ret = g_SecStorCa_ReadFile(sizeof(newFileName), newFileName, 60U, readBuf);
    // if(FAIL == l_Ret)
    // {
    //     TF("Read secure file fail\n");
    //     return 0;
    // }
    // else
    // {
    //     g_CA_PrintfBuffer(readBuf, 60U);
    //     TF("The read data is:\n");
    //     TF("%s\n", readBuf);
    // }



    // TF("Delete operation!\n");
    // /** 10) Delete secure file */
    // l_Ret = g_SecStorCa_DeleteFile(sizeof(newFileName), newFileName);
    // if(FAIL == l_Ret)
    // {
    //     TF("Write secure file fail\n");
    //     return 0;
    // }
}






















/**
 * @}
 */
