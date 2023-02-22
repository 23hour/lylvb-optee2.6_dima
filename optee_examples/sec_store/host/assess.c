#include "secStorCaType.h"
#include "secStorCaDebug.h"
#include "secStorCaTest.h"
#include "secStorCaHandle.h"
#include "assess.h"
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

CHAR oldFileName[15] ;
CHAR readBuf[256] = {0};

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
        printf("ok !\n");
    } else {
        printf("not ok\n");
        return 0;
    }
    
    return 1;
}
