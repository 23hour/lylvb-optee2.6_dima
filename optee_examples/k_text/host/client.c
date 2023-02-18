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
#include <err.h>
/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>
/* To the the UUID (found the the TA's h-file(s)) */
#include <ktext_ta.h>   //1改！(放到include文件夹中)

#define GAT_KTEXT_CMD    _IOW('d', 1, int)

#define DIMA_SET_MEASUREMENT_LOCK_MODE_CMD        _IO('d', 2)
#define DIMA_SET_MEASUREMENT_UNLOCK_MODE_CMD    _IO('d', 3)


#define NETLINK_TEST    30
#define MSG_LEN            12500
#define MAX_PLOAD        125

#define DIMA_NAME_LEN 100
#define MODULE_NAME_LEN (64 - sizeof(unsigned long))

typedef struct _user_msg_info
{
    struct nlmsghdr hdr;
    unsigned char msg[MSG_LEN];
} user_msg_info;

int main() {

    int skfd;
    int ret;
    user_msg_info u_info;
    socklen_t len;
    struct nlmsghdr *nlh = NULL;
    struct sockaddr_nl saddr, daddr;
    char *umsg = "hello netlink!!";
    int count = 0;
    int fd, err;
    int j = 0;

    fd = open("/dev/ktext",O_RDWR);
    if (fd < 0) {
        printf("error open");
        return -1;
    }

    /* 获取内核中的模块代码段信息 */

    /* 创建NETLINK socket */
    skfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_TEST);
    if(skfd == -1)
    {
        perror("create socket error\n");
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.nl_family = AF_NETLINK; //AF_NETLINK
    saddr.nl_pid = 102;  //端口号(port ID) 
    saddr.nl_groups = 0;
    if(bind(skfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0)//地址绑定；为0为成功
    {
        perror("bind() error\n");
        close(skfd);
        return -1;
    }

    memset(&daddr, 0, sizeof(daddr));
    daddr.nl_family = AF_NETLINK;
    daddr.nl_pid = 0; // to kernel 
    daddr.nl_groups = 0;

    unsigned char msg[200];
    int flag = 0;
    while(1)
    {
	printf("begin!");
    	ioctl(fd,DIMA_SET_MEASUREMENT_UNLOCK_MODE_CMD);
    	read(fd,msg,176);//GAI
    	ioctl(fd,DIMA_SET_MEASUREMENT_LOCK_MODE_CMD);
    	printf("over!");
    	for(int i=0;i<176;i+=4)
    	{
    		printf("%x %x %x %x",msg[i],msg[i+1],msg[i+2],msg[i+3]);
    	}

    	/*传递msg给TA*/
    	TEEC_Result res;
    	TEEC_Context ctx;
    	TEEC_UUID uuid = TA_KTEXT_UUID;//2改！
    	uint32_t err_origin;
    	/* Initialize a context connecting us to the TEE */
    	res = TEEC_InitializeContext(NULL, &ctx);
    	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
		
    	TEEC_Session sess;
    	TEEC_Operation op;

     	/* Open a session to the "hello world" TA, the TA will print "hello world!" in the log when the session is created. */
   	 res = TEEC_OpenSession(&ctx, &sess, &uuid,TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
   	 if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);
	/*
	 * Execute a function in the TA by invoking it, in this case
	 * we're incrementing a number.
	 */

	/* Clear the TEEC_Operation struct */
   	 memset(&op, 0, sizeof(op));
    	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT,TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);
   	op.params[0].tmpref.size = 176;//1改？
    	op.params[0].tmpref.buffer = msg;//1改？
	op.params[1].value.a = flag;
    	res = TEEC_InvokeCommand(&sess, TA_MONITOR, &op,&err_origin);//改！
    	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

    	TEEC_CloseSession(&sess);
    	TEEC_FinalizeContext(&ctx);
        j++;
	flag = 1;
        sleep(10);
    }

    close(skfd);

    free((void *)nlh);
    close(fd);

    return 0;

}
