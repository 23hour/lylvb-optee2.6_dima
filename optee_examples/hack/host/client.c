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

#define GAT_PROCESS_HACK_CMD    _IOW('d', 1, int)

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

int main(int argc, char *argv[]) {

    int skfd;
    int ret;
    user_msg_info u_info;
    socklen_t len;
    struct nlmsghdr *nlh = NULL;
    struct sockaddr_nl saddr, daddr;
    char *umsg = "hello netlink!!";
    int count = 0;
    int fd, err;

    if (argc < 1) {
        printf("error input\n");
    }
    int pid = atoi(argv[1]);//从命令行读取pid号

    printf("pid = %d\n", pid);

    fd = open("/dev/hack",O_RDWR);
    //fd = open("/dev/fack_hack",O_RDWR);
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
    saddr.nl_pid = 101;  //端口号(port ID) 
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

    printf("begin send pid!");
    ioctl(fd,DIMA_SET_MEASUREMENT_UNLOCK_MODE_CMD);
    ioctl(fd,GAT_PROCESS_HACK_CMD,(unsigned long)&pid);
    ioctl(fd,DIMA_SET_MEASUREMENT_LOCK_MODE_CMD);
    printf("send pid over!");
    
    close(skfd);

    free((void *)nlh);
    close(fd);

    return 0;

}
