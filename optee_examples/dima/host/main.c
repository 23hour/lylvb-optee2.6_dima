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

#define DIMA_MEASUREMENT_PROCESS_CMD    _IOW('d', 2, int)//写数据到驱动(类型 序号 数据类型)序号为2
#define DIMA_SET_MEASUREMENT_LOCK_MODE_CMD        _IO('d', 4)//序号为4
#define DIMA_SET_MEASUREMENT_UNLOCK_MODE_CMD    _IO('d', 5)//序号为5





#define NETLINK_TEST    30
#define MSG_LEN            12500
#define MAX_PLOAD        125

typedef struct _user_msg_info
{
    struct nlmsghdr hdr;
    unsigned char msg[MSG_LEN];
} user_msg_info;



// int main(int argc, char **argv)
// {
//     int skfd;
//     int ret;
//     user_msg_info u_info;
//     socklen_t len;
//     struct nlmsghdr *nlh = NULL;
//     struct sockaddr_nl saddr, daddr;
//     char *umsg = "hello netlink!!";

//     /* 创建NETLINK socket */
//     skfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_TEST);
//     if(skfd == -1)
//     {
//         perror("create socket error\n");
//         return -1;
//     }

//     memset(&saddr, 0, sizeof(saddr));
//     saddr.nl_family = AF_NETLINK; //AF_NETLINK
//     saddr.nl_pid = 100;  //端口号(port ID) 
//     saddr.nl_groups = 0;
//     if(bind(skfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0)
//     {
//         perror("bind() error\n");
//         close(skfd);
//         return -1;
//     }

//     memset(&daddr, 0, sizeof(daddr));
//     daddr.nl_family = AF_NETLINK;
//     daddr.nl_pid = 0; // to kernel 
//     daddr.nl_groups = 0;

//     // nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PLOAD));
//     // memset(nlh, 0, sizeof(struct nlmsghdr));
//     // nlh->nlmsg_len = NLMSG_SPACE(MAX_PLOAD);
//     // nlh->nlmsg_flags = 0;
//     // nlh->nlmsg_type = 0;
//     // nlh->nlmsg_seq = 0;
//     // nlh->nlmsg_pid = saddr.nl_pid; //self port

//     // memcpy(NLMSG_DATA(nlh), umsg, strlen(umsg));
//     // ret = sendto(skfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr_nl));
//     // if(!ret)
//     // {
//     //     perror("sendto error\n");
//     //     close(skfd);
//     //     exit(-1);
//     // }
//     // printf("send kernel:%s\n", umsg);

//     while (1)
//     {
//         memset(&u_info, 0, sizeof(u_info));
//         len = sizeof(struct sockaddr_nl);
//         ret = recvfrom(skfd, &u_info, sizeof(user_msg_info), 0, (struct sockaddr *)&daddr, &len);
//         if(!ret)
//         {
//             perror("recv form kernel error\n");
//             close(skfd);
//             exit(-1);
//         }

//         printf("from kernel:%s\n", u_info.msg);
//     }
    
//     close(skfd);

//     free((void *)nlh);
//     return 0;
// }







// static int func(int pid)
// {
//     int fd, err;
    
//     fd = open("/dev/dima",O_RDWR);
//     if (fd < 0) {
//         printf("error open");
//         return -1;
//     }

//     /* May be I need to add the lock, we can go to the measure_process branch statement */
//     ioctl(fd,DIMA_SET_MEASUREMENT_UNLOCK_MODE_CMD);
//     /* Now I jast can translate the pid to the kernal state */
//     /* Next I will translate more imformation to kernal state */
//     ioctl(fd,DIMA_MEASUREMENT_PROCESS_CMD,(unsigned long)&pid);
//     ioctl(fd,DIMA_SET_MEASUREMENT_LOCK_MODE_CMD);

//     close(fd);
//     return 0;
// }


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
    int pid = atoi(argv[1]);

    printf("pid = %d\n", pid);
    // func(a);

    fd = open("/dev/dima",O_RDWR);
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
    if(bind(skfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0)//为0为成功
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

    while (1)
    {   
        printf("count = %d\n", count++);
        /* May be I need to add the lock, we can go to the measure_process branch statement */
        ioctl(fd,DIMA_SET_MEASUREMENT_UNLOCK_MODE_CMD);
        /* Now I jast can translate the pid to the kernal state */
        /* Next I will translate more imformation to kernal state */
        ioctl(fd,DIMA_MEASUREMENT_PROCESS_CMD,(unsigned long)&pid);
        ioctl(fd,DIMA_SET_MEASUREMENT_LOCK_MODE_CMD);

        memset(&u_info, 0, sizeof(u_info));
        len = sizeof(struct sockaddr_nl);
        ret = recvfrom(skfd, &u_info, sizeof(user_msg_info), 0, (struct sockaddr *)&daddr, &len);
        if(!ret)
        {
            perror("recv form kernel error\n");
            close(skfd);
            exit(-1);
        }

        int i;
        for (i = 0; i < 20; i++)
            printf("%02x?", *(u_info.msg + i));//度量信息？
        printf("\n");
        // printf("from kernel:%s\n", u_info.msg);

        sleep(1);
    }
    
    close(skfd);

    free((void *)nlh);
    close(fd);

    return 0;

}
