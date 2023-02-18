#ifndef __LINUX_DIMA_H
#define __LINUX_DIMA_H

#include <linux/types.h>
#include <linux/security.h>
#include <linux/hash.h>
#include <linux/tpm.h>
#include <linux/audit.h>
#include <linux/types.h>
#include <linux/integrity.h>
#include <linux/key.h>
#include <linux/tpm.h>
#include <linux/module.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>

#define GAT_KTEXT_CMD    _IOW('d', 1, int)

#define DIMA_SET_MEASUREMENT_LOCK_MODE_CMD        _IO('d', 2)
#define DIMA_SET_MEASUREMENT_UNLOCK_MODE_CMD    _IO('d', 3)

int lkm_init(unsigned char data[]);
int t_netlink_init(void);
void test_netlink_exit(void);
int send_usrmsg(char *pbuf, uint16_t len);
void netlink_rcv_msg(struct sk_buff *skb);


#endif
