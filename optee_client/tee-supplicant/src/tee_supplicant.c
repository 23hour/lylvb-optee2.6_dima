/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <gprof.h>
#include <inttypes.h>
#include <pthread.h>
#include <rpmb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <tee_client_api.h>
#include <teec_ta_load.h>
#include <teec_trace.h>
#include <tee_socket.h>
#include <tee_supp_fs.h>
#include <tee_supplicant.h>
#include <unistd.h>

#include "optee_msg_supplicant.h"

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/tee.h>

#define RPC_NUM_PARAMS	5

#define RPC_BUF_SIZE	(sizeof(struct tee_iocl_supp_send_arg) + \
			 RPC_NUM_PARAMS * sizeof(struct tee_ioctl_param))

union tee_rpc_invoke {
	uint64_t buf[(RPC_BUF_SIZE - 1) / sizeof(uint64_t) + 1];
	struct tee_iocl_supp_recv_arg recv;
	struct tee_iocl_supp_send_arg send;
};

struct tee_shm {
	int id;
	void *p;
	size_t size;
	bool registered;
	int fd;
	struct tee_shm *next;
};

struct thread_arg {
	int fd;
	uint32_t gen_caps;
	bool abort;
	size_t num_waiters;
	pthread_mutex_t mutex;
};

static pthread_mutex_t shm_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct tee_shm *shm_head;

static const char *ta_dir;

static void *thread_main(void *a);

static size_t num_waiters_inc(struct thread_arg *arg)
{
	size_t ret;

	tee_supp_mutex_lock(&arg->mutex);
	arg->num_waiters++;
	assert(arg->num_waiters);
	ret = arg->num_waiters;
	tee_supp_mutex_unlock(&arg->mutex);

	return ret;
}

static size_t num_waiters_dec(struct thread_arg *arg)
{
	size_t ret;

	tee_supp_mutex_lock(&arg->mutex);
	assert(arg->num_waiters);
	arg->num_waiters--;
	ret = arg->num_waiters;
	tee_supp_mutex_unlock(&arg->mutex);

	return ret;
}

static int get_value(size_t num_params, struct tee_ioctl_param *params,
		     const uint32_t idx, struct tee_ioctl_param_value **value)
{
	if (idx >= num_params)
		return -1;

	switch (params[idx].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) {
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
		*value = &params[idx].u.value;
		return 0;
	default:
		return -1;
	}
}

static struct tee_shm *find_tshm(int id)
{
	struct tee_shm *tshm;

	tee_supp_mutex_lock(&shm_mutex);

	tshm = shm_head;
	while (tshm && tshm->id != id)
		tshm = tshm->next;

	tee_supp_mutex_unlock(&shm_mutex);

	return tshm;
}

static struct tee_shm *pop_tshm(int id)
{
	struct tee_shm *tshm;
	struct tee_shm *prev;

	tee_supp_mutex_lock(&shm_mutex);

	tshm = shm_head;
	if (!tshm)
		goto out;

	if (tshm->id == id) {
		shm_head = tshm->next;
		goto out;
	}

	do {
		prev = tshm;
		tshm = tshm->next;
		if (!tshm)
			goto out;
	} while (tshm->id != id);
	prev->next = tshm->next;

out:
	tee_supp_mutex_unlock(&shm_mutex);

	return tshm;
}

static void push_tshm(struct tee_shm *tshm)
{
	tee_supp_mutex_lock(&shm_mutex);

	tshm->next = shm_head;
	shm_head = tshm;

	tee_supp_mutex_unlock(&shm_mutex);
}

/* Get parameter allocated by secure world */
static int get_param(size_t num_params, struct tee_ioctl_param *params,
		     const uint32_t idx, TEEC_SharedMemory *shm)
{
	struct tee_shm *tshm;

	if (idx >= num_params)
		return -1;

	switch (params[idx].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) {
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
		break;
	default:
		return -1;
	}

	memset(shm, 0, sizeof(*shm));

	tshm = find_tshm(params[idx].u.memref.shm_id);
	if (!tshm) {
		/*
		 * It doesn't make sense to query required size of an
		 * input buffer.
		 */
		if ((params[idx].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) ==
		    TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT)
			return -1;

		/*
		 * Buffer isn't found, the caller is querying required size
		 * of the buffer.
		 */
		return 0;
	}
	if ((params[idx].u.memref.size + params[idx].u.memref.shm_offs) <
	    params[idx].u.memref.size)
		return -1;
	if ((params[idx].u.memref.size + params[idx].u.memref.shm_offs) >
	    tshm->size)
		return -1;

	shm->flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	shm->size = params[idx].u.memref.size - params[idx].u.memref.shm_offs;
	shm->id = params[idx].u.memref.shm_id;
	shm->buffer = (uint8_t *)tshm->p + params[idx].u.memref.shm_offs;
	return 0;
}

static void uuid_from_octets(TEEC_UUID *d, const uint8_t s[TEE_IOCTL_UUID_LEN])
{
	d->timeLow = (s[0] << 24) | (s[1] << 16) | (s[2] << 8) | s[3];
	d->timeMid = (s[4] << 8) | s[5];
	d->timeHiAndVersion = (s[6] << 8) | s[7];
	memcpy(d->clockSeqAndNode, s + 8, sizeof(d->clockSeqAndNode));
}

static uint32_t load_ta(size_t num_params, struct tee_ioctl_param *params)
{
	int ta_found = 0;
	size_t size = 0;
	TEEC_UUID uuid;
	struct tee_ioctl_param_value *val_cmd;
	TEEC_SharedMemory shm_ta;

	memset(&shm_ta, 0, sizeof(shm_ta));
    
    /* 解析出需要加载的TA镜像的UUID以及配置将读取到的TA镜像的内容存放位置 */
	if (num_params != 2 || get_value(num_params, params, 0, &val_cmd) ||
	    get_param(num_params, params, 1, &shm_ta))
		return TEEC_ERROR_BAD_PARAMETERS;

    /* 解析出需要加载的TA镜像的UUID以及配置将读取到的TA镜像的内容存放位置 */
	uuid_from_octets(&uuid, (void *)val_cmd);

    /* 从ta_dir变量指定的目录中查找与UUID相符的TA镜像，并将其内容读取到共享内存中 */
	size = shm_ta.size;
	ta_found = TEECI_LoadSecureModule(ta_dir, &uuid, shm_ta.buffer, &size);
	if (ta_found != TA_BINARY_FOUND) {
		EMSG("  TA not found");
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

    /* 设定读取到的TA镜像的大小到返回参数的size成员中 */
	params[1].u.memref.size = size;

	/*
	 * If a buffer wasn't provided, just tell which size it should be.
	 * If it was provided but isn't big enough, report an error.
	 */
	if (shm_ta.buffer && size > shm_ta.size)
		return TEEC_ERROR_SHORT_BUFFER;

	return TEEC_SUCCESS;
}

static struct tee_shm *alloc_shm(int fd, size_t size)
{
	struct tee_ioctl_shm_alloc_data data;
	struct tee_shm *shm;

	memset(&data, 0, sizeof(data));

    /* 分配shm变量空间 */
	shm = calloc(1, sizeof(*shm));
	if (!shm)
		return NULL;

    /* 调用tee驱动分配共享空间 */
	data.size = size;
	shm->fd = ioctl(fd, TEE_IOC_SHM_ALLOC, &data);
	if (shm->fd < 0) {
		free(shm);
		return NULL;
	}

    /* 将分配好的共享内存的句柄映射到系统内存中 */
	shm->p = mmap(NULL, data.size, PROT_READ | PROT_WRITE, MAP_SHARED,
		      shm->fd, 0);
	if (shm->p == (void *)MAP_FAILED) {
		free(shm);
		close(shm->fd);
		return NULL;
	}

    /* 记录分配好的共享内存数据 */
	shm->id = data.id;
	shm->registered = false;
	return shm;
}

static struct tee_shm *register_local_shm(int fd, size_t size)
{
	struct tee_ioctl_shm_register_data data;
	struct tee_shm *shm;
	void *buf;

	memset(&data, 0, sizeof(data));

	buf = malloc(size);
	if (!buf)
		return NULL;

	shm = calloc(1, sizeof(*shm));
	if (!shm) {
		free(buf);
		return NULL;
	}

	data.addr = (uintptr_t)buf;
	data.length = size;

	shm->fd = ioctl(fd, TEE_IOC_SHM_REGISTER, &data);
	if (shm->fd < 0) {
		free(shm);
		free(buf);
		return NULL;
	}

	shm->p = buf;
	shm->registered = true;
	shm->id = data.id;

	return shm;
}

static uint32_t process_alloc(struct thread_arg *arg, size_t num_params,
			      struct tee_ioctl_param *params)
{
	struct tee_ioctl_param_value *val;
	struct tee_shm *shm;

    /* 获取从TA发送到tee_supplicant的value */
	if (num_params != 1 || get_value(num_params, params, 0, &val))
		return TEEC_ERROR_BAD_PARAMETERS;

	if (arg->gen_caps & TEE_GEN_CAP_REG_MEM)
		shm = register_local_shm(arg->fd, val->b);
	else
        /* 一系列操作 */
		shm = alloc_shm(arg->fd, val->b);

	if (!shm)
		return TEEC_ERROR_OUT_OF_MEMORY;

    /* 记录分配好的共享内存数据 */
	shm->size = val->b;
	val->c = shm->id;
	
    /* 将分配的共享内存添加到共享内存链表中 */
	push_tshm(shm);

	return TEEC_SUCCESS;
}

static uint32_t process_free(size_t num_params, struct tee_ioctl_param *params)
{
	struct tee_ioctl_param_value *val;
	struct tee_shm *shm;
	int id;

    /* 记录分配好的共享内存数据 */
	if (num_params != 1 || get_value(num_params, params, 0, &val))
		return TEEC_ERROR_BAD_PARAMETERS;

    /* 获取需要被释放的共享内存的id值 */
	id = val->b;

    /* 从共享内存链表删除指定的节点 */
	shm = pop_tshm(id);
	if (!shm)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (shm->registered) {
		free(shm->p);
	} else  {
        /* 取消掉系统内存映射 */
		if (munmap(shm->p, shm->size) != 0) {
			EMSG("munmap(%p, %zu) failed - Error = %s",
			     shm->p, shm->size, strerror(errno));
			close(shm->fd);
			free(shm);
			return TEEC_ERROR_BAD_PARAMETERS;
		}
	}

    /* 执行free操作 */
	close(shm->fd);
	free(shm);
	return TEEC_SUCCESS;
}



/* How many device sequence numbers will be tried before giving up */
#define MAX_DEV_SEQ	10

static int open_dev(const char *devname, uint32_t *gen_caps)
{
	struct tee_ioctl_version_data vers;
	int fd;

	fd = open(devname, O_RDWR);
	if (fd < 0)
		return -1;

	if (ioctl(fd, TEE_IOC_VERSION, &vers))
		goto err;

	/* Only OP-TEE supported */
	if (vers.impl_id != TEE_IMPL_ID_OPTEE)
		goto err;

	ta_dir = "optee_armtz";
	if (gen_caps)
		*gen_caps = vers.gen_caps;

	DMSG("using device \"%s\"", devname);
	return fd;
err:
	close(fd);
	return -1;
}

static int get_dev_fd(uint32_t *gen_caps)
{
	int fd;
	char name[PATH_MAX];
	size_t n;

	for (n = 0; n < MAX_DEV_SEQ; n++) {
		snprintf(name, sizeof(name), "/dev/teepriv%zu", n);
		fd = open_dev(name, gen_caps);
		if (fd >= 0)
			return fd;
	}
	return -1;
}

static int usage(void)
{
	fprintf(stderr, "usage: tee-supplicant [<device-name>]");
	return EXIT_FAILURE;
}

static uint32_t process_rpmb(size_t num_params, struct tee_ioctl_param *params)
{
	TEEC_SharedMemory req;
	TEEC_SharedMemory rsp;

    /* 指定存放请求和返回数据的共享内存 */
	if (get_param(num_params, params, 0, &req) ||
	    get_param(num_params, params, 1, &rsp))
		return TEEC_ERROR_BAD_PARAMETERS;
    
    /* 指定对rpmb分区的操作 */
	return rpmb_process_request(req.buffer, req.size, rsp.buffer, rsp.size);
}

static bool read_request(int fd, union tee_rpc_invoke *request)
{
	struct tee_ioctl_buf_data data;

	data.buf_ptr = (uintptr_t)request;
	data.buf_len = sizeof(*request);
	// 接受TA发过来的请求
	// data：数据（请求）
	/* 将在tee_supplicant中设定的用于存放TA请求的buffer和属性的地址作为参数，
    然后调用ioctl函数进入到tee驱动中等待来自TA的请求 */
	if (ioctl(fd, TEE_IOC_SUPPL_RECV, &data)) {
		EMSG("TEE_IOC_SUPPL_RECV: %s", strerror(errno));
		return false;
	}
	return true;
}

static bool write_response(int fd, union tee_rpc_invoke *request)
{
	struct tee_ioctl_buf_data data;

    /* 确保剩下的参数中没有属性为TEE_IOCTL_PARAM_ATTR_META的参数 */
	data.buf_ptr = (uintptr_t)&request->send;
	data.buf_len = sizeof(struct tee_iocl_supp_send_arg) +
		       sizeof(struct tee_ioctl_param) *
				request->send.num_params;

    /* 调用驱动中ioctl函数的TEE_IOC_SUPPL_SEND功能，进数据发送给TA */
	if (ioctl(fd, TEE_IOC_SUPPL_SEND, &data)) {
		EMSG("TEE_IOC_SUPPL_SEND: %s", strerror(errno));
		return false;
	}
	return true;
}

static bool find_params(union tee_rpc_invoke *request, uint32_t *func,
			size_t *num_params, struct tee_ioctl_param **params,
			size_t *num_meta)
{
	struct tee_ioctl_param *p;
	size_t n;

	p = (struct tee_ioctl_param *)(&request->recv + 1);

	/* Skip meta parameters in the front */	
    /* 跳过属性为TEE_IOCTL_PARAM_ATTR_META的参数 */
	for (n = 0; n < request->recv.num_params; n++)
		if (!(p[n].attr & TEE_IOCTL_PARAM_ATTR_META))
			break;

	*func = request->recv.func;                 //记录TA请求的操作编号
	*num_params = request->recv.num_params - n; //确定TA真正的参数个数
	*params = p + n;                            //将params指向TA发送过来的参数
	*num_meta = n;                              //定位meta的起始位置

	/* Make sure that no meta parameters follows a non-meta parameter */
	/* 确保剩下的参数中没有属性为TEE_IOCTL_PARAM_ATTR_META的参数 */
	for (; n < request->recv.num_params; n++) {
		if (p[n].attr & TEE_IOCTL_PARAM_ATTR_META) {
			EMSG("Unexpected meta parameter");
			return false;
		}
	}

	return true;
}

static bool spawn_thread(struct thread_arg *arg)
{
	pthread_t tid;
	int e;

	DMSG("Spawning a new thread");

	/*
	 * Increase number of waiters now to avoid starting another thread
	 * before this thread has been scheduled.
	 */
	num_waiters_inc(arg);

	e = pthread_create(&tid, NULL, thread_main, arg);
	if (e) {
		EMSG("pthread_create: %s", strerror(e));
		num_waiters_dec(arg);
		return false;
	}

	e = pthread_detach(tid);
	if (e)
		EMSG("pthread_detach: %s", strerror(e));

	return true;
}

static bool process_one_request(struct thread_arg *arg)
{
	union tee_rpc_invoke request;
	size_t num_params;
	size_t num_meta;
	struct tee_ioctl_param *params;
	uint32_t func;
	uint32_t ret;

	DMSG("looping");
	memset(&request, 0, sizeof(request));
	request.recv.num_params = RPC_NUM_PARAMS;

	/* Let it be known that we can deal with meta parameters */	
    /* 组合tee_supplican等待TA请求的参数 */
	params = (struct tee_ioctl_param *)(&request.send + 1);
	params->attr = TEE_IOCTL_PARAM_ATTR_META;

    /* 增加当前正在等待处理的tee_supplicant的数量 */
	num_waiters_inc(arg);

    // 读来自TA的请求
    /* 通过ioctl函数，将等待请求发送到tee驱动，在tee驱动中将会block住，
    直到有来自TA的请求才会返回 */
	if (!read_request(arg->fd, &request))
		return false;

    // 解析参数
    /* 解析从TA发送的请求，分离出TA需要tee_supplicant所做的事情ID和相关参数 */
	if (!find_params(&request, &func, &num_params, &params, &num_meta))
		return false;

    /* 创建新的线程来等待接收来自TA的请求，将等待请求的数量减一 */
	if (num_meta && !num_waiters_dec(arg) && !spawn_thread(arg))
		return false;

    // 处理请求
    /* 根据TA请求的ID来执行具体的handle */
	switch (func) {
	case OPTEE_MSG_RPC_CMD_LOAD_TA:         //加载在文件系统的TA镜像
		ret = load_ta(num_params, params);
		break;
	case OPTEE_MSG_RPC_CMD_FS:
		ret = tee_supp_fs_process(num_params, params);  //处理操作文件系统的请求
		break;
	case OPTEE_MSG_RPC_CMD_RPMB:
		ret = process_rpmb(num_params, params);         //处理对EMMC中rpmb分区的操作请求
		break;
	case OPTEE_MSG_RPC_CMD_SHM_ALLOC:
		ret = process_alloc(arg, num_params, params);   //处理分配共享内存的请求
		break;
	case OPTEE_MSG_RPC_CMD_SHM_FREE:
		ret = process_free(num_params, params);         //释放分配的共享内存的请求
		break;
	case OPTEE_MSG_RPC_CMD_GPROF:
		ret = gprof_process(num_params, params);        //处理gprof请求
		break;
	case OPTEE_MSG_RPC_CMD_SOCKET:
		ret = tee_socket_process(num_params, params);   //处理网络socket请求
		break;
	default:
		EMSG("Cmd [0x%" PRIx32 "] not supported", func);
		/* Not supported. */
		ret = TEEC_ERROR_NOT_SUPPORTED;
		break;
	}

	request.send.ret = ret;
	// 将处理好的值返回给TA
	return write_response(arg->fd, &request);
}

static void *thread_main(void *a)
{
	struct thread_arg *arg = a;

	/*
	 * Now that this thread has been scheduled, compensate for the
	 * initial increase in spawn_thread() before.
	 */
	num_waiters_dec(arg);

	while (!arg->abort) {
		if (!process_one_request(arg))
			arg->abort = true;
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	struct thread_arg arg = { .fd = -1 };
	int e;
    
    /* 初始化互斥体 */
	e = pthread_mutex_init(&arg.mutex, NULL);
	if (e) {
		EMSG("pthread_mutex_init: %s", strerror(e));
		EMSG("terminating...");
		exit(EXIT_FAILURE);
	}

    /* 判定是否带有启动参数，如果带有启动参数，则打开对应的驱动文件
    如果没有带参数，则打开默认的驱动文件 */
	if (argc > 2)
		return usage();
	if (argc == 2) {
		arg.fd = open_dev(argv[1], &arg.gen_caps);
		if (arg.fd < 0) {
			EMSG("failed to open \"%s\"", argv[1]);
			exit(EXIT_FAILURE);
		}
	} else {
	    // 这个fd是tee_supplicant和optee里面进行交互的媒介
        /*打开/dev/teepriv0设备，该设备为tee驱动设备文件，返回操作句柄*/
		arg.fd = get_dev_fd(&arg.gen_caps);
		if (arg.fd < 0) {
			EMSG("failed to find an OP-TEE supplicant device");
			exit(EXIT_FAILURE);
		}
	}

	if (tee_supp_fs_init() != 0) {
		EMSG("error tee_supp_fs_init");
		exit(EXIT_FAILURE);
	}

    /* 调用process_one_request函数接收来自TEE的请求，并加以处理 */
	while (!arg.abort) {
		if (!process_one_request(&arg))
			arg.abort = true;
	}

	close(arg.fd);

	return EXIT_FAILURE;
}

bool tee_supp_param_is_memref(struct tee_ioctl_param *param)
{
	switch (param->attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) {
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
		return true;
	default:
		return false;
	}
}

bool tee_supp_param_is_value(struct tee_ioctl_param *param)
{
	switch (param->attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) {
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
		return true;
	default:
		return false;
	}
}

void *tee_supp_param_to_va(struct tee_ioctl_param *param)
{
	struct tee_shm *tshm;
	size_t end_offs;

	if (!tee_supp_param_is_memref(param))
		return NULL;

	end_offs = param->u.memref.size + param->u.memref.shm_offs;
	if (end_offs < param->u.memref.size ||
	    end_offs < param->u.memref.shm_offs)
		return NULL;

	tshm = find_tshm(param->u.memref.shm_id);
	if (!tshm)
		return NULL;

	if (end_offs > tshm->size)
		return NULL;

	return (uint8_t *)tshm->p + param->u.memref.shm_offs;
}

void tee_supp_mutex_lock(pthread_mutex_t *mu)
{
	int e = pthread_mutex_lock(mu);

	if (e) {
		EMSG("pthread_mutex_lock: %s", strerror(e));
		EMSG("terminating...");
		exit(EXIT_FAILURE);
	}
}

void tee_supp_mutex_unlock(pthread_mutex_t *mu)
{
	int e = pthread_mutex_unlock(mu);

	if (e) {
		EMSG("pthread_mutex_unlock: %s", strerror(e));
		EMSG("terminating...");
		exit(EXIT_FAILURE);
	}
}
