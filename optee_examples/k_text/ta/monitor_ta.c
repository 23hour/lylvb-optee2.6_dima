/*
 * Copyright (c) 2016, Linaro Limited
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

#define STR_TRACE_USER_TA "KTEXT"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

#include "ktext_ta.h"
#include "sha1.h"
/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
char filename[] = "monitor_secFile.txt";
TEE_Result g_KtextTa_CreateFile(void);
TEE_Result g_KtextTa_Write(char *digest);
TEE_Result g_KtextTa_Read(char *readbuf);
int judgement(char *msg);

TEE_ObjectHandle g_FilesObj;

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
 
	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello lxq!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

TEE_Result g_KtextTa_CreateFile(void)
{
    TEE_Result l_ret = TEE_EXEC_FAIL;
    char* l_fileName = filename;
    UINT32 l_fileNameSize = 20;

    IMSG("[CREATE] start to create file: %s\n", l_fileName);
    l_ret = TEE_CreatePersistentObject(TEE_OBJECT_STORAGE_PRIVATE, l_fileName,
                       l_fileNameSize, TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_ACCESS_WRITE, 
                       TEE_HANDLE_NULL , NULL, 0, 
                       (&g_FilesObj));
    if (TEE_SUCCESS != l_ret)
    {
        IMSG("[CREATE] create file fail");
        return TEE_EXEC_FAIL;
    }
    else
    {
        TEE_CloseObject(g_FilesObj);
        return TEE_SUCCESS;
    }
}

static TEE_Result l_KtextTa_Open(const CHAR* fileName, UINT32 fileNameSize)
{
    TEE_Result l_ret = TEE_EXEC_FAIL; 
    UINT32 l_AccFlg = TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_READ;


    l_ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, fileName, 
                                   fileNameSize, l_AccFlg, (&g_FilesObj));
    if (TEE_SUCCESS != l_ret)
    {        
        return TEE_EXEC_FAIL;
    }
    else
    {
        return TEE_SUCCESS;
    }
}

TEE_Result g_KtextTa_Write(char *digest)
{
    TEE_Result l_ret = TEE_SUCCESS;
    CHAR* l_InBuf = digest;
    UINT32 l_WriteLen = 20;
    const CHAR* l_FileName = filename;
    UINT32 l_FileNameSize = 20;
    IMSG("[WRITE] start to write file: %s\n sizeof(l_FileName):%d\n", l_FileName,l_FileNameSize);
    l_ret = l_KtextTa_Open(l_FileName, l_FileNameSize);
    if (TEE_SUCCESS != l_ret)
    {     
        IMSG("[WRITE] open file fail\n");
        return TEE_EXEC_FAIL;
    }

    /** 2) Start write data from secure file */
    l_ret = TEE_WriteObjectData(g_FilesObj, l_InBuf, l_WriteLen);

    TEE_CloseObject(g_FilesObj);
    if (TEE_SUCCESS != l_ret)
    {        
        IMSG("[WRITE] wtire file fail\n");
        return TEE_EXEC_FAIL;
    }
    else
    {
        return TEE_SUCCESS;
    }
}

TEE_Result g_KtextTa_Read(char *readbuf)
{
    TEE_Result l_ret = TEE_SUCCESS;
    CHAR* l_OutBuf = readbuf;
    UINT32 l_ReadLen = 20;
    const CHAR* l_FileName = filename;
    UINT32 l_FileNameSize = 20;
    UINT32 l_Count = 0U;

    IMSG("[READ] start to read file: %s\n", l_FileName);
    l_ret = l_KtextTa_Open(l_FileName, l_FileNameSize);
    IMSG("OPEN success,ret is %d\n", l_ret);
    if (TEE_SUCCESS != l_ret)
    {        
        IMSG("[READ] open file fail\n");
        return TEE_EXEC_FAIL;
    }

    /** 2) Start read data from secure file */
    l_ret = TEE_ReadObjectData(g_FilesObj, l_OutBuf, l_ReadLen, &l_Count);
	IMSG("TEE_ReadObjectData success");
    TEE_CloseObject(g_FilesObj);
    if (TEE_SUCCESS != l_ret)
    {        
        IMSG("[READ] read file fail\n");
        return TEE_EXEC_FAIL;
    }
    else
    {
        return TEE_SUCCESS;
    }
}

int judgement(char *msg) {
    int l_Ret = FAIL;
    char readbuf[256] = {0};
    int i = 0;
    IMSG("read operation!\n");
    /** 2) Read data from secure file */
    l_Ret = g_KtextTa_Read(readbuf);
    if(FAIL == l_Ret)
    {
        IMSG("Read secure file fail\n");
        return 0;
    }
    else
    {
        IMSG("The read data is:\n");
        for (i = 0; i < 20; i++)
            printf("%02x", *(readbuf + i));
        printf("\n");
    }

    if (memcmp(msg, readbuf, 20) == 0) {//比较msg和readBuf的前20个字节
        printf("ok\n");
    } else {
        printf("not ok\n");
        return 0;
    }
    
    return 1;
}

static TEE_Result monitor(uint32_t param_types,
	TEE_Param params[4])
{
        int i=0;
        SHA1Schedule ctx;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,TEE_PARAM_TYPE_VALUE_INPUT,TEE_PARAM_TYPE_NONE,TEE_PARAM_TYPE_NONE);
	char* message = NULL;//加！
        char digest[20] = {0};

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	message=params[0].memref.buffer;
	IMSG("Got message from NW");
        for(int j=0;j<176;j+=4)
        {
    	    IMSG("%x %x %x %x",message[j],message[j+1],message[j+2],message[j+3]);
        }
	//开始计算hash值
	sha1_init(&ctx);
        DMSG("sha1_init has been completed");
        sha1_update(&ctx, message, 176);
	DMSG("sha1_update has been completed");
        sha1_final(&ctx, digest);
	DMSG("sha1_final has been completed");
        for (; i < 20; i++)
		DMSG("%02x", *(digest + i));//可以输出一下digest看看结果
        //第一次的话 存入安全文件；判断值是否可信
	if(params[1].value.a==0)
	{
		g_KtextTa_CreateFile();//创建安全文件		
		g_KtextTa_Write(digest);//写入安全文件
		judgement(digest);
	}
        else
	{
		judgement(digest);//判断比较是否可信
	}
	return TEE_SUCCESS;
}
/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_MONITOR:
		return monitor(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
