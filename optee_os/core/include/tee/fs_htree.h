/*
 * Copyright (c) 2017, Linaro Limited
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

#ifndef __TEE_FS_HTREE_H
#define __TEE_FS_HTREE_H

/*
 * The purpose of this API is to provide file integrity and confidentiality
 * in order to implement secure storage. On-disk data structures are
 * duplicated to make updates atomic, an update is finalized to disk with
 * tee_fs_htree_sync_to_storage().
 *
 * This implementation doesn't provide rollback protection, it only
 * guarantees the integrity and confidentiality of the file.
 */

#include <tee_api_types.h>
#include <utee_defines.h>

#define TEE_FS_HTREE_HASH_SIZE		TEE_SHA256_HASH_SIZE
#define TEE_FS_HTREE_IV_SIZE		16
#define TEE_FS_HTREE_FEK_SIZE		16
#define TEE_FS_HTREE_TAG_SIZE		16

/* Internal struct provided to let the rpc callbacks know the size if needed */
struct tee_fs_htree_node_image {
	/* Note that calc_node_hash() depends on hash first in struct */
	uint8_t hash[TEE_FS_HTREE_HASH_SIZE]; //保存节点的hash值，用于在操作文件的时候找到该文件的head
	uint8_t iv[TEE_FS_HTREE_IV_SIZE]; //加密安全文件数据区域中某一个block时使用的iv值，block数据的每次写入都会使用随机数更新
	uint8_t tag[TEE_FS_HTREE_TAG_SIZE]; //加密安全数据区域中够一个block数据时生成的ta
	uint16_t flags; //用于计算使用block中的那个ver
};

/*
 * This struct is not interpreted by the hash tree, it's up to the user of
 * the interface to update etc if needed.
 */
struct tee_fs_htree_meta {
	uint64_t length;
};

/* Internal struct needed by struct tee_fs_htree_image */
struct tee_fs_htree_imeta {
	struct tee_fs_htree_meta meta;
	uint32_t max_node_id;
};

/* Internal struct provided to let the rpc callbacks know the size if needed */
struct tee_fs_htree_image {
	uint8_t iv[TEE_FS_HTREE_IV_SIZE]; //加密iv+enc_fek时使用的iv值，每次保存head时会使用随机数更新
	uint8_t tag[TEE_FS_HTREE_TAG_SIZE]; //加密iv+Enc_fek生成的数据的tag部分
	uint8_t enc_fek[TEE_FS_HTREE_FEK_SIZE]; //使用TSK加密一个安全文件的fek生成的
	uint8_t imeta[sizeof(struct tee_fs_htree_imeta)]; //加密iv+Enc_fek生成的数据的imeta部分
	uint32_t counter; //用于计算在保存tee_fs_htree_image的时候是存到ver0还是ver1
};

/**
 * enum tee_fs_htree_type - type of hash tree element
 * @TEE_FS_HTREE_TYPE_HEAD: indicates a struct tee_fs_htree_image
 * @TEE_FS_HTREE_TYPE_NODE: indicates a struct tee_fs_htree_node_image
 * @TEE_FS_HTREE_TYPE_BLOCK: indicates a data block
 */
enum tee_fs_htree_type {
	TEE_FS_HTREE_TYPE_HEAD,
	TEE_FS_HTREE_TYPE_NODE,
	TEE_FS_HTREE_TYPE_BLOCK,
};

struct tee_fs_rpc_operation;

/**
 * struct tee_fs_htree_storage - storage description supplied by user of
 * this interface
 * @block_size:		size of data blocks
 * @rpc_read_init:	initialize a struct tee_fs_rpc_operation for an RPC read
 *			operation
 * @rpc_write_init:	initialize a struct tee_fs_rpc_operation for an RPC
 *			write operation
 *
 * The @idx arguments starts counting from 0. The @vers arguments are either
 * 0 or 1. The @data arguments is a pointer to a buffer in non-secure shared
 * memory where the encrypted data is stored.
 */
struct tee_fs_htree_storage {
	size_t block_size;
	TEE_Result (*rpc_read_init)(void *aux, struct tee_fs_rpc_operation *op,
				    enum tee_fs_htree_type type, size_t idx,
				    uint8_t vers, void **data);
	TEE_Result (*rpc_read_final)(struct tee_fs_rpc_operation *op,
				     size_t *bytes);
	TEE_Result (*rpc_write_init)(void *aux, struct tee_fs_rpc_operation *op,
				     enum tee_fs_htree_type type, size_t idx,
				     uint8_t vers, void **data);
	TEE_Result (*rpc_write_final)(struct tee_fs_rpc_operation *op);
};

struct tee_fs_htree;

/**
 * tee_fs_htree_open() - opens/creates a hash tree
 * @create:	true if a new hash tree is to be created, else the hash tree
 *		is read in and verified
 * @hash:	hash of root node, ignored if NULL
 * @uuid:	uuid of requesting TA, may be NULL if not from a TA
 * @stor:	storage description
 * @stor_aux:	auxilary pointer supplied to callbacks in struct
 *		tee_fs_htree_storage
 * @ht:		returned hash tree on success
 */
TEE_Result tee_fs_htree_open(bool create, uint8_t *hash, const TEE_UUID *uuid,
			     const struct tee_fs_htree_storage *stor,
			     void *stor_aux, struct tee_fs_htree **ht);
/**
 * tee_fs_htree_close() - close a hash tree
 * @ht:		hash tree
 */
void tee_fs_htree_close(struct tee_fs_htree **ht);

/**
 * tee_fs_htree_get_meta() - get a pointer to associated struct
 * tee_fs_htree_meta
 * @ht:		hash tree
 */
struct tee_fs_htree_meta *tee_fs_htree_get_meta(struct tee_fs_htree *ht);

/**
 * tee_fs_htree_meta_set_dirty() - tell hash tree that meta were modified
 */
void tee_fs_htree_meta_set_dirty(struct tee_fs_htree *ht);

/**
 * tee_fs_htree_sync_to_storage() - synchronize hash tree to storage
 * @ht:		hash tree
 * @hash:	hash of root node is copied to this if not NULL
 *
 * Frees the hash tree and sets *ht to NULL on failure and returns an error code
 */
TEE_Result tee_fs_htree_sync_to_storage(struct tee_fs_htree **ht,
					uint8_t *hash);

/**
 * tee_fs_htree_truncate() - truncate a hash tree
 * @ht:		hash tree
 * @block_num:	the number of nodes to truncate to
 *
 * Frees the hash tree and sets *ht to NULL on failure and returns an error code
 */
TEE_Result tee_fs_htree_truncate(struct tee_fs_htree **ht, size_t block_num);

/**
 * tee_fs_htree_write_block() - encrypt and write a data block to storage
 * @ht:		hash tree
 * @block_num:	block number
 * @block:	pointer to a block of stor->block_size size
 *
 * Frees the hash tree and sets *ht to NULL on failure and returns an error code
 */
TEE_Result tee_fs_htree_write_block(struct tee_fs_htree **ht, size_t block_num,
				    const void *block);
/**
 * tee_fs_htree_write_block() - read and decrypt a data block from storage
 * @ht:		hash tree
 * @block_num:	block number
 * @block:	pointer to a block of stor->block_size size
 *
 * Frees the hash tree and sets *ht to NULL on failure and returns an error code
 */
TEE_Result tee_fs_htree_read_block(struct tee_fs_htree **ht, size_t block_num,
				   void *block);

#endif /*__TEE_FS_HTREE_H*/
