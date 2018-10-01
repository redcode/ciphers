/* AES Cipher C API

Copyright (C) 2002, Dr Brian Gladman <brg@gladman.me.uk>, Worcester, UK.
All rights reserved.

LICENSE TERMS

The free distribution and use of this software in both source and binary
form is allowed (with or without changes) provided that:

  1. distributions of this source code include the above copyright
     notice, this list of conditions and the following disclaimer;

  2. distributions in binary form include the above copyright
     notice, this list of conditions and the following disclaimer
     in the documentation and/or other associated materials;

  3. the copyright holder's name is not used to endorse products
     built using this software without specific written permission.

ALTERNATIVELY, provided that this notice is retained in full, this product
may be distributed under the terms of the GNU General Public License (GPL),
in which case the provisions of the GPL apply INSTEAD OF those given above.

DISCLAIMER

This software is provided 'as is' with no explicit or implied warranties
in respect of its properties, including, but not limited to, correctness
and/or fitness for purpose.

Copyright (C) Alexander Kjeldaas.
Copyright (C) Herbert Valerio Riedel.
Copyright (C) Kyle McMartin.
Copyright (C) Adam J. Richter.
Copyright (C) 2011-2018 Manuel Sainz de Baranda y Goñi.
Released under the terms of the GNU Lesser General Public License v3. */

#ifndef __cipher_AES_H__
#define __cipher_AES_H__

#include <Z/ABIs/generic/cipher.h>

#define AES_128_KEY_SIZE 16
#define AES_192_KEY_SIZE 24
#define AES_256_KEY_SIZE 32
#define AES_WORD_SIZE	 16

typedef struct {
	zuint32 e[44];
	zuint32 d[44];
} AES128;

typedef struct {
	zuint32 e[52];
	zuint32 d[52];
} AES192;

typedef struct {
	zuint32 e[60];
	zuint32 d[60];
} AES256;

Z_C_SYMBOLS_BEGIN

#ifndef CIPHER_AES_ABI
#	ifdef CIPHER_AES_STATIC
#		define CIPHER_AES_ABI
#	else
#		define CIPHER_AES_ABI Z_API
#	endif
#endif

CIPHER_AES_ABI extern ZCipherABI const abi_cipher_aes_128;
CIPHER_AES_ABI extern ZCipherABI const abi_cipher_aes_192;
CIPHER_AES_ABI extern ZCipherABI const abi_cipher_aes_256;

#ifndef CIPHER_AES_API_OMIT_FUNCTION_PROTOTYPES

#	ifndef CIPHER_AES_API
#		ifdef CIPHER_AES_STATIC
#			define CIPHER_AES_API
#		else
#			define CIPHER_AES_API Z_API
#		endif
#	endif

	CIPHER_AES_API void aes_128_set_key (AES128*	 object,
					     void const* key,
					     zusize	 key_size);

	CIPHER_AES_API void aes_128_encipher(AES128*	 object,
					     void const* block,
					     zusize	 block_size,
					     void*	 output);

	CIPHER_AES_API void aes_128_decipher(AES128*	 object,
					     void const* block,
					     zusize	 block_size,
					     void*	 output);

	CIPHER_AES_API void aes_192_set_key (AES192*	 object,
					     void const* key,
					     zusize	 key_size);

	CIPHER_AES_API void aes_192_encipher(AES192*	 object,
					     void const* block,
					     zusize	 block_size,
					     void*	 output);

	CIPHER_AES_API void aes_192_decipher(AES192*	 object,
					     void const* block,
					     zusize	 block_size,
					     void*	 output);

	CIPHER_AES_API void aes_256_set_key (AES256*	 object,
					     void const* key,
					     zusize	 key_size);

	CIPHER_AES_API void aes_256_encipher(AES256*	 object,
					     void const* block,
					     zusize	 block_size,
					     void*	 output);

	CIPHER_AES_API void aes_256_decipher(AES256*	 object,
					     void const* block,
					     zusize	 block_size,
					     void*	 output);

#endif

Z_C_SYMBOLS_END

#endif /* __cipher_AES_H__ */
