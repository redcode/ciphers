/* FCrypt Cipher C API

Copyright (c) 1995-2000 Kungliga Tekniska Högskolan
(Royal Institute of Technology, Stockholm, Sweden).
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

3. Neither the name of the Institute nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.

Copyright © 2006 Red Hat, Inc.
	      __	   __
  _______ ___/ /______ ___/ /__
 / __/ -_) _  / __/ _ \ _  / -_)
/_/  \__/\_,_/\__/\___/_,_/\__/
Copyright © 2011-2016 Manuel Sainz de Baranda y Goñi.
Re-released under the terms of the GNU Lesser General Public License v3. */

#ifndef __cipher_FCrypt_H__
#define __cipher_FCrypt_H__

#include <Z/ABIs/generic/cipher.h>

#define F_CRYPT_KEY_SIZE  8
#define F_CRYPT_WORD_SIZE 8

typedef struct {zuint32 s[16];} FCrypt;

Z_C_SYMBOLS_BEGIN

#ifndef CIPHER_F_CRYPT_ABI
#	ifdef CIPHER_F_CRYPT_STATIC
#		define CIPHER_F_CRYPT_ABI
#	else
#		define CIPHER_F_CRYPT_ABI Z_API
#	endif
#endif

CIPHER_F_CRYPT_ABI extern ZCipherABI const abi_cipher_f_crypt;

#ifndef CIPHER_F_CRYPT_OMIT_FUNCTION_PROTOTYPES

#	ifndef CIPHER_F_CRYPT_API
#		ifdef CIPHER_F_CRYPT_STATIC
#			define CIPHER_F_CRYPT_API
#		else
#			define CIPHER_F_CRYPT_API Z_API
#		endif
#	endif

	CIPHER_F_CRYPT_API extern ZCipherABI const abi_cipher_f_crypt;

	CIPHER_F_CRYPT_API void f_crypt_set_key	 (FCrypt*     object,
						  void const* key,
						  zsize	      key_size);

	CIPHER_F_CRYPT_API void f_crypt_encipher (FCrypt*     object,
						  void const* block,
						  zsize	      block_size,
						  void*	      output);

	CIPHER_F_CRYPT_API void f_crypt_decipher (FCrypt*     object,
						  void const* block,
						  zsize	      block_size,
						  void*	      output);

#endif

Z_C_SYMBOLS_END

#endif /* __cipher_FCrypt_H__ */
