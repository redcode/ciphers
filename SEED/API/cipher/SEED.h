/* SEED Cipher C API
Copyright (C) Hye-Shik Chang.
Copyright (C) Kim Hyun.
Copyright (C) 2007 Korea Information Security Agency (KISA).
Copyright (C) 2011-2018 Manuel Sainz de Baranda y Goñi.
Released under the terms of the GNU Lesser General Public License v3. */

#ifndef _cipher_SEED_H_
#define _cipher_SEED_H_

#include <Z/ABIs/generic/cipher.h>

#define SEED_KEY_SIZE  16
#define SEED_WORD_SIZE 16

typedef struct {zuint32 ks[32];} SEED;

Z_C_SYMBOLS_BEGIN

#ifndef CIPHER_SEED_ABI
#	ifdef CIPHER_SEED_STATIC
#		define CIPHER_SEED_ABI
#	else
#		define CIPHER_SEED_ABI Z_API
#	endif
#endif

CIPHER_SEED_ABI extern ZCipherABI const abi_cipher_seed;

#ifndef CIPHER_SEED_OMIT_FUNCTION_PROTOTYPES

#	ifndef CIPHER_SEED_API
#		ifdef CIPHER_SEED_STATIC
#			define CIPHER_SEED_API
#		else
#			define CIPHER_SEED_API Z_API
#		endif
#	endif

	CIPHER_SEED_API void seed_set_key (SEED*       object,
					   void const* key,
					   zusize      key_size);

	CIPHER_SEED_API void seed_encipher(SEED*       object,
					   void const* block,
					   zusize      block_size,
					   void*       output);

	CIPHER_SEED_API void seed_decipher(SEED*       object,
					   void const* block,
					   zusize      block_size,
					   void*       output);

#endif

Z_C_SYMBOLS_END

#endif /* _cipher_SEED_H_ */
