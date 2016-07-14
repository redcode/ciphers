/* SEED Cipher C API
Copyright © Hye-Shik Chang.
Copyright © Kim Hyun.
Copyright © 2007 Korea Information Security Agency (KISA).
	      __	   __
  _______ ___/ /______ ___/ /__
 / __/ -_) _  / __/ _ \ _  / -_)
/_/  \__/\_,_/\__/\___/_,_/\__/
Copyright © 2011-2016 Manuel Sainz de Baranda y Goñi.
Released under the terms of the GNU Lesser General Public License v3. */

#ifndef __cipher_SEED_H__
#define __cipher_SEED_H__

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

	CIPHER_SEED_API void seed_set_key  (SEED*	object,
					    void const*	key,
					    zsize	key_size);

	CIPHER_SEED_API void seed_encipher (SEED*	object,
					    void const*	block,
					    zsize	block_size,
					    void*	output);

	CIPHER_SEED_API void seed_decipher (SEED*	object,
					    void const*	block,
					    zsize	block_size,
					    void*	output);

#endif

Z_C_SYMBOLS_END

#endif /* __cipher_SEED_H__ */
