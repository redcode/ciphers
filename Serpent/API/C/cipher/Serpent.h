/* Serpent Cipher C API
Copyright (C) 2002 Dag Arne Osvik.
Copyright (C) 2003 Herbert Valerio Riedel.
Copyright (C) 2004 Jesús García Hernández.
Copyright (C) 2011-2016 Manuel Sainz de Baranda y Goñi.
Released under the terms of the GNU Lesser General Public License v3. */

#ifndef __cipher_Serpent_H__
#define __cipher_Serpent_H__

#include <Z/ABIs/generic/cipher.h>

#define SERPENT_KEY_MINIMUM_SIZE 0
#define SERPENT_KEY_MAXIMUM_SIZE 32
#define SERPENT_KEY_WORD_SIZE	 1
#define SERPENT_WORD_SIZE	 16

typedef struct {zuint32 k[132];} Serpent;

Z_C_SYMBOLS_BEGIN

#ifndef CIPHER_SERPENT_ABI
#	ifdef CIPHER_SERPENT_STATIC
#		define CIPHER_SERPENT_ABI
#	else
#		define CIPHER_SERPENT_ABI Z_API
#	endif
#endif

CIPHER_SERPENT_ABI extern ZCipherABI const abi_cipher_serpent;

#ifndef CIPHER_SERPENT_OMIT_FUNCTION_PROTOTYPES

#	ifndef CIPHER_SERPENT_API
#		ifdef CIPHER_SERPENT_STATIC
#			define CIPHER_SERPENT_API
#		else
#			define CIPHER_SERPENT_API Z_API
#		endif
#	endif

	CIPHER_SERPENT_API void serpent_set_key	(Serpent*    object,
						 void const* key,
						 zusize	     key_size);

	CIPHER_SERPENT_API void serpent_encipher(Serpent*    object,
						 void const* block,
						 zusize	     block_size,
						 void*	     output);

	CIPHER_SERPENT_API void serpent_decipher(Serpent*    object,
						 void const* block,
						 zusize	     block_size,
						 void*	     output);

#endif

Z_C_SYMBOLS_END

#endif /* __cipher_Serpent_H__ */
