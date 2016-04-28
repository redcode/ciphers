/* Serpent Cipher C API
Copyright © 2002 Dag Arne Osvik.
Copyright © 2003 Herbert Valerio Riedel.
Copyright © 2004 Jesús García Hernández.
	      __	   __
  _______ ___/ /______ ___/ /__
 / __/ -_) _  / __/ _ \ _  / -_)
/_/  \__/\_,_/\__/\___/_,_/\__/
Copyright © 2011-2016 Manuel Sainz de Baranda y Goñi.
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
#	ifdef CIPHER_SERPENT_AS_STATIC
#		define CIPHER_SERPENT_ABI
#	else
#		define CIPHER_SERPENT_ABI Z_API
#	endif
#endif

CIPHER_SERPENT_ABI extern ZCipherABI const abi_cipher_serpent;

#ifndef CIPHER_SERPENT_OMIT_FUNCTION_PROTOTYPES

#	ifndef CIPHER_SERPENT_API
#		ifdef CIPHER_SERPENT_AS_STATIC
#			define CIPHER_SERPENT_API
#		else
#			define CIPHER_SERPENT_API Z_API
#		endif
#	endif

	CIPHER_SERPENT_API void serpent_set_key	 (Serpent*    object,
						  void const* key,
						  zsize	      key_size);

	CIPHER_SERPENT_API void serpent_encipher (Serpent*    object,
						  void const* block,
						  zsize	      block_size,
						  void*	      output);

	CIPHER_SERPENT_API void serpent_decipher (Serpent*    object,
						  void const* block,
						  zsize	      block_size,
						  void*	      output);

#endif

Z_C_SYMBOLS_END

#endif /* __cipher_Serpent_H__ */
