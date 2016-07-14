/* Khazad Cipher C API
Copyright © Paulo S. L. M. Barreto.
Copyright © Vincent Rijmen.
Copyright © 2004 Aaron Grothe.
	      __	   __
  _______ ___/ /______ ___/ /__
 / __/ -_) _  / __/ _ \ _  / -_)
/_/  \__/\_,_/\__/\___/_,_/\__/
Copyright © 2011-2016 Manuel Sainz de Baranda y Goñi.
Released under the terms of the GNU Lesser General Public License v3. */

#ifndef __cipher_Khazad_H__
#define __cipher_Khazad_H__

#include <Z/ABIs/generic/cipher.h>

#define KHAZAD_KEY_SIZE  16
#define KHAZAD_WORD_SIZE 8

typedef struct {
	zuint64 e[8 + 1];
	zuint64 d[8 + 1];
} Khazad;

Z_C_SYMBOLS_BEGIN

#ifndef CIPHER_KHAZAD_ABI
#	ifdef CIPHER_KHAZAD_STATIC
#		define CIPHER_KHAZAD_ABI
#	else
#		define CIPHER_KHAZAD_ABI Z_API
#	endif
#endif

CIPHER_KHAZAD_ABI extern ZCipherABI const abi_cipher_khazad;

#ifndef CIPHER_KHAZAD_OMIT_FUNCTION_PROTOTYPES

#	ifndef CIPHER_KHAZAD_API
#		ifdef CIPHER_KHAZAD_STATIC
#			define CIPHER_KHAZAD_API
#		else
#			define CIPHER_KHAZAD_API Z_API
#		endif
#	endif

	CIPHER_KHAZAD_API void khazad_set_key  (Khazad*	    object,
						void const* key,
						zsize	    key_size);

	CIPHER_KHAZAD_API void khazad_encipher (Khazad*	    object,
						void const* block,
						zsize	    block_size,
						void*	    output);

	CIPHER_KHAZAD_API void khazad_decipher (Khazad*	    object,
						void const* block,
						zsize	    block_size,
						void*	    output);

#endif

Z_C_SYMBOLS_END

#endif /* __cipher_Khazad_H__ */
