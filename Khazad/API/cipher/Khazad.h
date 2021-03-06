/* Khazad Cipher C API
Copyright (C) Paulo S. L. M. Barreto.
Copyright (C) Vincent Rijmen.
Copyright (C) 2004 Aaron Grothe.
Copyright (C) 2011-2018 Manuel Sainz de Baranda y Goñi.
Released under the terms of the GNU Lesser General Public License v3. */

#ifndef _cipher_Khazad_H_
#define _cipher_Khazad_H_

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

	CIPHER_KHAZAD_API void khazad_set_key (Khazad*	   object,
					       void const* key,
					       zusize	   key_size);

	CIPHER_KHAZAD_API void khazad_encipher(Khazad*	   object,
					       void const* block,
					       zusize	   block_size,
					       void*	   output);

	CIPHER_KHAZAD_API void khazad_decipher(Khazad*	   object,
					       void const* block,
					       zusize	   block_size,
					       void*	   output);

#endif

Z_C_SYMBOLS_END

#endif /* _cipher_Khazad_H_ */
