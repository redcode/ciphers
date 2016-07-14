/* Anubis Cipher C API
Copyright © Paulo S. L. M. Barreto.
Copyright © Vincent Rijmen.
Copyright © 2004 Aaron Grothe.
	      __	   __
  _______ ___/ /______ ___/ /__
 / __/ -_) _  / __/ _ \ _  / -_)
/_/  \__/\_,_/\__/\___/_,_/\__/
Copyright © 2011-2016 Manuel Sainz de Baranda y Goñi.
Released under the terms of the GNU Lesser General Public License v3. */

#ifndef __cipher_Anubis_H__
#define __cipher_Anubis_H__

#include <Z/ABIs/generic/cipher.h>

#define ANUBIS_KEY_MINIMUM_SIZE 16
#define ANUBIS_KEY_MAXIMUM_SIZE 40
#define ANUBIS_KEY_WORD_SIZE	1
#define ANUBIS_WORD_SIZE	16

typedef struct {
	zint	r;
	zuint32 e[19][4];
	zuint32 d[19][4];
} Anubis;

Z_C_SYMBOLS_BEGIN

#ifndef CIPHER_ANUBIS_ABI
#	ifdef CIPHER_ANUBIS_STATIC
#		define CIPHER_ANUBIS_ABI
#	else
#		define CIPHER_ANUBIS_ABI Z_API
#	endif
#endif

CIPHER_ANUBIS_ABI extern ZCipherABI const abi_cipher_anubis;


#ifndef CIPHER_ANUBIS_OMIT_FUNCTION_PROTOTYPES

#	ifndef CIPHER_ANUBIS_API
#		ifdef CIPHER_ANUBIS_STATIC
#			define CIPHER_ANUBIS_API
#		else
#			define CIPHER_ANUBIS_API Z_API
#		endif
#	endif

	CIPHER_ANUBIS_API void anubis_set_key  (Anubis*	    object,
						void const* key,
						zsize	    key_size);

	CIPHER_ANUBIS_API void anubis_encipher (Anubis*	    object,
						void const* block,
						zsize	    block_size,
						void*	    output);

	CIPHER_ANUBIS_API void anubis_decipher (Anubis*	    object,
						void const* block,
						zsize	    block_size,
						void*	    output);

#endif

Z_C_SYMBOLS_END

#endif /* __cipher_Anubis_H__ */
