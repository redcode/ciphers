/* Blowfish Cipher C API
Copyright © 1997 Paul Kocher.
	      __	   __
  _______ ___/ /______ ___/ /__
 / __/ -_) _  / __/ _ \ _  / -_)
/_/  \__/\_,_/\__/\___/_,_/\__/
Copyright © 2009-2016 Manuel Sainz de Baranda y Goñi.
Released under the terms of the GNU Lesser General Public License v3. */

#ifndef __cipher_Blowfish_H__
#define __cipher_Blowfish_H__

#include <Z/ABIs/generic/cipher.h>

#define BLOWFISH_KEY_MINIMUM_SIZE 8
#define BLOWFISH_KEY_MAXIMUM_SIZE 56
#define BLOWFISH_KEY_WORD_SIZE	  1
#define BLOWFISH_WORD_SIZE	  8

typedef struct {
	zuint32 p[18];
	zuint32 s[4][256];
} Blowfish;

Z_C_SYMBOLS_BEGIN

#ifndef CIPHER_BLOWFISH_ABI
#	ifdef CIPHER_BLOWFISH_AS_STATIC
#		define CIPHER_BLOWFISH_ABI
#	else
#		define CIPHER_BLOWFISH_ABI Z_API
#	endif
#endif

CIPHER_BLOWFISH_ABI extern ZCipherABI const abi_cipher_blowfish;

#ifndef CIPHER_BLOWFISH_OMIT_FUNCTION_PROTOTYPES

#	ifndef CIPHER_BLOWFISH_API
#		ifdef CIPHER_BLOWFISH_AS_STATIC
#			define CIPHER_BLOWFISH_API
#		else
#			define CIPHER_BLOWFISH_API Z_API
#		endif
#	endif

	CIPHER_BLOWFISH_API extern ZCipherABI const abi_cipher_blowfish;

	CIPHER_BLOWFISH_API void blowfish_set_key  (Blowfish*	object,
						    void const* key,
						    zsize	key_size);

	CIPHER_BLOWFISH_API void blowfish_encipher (Blowfish*	object,
						    void const* block,
						    zsize	block_size,
						    void*	output);

	CIPHER_BLOWFISH_API void blowfish_decipher (Blowfish*	object,
						    void const* block,
						    zsize	block_size,
						    void*	output);

#endif

Z_C_SYMBOLS_END

#endif /* __cipher_Blowfish_H__ */
