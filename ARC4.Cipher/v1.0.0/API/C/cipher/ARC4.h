/* ARC4 Cipher C API
Copyright © 2011 Jon Oberheide.
	      __	   __
  _______ ___/ /______ ___/ /__
 / __/ -_) _  / __/ _ \ _  / -_)
/_/  \__/\_,_/\__/\___/_,_/\__/
Copyright © 2011-2016 Manuel Sainz de Baranda y Goñi.
Released under the terms of the GNU Lesser General Public License v3. */

#ifndef __cipher_ARC4_H__
#define __cipher_ARC4_H__

#include <Z/ABIs/generic/cipher.h>

#define ARC4_KEY_MINIMUM_SIZE 1
#define ARC4_KEY_MAXIMUM_SIZE 256
#define ARC4_KEY_WORD_SIZE    1
#define ARC4_WORD_SIZE	      1

typedef struct {
	zuint8 s[256];
	zuint8 x, y;
} ARC4;

Z_C_SYMBOLS_BEGIN

#ifndef CIPHER_ARC4_ABI
#	ifdef CIPHER_ARC4_STATIC
#		define CIPHER_ARC4_ABI
#	else
#		define CIPHER_ARC4_ABI Z_API
#	endif
#endif

CIPHER_ARC4_ABI extern ZCipherABI const abi_cipher_arc4;

#ifndef CIPHER_ARC4_OMIT_FUNCTION_PROTOTYPES

#	ifndef CIPHER_ARC4_API
#		ifdef CIPHER_ARC4_STATIC
#			define CIPHER_ARC4_API
#		else
#			define CIPHER_ARC4_API Z_API
#		endif
#	endif

	CIPHER_ARC4_API void arc4_set_key (ARC4*       object,
					   void const* key,
					   zsize       key_size);

	CIPHER_ARC4_API void arc4_cipher  (ARC4*       object,
					   void const* block,
					   zsize       block_size,
					   void*       output);

#endif

Z_C_SYMBOLS_END

#endif /* __cipher_ARC4_H__ */
