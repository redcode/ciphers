/* TEA Cipher C API
Copyright © David John Wheeler.
Copyright © Roger Michael Needham.
Copyright © 2004 Aaron Grothe.
	      __	   __
  _______ ___/ /______ ___/ /__
 / __/ -_) _  / __/ _ \ _  / -_)
/_/  \__/\_,_/\__/\___/_,_/\__/
Copyright © 2011-2016 Manuel Sainz de Baranda y Goñi.
Released under the terms of the GNU Lesser General Public License v3. */

#ifndef __cipher_TEA_H__
#define __cipher_TEA_H__

#include <Z/ABIs/generic/cipher.h>

#define TEA_KEY_SIZE  16
#define TEA_WORD_SIZE 8

typedef struct {zuint32 key[4];} TEA;

Z_C_SYMBOLS_BEGIN

#ifndef CIPHER_TEA_ABI
#	ifdef CIPHER_TEA_STATIC
#		define CIPHER_TEA_ABI
#	else
#		define CIPHER_TEA_ABI Z_API
#	endif
#endif

CIPHER_TEA_ABI extern ZCipherABI const abi_cipher_tea;
CIPHER_TEA_ABI extern ZCipherABI const abi_cipher_xtea;
CIPHER_TEA_ABI extern ZCipherABI const abi_cipher_xeta;

#ifndef CIPHER_TEA_OMIT_FUNCTION_PROTOTYPES

#	ifndef CIPHER_TEA_API
#		ifdef CIPHER_TEA_STATIC
#			define CIPHER_TEA_API
#		else
#			define CIPHER_TEA_API Z_API
#		endif
#	endif

	CIPHER_TEA_API void tea_set_key	  (TEA*	       object,
					   void const* key,
					   zsize       key_size);

	CIPHER_TEA_API void tea_encipher  (TEA*	       object,
					   void const* block,
					   zsize       block_size,
					   void*       output);

	CIPHER_TEA_API void tea_decipher  (TEA*	       object,
					   void const* block,
					   zsize       block_size,
					   void*       output);

	CIPHER_TEA_API void xtea_encipher (TEA*	       object,
					   void const* block,
					   zsize       block_size,
					   void*       output);

	CIPHER_TEA_API void xtea_decipher (TEA*	       object,
					   void const* block,
					   zsize       block_size,
					   void*       output);

	CIPHER_TEA_API void xeta_encipher (TEA*	       object,
					   void const* block,
					   zsize       block_size,
					   void*       output);

	CIPHER_TEA_API void xeta_decipher (TEA*	       object,
					   void const* block,
					   zsize       block_size,
					   void*       output);

#endif

Z_C_SYMBOLS_END

#endif /* __cipher_TEA_H__ */
