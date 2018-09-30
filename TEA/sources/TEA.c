/* TEA Cipher
Copyright (C) David John Wheeler.
Copyright (C) Roger Michael Needham.
Copyright (C) 2004 Aaron Grothe.
Copyright (C) 2011-2016 Manuel Sainz de Baranda y Goñi.
Released under the terms of the GNU Lesser General Public License v3. */

#if defined(CIPHER_TEA_HIDE_API)
#	define CIPHER_TEA_API static
#elif defined(CIPHER_TEA_STATIC)
#	define CIPHER_TEA_API
#else
#	define CIPHER_TEA_API Z_API_EXPORT
#endif

#if defined(CIPHER_TEA_HIDE_ABI)
#	define CIPHER_TEA_ABI static
#elif defined(CIPHER_TEA_STATIC)
#	define CIPHER_TEA_ABI
#else
#	define CIPHER_TEA_ABI Z_API_EXPORT
#endif

#define CIPHER_TEA_OMIT_FUNCTION_PROTOTYPES

#if defined(CIPHER_TEA_USE_LOCAL_HEADER)
#	include "TEA.h"
#else
#	include <cipher/TEA.h>
#endif

#include <Z/functions/base/value.h>

#define TEA_ROUNDS 32
#define TEA_DELTA  Z_UINT32(0x9E3779B9)


CIPHER_TEA_API
void tea_set_key(TEA *object, const zuint32 *key, zusize key_size)
	{
	object->key[0] = z_uint32_little_endian(key[0]);
	object->key[1] = z_uint32_little_endian(key[1]);
	object->key[2] = z_uint32_little_endian(key[2]);
	object->key[3] = z_uint32_little_endian(key[3]);
	}


CIPHER_TEA_API
void tea_encipher(TEA *object, zuint32 const *block, zusize block_size, zuint32 *output)
	{
	zuint32 y, z, n, sum;
	zuint32	k0 = object->key[0], k1 = object->key[1],
		k2 = object->key[2], k3 = object->key[3];

	for (block_size >>= 3; block_size; block_size--, block += 2, output += 2)
		{
		y = z_uint32_little_endian(block[0]);
		z = z_uint32_little_endian(block[1]);
		sum = 0;

		for (n = TEA_ROUNDS; n; n--)
			{
			sum += TEA_DELTA;
			y += ((z << 4) + k0) ^ (z + sum) ^ ((z >> 5) + k1);
			z += ((y << 4) + k2) ^ (y + sum) ^ ((y >> 5) + k3);
			}

		output[0] = z_uint32_little_endian(y);
		output[1] = z_uint32_little_endian(z);
		}
	}


CIPHER_TEA_API
void tea_decipher(TEA *object, zuint32 const *block, zusize block_size, zuint32 *output)
	{
	zuint32 y, z, n, sum;
	zuint32	k0 = object->key[0], k1 = object->key[1],
		k2 = object->key[2], k3 = object->key[3];

	for (block_size >>= 3; block_size; block_size--, block += 2, output += 2)
		{
		y = z_uint32_little_endian(block[0]);
		z = z_uint32_little_endian(block[1]);
		sum = TEA_DELTA << 5;

		for (n = TEA_ROUNDS; n; n--)
			{
			z -= ((y << 4) + k2) ^ (y + sum) ^ ((y >> 5) + k3);
			y -= ((z << 4) + k0) ^ (z + sum) ^ ((z >> 5) + k1);
			sum -= TEA_DELTA;
			}
	
		output[0] = z_uint32_little_endian(y);
		output[1] = z_uint32_little_endian(z);
		}
	}


CIPHER_TEA_API
void xtea_encipher(TEA *object, zuint32 const *block, zusize block_size, zuint32 *output)
	{
	zuint32 y, z, sum;

	for (block_size >>= 3; block_size; block_size--, block += 2, output += 2)
		{
		y = z_uint32_little_endian(block[0]);
		z = z_uint32_little_endian(block[1]);

		for (sum = 0; sum != TEA_DELTA * TEA_ROUNDS;)
			{
			y += ((z << 4 ^ z >> 5) + z) ^ (sum + object->key[sum & 3]); 
			sum += TEA_DELTA;
			z += ((y << 4 ^ y >> 5) + y) ^ (sum + object->key[sum >> 11 & 3]); 
			}
	
		output[0] = z_uint32_little_endian(y);
		output[1] = z_uint32_little_endian(z);
		}
	}


CIPHER_TEA_API
void xtea_decipher(TEA *object, zuint32 const *block, zusize block_size, zuint32 *output)
	{
	zuint32 y, z, sum;

	for (block_size >>= 3; block_size; block_size--, block += 2, output += 2)
		{
		y = z_uint32_little_endian(block[0]);
		z = z_uint32_little_endian(block[1]);

		for (sum = TEA_DELTA * TEA_ROUNDS; sum;)
			{
			z -= ((y << 4 ^ y >> 5) + y) ^ (sum + object->key[sum >> 11 & 3]);
			sum -= TEA_DELTA;
			y -= ((z << 4 ^ z >> 5) + z) ^ (sum + object->key[sum & 3]);
			}
	
		output[0] = z_uint32_little_endian(y);
		output[1] = z_uint32_little_endian(z);
		}
	}


CIPHER_TEA_API
void xeta_encipher(TEA *object, zuint32 const *block, zusize block_size, zuint32 *output)
	{
	zuint32 y, z, sum;

	for (block_size >>= 3; block_size; block_size--, block += 2, output += 2)
		{
		y = z_uint32_little_endian(block[0]);
		z = z_uint32_little_endian(block[1]);

		for (sum = 0; sum != TEA_DELTA * TEA_ROUNDS;)
			{
			y += (z << 4 ^ z >> 5) + (z ^ sum) + object->key[sum & 3];
			sum += TEA_DELTA;
			z += (y << 4 ^ y >> 5) + (y ^ sum) + object->key[sum >> 11 & 3];
			}
	
		output[0] = z_uint32_little_endian(y);
		output[1] = z_uint32_little_endian(z);
		}
	}


CIPHER_TEA_API
void xeta_decipher(TEA *object, zuint32 const *block, zusize block_size, zuint32 *output)
	{
	zuint32 y, z, sum;

	for (block_size >>= 3; block_size; block_size--, block += 2, output += 2)
		{
		y = z_uint32_little_endian(block[0]);
		z = z_uint32_little_endian(block[1]);

		for (sum = TEA_DELTA * TEA_ROUNDS; sum;)
			{
			z -= (y << 4 ^ y >> 5) + (y ^ sum) + object->key[sum >> 11 & 3];
			sum -= TEA_DELTA;
			y -= (z << 4 ^ z >> 5) + (z ^ sum) + object->key[sum & 3];
			}

		output[0] = z_uint32_little_endian(y);
		output[1] = z_uint32_little_endian(z);
		}
	}


#if defined(CIPHER_TEA_BUILD_ABI) || defined(CIPHER_TEA_BUILD_MODULE_ABI)

	CIPHER_TEA_ABI ZCipherABI const abi_cipher_tea = {
		/* test_key		 */ NULL,
		/* set_key		 */ (ZCipherSetKey )tea_set_key,
		/* encipher		 */ (ZCipherProcess)tea_encipher,
		/* decipher		 */ (ZCipherProcess)tea_decipher,
		/* enciphering_size	 */ NULL,
		/* deciphering_size	 */ NULL,
		/* instance_size	 */ sizeof(TEA),
		/* key_minimum_size	 */ TEA_KEY_SIZE,
		/* key_maximum_size	 */ TEA_KEY_SIZE,
		/* key_word_size	 */ TEA_KEY_SIZE,
		/* enciphering_word_size */ TEA_WORD_SIZE,
		/* deciphering_word_size */ TEA_WORD_SIZE,
		/* features		 */ FALSE
	};

	CIPHER_TEA_ABI ZCipherABI const abi_cipher_xtea = {
		/* test_key		 */ NULL,
		/* set_key		 */ (ZCipherSetKey )tea_set_key,
		/* encipher		 */ (ZCipherProcess)xtea_encipher,
		/* decipher		 */ (ZCipherProcess)xtea_decipher,
		/* enciphering_size	 */ NULL,
		/* deciphering_size	 */ NULL,
		/* instance_size	 */ sizeof(TEA),
		/* key_minimum_size	 */ TEA_KEY_SIZE,
		/* key_maximum_size	 */ TEA_KEY_SIZE,
		/* key_word_size	 */ TEA_KEY_SIZE,
		/* enciphering_word_size */ TEA_WORD_SIZE,
		/* deciphering_word_size */ TEA_WORD_SIZE,
		/* features		 */ FALSE
	};

	CIPHER_TEA_ABI ZCipherABI const abi_cipher_xeta = {
		/* test_key		 */ NULL,
		/* set_key		 */ (ZCipherSetKey )tea_set_key,
		/* encipher		 */ (ZCipherProcess)xeta_encipher,
		/* decipher		 */ (ZCipherProcess)xeta_decipher,
		/* enciphering_size	 */ NULL,
		/* deciphering_size	 */ NULL,
		/* instance_size	 */ sizeof(TEA),
		/* key_minimum_size	 */ TEA_KEY_SIZE,
		/* key_maximum_size	 */ TEA_KEY_SIZE,
		/* key_word_size	 */ TEA_KEY_SIZE,
		/* enciphering_word_size */ TEA_WORD_SIZE,
		/* deciphering_word_size */ TEA_WORD_SIZE,
		/* features		 */ FALSE
	};

#endif

#if defined(CIPHER_TEA_BUILD_MODULE_ABI)

#	include <Z/ABIs/generic/module.h>

	static ZModuleUnit const units[] = {
		{"TEA",  "TEA",  Z_VERSION(1, 0, 0), &abi_cipher_tea },
		{"XTEA", "XTEA", Z_VERSION(1, 0, 0), &abi_cipher_xtea},
		{"XETA", "XETA", Z_VERSION(1, 0, 0), &abi_cipher_xeta}
	};

	static ZModuleDomain const domain = {"Cipher", Z_VERSION(1, 0, 0), 3, units};
	Z_API_WEAK_EXPORT ZModuleABI const __module_abi__ = {1, &domain};

#endif


/* TEA.c EOF */
