/* FCrypt Cipher

Copyright (c) 1995-2000 Kungliga Tekniska Högskolan
(Royal Institute of Technology, Stockholm, Sweden).
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

3. Neither the name of the Institute nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.

Copyright © 2006 Red Hat, Inc.
	      __	   __
  _______ ___/ /______ ___/ /__
 / __/ -_) _  / __/ _ \ _  / -_)
/_/  \__/\_,_/\__/\___/_,_/\__/
Copyright © 2011-2016 Manuel Sainz de Baranda y Goñi.
Re-released under the terms of the GNU Lesser General Public License v3. */

#if defined(CIPHER_F_CRYPT_HIDE_API)
#	define CIPHER_F_CRYPT_API static
#elif defined(CIPHER_F_CRYPT_AS_DYNAMIC)
#	define CIPHER_F_CRYPT_API Z_API_EXPORT
#else
#	define CIPHER_F_CRYPT_API
#endif

#if defined(CIPHER_F_CRYPT_HIDE_ABI)
#	define CIPHER_F_CRYPT_ABI static
#elif defined(CIPHER_F_CRYPT_AS_DYNAMIC)
#	define CIPHER_F_CRYPT_ABI Z_API_EXPORT
#else
#	define CIPHER_F_CRYPT_ABI
#endif

#define CIPHER_F_CRYPT_OMIT_FUNCTION_PROTOTYPES

#ifdef CIPHER_F_CRYPT_USE_LOCAL_HEADER
#	include "FCrypt.h"
#else
#	include <cipher/FCrypt.h>
#endif

#include <Z/functions/base/value.h>

#define C(value) Z_32BIT_BIG_ENDIAN(Z_UINT32(0x##value) << 3)

static zuint32 const s_box_0[256] = {
	C(EA), C(7F), C(B2), C(64), C(9D), C(B0), C(D9), C(11),
	C(CD), C(86), C(86), C(91), C(0A), C(B2), C(93), C(06),
	C(0E), C(06), C(D2), C(65), C(73), C(C5), C(28), C(60),
	C(F2), C(20), C(B5), C(38), C(7E), C(DA), C(9F), C(E3),
	C(D2), C(CF), C(C4), C(3C), C(61), C(FF), C(4A), C(4A),
	C(35), C(AC), C(AA), C(5F), C(2B), C(BB), C(BC), C(53),
	C(4E), C(9D), C(78), C(A3), C(DC), C(09), C(32), C(10),
	C(C6), C(6F), C(66), C(D6), C(AB), C(A9), C(AF), C(FD),
	C(3B), C(95), C(E8), C(34), C(9A), C(81), C(72), C(80),
	C(9C), C(F3), C(EC), C(DA), C(9F), C(26), C(76), C(15),
	C(3E), C(55), C(4D), C(DE), C(84), C(EE), C(AD), C(C7),
	C(F1), C(6B), C(3D), C(D3), C(04), C(49), C(AA), C(24),
	C(0B), C(8A), C(83), C(BA), C(FA), C(85), C(A0), C(A8),
	C(B1), C(D4), C(01), C(D8), C(70), C(64), C(F0), C(51),
	C(D2), C(C3), C(A7), C(75), C(8C), C(A5), C(64), C(EF),
	C(10), C(4E), C(B7), C(C6), C(61), C(03), C(EB), C(44),
	C(3D), C(E5), C(B3), C(5B), C(AE), C(D5), C(AD), C(1D),
	C(FA), C(5A), C(1E), C(33), C(AB), C(93), C(A2), C(B7),
	C(E7), C(A8), C(45), C(A4), C(CD), C(29), C(63), C(44),
	C(B6), C(69), C(7E), C(2E), C(62), C(03), C(C8), C(E0),
	C(17), C(BB), C(C7), C(F3), C(3F), C(36), C(BA), C(71),
	C(8E), C(97), C(65), C(60), C(69), C(B6), C(F6), C(E6),
	C(6E), C(E0), C(81), C(59), C(E8), C(AF), C(DD), C(95),
	C(22), C(99), C(FD), C(63), C(19), C(74), C(61), C(B1),
	C(B6), C(5B), C(AE), C(54), C(B3), C(70), C(FF), C(C6),
	C(3B), C(3E), C(C1), C(D7), C(E1), C(0E), C(76), C(E5),
	C(36), C(4F), C(59), C(C7), C(08), C(6E), C(82), C(A6),
	C(93), C(C4), C(AA), C(26), C(49), C(E0), C(21), C(64),
	C(07), C(9F), C(64), C(81), C(9C), C(BF), C(F9), C(D1),
	C(43), C(F8), C(B6), C(B9), C(F1), C(24), C(75), C(03),
	C(E4), C(B0), C(99), C(46), C(3D), C(F5), C(D1), C(39),
	C(72), C(12), C(F6), C(BA), C(0C), C(0D), C(42), C(2E)
};

#undef C
#define C(value) \
Z_32BIT_BIG_ENDIAN(((Z_UINT32(0x##value) & 0x1F) << 27) | (Z_UINT32(0x##value) >> 5))

static zuint32 const s_box_1[256] = {
	C(77), C(14), C(A6), C(FE), C(B2), C(5E), C(8C), C(3E),
	C(67), C(6C), C(A1), C(0D), C(C2), C(A2), C(C1), C(85),
	C(6C), C(7B), C(67), C(C6), C(23), C(E3), C(F2), C(89),
	C(50), C(9C), C(03), C(B7), C(73), C(E6), C(E1), C(39),
	C(31), C(2C), C(27), C(9F), C(A5), C(69), C(44), C(D6),
	C(23), C(83), C(98), C(7D), C(3C), C(B4), C(2D), C(99),
	C(1C), C(1F), C(8C), C(20), C(03), C(7C), C(5F), C(AD),
	C(F4), C(FA), C(95), C(CA), C(76), C(44), C(CD), C(B6),
	C(B8), C(A1), C(A1), C(BE), C(9E), C(54), C(8F), C(0B),
	C(16), C(74), C(31), C(8A), C(23), C(17), C(04), C(FA),
	C(79), C(84), C(B1), C(F5), C(13), C(AB), C(B5), C(2E),
	C(AA), C(0C), C(60), C(6B), C(5B), C(C4), C(4B), C(BC),
	C(E2), C(AF), C(45), C(73), C(FA), C(C9), C(49), C(CD),
	C(00), C(92), C(7D), C(97), C(7A), C(18), C(60), C(3D),
	C(CF), C(5B), C(DE), C(C6), C(E2), C(E6), C(BB), C(8B),
	C(06), C(DA), C(08), C(15), C(1B), C(88), C(6A), C(17),
	C(89), C(D0), C(A9), C(C1), C(C9), C(70), C(6B), C(E5),
	C(43), C(F4), C(68), C(C8), C(D3), C(84), C(28), C(0A),
	C(52), C(66), C(A3), C(CA), C(F2), C(E3), C(7F), C(7A),
	C(31), C(F7), C(88), C(94), C(5E), C(9C), C(63), C(D5),
	C(24), C(66), C(FC), C(B3), C(57), C(25), C(BE), C(89),
	C(44), C(C4), C(E0), C(8F), C(23), C(3C), C(12), C(52),
	C(F5), C(1E), C(F4), C(CB), C(18), C(33), C(1F), C(F8),
	C(69), C(10), C(9D), C(D3), C(F7), C(28), C(F8), C(30),
	C(05), C(5E), C(32), C(C0), C(D5), C(19), C(BD), C(45),
	C(8B), C(5B), C(FD), C(BC), C(E2), C(5C), C(A9), C(96),
	C(EF), C(70), C(CF), C(C2), C(2A), C(B3), C(61), C(AD),
	C(80), C(48), C(81), C(B7), C(1D), C(43), C(D9), C(D7),
	C(45), C(F0), C(D8), C(8A), C(59), C(7C), C(57), C(C1),
	C(79), C(C7), C(34), C(D6), C(43), C(DF), C(E4), C(78),
	C(16), C(06), C(DA), C(92), C(76), C(51), C(E1), C(D4),
	C(70), C(03), C(E0), C(2F), C(96), C(91), C(82), C(80)
};

#undef C
#define C(value) Z_32BIT_BIG_ENDIAN(Z_UINT32(0x##value) << 11)

static zuint32 const s_box_2[256] = {
	C(F0), C(37), C(24), C(53), C(2A), C(03), C(83), C(86),
	C(D1), C(EC), C(50), C(F0), C(42), C(78), C(2F), C(6D),
	C(BF), C(80), C(87), C(27), C(95), C(E2), C(C5), C(5D),
	C(F9), C(6F), C(DB), C(B4), C(65), C(6E), C(E7), C(24),
	C(C8), C(1A), C(BB), C(49), C(B5), C(0A), C(7D), C(B9),
	C(E8), C(DC), C(B7), C(D9), C(45), C(20), C(1B), C(CE),
	C(59), C(9D), C(6B), C(BD), C(0E), C(8F), C(A3), C(A9),
	C(BC), C(74), C(A6), C(F6), C(7F), C(5F), C(B1), C(68),
	C(84), C(BC), C(A9), C(FD), C(55), C(50), C(E9), C(B6),
	C(13), C(5E), C(07), C(B8), C(95), C(02), C(C0), C(D0),
	C(6A), C(1A), C(85), C(BD), C(B6), C(FD), C(FE), C(17),
	C(3F), C(09), C(A3), C(8D), C(FB), C(ED), C(DA), C(1D),
	C(6D), C(1C), C(6C), C(01), C(5A), C(E5), C(71), C(3E),
	C(8B), C(6B), C(BE), C(29), C(EB), C(12), C(19), C(34),
	C(CD), C(B3), C(BD), C(35), C(EA), C(4B), C(D5), C(AE),
	C(2A), C(79), C(5A), C(A5), C(32), C(12), C(7B), C(DC),
	C(2C), C(D0), C(22), C(4B), C(B1), C(85), C(59), C(80),
	C(C0), C(30), C(9F), C(73), C(D3), C(14), C(48), C(40),
	C(07), C(2D), C(8F), C(80), C(0F), C(CE), C(0B), C(5E),
	C(B7), C(5E), C(AC), C(24), C(94), C(4A), C(18), C(15),
	C(05), C(E8), C(02), C(77), C(A9), C(C7), C(40), C(45),
	C(89), C(D1), C(EA), C(DE), C(0C), C(79), C(2A), C(99),
	C(6C), C(3E), C(95), C(DD), C(8C), C(7D), C(AD), C(6F),
	C(DC), C(FF), C(FD), C(62), C(47), C(B3), C(21), C(8A),
	C(EC), C(8E), C(19), C(18), C(B4), C(6E), C(3D), C(FD),
	C(74), C(54), C(1E), C(04), C(85), C(D8), C(BC), C(1F),
	C(56), C(E7), C(3A), C(56), C(67), C(D6), C(C8), C(A5),
	C(F3), C(8E), C(DE), C(AE), C(37), C(49), C(B7), C(FA),
	C(C8), C(F4), C(1F), C(E0), C(2A), C(9B), C(15), C(D1),
	C(34), C(0E), C(B5), C(E0), C(44), C(78), C(84), C(59),
	C(56), C(68), C(77), C(A5), C(14), C(06), C(F5), C(2F),
	C(8C), C(8A), C(73), C(80), C(76), C(B4), C(10), C(86)
};

#undef C
#define C(value) Z_32BIT_BIG_ENDIAN(Z_UINT32(0x##value) << 19)

static zuint32 const s_box_3[256] = {
	C(A9), C(2A), C(48), C(51), C(84), C(7E), C(49), C(E2),
	C(B5), C(B7), C(42), C(33), C(7D), C(5D), C(A6), C(12),
	C(44), C(48), C(6D), C(28), C(AA), C(20), C(6D), C(57),
	C(D6), C(6B), C(5D), C(72), C(F0), C(92), C(5A), C(1B),
	C(53), C(80), C(24), C(70), C(9A), C(CC), C(A7), C(66),
	C(A1), C(01), C(A5), C(41), C(97), C(41), C(31), C(82),
	C(F1), C(14), C(CF), C(53), C(0D), C(A0), C(10), C(CC),
	C(2A), C(7D), C(D2), C(BF), C(4B), C(1A), C(DB), C(16),
	C(47), C(F6), C(51), C(36), C(ED), C(F3), C(B9), C(1A),
	C(A7), C(DF), C(29), C(43), C(01), C(54), C(70), C(A4),
	C(BF), C(D4), C(0B), C(53), C(44), C(60), C(9E), C(23),
	C(A1), C(18), C(68), C(4F), C(F0), C(2F), C(82), C(C2),
	C(2A), C(41), C(B2), C(42), C(0C), C(ED), C(0C), C(1D),
	C(13), C(3A), C(3C), C(6E), C(35), C(DC), C(60), C(65),
	C(85), C(E9), C(64), C(02), C(9A), C(3F), C(9F), C(87),
	C(96), C(DF), C(BE), C(F2), C(CB), C(E5), C(6C), C(D4),
	C(5A), C(83), C(BF), C(92), C(1B), C(94), C(00), C(42),
	C(CF), C(4B), C(00), C(75), C(BA), C(8F), C(76), C(5F),
	C(5D), C(3A), C(4D), C(09), C(12), C(08), C(38), C(95),
	C(17), C(E4), C(01), C(1D), C(4C), C(A9), C(CC), C(85),
	C(82), C(4C), C(9D), C(2F), C(3B), C(66), C(A1), C(34),
	C(10), C(CD), C(59), C(89), C(A5), C(31), C(CF), C(05),
	C(C8), C(84), C(FA), C(C7), C(BA), C(4E), C(8B), C(1A),
	C(19), C(F1), C(A1), C(3B), C(18), C(12), C(17), C(B0),
	C(98), C(8D), C(0B), C(23), C(C3), C(3A), C(2D), C(20),
	C(DF), C(13), C(A0), C(A8), C(4C), C(0D), C(6C), C(2F),
	C(47), C(13), C(13), C(52), C(1F), C(2D), C(F5), C(79),
	C(3D), C(A2), C(54), C(BD), C(69), C(C8), C(6B), C(F3),
	C(05), C(28), C(F1), C(16), C(46), C(40), C(B0), C(11),
	C(D3), C(B7), C(95), C(49), C(CF), C(C3), C(1D), C(8F),
	C(D8), C(E1), C(73), C(DB), C(AD), C(C8), C(C9), C(A9),
	C(A1), C(C2), C(C5), C(E3), C(BA), C(FC), C(0E), C(25)
};


/* Key schedule generation
.----------------------------------------------------------------------------.
| When generating a key schedule from key, the least significant bit in each |
| key byte is parity and shall be ignored. This leaves 56 significant bits   |
| in the key to scatter over the 16 key schedules. For each schedule extract |
| the low order 32 bits and use as schedule, then rotate right by 11 bits.   |
'---------------------------------------------------------------------------*/

#if Z_UINTTOP_BITS >= 64 && Z_IS_AVAILABLE(UINT64)

	/*---------------------------------------------------.
	| Rotate right 64-bit k variable as a 56-bit number. |
	'---------------------------------------------------*/
	#define ROR_56_64 k = (k >> 11) | ((k & ((1 << 11) - 1)) << (56 - 11));


	CIPHER_F_CRYPT_API
	void f_crypt_set_key(FCrypt *object, const zuint8 *key, zsize key_size)
		{
		/*--------------------------------.
		| k holds all 56 non-parity bits. |
		'--------------------------------*/
		zuint64 k;

		/*-------------------------.
		| Discard the parity bits. |
		'-------------------------*/
		k  = (*key++) >> 1; k <<= 7;
		k |= (*key++) >> 1; k <<= 7;
		k |= (*key++) >> 1; k <<= 7;
		k |= (*key++) >> 1; k <<= 7;
		k |= (*key++) >> 1; k <<= 7;
		k |= (*key++) >> 1; k <<= 7;
		k |= (*key++) >> 1; k <<= 7;
		k |= (*key  ) >> 1;

		/*--------------------------------------------------------------------.
		| Use lower 32 bits for schedule, rotate by 11 each round (16 times). |
		'--------------------------------------------------------------------*/
		object->s[0x0] = z_uint32_big_endian((zuint32)k); ROR_56_64;
		object->s[0x1] = z_uint32_big_endian((zuint32)k); ROR_56_64;
		object->s[0x2] = z_uint32_big_endian((zuint32)k); ROR_56_64;
		object->s[0x3] = z_uint32_big_endian((zuint32)k); ROR_56_64;
		object->s[0x4] = z_uint32_big_endian((zuint32)k); ROR_56_64;
		object->s[0x5] = z_uint32_big_endian((zuint32)k); ROR_56_64;
		object->s[0x6] = z_uint32_big_endian((zuint32)k); ROR_56_64;
		object->s[0x7] = z_uint32_big_endian((zuint32)k); ROR_56_64;
		object->s[0x8] = z_uint32_big_endian((zuint32)k); ROR_56_64;
		object->s[0x9] = z_uint32_big_endian((zuint32)k); ROR_56_64;
		object->s[0xA] = z_uint32_big_endian((zuint32)k); ROR_56_64;
		object->s[0xB] = z_uint32_big_endian((zuint32)k); ROR_56_64;
		object->s[0xC] = z_uint32_big_endian((zuint32)k); ROR_56_64;
		object->s[0xD] = z_uint32_big_endian((zuint32)k); ROR_56_64;
		object->s[0xE] = z_uint32_big_endian((zuint32)k); ROR_56_64;
		object->s[0xF] = z_uint32_big_endian((zuint32)k);
		}

#else

	/*----------------------------------------------------------.
	| Rotate right h and l 32-bit variables as a 56-bit number. |
	'----------------------------------------------------------*/
	#define ROR_56						      \
		t = l & ((1 << 11) - 1);			      \
		l = (l >> 11) | ((h & ((1 << 11) - 1)) << (32 - 11)); \
		h = (h >> 11) | (t << (24 - 11));


	CIPHER_F_CRYPT_API
	void f_crypt_set_key(FCrypt *object, const zuint8 *key, zsize key_size)
		{
		/*---------------------------------------------.
		| h is upper 24 bits and l lower 32, total 56. |
		'---------------------------------------------*/
		zuint32 h, l, t;

		/*-------------------------.
		| Discard the parity bits. |
		'-------------------------*/
		l  = (*key++) >> 1; l <<= 7;
		l |= (*key++) >> 1; l <<= 7;
		l |= (*key++) >> 1; l <<= 7;
		l |= (*key++) >> 1; h = l >> 4; l &= 0xF; l <<= 7;
		l |= (*key++) >> 1; l <<= 7;
		l |= (*key++) >> 1; l <<= 7;
		l |= (*key++) >> 1; l <<= 7;
		l |= (*key  ) >> 1;

		/*--------------------------------------------------------------------.
		| Use lower 32 bits for schedule, rotate by 11 each round (16 times). |
		'--------------------------------------------------------------------*/
		object->s[0x0] = z_uint32_big_endian(l); ROR_56;
		object->s[0x1] = z_uint32_big_endian(l); ROR_56;
		object->s[0x2] = z_uint32_big_endian(l); ROR_56;
		object->s[0x3] = z_uint32_big_endian(l); ROR_56;
		object->s[0x4] = z_uint32_big_endian(l); ROR_56;
		object->s[0x5] = z_uint32_big_endian(l); ROR_56;
		object->s[0x6] = z_uint32_big_endian(l); ROR_56;
		object->s[0x7] = z_uint32_big_endian(l); ROR_56;
		object->s[0x8] = z_uint32_big_endian(l); ROR_56;
		object->s[0x9] = z_uint32_big_endian(l); ROR_56;
		object->s[0xA] = z_uint32_big_endian(l); ROR_56;
		object->s[0xB] = z_uint32_big_endian(l); ROR_56;
		object->s[0xC] = z_uint32_big_endian(l); ROR_56;
		object->s[0xD] = z_uint32_big_endian(l); ROR_56;
		object->s[0xE] = z_uint32_big_endian(l); ROR_56;
		object->s[0xF] = z_uint32_big_endian(l);
		}

#endif


#define L w.array_uint32[0]
#define R w.array_uint32[1]

#define F(a, b, k)							\
	t.value_uint32 = k ^ a;						\
	b ^=	s_box_0[t.array_uint8[0]] ^ s_box_1[t.array_uint8[1]] ^ \
		s_box_2[t.array_uint8[2]] ^ s_box_3[t.array_uint8[3]];  \


CIPHER_F_CRYPT_API
void f_crypt_encipher(FCrypt *object, Z64Bit const *block, zsize block_size, Z64Bit *output)
	{
	Z64Bit w;
	Z32Bit t;

	for (block_size >>= 3; block_size; block_size--)
		{
		w = *block++;

		F(R, L, object->s[0x0]);
		F(L, R, object->s[0x1]);
		F(R, L, object->s[0x2]);
		F(L, R, object->s[0x3]);
		F(R, L, object->s[0x4]);
		F(L, R, object->s[0x5]);
		F(R, L, object->s[0x6]);
		F(L, R, object->s[0x7]);
		F(R, L, object->s[0x8]);
		F(L, R, object->s[0x9]);
		F(R, L, object->s[0xA]);
		F(L, R, object->s[0xB]);
		F(R, L, object->s[0xC]);
		F(L, R, object->s[0xD]);
		F(R, L, object->s[0xE]);
		F(L, R, object->s[0xF]);

		*output++ = w;
		}
	}


CIPHER_F_CRYPT_API
void f_crypt_decipher(FCrypt *object, Z64Bit const *block, zsize block_size, Z64Bit *output)
	{
	Z64Bit w;
	Z32Bit t;

	for (block_size >>= 3; block_size; block_size--)
		{
		w = *block++;

		F(L, R, object->s[0xF]);
		F(R, L, object->s[0xE]);
		F(L, R, object->s[0xD]);
		F(R, L, object->s[0xC]);
		F(L, R, object->s[0xB]);
		F(R, L, object->s[0xA]);
		F(L, R, object->s[0x9]);
		F(R, L, object->s[0x8]);
		F(L, R, object->s[0x7]);
		F(R, L, object->s[0x6]);
		F(L, R, object->s[0x5]);
		F(R, L, object->s[0x4]);
		F(L, R, object->s[0x3]);
		F(R, L, object->s[0x2]);
		F(L, R, object->s[0x1]);
		F(R, L, object->s[0x0]);

		*output++ = w;
		}
	}


#if defined(CIPHER_F_CRYPT_BUILD_ABI) || defined(CIPHER_F_CRYPT_BUILD_MODULE_ABI)

	CIPHER_F_CRYPT_ABI ZCipherABI const abi_cipher_f_crypt = {
		/* test_key		 */ NULL,
		/* set_key		 */ (ZCipherSetKey )f_crypt_set_key,
		/* encipher		 */ (ZCipherProcess)f_crypt_encipher,
		/* decipher		 */ (ZCipherProcess)f_crypt_decipher,
		/* enciphering_size	 */ NULL,
		/* deciphering_size	 */ NULL,
		/* instance_size	 */ sizeof(FCrypt),
		/* key_minimum_size	 */ F_CRYPT_KEY_SIZE,
		/* key_maximum_size	 */ F_CRYPT_KEY_SIZE,
		/* key_word_size	 */ F_CRYPT_KEY_SIZE,
		/* enciphering_word_size */ F_CRYPT_WORD_SIZE,
		/* deciphering_word_size */ F_CRYPT_WORD_SIZE,
		/* features		 */ FALSE
	};

#endif

#ifdef CIPHER_F_CRYPT_BUILD_MODULE_ABI

#	include <Z/ABIs/generic/module.h>

	static zcharacter const information[] =
		"C1995-2000 Kungliga Tekniska Högskolan\n"
		"C2006 Red Hat\n"
		"C2011-2016 Manuel Sainz de Baranda y Goñi\n"
		"LLGPLv3";

	static ZModuleUnit const unit = {
		"FCrypt", Z_VERSION(1, 0, 0), information, &abi_cipher_f_crypt
	};

	static ZModuleDomain const domain = {"cipher", Z_VERSION(1, 0, 0), 3, &unit};
	Z_API_WEAK_EXPORT ZModuleABI const __module_abi__ = {1, &domain};

#endif


/* FCrypt.c EOF */
