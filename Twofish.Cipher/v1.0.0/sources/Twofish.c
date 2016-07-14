/* Twofish Cipher
Copyright © 1998 Matthew Skala.
Copyright © 1998 Werner Koch.
Copyright © Marc Mutz.
Copyright © Colin Slater.
	      __	   __
  _______ ___/ /______ ___/ /__
 / __/ -_) _  / __/ _ \ _  / -_)
/_/  \__/\_,_/\__/\___/_,_/\__/
Copyright © 2011-2016 Manuel Sainz de Baranda y Goñi.
Released under the terms of the GNU Lesser General Public License v3.

.-------------------------------------------------------------------------.
| This code is a "clean room" implementation, written from the paper	  |
| "Twofish: A 128-Bit Block Cipher" by Bruce Schneier, John Kelsey,	  |
| Doug Whiting, David Wagner, Chris Hall, and Niels Ferguson, available	  |
| through: http://www.counterpane.com/twofish.html			  |
|									  |
| For background information on multiplication in finite fields, used for |
| the matrix operations in the key schedule, see the book "Contemporary	  |
| Abstract Algebra" by Joseph A. Gallian, especially chapter 22 in the	  |
| Third Edition.							  |
'------------------------------------------------------------------------*/

#define DEFINED(WHAT) (defined CIPHER_TWOFISH_##WHAT)

#if DEFINED(HIDE_API)
#	define CIPHER_TWOFISH_API static
#elif DEFINED(DYNAMIC)
#	define CIPHER_TWOFISH_API Z_API_EXPORT
#else
#	define CIPHER_TWOFISH_API
#endif

#if DEFINED(HIDE_ABI)
#	define CIPHER_TWOFISH_ABI static
#elif DEFINED(DYNAMIC)
#	define CIPHER_TWOFISH_ABI Z_API_EXPORT
#else
#	define CIPHER_TWOFISH_ABI
#endif

#define CIPHER_TWOFISH_OMIT_FUNCTION_PROTOTYPES

#if DEFINED(USE_LOCAL_HEADER)
#	include "Twofish.h"
#else
#	include <cipher/Twofish.h>
#endif

#include <Z/functions/base/value.h>

#define C(value) Z_UINT32(0x##value)

/*-------------------------------------------------------------------.
| q0 and q1 permutations, exactly as described in the Twofish paper. |
'-------------------------------------------------------------------*/

static zuint8 const q0[256] = {
	0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76,
	0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
	0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C,
	0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
	0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23,
	0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
	0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C,
	0xA6, 0xEB, 0xA5, 0xBE,	0x16, 0x0C, 0xE3, 0x61,
	0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B,
	0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
	0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66,
	0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
	0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA,
	0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
	0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8,
	0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
	0xA1, 0x1D, 0xAA, 0xED,	0x06, 0x70, 0xB2, 0xD2,
	0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
	0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB,
	0x9E, 0x9C, 0x52, 0x1B,	0x5F, 0x93, 0x0A, 0xEF,
	0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B,
	0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
	0x2A, 0xCE, 0xCB, 0x2F,	0xFC, 0x97, 0x05, 0x7A,
	0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
	0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02,
	0xB8, 0xDA, 0xB0, 0x17,	0x55, 0x1F, 0x8A, 0x7D,
	0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72,
	0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
	0x6E, 0x50, 0xDE, 0x68,	0x65, 0xBC, 0xDB, 0xF8,
	0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
	0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00,
	0x6F, 0x9D, 0x36, 0x42,	0x4A, 0x5E, 0xC1, 0xE0
};

static zuint8 const q1[256] = {
	0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8,
	0x4A, 0xD3, 0xE6, 0x6B,	0x45, 0x7D, 0xE8, 0x4B,
	0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1,
	0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
	0x5E, 0xBA, 0xAE, 0x5B,	0x8A, 0x00, 0xBC, 0x9D,
	0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
	0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3,
	0xB2, 0x73, 0x4C, 0x54,	0x92, 0x74, 0x36, 0x51,
	0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96,
	0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
	0x13, 0x95, 0x9C, 0xC7,	0x24, 0x46, 0x3B, 0x70,
	0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
	0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC,
	0x03, 0x6F, 0x08, 0xBF,	0x40, 0xE7, 0x2B, 0xE2,
	0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9,
	0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
	0x66, 0x94, 0xA1, 0x1D,	0x3D, 0xF0, 0xDE, 0xB3,
	0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
	0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49,
	0x81, 0x88, 0xEE, 0x21,	0xC4, 0x1A, 0xEB, 0xD9,
	0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01,
	0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
	0x4F, 0xF2, 0x65, 0x8E,	0x78, 0x5C, 0x58, 0x19,
	0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
	0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5,
	0xCE, 0xE9, 0x68, 0x44,	0xE0, 0x4D, 0x43, 0x69,
	0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E,
	0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
	0x22, 0xC9, 0xC0, 0x9B,	0x89, 0xD4, 0xED, 0xAB,
	0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
	0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2,
	0x16, 0x25, 0x86, 0x56,	0x55, 0x09, 0xBE, 0x91
};

/*-----------------------------------------------------------------------.
| These MDS tables are actually tables of MDS composed with q0 and q1,	 |
| because it is only ever used that way and we can save some time by	 |
| precomputing. Of course the main saving comes from precomputing the	 |
| GF(2 ^ 8) multiplication involved in the MDS matrix multiply.		 |
| By looking things up in these tables we reduce the matrix multiply	 |
| to four lookups and three XORs.					 |
|									 |
| Semi-formally, the definition of these tables is:			 |
|									 |
|  mds[0][i] = MDS (q1[i] 0 0 0) ^ T; mds[1][i] = MDS (0 q0[i] 0 0) ^ T; |
|  mds[2][i] = MDS (0 0 q1[i] 0) ^ T; mds[3][i] = MDS (0 0 0 q0[i]) ^ T; |
|									 |
| Where "^ T" means "transpose". The matrix multiply is performed in	 |
| GF(2 ^ 8) represented as GF(2)[x] / v(x). v(x) is calculated as	 |
| x ^ 8 + x ^ 6 + x ^ 5 + x ^ 3 + 1, as described by Schneier et al,	 |
| and I'm casually glossing over the byte/word conversion issues.	 |
'-----------------------------------------------------------------------*/

static zuint32 const mds[4][256] = {
	{C(BCBC3275), C(ECEC21F3), C(202043C6), C(B3B3C9F4),
	 C(DADA03DB), C(02028B7B), C(E2E22BFB), C(9E9EFAC8),
	 C(C9C9EC4A), C(D4D409D3), C(18186BE6), C(1E1E9F6B),
	 C(98980E45), C(B2B2387D), C(A6A6D2E8), C(2626B74B),
	 C(3C3C57D6), C(93938A32), C(8282EED8), C(525298FD),
	 C(7B7BD437), C(BBBB3771), C(5B5B97F1), C(474783E1),
	 C(24243C30), C(5151E20F), C(BABAC6F8), C(4A4AF31B),
	 C(BFBF4887), C(0D0D70FA), C(B0B0B306), C(7575DE3F),
	 C(D2D2FD5E), C(7D7D20BA), C(666631AE), C(3A3AA35B),
	 C(59591C8A), C(00000000), C(CDCD93BC), C(1A1AE09D),
	 C(AEAE2C6D), C(7F7FABC1), C(2B2BC7B1), C(BEBEB90E),
	 C(E0E0A080), C(8A8A105D), C(3B3B52D2), C(6464BAD5),
	 C(D8D888A0), C(E7E7A584), C(5F5FE807), C(1B1B1114),
	 C(2C2CC2B5), C(FCFCB490), C(3131272C), C(808065A3),
	 C(73732AB2), C(0C0C8173), C(79795F4C), C(6B6B4154),
	 C(4B4B0292), C(53536974), C(94948F36), C(83831F51),
	 C(2A2A3638), C(C4C49CB0), C(2222C8BD), C(D5D5F85A),
	 C(BDBDC3FC), C(48487860), C(FFFFCE62), C(4C4C0796),
	 C(4141776C), C(C7C7E642), C(EBEB24F7), C(1C1C1410),
	 C(5D5D637C), C(36362228), C(6767C027), C(E9E9AF8C),
	 C(4444F913), C(1414EA95), C(F5F5BB9C), C(CFCF18C7),
	 C(3F3F2D24), C(C0C0E346), C(7272DB3B), C(54546C70),
	 C(29294CCA), C(F0F035E3), C(0808FE85), C(C6C617CB),
	 C(F3F34F11), C(8C8CE4D0), C(A4A45993), C(CACA96B8),
	 C(68683BA6), C(B8B84D83), C(38382820), C(E5E52EFF),
	 C(ADAD569F), C(0B0B8477), C(C8C81DC3), C(9999FFCC),
	 C(5858ED03), C(19199A6F), C(0E0E0A08), C(95957EBF),
	 C(70705040), C(F7F730E7), C(6E6ECF2B), C(1F1F6EE2),
	 C(B5B53D79), C(09090F0C), C(616134AA), C(57571682),
	 C(9F9F0B41), C(9D9D803A), C(111164EA), C(2525CDB9),
	 C(AFAFDDE4), C(4545089A), C(DFDF8DA4), C(A3A35C97),
	 C(EAEAD57E), C(353558DA), C(EDEDD07A), C(4343FC17),
	 C(F8F8CB66), C(FBFBB194), C(3737D3A1), C(FAFA401D),
	 C(C2C2683D), C(B4B4CCF0), C(32325DDE), C(9C9C71B3),
	 C(5656E70B), C(E3E3DA72), C(878760A7), C(15151B1C),
	 C(F9F93AEF), C(6363BFD1), C(3434A953), C(9A9A853E),
	 C(B1B1428F), C(7C7CD133), C(88889B26), C(3D3DA65F),
	 C(A1A1D7EC), C(E4E4DF76), C(8181942A), C(91910149),
	 C(0F0FFB81), C(EEEEAA88), C(161661EE), C(D7D77321),
	 C(9797F5C4), C(A5A5A81A), C(FEFE3FEB), C(6D6DB5D9),
	 C(7878AEC5), C(C5C56D39), C(1D1DE599), C(7676A4CD),
	 C(3E3EDCAD), C(CBCB6731), C(B6B6478B), C(EFEF5B01),
	 C(12121E18), C(6060C523), C(6A6AB0DD), C(4D4DF61F),
	 C(CECEE94E), C(DEDE7C2D), C(55559DF9), C(7E7E5A48),
	 C(2121B24F), C(03037AF2), C(A0A02665), C(5E5E198E),
	 C(5A5A6678), C(65654B5C), C(62624E58), C(FDFD4519),
	 C(0606F48D), C(404086E5), C(F2F2BE98), C(3333AC57),
	 C(17179067), C(05058E7F), C(E8E85E05), C(4F4F7D64),
	 C(89896AAF), C(10109563), C(74742FB6), C(0A0A75FE),
	 C(5C5C92F5), C(9B9B74B7), C(2D2D333C), C(3030D6A5),
	 C(2E2E49CE), C(494989E9), C(46467268), C(77775544),
	 C(A8A8D8E0), C(9696044D), C(2828BD43), C(A9A92969),
	 C(D9D97929), C(8686912E), C(D1D187AC), C(F4F44A15),
	 C(8D8D1559), C(D6D682A8), C(B9B9BC0A), C(42420D9E),
	 C(F6F6C16E), C(2F2FB847), C(DDDD06DF), C(23233934),
	 C(CCCC6235), C(F1F1C46A), C(C1C112CF), C(8585EBDC),
	 C(8F8F9E22), C(7171A1C9), C(9090F0C0), C(AAAA539B),
	 C(0101F189), C(8B8BE1D4), C(4E4E8CED), C(8E8E6FAB),
	 C(ABABA212), C(6F6F3EA2), C(E6E6540D), C(DBDBF252),
	 C(92927BBB), C(B7B7B602), C(6969CA2F), C(3939D9A9),
	 C(D3D30CD7), C(A7A72361), C(A2A2AD1E), C(C3C399B4),
	 C(6C6C4450), C(07070504), C(04047FF6), C(272746C2),
	 C(ACACA716), C(D0D07625), C(50501386), C(DCDCF756),
	 C(84841A55), C(E1E15109), C(7A7A25BE), C(1313EF91)},

	{C(A9D93939), C(67901717), C(B3719C9C), C(E8D2A6A6),
	 C(04050707), C(FD985252), C(A3658080), C(76DFE4E4),
	 C(9A084545), C(92024B4B), C(80A0E0E0), C(78665A5A),
	 C(E4DDAFAF), C(DDB06A6A), C(D1BF6363), C(38362A2A),
	 C(0D54E6E6), C(C6432020), C(3562CCCC), C(98BEF2F2),
	 C(181E1212), C(F724EBEB), C(ECD7A1A1), C(6C774141),
	 C(43BD2828), C(7532BCBC), C(37D47B7B), C(269B8888),
	 C(FA700D0D), C(13F94444), C(94B1FBFB), C(485A7E7E),
	 C(F27A0303), C(D0E48C8C), C(8B47B6B6), C(303C2424),
	 C(84A5E7E7), C(54416B6B), C(DF06DDDD), C(23C56060),
	 C(1945FDFD), C(5BA33A3A), C(3D68C2C2), C(59158D8D),
	 C(F321ECEC), C(AE316666), C(A23E6F6F), C(82165757),
	 C(63951010), C(015BEFEF), C(834DB8B8), C(2E918686),
	 C(D9B56D6D), C(511F8383), C(9B53AAAA), C(7C635D5D),
	 C(A63B6868), C(EB3FFEFE), C(A5D63030), C(BE257A7A),
	 C(16A7ACAC), C(0C0F0909), C(E335F0F0), C(6123A7A7),
	 C(C0F09090), C(8CAFE9E9), C(3A809D9D), C(F5925C5C),
	 C(73810C0C), C(2C273131), C(2576D0D0), C(0BE75656),
	 C(BB7B9292), C(4EE9CECE), C(89F10101), C(6B9F1E1E),
	 C(53A93434), C(6AC4F1F1), C(B499C3C3), C(F1975B5B),
	 C(E1834747), C(E66B1818), C(BDC82222), C(450E9898),
	 C(E26E1F1F), C(F4C9B3B3), C(B62F7474), C(66CBF8F8),
	 C(CCFF9999), C(95EA1414), C(03ED5858), C(56F7DCDC),
	 C(D4E18B8B), C(1C1B1515), C(1EADA2A2), C(D70CD3D3),
	 C(FB2BE2E2), C(C31DC8C8), C(8E195E5E), C(B5C22C2C),
	 C(E9894949), C(CF12C1C1), C(BF7E9595), C(BA207D7D),
	 C(EA641111), C(77840B0B), C(396DC5C5), C(AF6A8989),
	 C(33D17C7C), C(C9A17171), C(62CEFFFF), C(7137BBBB),
	 C(81FB0F0F), C(793DB5B5), C(0951E1E1), C(ADDC3E3E),
	 C(242D3F3F), C(CDA47676), C(F99D5555), C(D8EE8282),
	 C(E5864040), C(C5AE7878), C(B9CD2525), C(4D049696),
	 C(44557777), C(080A0E0E), C(86135050), C(E730F7F7),
	 C(A1D33737), C(1D40FAFA), C(AA346161), C(ED8C4E4E),
	 C(06B3B0B0), C(706C5454), C(B22A7373), C(D2523B3B),
	 C(410B9F9F), C(7B8B0202), C(A088D8D8), C(114FF3F3),
	 C(3167CBCB), C(C2462727), C(27C06767), C(90B4FCFC),
	 C(20283838), C(F67F0404), C(60784848), C(FF2EE5E5),
	 C(96074C4C), C(5C4B6565), C(B1C72B2B), C(AB6F8E8E),
	 C(9E0D4242), C(9CBBF5F5), C(52F2DBDB), C(1BF34A4A),
	 C(5FA63D3D), C(9359A4A4), C(0ABCB9B9), C(EF3AF9F9),
	 C(91EF1313), C(85FE0808), C(49019191), C(EE611616),
	 C(2D7CDEDE), C(4FB22121), C(8F42B1B1), C(3BDB7272),
	 C(47B82F2F), C(8748BFBF), C(6D2CAEAE), C(46E3C0C0),
	 C(D6573C3C), C(3E859A9A), C(6929A9A9), C(647D4F4F),
	 C(2A948181), C(CE492E2E), C(CB17C6C6), C(2FCA6969),
	 C(FCC3BDBD), C(975CA3A3), C(055EE8E8), C(7AD0EDED),
	 C(AC87D1D1), C(7F8E0505), C(D5BA6464), C(1AA8A5A5),
	 C(4BB72626), C(0EB9BEBE), C(A7608787), C(5AF8D5D5),
	 C(28223636), C(14111B1B), C(3FDE7575), C(2979D9D9),
	 C(88AAEEEE), C(3C332D2D), C(4C5F7979), C(02B6B7B7),
	 C(B896CACA), C(DA583535), C(B09CC4C4), C(17FC4343),
	 C(551A8484), C(1FF64D4D), C(8A1C5959), C(7D38B2B2),
	 C(57AC3333), C(C718CFCF), C(8DF40606), C(74695353),
	 C(B7749B9B), C(C4F59797), C(9F56ADAD), C(72DAE3E3),
	 C(7ED5EAEA), C(154AF4F4), C(229E8F8F), C(12A2ABAB),
	 C(584E6262), C(07E85F5F), C(99E51D1D), C(34392323),
	 C(6EC1F6F6), C(50446C6C), C(DE5D3232), C(68724646),
	 C(6526A0A0), C(BC93CDCD), C(DB03DADA), C(F8C6BABA),
	 C(C8FA9E9E), C(A882D6D6), C(2BCF6E6E), C(40507070),
	 C(DCEB8585), C(FE750A0A), C(328A9393), C(A48DDFDF),
	 C(CA4C2929), C(10141C1C), C(2173D7D7), C(F0CCB4B4),
	 C(D309D4D4), C(5D108A8A), C(0FE25151), C(00000000),
	 C(6F9A1919), C(9DE01A1A), C(368F9494), C(42E6C7C7),
	 C(4AECC9C9), C(5EFDD2D2), C(C1AB7F7F), C(E0D8A8A8)},

	{C(BC75BC32), C(ECF3EC21), C(20C62043), C(B3F4B3C9),
	 C(DADBDA03), C(027B028B), C(E2FBE22B), C(9EC89EFA),
	 C(C94AC9EC), C(D4D3D409), C(18E6186B), C(1E6B1E9F),
	 C(9845980E), C(B27DB238), C(A6E8A6D2), C(264B26B7),
	 C(3CD63C57), C(9332938A), C(82D882EE), C(52FD5298),
	 C(7B377BD4), C(BB71BB37), C(5BF15B97), C(47E14783),
	 C(2430243C), C(510F51E2), C(BAF8BAC6), C(4A1B4AF3),
	 C(BF87BF48), C(0DFA0D70), C(B006B0B3), C(753F75DE),
	 C(D25ED2FD), C(7DBA7D20), C(66AE6631), C(3A5B3AA3),
	 C(598A591C), C(00000000), C(CDBCCD93), C(1A9D1AE0),
	 C(AE6DAE2C), C(7FC17FAB), C(2BB12BC7), C(BE0EBEB9),
	 C(E080E0A0), C(8A5D8A10), C(3BD23B52), C(64D564BA),
	 C(D8A0D888), C(E784E7A5), C(5F075FE8), C(1B141B11),
	 C(2CB52CC2), C(FC90FCB4), C(312C3127), C(80A38065),
	 C(73B2732A), C(0C730C81), C(794C795F), C(6B546B41),
	 C(4B924B02), C(53745369), C(9436948F), C(8351831F),
	 C(2A382A36), C(C4B0C49C), C(22BD22C8), C(D55AD5F8),
	 C(BDFCBDC3), C(48604878), C(FF62FFCE), C(4C964C07),
	 C(416C4177), C(C742C7E6), C(EBF7EB24), C(1C101C14),
	 C(5D7C5D63), C(36283622), C(672767C0), C(E98CE9AF),
	 C(441344F9), C(149514EA), C(F59CF5BB), C(CFC7CF18),
	 C(3F243F2D), C(C046C0E3), C(723B72DB), C(5470546C),
	 C(29CA294C), C(F0E3F035), C(088508FE), C(C6CBC617),
	 C(F311F34F), C(8CD08CE4), C(A493A459), C(CAB8CA96),
	 C(68A6683B), C(B883B84D), C(38203828), C(E5FFE52E),
	 C(AD9FAD56), C(0B770B84), C(C8C3C81D), C(99CC99FF),
	 C(580358ED), C(196F199A), C(0E080E0A), C(95BF957E),
	 C(70407050), C(F7E7F730), C(6E2B6ECF), C(1FE21F6E),
	 C(B579B53D), C(090C090F), C(61AA6134), C(57825716),
	 C(9F419F0B), C(9D3A9D80), C(11EA1164), C(25B925CD),
	 C(AFE4AFDD), C(459A4508), C(DFA4DF8D), C(A397A35C),
	 C(EA7EEAD5), C(35DA3558), C(ED7AEDD0), C(431743FC),
	 C(F866F8CB), C(FB94FBB1), C(37A137D3), C(FA1DFA40),
	 C(C23DC268), C(B4F0B4CC), C(32DE325D), C(9CB39C71),
	 C(560B56E7), C(E372E3DA), C(87A78760), C(151C151B),
	 C(F9EFF93A), C(63D163BF), C(345334A9), C(9A3E9A85),
	 C(B18FB142), C(7C337CD1), C(8826889B), C(3D5F3DA6),
	 C(A1ECA1D7), C(E476E4DF), C(812A8194), C(91499101),
	 C(0F810FFB), C(EE88EEAA), C(16EE1661), C(D721D773),
	 C(97C497F5), C(A51AA5A8), C(FEEBFE3F), C(6DD96DB5),
	 C(78C578AE), C(C539C56D), C(1D991DE5), C(76CD76A4),
	 C(3EAD3EDC), C(CB31CB67), C(B68BB647), C(EF01EF5B),
	 C(1218121E), C(602360C5), C(6ADD6AB0), C(4D1F4DF6),
	 C(CE4ECEE9), C(DE2DDE7C), C(55F9559D), C(7E487E5A),
	 C(214F21B2), C(03F2037A), C(A065A026), C(5E8E5E19),
	 C(5A785A66), C(655C654B), C(6258624E), C(FD19FD45),
	 C(068D06F4), C(40E54086), C(F298F2BE), C(335733AC),
	 C(17671790), C(057F058E), C(E805E85E), C(4F644F7D),
	 C(89AF896A), C(10631095), C(74B6742F), C(0AFE0A75),
	 C(5CF55C92), C(9BB79B74), C(2D3C2D33), C(30A530D6),
	 C(2ECE2E49), C(49E94989), C(46684672), C(77447755),
	 C(A8E0A8D8), C(964D9604), C(284328BD), C(A969A929),
	 C(D929D979), C(862E8691), C(D1ACD187), C(F415F44A),
	 C(8D598D15), C(D6A8D682), C(B90AB9BC), C(429E420D),
	 C(F66EF6C1), C(2F472FB8), C(DDDFDD06), C(23342339),
	 C(CC35CC62), C(F16AF1C4), C(C1CFC112), C(85DC85EB),
	 C(8F228F9E), C(71C971A1), C(90C090F0), C(AA9BAA53),
	 C(018901F1), C(8BD48BE1), C(4EED4E8C), C(8EAB8E6F),
	 C(AB12ABA2), C(6FA26F3E), C(E60DE654), C(DB52DBF2),
	 C(92BB927B), C(B702B7B6), C(692F69CA), C(39A939D9),
	 C(D3D7D30C), C(A761A723), C(A21EA2AD), C(C3B4C399),
	 C(6C506C44), C(07040705), C(04F6047F), C(27C22746),
	 C(AC16ACA7), C(D025D076), C(50865013), C(DC56DCF7),
	 C(8455841A), C(E109E151), C(7ABE7A25), C(139113EF)},

	{C(D939A9D9), C(90176790), C(719CB371), C(D2A6E8D2),
	 C(05070405), C(9852FD98), C(6580A365), C(DFE476DF),
	 C(08459A08), C(024B9202), C(A0E080A0), C(665A7866),
	 C(DDAFE4DD), C(B06ADDB0), C(BF63D1BF), C(362A3836),
	 C(54E60D54), C(4320C643), C(62CC3562), C(BEF298BE),
	 C(1E12181E), C(24EBF724), C(D7A1ECD7), C(77416C77),
	 C(BD2843BD), C(32BC7532), C(D47B37D4), C(9B88269B),
	 C(700DFA70), C(F94413F9), C(B1FB94B1), C(5A7E485A),
	 C(7A03F27A), C(E48CD0E4), C(47B68B47), C(3C24303C),
	 C(A5E784A5), C(416B5441), C(06DDDF06), C(C56023C5),
	 C(45FD1945), C(A33A5BA3), C(68C23D68), C(158D5915),
	 C(21ECF321), C(3166AE31), C(3E6FA23E), C(16578216),
	 C(95106395), C(5BEF015B), C(4DB8834D), C(91862E91),
	 C(B56DD9B5), C(1F83511F), C(53AA9B53), C(635D7C63),
	 C(3B68A63B), C(3FFEEB3F), C(D630A5D6), C(257ABE25),
	 C(A7AC16A7), C(0F090C0F), C(35F0E335), C(23A76123),
	 C(F090C0F0), C(AFE98CAF), C(809D3A80), C(925CF592),
	 C(810C7381), C(27312C27), C(76D02576), C(E7560BE7),
	 C(7B92BB7B), C(E9CE4EE9), C(F10189F1), C(9F1E6B9F),
	 C(A93453A9), C(C4F16AC4), C(99C3B499), C(975BF197),
	 C(8347E183), C(6B18E66B), C(C822BDC8), C(0E98450E),
	 C(6E1FE26E), C(C9B3F4C9), C(2F74B62F), C(CBF866CB),
	 C(FF99CCFF), C(EA1495EA), C(ED5803ED), C(F7DC56F7),
	 C(E18BD4E1), C(1B151C1B), C(ADA21EAD), C(0CD3D70C),
	 C(2BE2FB2B), C(1DC8C31D), C(195E8E19), C(C22CB5C2),
	 C(8949E989), C(12C1CF12), C(7E95BF7E), C(207DBA20),
	 C(6411EA64), C(840B7784), C(6DC5396D), C(6A89AF6A),
	 C(D17C33D1), C(A171C9A1), C(CEFF62CE), C(37BB7137),
	 C(FB0F81FB), C(3DB5793D), C(51E10951), C(DC3EADDC),
	 C(2D3F242D), C(A476CDA4), C(9D55F99D), C(EE82D8EE),
	 C(8640E586), C(AE78C5AE), C(CD25B9CD), C(04964D04),
	 C(55774455), C(0A0E080A), C(13508613), C(30F7E730),
	 C(D337A1D3), C(40FA1D40), C(3461AA34), C(8C4EED8C),
	 C(B3B006B3), C(6C54706C), C(2A73B22A), C(523BD252),
	 C(0B9F410B), C(8B027B8B), C(88D8A088), C(4FF3114F),
	 C(67CB3167), C(4627C246), C(C06727C0), C(B4FC90B4),
	 C(28382028), C(7F04F67F), C(78486078), C(2EE5FF2E),
	 C(074C9607), C(4B655C4B), C(C72BB1C7), C(6F8EAB6F),
	 C(0D429E0D), C(BBF59CBB), C(F2DB52F2), C(F34A1BF3),
	 C(A63D5FA6), C(59A49359), C(BCB90ABC), C(3AF9EF3A),
	 C(EF1391EF), C(FE0885FE), C(01914901), C(6116EE61),
	 C(7CDE2D7C), C(B2214FB2), C(42B18F42), C(DB723BDB),
	 C(B82F47B8), C(48BF8748), C(2CAE6D2C), C(E3C046E3),
	 C(573CD657), C(859A3E85), C(29A96929), C(7D4F647D),
	 C(94812A94), C(492ECE49), C(17C6CB17), C(CA692FCA),
	 C(C3BDFCC3), C(5CA3975C), C(5EE8055E), C(D0ED7AD0),
	 C(87D1AC87), C(8E057F8E), C(BA64D5BA), C(A8A51AA8),
	 C(B7264BB7), C(B9BE0EB9), C(6087A760), C(F8D55AF8),
	 C(22362822), C(111B1411), C(DE753FDE), C(79D92979),
	 C(AAEE88AA), C(332D3C33), C(5F794C5F), C(B6B702B6),
	 C(96CAB896), C(5835DA58), C(9CC4B09C), C(FC4317FC),
	 C(1A84551A), C(F64D1FF6), C(1C598A1C), C(38B27D38),
	 C(AC3357AC), C(18CFC718), C(F4068DF4), C(69537469),
	 C(749BB774), C(F597C4F5), C(56AD9F56), C(DAE372DA),
	 C(D5EA7ED5), C(4AF4154A), C(9E8F229E), C(A2AB12A2),
	 C(4E62584E), C(E85F07E8), C(E51D99E5), C(39233439),
	 C(C1F66EC1), C(446C5044), C(5D32DE5D), C(72466872),
	 C(26A06526), C(93CDBC93), C(03DADB03), C(C6BAF8C6),
	 C(FA9EC8FA), C(82D6A882), C(CF6E2BCF), C(50704050),
	 C(EB85DCEB), C(750AFE75), C(8A93328A), C(8DDFA48D),
	 C(4C29CA4C), C(141C1014), C(73D72173), C(CCB4F0CC),
	 C(09D4D309), C(108A5D10), C(E2510FE2), C(00000000),
	 C(9A196F9A), C(E01A9DE0), C(8F94368F), C(E6C742E6),
	 C(ECC94AEC), C(FDD25EFD), C(AB7FC1AB), C(D8A8E0D8)}
};

/*-----------------------------------------------------------------------------.
| The p2e and e2p tables are used to perform efficient operations in GF(2 ^ 8) |
| represented as GF(2)[x] / w(x). w(x) is x^8 + x^6 + x^3 + x^2 + 1. It's part |
| of the definition of the RS matrix in the key schedule, so we care about     |
| doing that. Elements of that field are polynomials of degree not greater     |
| than 7 and all coefficients 0 or 1, which can be represented naturally by    |
| bytes (just substitute x = 2). In that form, GF(2^8) addition is the same as |
| bitwise XOR, but GF(2^8) multiplication is inefficient without hardware      |
| support. To multiply faster, I benefit from the fact x is a generator for    |
| the nonzero elements, so that every element p of GF(2)[x] / w(x) is either 0 |
| or equal to (x)^n for some n in 0..254. Note that caret is exponentiation in |
| GF(2^8), *not* polynomial notation.					       |
|									       |
| So if I want to compute pq where p and q are in GF(2^8), I can just say:     |
|   1. if p = 0 or q = 0 then pq = 0					       |
|   2. otherwise, find m and n such that p = x^m and q = x^n		       |
|   3. pq = (x^m)(x^n) = x^(m + n), so add m and n and find pq		       |
|									       |
| The translations in steps 2 and 3 are looked up in the tables p2e for step 2 |
| and e2p for step 3. To see this in action, look at the S() macro.	       |
| As additional wrinkles, note that one of my operands is always a constant,   |
| so the p2e lookup on it is done in advance; I included the original values   |
| in the comments so readers can have some chance of recognizing that this is  |
| the RS matrix from the Twofish paper. I've only included the table entries I |
| actually need; I never do a lookup on a variable input of zero and the       |
| biggest exponents I'll ever see are 254 (variable) and 237 (constant), so    |
| they'll never sum to more than 491. I'm repeating part of the e2p table so   |
| that I don't have to do mod-255 reduction in the exponent arithmetic.	       |
| Since I know my constant operands are never zero, I only have to worry about |
| zero values in the variable operand, and I do it with a simple conditional   |
| branch. I know conditionals are expensive, but I couldn't see a non-horrible |
| way of avoiding them, and I did manage to group the statements so that each  |
| if covers four group multiplications.					       |
'-----------------------------------------------------------------------------*/

static zuint8 const p2e[255] = {
	0x00, 0x01, 0x17, 0x02, 0x2E, 0x18, 0x53, 0x03,
	0x6A, 0x2F, 0x93, 0x19, 0x34, 0x54, 0x45, 0x04,
	0x5C, 0x6B, 0xB6, 0x30, 0xA6, 0x94, 0x4B, 0x1A,
	0x8C, 0x35, 0x81, 0x55, 0xAA, 0x46, 0x0D, 0x05,
	0x24, 0x5D, 0x87, 0x6C,	0x9B, 0xB7, 0xC1, 0x31,
	0x2B, 0xA7, 0xA3, 0x95, 0x98, 0x4C, 0xCA, 0x1B,
	0xE6, 0x8D, 0x73, 0x36, 0xCD, 0x82, 0x12, 0x56,
	0x62, 0xAB, 0xF0, 0x47,	0x4F, 0x0E, 0xBD, 0x06,
	0xD4, 0x25, 0xD2, 0x5E, 0x27, 0x88, 0x66, 0x6D,
	0xD6, 0x9C, 0x79, 0xB8, 0x08, 0xC2, 0xDF, 0x32,
	0x68, 0x2C, 0xFD, 0xA8,	0x8A, 0xA4, 0x5A, 0x96,
	0x29, 0x99, 0x22, 0x4D, 0x60, 0xCB, 0xE4, 0x1C,
	0x7B, 0xE7, 0x3B, 0x8E, 0x9E, 0x74, 0xF4, 0x37,
	0xD8, 0xCE, 0xF9, 0x83,	0x6F, 0x13, 0xB2, 0x57,
	0xE1, 0x63, 0xDC, 0xAC, 0xC4, 0xF1, 0xAF, 0x48,
	0x0A, 0x50, 0x42, 0x0F, 0xBA, 0xBE, 0xC7, 0x07,
	0xDE, 0xD5, 0x78, 0x26,	0x65, 0xD3, 0xD1, 0x5F,
	0xE3, 0x28, 0x21, 0x89, 0x59, 0x67, 0xFC, 0x6E,
	0xB1, 0xD7, 0xF8, 0x9D, 0xF3, 0x7A, 0x3A, 0xB9,
	0xC6, 0x09, 0x41, 0xC3,	0xAE, 0xE0, 0xDB, 0x33,
	0x44, 0x69, 0x92, 0x2D, 0x52, 0xFE, 0x16, 0xA9,
	0x0C, 0x8B, 0x80, 0xA5, 0x4A, 0x5B, 0xB5, 0x97,
	0xC9, 0x2A, 0xA2, 0x9A,	0xC0, 0x23, 0x86, 0x4E,
	0xBC, 0x61, 0xEF, 0xCC, 0x11, 0xE5, 0x72, 0x1D,
	0x3D, 0x7C, 0xEB, 0xE8, 0xE9, 0x3C, 0xEA, 0x8F,
	0x7D, 0x9F, 0xEC, 0x75,	0x1E, 0xF5, 0x3E, 0x38,
	0xF6, 0xD9, 0x3F, 0xCF, 0x76, 0xFA, 0x1F, 0x84,
	0xA0, 0x70, 0xED, 0x14, 0x90, 0xB3, 0x7E, 0x58,
	0xFB, 0xE2, 0x20, 0x64,	0xD0, 0xDD, 0x77, 0xAD,
	0xDA, 0xC5, 0x40, 0xF2, 0x39, 0xB0, 0xF7, 0x49,
	0xB4, 0x0B, 0x7F, 0x51, 0x15, 0x43, 0x91, 0x10,
	0x71, 0xBB, 0xEE, 0xBF,	0x85, 0xC8, 0xA1
};

static zuint8 const e2p[492] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
	0x4D, 0x9A, 0x79, 0xF2,	0xA9, 0x1F, 0x3E, 0x7C,
	0xF8, 0xBD, 0x37, 0x6E, 0xDC, 0xF5, 0xA7, 0x03,
	0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0xCD, 0xD7,
	0xE3, 0x8B, 0x5B, 0xB6,	0x21, 0x42, 0x84, 0x45,
	0x8A, 0x59, 0xB2, 0x29, 0x52, 0xA4, 0x05, 0x0A,
	0x14, 0x28, 0x50, 0xA0, 0x0D, 0x1A, 0x34, 0x68,
	0xD0, 0xED, 0x97, 0x63,	0xC6, 0xC1, 0xCF, 0xD3,
	0xEB, 0x9B, 0x7B, 0xF6, 0xA1, 0x0F, 0x1E, 0x3C,
	0x78, 0xF0, 0xAD, 0x17, 0x2E, 0x5C, 0xB8, 0x3D,
	0x7A, 0xF4, 0xA5, 0x07,	0x0E, 0x1C, 0x38, 0x70,
	0xE0, 0x8D, 0x57, 0xAE, 0x11, 0x22, 0x44, 0x88,
	0x5D, 0xBA, 0x39, 0x72, 0xE4, 0x85, 0x47, 0x8E,
	0x51, 0xA2, 0x09, 0x12,	0x24, 0x48, 0x90, 0x6D,
	0xDA, 0xF9, 0xBF, 0x33, 0x66, 0xCC, 0xD5, 0xE7,
	0x83, 0x4B, 0x96, 0x61, 0xC2, 0xC9, 0xDF, 0xF3,
	0xAB, 0x1B, 0x36, 0x6C,	0xD8, 0xFD, 0xB7, 0x23,
	0x46, 0x8C, 0x55, 0xAA, 0x19, 0x32, 0x64, 0xC8,
	0xDD, 0xF7, 0xA3, 0x0B, 0x16, 0x2C, 0x58, 0xB0,
	0x2D, 0x5A, 0xB4, 0x25,	0x4A, 0x94, 0x65, 0xCA,
	0xD9, 0xFF, 0xB3, 0x2B, 0x56, 0xAC, 0x15, 0x2A,
	0x54, 0xA8, 0x1D, 0x3A, 0x74, 0xE8, 0x9D, 0x77,
	0xEE, 0x91, 0x6F, 0xDE,	0xF1, 0xAF, 0x13, 0x26,
	0x4C, 0x98, 0x7D, 0xFA, 0xB9, 0x3F, 0x7E, 0xFC,
	0xB5, 0x27, 0x4E, 0x9C, 0x75, 0xEA, 0x99, 0x7F,
	0xFE, 0xB1, 0x2F, 0x5E,	0xBC, 0x35, 0x6A, 0xD4,
	0xE5, 0x87, 0x43, 0x86, 0x41, 0x82, 0x49, 0x92,
	0x69, 0xD2, 0xE9, 0x9F, 0x73, 0xE6, 0x81, 0x4F,
	0x9E, 0x71, 0xE2, 0x89,	0x5F, 0xBE, 0x31, 0x62,
	0xC4, 0xC5, 0xC7, 0xC3, 0xCB, 0xDB, 0xFB, 0xBB,
	0x3B, 0x76, 0xEC, 0x95, 0x67, 0xCE, 0xD1, 0xEF,
	0x93, 0x6B, 0xD6, 0xE1,	0x8F, 0x53, 0xA6, 0x01,
	0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x4D,
	0x9A, 0x79, 0xF2, 0xA9, 0x1F, 0x3E, 0x7C, 0xF8,
	0xBD, 0x37, 0x6E, 0xDC,	0xF5, 0xA7, 0x03, 0x06,
	0x0C, 0x18, 0x30, 0x60, 0xC0, 0xCD, 0xD7, 0xE3,
	0x8B, 0x5B, 0xB6, 0x21, 0x42, 0x84, 0x45, 0x8A,
	0x59, 0xB2, 0x29, 0x52,	0xA4, 0x05, 0x0A, 0x14,
	0x28, 0x50, 0xA0, 0x0D, 0x1A, 0x34, 0x68, 0xD0,
	0xED, 0x97, 0x63, 0xC6, 0xC1, 0xCF, 0xD3, 0xEB,
	0x9B, 0x7B, 0xF6, 0xA1,	0x0F, 0x1E, 0x3C, 0x78,
	0xF0, 0xAD, 0x17, 0x2E, 0x5C, 0xB8, 0x3D, 0x7A,
	0xF4, 0xA5, 0x07, 0x0E, 0x1C, 0x38, 0x70, 0xE0,
	0x8D, 0x57, 0xAE, 0x11,	0x22, 0x44, 0x88, 0x5D,
	0xBA, 0x39, 0x72, 0xE4, 0x85, 0x47, 0x8E, 0x51,
	0xA2, 0x09, 0x12, 0x24, 0x48, 0x90, 0x6D, 0xDA,
	0xF9, 0xBF, 0x33, 0x66,	0xCC, 0xD5, 0xE7, 0x83,
	0x4B, 0x96, 0x61, 0xC2, 0xC9, 0xDF, 0xF3, 0xAB,
	0x1B, 0x36, 0x6C, 0xD8, 0xFD, 0xB7, 0x23, 0x46,
	0x8C, 0x55, 0xAA, 0x19,	0x32, 0x64, 0xC8, 0xDD,
	0xF7, 0xA3, 0x0B, 0x16, 0x2C, 0x58, 0xB0, 0x2D,
	0x5A, 0xB4, 0x25, 0x4A, 0x94, 0x65, 0xCA, 0xD9,
	0xFF, 0xB3, 0x2B, 0x56,	0xAC, 0x15, 0x2A, 0x54,
	0xA8, 0x1D, 0x3A, 0x74, 0xE8, 0x9D, 0x77, 0xEE,
	0x91, 0x6F, 0xDE, 0xF1, 0xAF, 0x13, 0x26, 0x4C,
	0x98, 0x7D, 0xFA, 0xB9,	0x3F, 0x7E, 0xFC, 0xB5,
	0x27, 0x4E, 0x9C, 0x75, 0xEA, 0x99, 0x7F, 0xFE,
	0xB1, 0x2F, 0x5E, 0xBC, 0x35, 0x6A, 0xD4, 0xE5,
	0x87, 0x43, 0x86, 0x41,	0x82, 0x49, 0x92, 0x69,
	0xD2, 0xE9, 0x9F, 0x73, 0xE6, 0x81, 0x4F, 0x9E,
	0x71, 0xE2, 0x89, 0x5F, 0xBE, 0x31, 0x62, 0xC4,
	0xC5, 0xC7, 0xC3, 0xCB
};

/*--------------------------------------------------.
| The table constants are indices of S-box entries, |
| preprocessed through q0 and q1.		    |
'--------------------------------------------------*/
static zuint8 const calc_sb_tbl[512] = {
	0xA9, 0x75, 0x67, 0xF3, 0xB3, 0xC6, 0xE8, 0xF4,
	0x04, 0xDB, 0xFD, 0x7B, 0xA3, 0xFB, 0x76, 0xC8,
	0x9A, 0x4A, 0x92, 0xD3, 0x80, 0xE6, 0x78, 0x6B,
	0xE4, 0x45, 0xDD, 0x7D, 0xD1, 0xE8, 0x38, 0x4B,
	0x0D, 0xD6, 0xC6, 0x32, 0x35, 0xD8, 0x98, 0xFD,
	0x18, 0x37, 0xF7, 0x71, 0xEC, 0xF1, 0x6C, 0xE1,
	0x43, 0x30, 0x75, 0x0F, 0x37, 0xF8, 0x26, 0x1B,
	0xFA, 0x87, 0x13, 0xFA, 0x94, 0x06, 0x48, 0x3F,
	0xF2, 0x5E, 0xD0, 0xBA, 0x8B, 0xAE, 0x30, 0x5B,
	0x84, 0x8A, 0x54, 0x00, 0xDF, 0xBC, 0x23, 0x9D,
	0x19, 0x6D, 0x5B, 0xC1, 0x3D, 0xB1, 0x59, 0x0E,
	0xF3, 0x80, 0xAE, 0x5D, 0xA2, 0xD2, 0x82, 0xD5,
	0x63, 0xA0, 0x01, 0x84, 0x83, 0x07, 0x2E, 0x14,
	0xD9, 0xB5, 0x51, 0x90, 0x9B, 0x2C, 0x7C, 0xA3,
	0xA6, 0xB2, 0xEB, 0x73, 0xA5, 0x4C, 0xBE, 0x54,
	0x16, 0x92, 0x0C, 0x74, 0xE3, 0x36, 0x61, 0x51,
	0xC0, 0x38, 0x8C, 0xB0, 0x3A, 0xBD, 0xF5, 0x5A,
	0x73, 0xFC, 0x2C, 0x60, 0x25, 0x62, 0x0B, 0x96,
	0xBB, 0x6C, 0x4E, 0x42, 0x89, 0xF7, 0x6B, 0x10,
	0x53, 0x7C, 0x6A, 0x28, 0xB4, 0x27, 0xF1, 0x8C,
	0xE1, 0x13, 0xE6, 0x95, 0xBD, 0x9C, 0x45, 0xC7,
	0xE2, 0x24, 0xF4, 0x46, 0xB6, 0x3B, 0x66, 0x70,
	0xCC, 0xCA, 0x95, 0xE3, 0x03, 0x85, 0x56, 0xCB,
	0xD4, 0x11, 0x1C, 0xD0, 0x1E, 0x93, 0xD7, 0xB8,
	0xFB, 0xA6, 0xC3, 0x83, 0x8E, 0x20, 0xB5, 0xFF,
	0xE9, 0x9F, 0xCF, 0x77, 0xBF, 0xC3, 0xBA, 0xCC,
	0xEA, 0x03, 0x77, 0x6F, 0x39, 0x08, 0xAF, 0xBF,
	0x33, 0x40, 0xC9, 0xE7, 0x62, 0x2B, 0x71, 0xE2,
	0x81, 0x79, 0x79, 0x0C, 0x09, 0xAA, 0xAD, 0x82,
	0x24, 0x41, 0xCD, 0x3A, 0xF9, 0xEA, 0xD8, 0xB9,
	0xE5, 0xE4, 0xC5, 0x9A, 0xB9, 0xA4, 0x4D, 0x97,
	0x44, 0x7E, 0x08, 0xDA, 0x86, 0x7A, 0xE7, 0x17,
	0xA1, 0x66, 0x1D, 0x94, 0xAA, 0xA1, 0xED, 0x1D,
	0x06, 0x3D, 0x70, 0xF0, 0xB2, 0xDE, 0xD2, 0xB3,
	0x41, 0x0B, 0x7B, 0x72, 0xA0, 0xA7, 0x11, 0x1C,
	0x31, 0xEF, 0xC2, 0xD1, 0x27, 0x53, 0x90, 0x3E,
	0x20, 0x8F, 0xF6, 0x33, 0x60, 0x26, 0xFF, 0x5F,
	0x96, 0xEC, 0x5C, 0x76, 0xB1, 0x2A, 0xAB, 0x49,
	0x9E, 0x81, 0x9C, 0x88, 0x52, 0xEE, 0x1B, 0x21,
	0x5F, 0xC4, 0x93, 0x1A, 0x0A, 0xEB, 0xEF, 0xD9,
	0x91, 0xC5, 0x85, 0x39, 0x49, 0x99, 0xEE, 0xCD,
	0x2D, 0xAD, 0x4F, 0x31, 0x8F, 0x8B, 0x3B, 0x01,
	0x47, 0x18, 0x87, 0x23, 0x6D, 0xDD, 0x46, 0x1F,
	0xD6, 0x4E, 0x3E, 0x2D, 0x69, 0xF9, 0x64, 0x48,
	0x2A, 0x4F, 0xCE, 0xF2, 0xCB, 0x65, 0x2F, 0x8E,
	0xFC, 0x78, 0x97, 0x5C, 0x05, 0x58, 0x7A, 0x19,
	0xAC, 0x8D, 0x7F, 0xE5, 0xD5, 0x98, 0x1A, 0x57,
	0x4B, 0x67, 0x0E, 0x7F, 0xA7, 0x05, 0x5A, 0x64,
	0x28, 0xAF, 0x14, 0x63, 0x3F, 0xB6, 0x29, 0xFE,
	0x88, 0xF5, 0x3C, 0xB7, 0x4C, 0x3C, 0x02, 0xA5,
	0xB8, 0xCE, 0xDA, 0xE9, 0xB0, 0x68, 0x17, 0x44,
	0x55, 0xE0, 0x1F, 0x4D, 0x8A, 0x43, 0x7D, 0x69,
	0x57, 0x29, 0xC7, 0x2E, 0x8D, 0xAC, 0x74, 0x15,
	0xB7, 0x59, 0xC4, 0xA8, 0x9F, 0x0A, 0x72, 0x9E,
	0x7E, 0x6E, 0x15, 0x47, 0x22, 0xDF, 0x12, 0x34,
	0x58, 0x35, 0x07, 0x6A, 0x99, 0xCF, 0x34, 0xDC,
	0x6E, 0x22, 0x50, 0xC9, 0xDE, 0xC0, 0x68, 0x9B,
	0x65, 0x89, 0xBC, 0xD4, 0xDB, 0xED, 0xF8, 0xAB,
	0xC8, 0x12, 0xA8, 0xA2, 0x2B, 0x0D, 0x40, 0x52,
	0xDC, 0xBB, 0xFE, 0x02, 0x32, 0x2F, 0xA4, 0xA9,
	0xCA, 0xD7, 0x10, 0x61, 0x21, 0x1E, 0xF0, 0xB4,
	0xD3, 0x50, 0x5D, 0x04, 0x0F, 0xF6, 0x00, 0xC2,
	0x6F, 0x16, 0x9D, 0x25, 0x36, 0x86, 0x42, 0x56,
	0x4A, 0x55, 0x5E, 0x09, 0xC1, 0xBE, 0xE0, 0x91
};

/*------------------------------------------------------------------.
| Macro to perform one column of the RS matrix multiplication.The   |
| parameters a, b, c, and d are the four bytes of output; i is the  |
| index of the key bytes, and w, x, y, and z, are the column of	    |
| constants from the RS matrix, preprocessed through the p2e table. |
'------------------------------------------------------------------*/

#define S(a, b, c, d, i, w, x, y, z) \
   if (key[i])			     \
   	{			     \
	t = p2e[key[i] - 1];	     \
	(a) ^= e2p[t + (w)];	     \
	(b) ^= e2p[t + (x)];	     \
	(c) ^= e2p[t + (y)];	     \
	(d) ^= e2p[t + (z)];	     \
	}

/*---------------------------------------------------------------------------.
| Macros to calculate the key-dependent S-boxes for a 128-bit key using	     |
| the S vector from S(). SB_2() computes a single entry in all four S-boxes, |
| where i is the index of the entry to compute, and a and b are the index    |
| numbers preprocessed through the q0 and q1 tables respectively.	     |
'---------------------------------------------------------------------------*/

#define SB_2(i, a, b)				     \
	{					     \
	object->s[0][i] = mds[0][q0[(a) ^ sa] ^ se]; \
	object->s[1][i] = mds[1][q0[(b) ^ sb] ^ sf]; \
	object->s[2][i] = mds[2][q1[(a) ^ sc] ^ sg]; \
	object->s[3][i] = mds[3][q1[(b) ^ sd] ^ sh]; \
	}

/*-----------------------------------------------.
| Macro exactly like SB_2, but for 192-bit keys. |
'-----------------------------------------------*/

#define SB192_2(i, a, b)				      \
	{						      \
	object->s[0][i] = mds[0][q0[q0[(b) ^ sa] ^ se] ^ si]; \
	object->s[1][i] = mds[1][q0[q1[(b) ^ sb] ^ sf] ^ sj]; \
	object->s[2][i] = mds[2][q1[q0[(a) ^ sc] ^ sg] ^ sk]; \
	object->s[3][i] = mds[3][q1[q1[(a) ^ sd] ^ sh] ^ sl]; \
	}

/*-----------------------------------------------.
| Macro exactly like SB_2, but for 256-bit keys. |
'-----------------------------------------------*/

#define SB256_2(i, a, b)					       \
	{							       \
	object->s[0][i] = mds[0][q0[q0[q1[(b) ^ sa] ^ se] ^ si] ^ sm]; \
	object->s[1][i] = mds[1][q0[q1[q1[(a) ^ sb] ^ sf] ^ sj] ^ sn]; \
	object->s[2][i] = mds[2][q1[q0[q0[(a) ^ sc] ^ sg] ^ sk] ^ so]; \
	object->s[3][i] = mds[3][q1[q1[q0[(b) ^ sd] ^ sh] ^ sl] ^ sp]; \
	}

/*-----------------------------------------------------------------------------.
| Macros to calculate the whitening and round subkeys.			       |
|									       |
| K_2() computes the last two stages of the h() function for a given index     |
| (either 2i or 2i + 1). a, b, c, and d are the four bytes going into the last |
| two stages. For 128-bit keys, this is the entire h() function and a and c    |
| are the index preprocessed through q0 and q1 respectively; for longer keys   |
| they are the output of previous stages. j is the index of the first key byte |
| to use.								       |
|									       |
| K() computes a pair of subkeys for 128-bit Twofish, by calling K_2() twice,  |
| doing the Pseudo-Hadamard Transform, and doing the necessary rotations. a is |
| the array to write the results into. j is the index of the first output      |
| entry. k and l are the preprocessed indices for index 2i. m and n are the    |
| preprocessed indices for index 2i + 1.				       |
|									       |
| K192_2() expands K_2() to handle 192-bit keys, by doing an additional	       |
| lookup-and-XOR stage. The parameters a, b, c and d are the four bytes going  |
| into the last three stages. For 192-bit keys, c = d are the index	       |
| preprocessed through q0, and a = b are the index preprocessed through q1.    |
| j is the index of the first key byte to use.				       |
|									       |
| K192() is identical to K() but uses the K192_2() macro instead of K_2().     |
|									       |
| K256_2() expands K192_2() to handle 256-bit keys, by doing an additional     |
| lookup-and-XOR stage. The parameters a and b are the index preprocessed      |
| through q0 and q1 respectively. j is the index of the first key byte to use. |
|									       |
| K256() is identical to K() but uses the K256_2() macro instead of K_2().     |
'-----------------------------------------------------------------------------*/

#define K_2(a, b, c, d, j)			    \
     mds[0][q0[a ^ key[(j) +  8]] ^ key[j      ]] ^ \
     mds[1][q0[b ^ key[(j) +  9]] ^ key[(j) + 1]] ^ \
     mds[2][q1[c ^ key[(j) + 10]] ^ key[(j) + 2]] ^ \
     mds[3][q1[d ^ key[(j) + 11]] ^ key[(j) + 3]]

#define K(a, j, k, l, m, n)				 \
	{						 \
	x = K_2(k, l, k, l, 0);				 \
	y = K_2(m, n, m, n, 4);				 \
	y = z_uint32_rotate_left(y, 8);			 \
	x += y; y += x; object->a[j] = x;		 \
	object->a[(j) + 1] = z_uint32_rotate_left(y, 9); \
	}

#define K192_2(a, b, c, d, j) K_2			  \
	(q0[a ^ key[(j) + 16]], q1[b ^ key[(j) + 17]],	  \
	 q0[c ^ key[(j) + 18]], q1[d ^ key[(j) + 19]], j)

#define K192(a, j, k, l, m, n)				 \
	{						 \
	x = K192_2(l, l, k, k, 0);			 \
	y = K192_2(n, n, m, m, 4);			 \
	y = z_uint32_rotate_left(y, 8);			 \
	x += y; y += x; object->a[j] = x;		 \
	object->a[(j) + 1] = z_uint32_rotate_left(y, 9); \
	}

#define K256_2(a, b, j) K192_2				  \
	(q1[b ^ key[(j) + 24]], q1[a ^ key[(j) + 25]],	  \
	 q0[a ^ key[(j) + 26]], q0[b ^ key[(j) + 27]], j)

#define K256(a, j, k, l, m, n)				 \
	{						 \
	x = K256_2(k, l, 0);				 \
	y = K256_2(m, n, 4);				 \
	y = z_uint32_rotate_left(y, 8);			 \
	x += y; y += x; object->a[j] = x;		 \
	object->a[(j) + 1] = z_uint32_rotate_left(y, 9); \
	}


CIPHER_TWOFISH_API void twofish_set_key(Twofish *object, const zuint8 *key, zsize key_size)
	{
	zint i, j, k;

	/*-------------------.
	| Temporaries for K. |
	'-------------------*/
	zuint32 x, y;

	/*--------------------------------------------------------------.
	| The S vector used to key the S-boxes, split up into bytes.	|
	| 128-bit keys use only sa through sh; 256-bit use all of them. |
	'--------------------------------------------------------------*/
	zuint8 sa = 0, sb = 0, sc = 0, sd = 0, se = 0, sf = 0, sg = 0, sh = 0;
	zuint8 si = 0, sj = 0, sk = 0, sl = 0, sm = 0, sn = 0, so = 0, sp = 0;

	/*-----------------.
	| Temporary for S. |
	'-----------------*/
	zuint8 t;

	/*---------------------------------------------------------------.
	| Compute the first two words of the S vector. The magic numbers |
	| are the entries of the RS matrix, preprocessed through p2e.	 |
	| The numbers in the comments are the original (polynomial form) |
	| matrix entries.						 |
	'---------------------------------------------------------------*/
	S(sa, sb, sc, sd,  0, 0x00, 0x2D, 0x01, 0x2D); /* 01 A4 02 A4 */
	S(sa, sb, sc, sd,  1, 0x2D, 0xA4, 0x44, 0x8A); /* A4 56 A1 55 */
	S(sa, sb, sc, sd,  2, 0x8A, 0xD5, 0xBF, 0xD1); /* 55 82 FC 87 */
	S(sa, sb, sc, sd,  3, 0xD1, 0x7F, 0x3D, 0x99); /* 87 F3 C1 5A */
	S(sa, sb, sc, sd,  4, 0x99, 0x46, 0x66, 0x96); /* 5A 1E 47 58 */
	S(sa, sb, sc, sd,  5, 0x96, 0x3C, 0x5B, 0xED); /* 58 C6 AE DB */
	S(sa, sb, sc, sd,  6, 0xED, 0x37, 0x4F, 0xE0); /* DB 68 3D 9E */
	S(sa, sb, sc, sd,  7, 0xE0, 0xD0, 0x8C, 0x17); /* 9E E5 19 03 */
	S(se, sf, sg, sh,  8, 0x00, 0x2D, 0x01, 0x2D); /* 01 A4 02 A4 */
	S(se, sf, sg, sh,  9, 0x2D, 0xA4, 0x44, 0x8A); /* A4 56 A1 55 */
	S(se, sf, sg, sh, 10, 0x8A, 0xD5, 0xBF, 0xD1); /* 55 82 FC 87 */
	S(se, sf, sg, sh, 11, 0xD1, 0x7F, 0x3D, 0x99); /* 87 F3 C1 5A */
	S(se, sf, sg, sh, 12, 0x99, 0x46, 0x66, 0x96); /* 5A 1E 47 58 */
	S(se, sf, sg, sh, 13, 0x96, 0x3C, 0x5B, 0xED); /* 58 C6 AE DB */
	S(se, sf, sg, sh, 14, 0xED, 0x37, 0x4F, 0xE0); /* DB 68 3D 9E */
	S(se, sf, sg, sh, 15, 0xE0, 0xD0, 0x8C, 0x17); /* 9E E5 19 03 */

	/*--------------------------.
	| 192-bit or 256-bit key... |
	'--------------------------*/
	if (key_size == 24 || key_size == 32)
		{
		/*------------------------------------------.
		| Calculate the third word of the S vector. |
		'------------------------------------------*/
		S(si, sj, sk, sl, 16, 0x00, 0x2D, 0x01, 0x2D); /* 01 A4 02 A4 */
		S(si, sj, sk, sl, 17, 0x2D, 0xA4, 0x44, 0x8A); /* A4 56 A1 55 */
		S(si, sj, sk, sl, 18, 0x8A, 0xD5, 0xBF, 0xD1); /* 55 82 FC 87 */
		S(si, sj, sk, sl, 19, 0xD1, 0x7F, 0x3D, 0x99); /* 87 F3 C1 5A */
		S(si, sj, sk, sl, 20, 0x99, 0x46, 0x66, 0x96); /* 5A 1E 47 58 */
		S(si, sj, sk, sl, 21, 0x96, 0x3C, 0x5B, 0xED); /* 58 C6 AE DB */
		S(si, sj, sk, sl, 22, 0xED, 0x37, 0x4F, 0xE0); /* DB 68 3D 9E */
		S(si, sj, sk, sl, 23, 0xE0, 0xD0, 0x8C, 0x17); /* 9E E5 19 03 */
		}

	/*---------------.
	| 256-bit key... |
	'---------------*/
	if (key_size == 32)
		{
		/*-------------------------------------------.
		| Calculate the fourth word of the S vector. |
		'-------------------------------------------*/
		S(sm, sn, so, sp, 24, 0x00, 0x2D, 0x01, 0x2D); /* 01 A4 02 A4 */
		S(sm, sn, so, sp, 25, 0x2D, 0xA4, 0x44, 0x8A); /* A4 56 A1 55 */
		S(sm, sn, so, sp, 26, 0x8A, 0xD5, 0xBF, 0xD1); /* 55 82 FC 87 */
		S(sm, sn, so, sp, 27, 0xD1, 0x7F, 0x3D, 0x99); /* 87 F3 C1 5A */
		S(sm, sn, so, sp, 28, 0x99, 0x46, 0x66, 0x96); /* 5A 1E 47 58 */
		S(sm, sn, so, sp, 29, 0x96, 0x3C, 0x5B, 0xED); /* 58 C6 AE DB */
		S(sm, sn, so, sp, 30, 0xED, 0x37, 0x4F, 0xE0); /* DB 68 3D 9E */
		S(sm, sn, so, sp, 31, 0xE0, 0xD0, 0x8C, 0x17); /* 9E E5 19 03 */

		/*---------------------.
		| Compute the S-boxes. |
		'---------------------*/
		for (i = j = 0, k = 1; i < 256; i++, j += 2, k += 2)
			SB256_2(i, calc_sb_tbl[j], calc_sb_tbl[k])

		/*---------------------------------------.
		| Calculate whitening and round subkeys. |
		'---------------------------------------*/
		for (i = 0; i <  8; i += 2) K256(w, i, q0[i    ], q1[i	  ], q0[i + 1], q1[i + 1])
		for (i = 0; i < 32; i += 2) K256(k, i, q0[i + 8], q1[i + 8], q0[i + 9], q1[i + 9])
		}

	else if (key_size == 24)  /* 192-bit key */
		{
		/*---------------------.
		| Compute the S-boxes. |
		'---------------------*/
		for (i = j = 0, k = 1; i < 256; i++, j += 2, k += 2)
		        SB192_2(i, calc_sb_tbl[j], calc_sb_tbl[k])

		/*---------------------------------------.
		| Calculate whitening and round subkeys. |
		'---------------------------------------*/
		for (i = 0; i <  8; i += 2) K192(w, i, q0[i    ], q1[i	  ], q0[i + 1], q1[i + 1])
		for (i = 0; i < 32; i += 2) K192(k, i, q0[i + 8], q1[i + 8], q0[i + 9], q1[i + 9])
		}

	/*---------------.
	| 128-bit key... |
	'---------------*/
	else	{
		/*---------------------.
		| Compute the S-boxes. |
		'---------------------*/
		for (i = j = 0, k = 1; i < 256; i++, j += 2, k += 2)
			SB_2(i, calc_sb_tbl[j], calc_sb_tbl[k])

		/*---------------------------------------.
		| Calculate whitening and round subkeys. |
		'---------------------------------------*/
		for (i = 0; i <  8; i += 2) K(w, i, q0[i    ], q1[i    ], q0[i + 1], q1[i + 1])
		for (i = 0; i < 32; i += 2) K(k, i, q0[i + 8], q1[i + 8], q0[i + 9], q1[i + 9])
		}
	}


/*------------------------------------------------------------.
| Macros to compute the g() function in the ciphering rounds. |
| G1 is the straight g() function.			      |
| G2 includes the 8-bit rotation for the high 32-bit word.    |
'------------------------------------------------------------*/

#define G1(a)				     \
	(object->s[0][ (a)	  & 0xFF]) ^ \
	(object->s[1][((a) >>  8) & 0xFF]) ^ \
	(object->s[2][((a) >> 16) & 0xFF]) ^ \
	(object->s[3][ (a) >> 24	])

#define G2(b)				     \
	(object->s[1][ (b)	  & 0xFF]) ^ \
	(object->s[2][((b) >>  8) & 0xFF]) ^ \
	(object->s[3][((b) >> 16) & 0xFF]) ^ \
	(object->s[0][ (b) >> 24	])

/*----------------------------------------------------------------------------.
| Ciphering Feistel rounds. Each one calls the two Gn() macros, does the PHT, |
| and performs the XOR and the appropriate bit rotations.		      |
| The parameters are the round number (used to select subkeys), and the four  |
| 32-bit chunks of the text.						      |
'----------------------------------------------------------------------------*/

#define ENCIPHERING_ROUND(n, a, b, c, d)      \
	x    = G1(a);			      \
	y    = G2(b);			      \
	x   += y;			      \
	y   += x + object->k[2 * (n) + 1];    \
	(c) ^= x + object->k[2 * (n)	];    \
	(c)  = z_uint32_rotate_right((c), 1); \
	(d)  = z_uint32_rotate_left ((d), 1) ^ y

#define DECIPHERING_ROUND(n, a, b, c, d)      \
	x    = G1(a);			      \
	y    = G2(b);			      \
	x   += y;			      \
	y   += x;			      \
	(d) ^= y + object->k[2 * (n) + 1];    \
	(d)  = z_uint32_rotate_right((d), 1); \
	(c)  = z_uint32_rotate_left ((c), 1); \
	(c) ^= (x + object->k[2 * (n)])

/*----------------------------------------------------------.
| Ciphering cycles. Each one is simply two Feistel rounds   |
| with the 32-bit chunks re-ordered to simulate the "swap". |
'----------------------------------------------------------*/

#define ENCIPHERING_CYCLE(n)			    \
	ENCIPHERING_ROUND(2 * (n),     a, b, c, d); \
	ENCIPHERING_ROUND(2 * (n) + 1, c, d, a, b)

#define DECIPHERING_CYCLE(n)			    \
	DECIPHERING_ROUND(2 * (n) + 1, c, d, a, b); \
	DECIPHERING_ROUND(2 * (n),     a, b, c, d)

/*----------------------------------------------------------------.
| Macros to convert the input and output bytes into 32-bit words, |
| and simultaneously perform the whitening step. INPUT packs word |
| number n into the variable named by x, using whitening subkey	  |
| number m. OUTPUT unpacks word number n from the variable named  |
| by x, using whitening subkey number m.			  |
'----------------------------------------------------------------*/

#define INPUT(n, x, m) \
	x = z_uint32_little_endian(block[n]) ^ object->w[m]

#define OUTPUT(n, x, m)	   \
	x ^= object->w[m]; \
	output[n] = z_uint32_little_endian(x)


CIPHER_TWOFISH_API
void twofish_encipher(Twofish *object, const zuint32 *block, zsize block_size, zuint32 *output)
	{
	zuint32 a, b, c, d, x, y;

	for (block_size >>= 4; block_size; block_size--, block += 4, output += 4)
		{
		/*-----------------------------.
		| Input whitening and packing. |
		'-----------------------------*/
		INPUT(0, a, 0);
		INPUT(1, b, 1);
		INPUT(2, c, 2);
		INPUT(3, d, 3);
	
		/*----------------------------.
		| Enciphering Feistel cycles. |
		'----------------------------*/
		ENCIPHERING_CYCLE(0);
		ENCIPHERING_CYCLE(1);
		ENCIPHERING_CYCLE(2);
		ENCIPHERING_CYCLE(3);
		ENCIPHERING_CYCLE(4);
		ENCIPHERING_CYCLE(5);
		ENCIPHERING_CYCLE(6);
		ENCIPHERING_CYCLE(7);
	
		/*--------------------------------.
		| Output whitening and unpacking. |
		'--------------------------------*/
		OUTPUT(0, c, 4);
		OUTPUT(1, d, 5);
		OUTPUT(2, a, 6);
		OUTPUT(3, b, 7);
		}
	}


CIPHER_TWOFISH_API
void twofish_decipher(Twofish *object, const zuint32 *block, zsize block_size, zuint32 *output)
	{
	zuint32 a, b, c, d, x, y;

	for (block_size >>= 4; block_size; block_size--, block += 4, output += 4)
		{
		/*-----------------------------.
		| Input whitening and packing. |
		'-----------------------------*/
		INPUT(0, c, 4);
		INPUT(1, d, 5);
		INPUT(2, a, 6);
		INPUT(3, b, 7);
	
		/*----------------------------.
		| Deciphering Feistel cycles. |
		'----------------------------*/
		DECIPHERING_CYCLE(7);
		DECIPHERING_CYCLE(6);
		DECIPHERING_CYCLE(5);
		DECIPHERING_CYCLE(4);
		DECIPHERING_CYCLE(3);
		DECIPHERING_CYCLE(2);
		DECIPHERING_CYCLE(1);
		DECIPHERING_CYCLE(0);

		/*--------------------------------.
		| Output whitening and unpacking. |
		'--------------------------------*/
		OUTPUT(0, a, 0);
		OUTPUT(1, b, 1);
		OUTPUT(2, c, 2);
		OUTPUT(3, d, 3);
		}
	}


#if DEFINED(BUILD_ABI) || DEFINED(BUILD_MODULE_ABI)

	CIPHER_TWOFISH_ABI ZCipherABI const abi_cipher_twofish = {
		/* test_key		 */ NULL,
		/* set_key		 */ (ZCipherSetKey )twofish_set_key,
		/* encipher		 */ (ZCipherProcess)twofish_encipher,
		/* decipher		 */ (ZCipherProcess)twofish_decipher,
		/* enciphering_size	 */ NULL,
		/* deciphering_size	 */ NULL,
		/* instance_size	 */ sizeof(Twofish),
		/* key_minimum_size	 */ TWOFISH_KEY_MINIMUM_SIZE,
		/* key_maximum_size	 */ TWOFISH_KEY_MAXIMUM_SIZE,
		/* key_word_size	 */ TWOFISH_KEY_WORD_SIZE,
		/* enciphering_word_size */ TWOFISH_WORD_SIZE,
		/* deciphering_word_size */ TWOFISH_WORD_SIZE,
		/* features		 */ FALSE
	};

#endif

#if DEFINED(BUILD_MODULE_ABI)

#	include <Z/ABIs/generic/module.h>

	static zcharacter const information[] =
		"C1998 Matthew Skala\n"
		"C1998 Werner Koch\n"
		"CMarc Mutz\n"
		"CColin Slater\n"
		"C2011-2016 Manuel Sainz de Baranda y Goñi\n"
		"LLGPLv3";

	static ZModuleUnit const unit = {
		"Twofish", "Twofish", Z_VERSION(1, 0, 0), information, &abi_cipher_twofish
	};

	static ZModuleDomain const domain = {"cipher", Z_VERSION(1, 0, 0), 1, &unit};
	Z_API_WEAK_EXPORT ZModuleABI const __module_abi__ = {1, &domain};

#endif


/* Twofish.c EOF */
