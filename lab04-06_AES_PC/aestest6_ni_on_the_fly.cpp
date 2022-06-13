#include <stdio.h>
#include <chrono>
#include <iostream>
#include <stdint.h>
#include <wmmintrin.h>
#include <smmintrin.h> 


/* AES-128 simple implementation template and testing */

/*
Author: Jiri Pasek, pasekji1@fit.cvut.cz
Template: Jiri Bucek 2017
AES specification:
http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
*/


/* Helper functions */
void hexprint16(uint8_t *p) {
	for (int i = 0; i < 16; i++)
		printf("%02hhx ", p[i]);
	puts("");
}

void hexprintw(uint32_t w) {
	for (int i = 0; i < 32; i += 8)
		printf("%02hhx ", (w >> i) & 0xffU);
}

void hexprintws(uint32_t * p, int cnt) {
	for (int i = 0; i < cnt; i++)
		hexprintw(p[i]);
	puts("");
}

// source: https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
// source: https://gist.github.com/acapola/d5b940da024080dfaf5f
void aes(uint8_t *in, uint8_t *out, uint8_t *k)
{
	__m128i tmp, tmp1, tmp2;
	__m128i r = _mm_set_epi32(1,1,1,1);
	__m128i sm = _mm_set_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d); 
	__m128i cipher = _mm_loadu_si128((__m128i*) in);
	tmp = _mm_loadu_si128((__m128i*) k);
	cipher = _mm_xor_si128(cipher, tmp);

	tmp1 = _mm_shuffle_epi8(tmp, sm);
	tmp1 = _mm_aesenclast_si128(tmp1, r);
	r = _mm_slli_epi32(r,1);
	tmp2 = _mm_slli_si128(tmp, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp = _mm_xor_si128(tmp, tmp1);
	cipher = _mm_aesenc_si128(cipher, tmp);

	tmp1 = _mm_shuffle_epi8(tmp, sm);
	tmp1 = _mm_aesenclast_si128(tmp1, r);
	r = _mm_slli_epi32(r,1);
	tmp2 = _mm_slli_si128(tmp, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp = _mm_xor_si128(tmp, tmp1);
	cipher = _mm_aesenc_si128(cipher, tmp);

	tmp1 = _mm_shuffle_epi8(tmp, sm);
	tmp1 = _mm_aesenclast_si128(tmp1, r);
	r = _mm_slli_epi32(r,1);
	tmp2 = _mm_slli_si128(tmp, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp = _mm_xor_si128(tmp, tmp1);
	cipher = _mm_aesenc_si128(cipher, tmp);

	tmp1 = _mm_shuffle_epi8(tmp, sm);
	tmp1 = _mm_aesenclast_si128(tmp1, r);
	r = _mm_slli_epi32(r,1);
	tmp2 = _mm_slli_si128(tmp, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp = _mm_xor_si128(tmp, tmp1);
	cipher = _mm_aesenc_si128(cipher, tmp);

	tmp1 = _mm_shuffle_epi8(tmp, sm);
	tmp1 = _mm_aesenclast_si128(tmp1, r);
	r = _mm_slli_epi32(r,1);
	tmp2 = _mm_slli_si128(tmp, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp = _mm_xor_si128(tmp, tmp1);
	cipher = _mm_aesenc_si128(cipher, tmp);

	tmp1 = _mm_shuffle_epi8(tmp, sm);
	tmp1 = _mm_aesenclast_si128(tmp1, r);
	r = _mm_slli_epi32(r,1);
	tmp2 = _mm_slli_si128(tmp, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp = _mm_xor_si128(tmp, tmp1);
	cipher = _mm_aesenc_si128(cipher, tmp);

	tmp1 = _mm_shuffle_epi8(tmp, sm);
	tmp1 = _mm_aesenclast_si128(tmp1, r);
	r = _mm_slli_epi32(r,1);
	tmp2 = _mm_slli_si128(tmp, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp = _mm_xor_si128(tmp, tmp1);
	cipher = _mm_aesenc_si128(cipher, tmp);

	tmp1 = _mm_shuffle_epi8(tmp, sm);
	tmp1 = _mm_aesenclast_si128(tmp1, r);
	r = _mm_slli_epi32(r,1);
	tmp2 = _mm_slli_si128(tmp, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp = _mm_xor_si128(tmp, tmp1);
	cipher = _mm_aesenc_si128(cipher, tmp);

	r = _mm_set_epi32(0x1b,0x1b,0x1b,0x1b);
	tmp1 = _mm_shuffle_epi8(tmp, sm);
	tmp1 = _mm_aesenclast_si128(tmp1, r);
	r = _mm_slli_epi32(r, 1);
	tmp2 = _mm_slli_si128(tmp, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp = _mm_xor_si128(tmp, tmp1);
	cipher = _mm_aesenc_si128(cipher, tmp);

	tmp1 = _mm_shuffle_epi8(tmp, sm);
	tmp1 = _mm_aesenclast_si128(tmp1, r);
	tmp2 = _mm_slli_si128(tmp, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp2 = _mm_slli_si128(tmp2, 0x4);
	tmp = _mm_xor_si128(tmp, tmp2);
	tmp = _mm_xor_si128(tmp, tmp1);
	cipher = _mm_aesenclast_si128(cipher, tmp);

	_mm_storeu_si128((__m128i*) out, cipher);
}

//****************************
// MAIN function: AES testing
//****************************
int main(int argc, char* argv[])
{
	// test aes encryption
	// test aes encryption
	int cycles = 1000000;
	if(argc == 2)
		cycles = atoi(argv[1]);

	uint8_t key[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	uint8_t in[16] =  { 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89};
	uint8_t out[16] = { 0, /*...*/ };
	uint8_t res_out[16] = { 0xa3, 0x3a, 0xca, 0x68, 0x72, 0xa2, 0x27, 0x74, 0xbf, 0x99, 0xf3, 0x71, 0xaa, 0x99, 0xd2, 0x5a };

	// source: https://en.cppreference.com/w/cpp/chrono
	auto start = std::chrono::high_resolution_clock::now();
	for(int i = 0; i < cycles; i++)
	{
		aes(in, in, key);
	}
	auto end = std::chrono::high_resolution_clock::now();
	auto milisec = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
	std::cout << "elapsed time: " << milisec << "ms\n";

	return in[0];
}
