#include <stdio.h>
#include <cstdlib>
#include <chrono>
#include <iostream>
#include <stdint.h>
#include <wmmintrin.h>



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
void expandKey(uint8_t *k, __m128i expKey[11])
{
	__m128i tmp, tmp1, tmp2;
	expKey[0] = _mm_loadu_si128((__m128i*) k);

	tmp = _mm_aeskeygenassist_si128(expKey[0], 0x01);
	tmp = _mm_shuffle_epi32(tmp, 0xff);
	tmp1 = expKey[0];
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	expKey[1] = _mm_xor_si128(tmp1, tmp);

	tmp = _mm_aeskeygenassist_si128(expKey[1], 0x02);
	tmp = _mm_shuffle_epi32(tmp, 0xff);
	tmp1 = expKey[1];
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	expKey[2] = _mm_xor_si128(tmp1, tmp);

	tmp = _mm_aeskeygenassist_si128(expKey[2], 0x04);
	tmp = _mm_shuffle_epi32(tmp, 0xff);
	tmp1 = expKey[2];
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	expKey[3] = _mm_xor_si128(tmp1, tmp);

	tmp = _mm_aeskeygenassist_si128(expKey[3], 0x08);
	tmp = _mm_shuffle_epi32(tmp, 0xff);
	tmp1 = expKey[3];
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	expKey[4] = _mm_xor_si128(tmp1, tmp);

	tmp = _mm_aeskeygenassist_si128(expKey[4], 0x10);
	tmp = _mm_shuffle_epi32(tmp, 0xff);
	tmp1 = expKey[4];
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	expKey[5] = _mm_xor_si128(tmp1, tmp);

	tmp = _mm_aeskeygenassist_si128(expKey[5], 0x20);
	tmp = _mm_shuffle_epi32(tmp, 0xff);
	tmp1 = expKey[5];
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	expKey[6] = _mm_xor_si128(tmp1, tmp);

	tmp = _mm_aeskeygenassist_si128(expKey[6], 0x40);
	tmp = _mm_shuffle_epi32(tmp, 0xff);
	tmp1 = expKey[6];
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	expKey[7] = _mm_xor_si128(tmp1, tmp);

	tmp = _mm_aeskeygenassist_si128(expKey[7], 0x80);
	tmp = _mm_shuffle_epi32(tmp, 0xff);
	tmp1 = expKey[7];
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	expKey[8] = _mm_xor_si128(tmp1, tmp);

	tmp = _mm_aeskeygenassist_si128(expKey[8], 0x1B);
	tmp = _mm_shuffle_epi32(tmp, 0xff);
	tmp1 = expKey[8];
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	expKey[9] = _mm_xor_si128(tmp1, tmp);

	tmp = _mm_aeskeygenassist_si128(expKey[9], 0x36);
	tmp = _mm_shuffle_epi32(tmp, 0xff);
	tmp1 = expKey[9];
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	tmp2 = _mm_slli_si128(tmp1, 4);
	tmp1 = _mm_xor_si128(tmp1, tmp2);
	expKey[10] = _mm_xor_si128(tmp1, tmp);
}

// source: https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
// source: https://gist.github.com/acapola/d5b940da024080dfaf5f
void aes(uint8_t *in, uint8_t *out, __m128i expKey[11])
{
	__m128i tmp = _mm_loadu_si128((__m128i*) in);
	tmp = _mm_xor_si128(tmp, expKey[0]);
	tmp = _mm_aesenc_si128(tmp, expKey[1]);
	tmp = _mm_aesenc_si128(tmp, expKey[2]);
	tmp = _mm_aesenc_si128(tmp, expKey[3]);
	tmp = _mm_aesenc_si128(tmp, expKey[4]);
	tmp = _mm_aesenc_si128(tmp, expKey[5]);
	tmp = _mm_aesenc_si128(tmp, expKey[6]);
	tmp = _mm_aesenc_si128(tmp, expKey[7]);
	tmp = _mm_aesenc_si128(tmp, expKey[8]);
	tmp = _mm_aesenc_si128(tmp, expKey[9]);
	tmp = _mm_aesenclast_si128(tmp, expKey[10]);
	_mm_storeu_si128((__m128i*) out, tmp);
}

//****************************
// MAIN function: AES testing
//****************************
int main(int argc, char* argv[])
{
	// test aes encryption
	int cycles = 1000000;
	if(argc == 2)
		cycles = atoi(argv[1]);

	uint8_t key[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	uint8_t in[16] =  { 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89};
	uint8_t out[16] = { 0, /*...*/ };
	uint8_t res_out[16] = { 0xa3, 0x3a, 0xca, 0x68, 0x72, 0xa2, 0x27, 0x74, 0xbf, 0x99, 0xf3, 0x71, 0xaa, 0x99, 0xd2, 0x5a };
	static __m128i expKey[11];

	expandKey(key, expKey);

	// source: https://en.cppreference.com/w/cpp/chrono
	auto start = std::chrono::high_resolution_clock::now();
	for(int i = 0; i < cycles; i++)
	{
		aes(in, in, expKey);
	}
	auto end = std::chrono::high_resolution_clock::now();
	auto milisec = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
	std::cout << "elapsed time: " << milisec << "ms\n";

	return in[0];
}
