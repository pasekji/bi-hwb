#include <stdio.h>
#include <stdint.h>
#include <cstdlib>
#include <chrono>
#include <iostream>


/* AES-128 simple implementation template and testing */

/*
Author: Jiri Pasek, pasekji1@fit.cvut.cz
Template: Jiri Bucek 2017
AES specification:
http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
*/

/* AES Constants */

// source: https://cryptography.fandom.com/wiki/Rijndael_S-box
const uint8_t SBOX[256] =  
{0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,0x30 ,0x01 ,0x67 ,0x2b ,0xfe ,0xd7 ,0xab ,0x76
 ,0xca ,0x82 ,0xc9 ,0x7d ,0xfa ,0x59 ,0x47 ,0xf0 ,0xad ,0xd4 ,0xa2 ,0xaf ,0x9c ,0xa4 ,0x72 ,0xc0
 ,0xb7 ,0xfd ,0x93 ,0x26 ,0x36 ,0x3f ,0xf7 ,0xcc ,0x34 ,0xa5 ,0xe5 ,0xf1 ,0x71 ,0xd8 ,0x31 ,0x15
 ,0x04 ,0xc7 ,0x23 ,0xc3 ,0x18 ,0x96 ,0x05 ,0x9a ,0x07 ,0x12 ,0x80 ,0xe2 ,0xeb ,0x27 ,0xb2 ,0x75
 ,0x09 ,0x83 ,0x2c ,0x1a ,0x1b ,0x6e ,0x5a ,0xa0 ,0x52 ,0x3b ,0xd6 ,0xb3 ,0x29 ,0xe3 ,0x2f ,0x84
 ,0x53 ,0xd1 ,0x00 ,0xed ,0x20 ,0xfc ,0xb1 ,0x5b ,0x6a ,0xcb ,0xbe ,0x39 ,0x4a ,0x4c ,0x58 ,0xcf
 ,0xd0 ,0xef ,0xaa ,0xfb ,0x43 ,0x4d ,0x33 ,0x85 ,0x45 ,0xf9 ,0x02 ,0x7f ,0x50 ,0x3c ,0x9f ,0xa8
 ,0x51 ,0xa3 ,0x40 ,0x8f ,0x92 ,0x9d ,0x38 ,0xf5 ,0xbc ,0xb6 ,0xda ,0x21 ,0x10 ,0xff ,0xf3 ,0xd2
 ,0xcd ,0x0c ,0x13 ,0xec ,0x5f ,0x97 ,0x44 ,0x17 ,0xc4 ,0xa7 ,0x7e ,0x3d ,0x64 ,0x5d ,0x19 ,0x73
 ,0x60 ,0x81 ,0x4f ,0xdc ,0x22 ,0x2a ,0x90 ,0x88 ,0x46 ,0xee ,0xb8 ,0x14 ,0xde ,0x5e ,0x0b ,0xdb
 ,0xe0 ,0x32 ,0x3a ,0x0a ,0x49 ,0x06 ,0x24 ,0x5c ,0xc2 ,0xd3 ,0xac ,0x62 ,0x91 ,0x95 ,0xe4 ,0x79
 ,0xe7 ,0xc8 ,0x37 ,0x6d ,0x8d ,0xd5 ,0x4e ,0xa9 ,0x6c ,0x56 ,0xf4 ,0xea ,0x65 ,0x7a ,0xae ,0x08
 ,0xba ,0x78 ,0x25 ,0x2e ,0x1c ,0xa6 ,0xb4 ,0xc6 ,0xe8 ,0xdd ,0x74 ,0x1f ,0x4b ,0xbd ,0x8b ,0x8a
 ,0x70 ,0x3e ,0xb5 ,0x66 ,0x48 ,0x03 ,0xf6 ,0x0e ,0x61 ,0x35 ,0x57 ,0xb9 ,0x86 ,0xc1 ,0x1d ,0x9e
 ,0xe1 ,0xf8 ,0x98 ,0x11 ,0x69 ,0xd9 ,0x8e ,0x94 ,0x9b ,0x1e ,0x87 ,0xe9 ,0xce ,0x55 ,0x28 ,0xdf
 ,0x8c ,0xa1 ,0x89 ,0x0d ,0xbf ,0xe6 ,0x42 ,0x68 ,0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16};

const uint8_t rCon[12] = 
{
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

/* AES state type */
typedef uint32_t t_state[4];

/* Helper functions */
void hexprint16(uint8_t *p)
{
	for (int i = 0; i < 16; i++)
		printf("%02hhx ", p[i]);
	puts("");
}

void hexprintw(uint32_t w)
{
	for (int i = 0; i < 32; i += 8)
		printf("%02hhx ", (w >> i) & 0xffU);
}

void hexprintws(uint32_t * p, int cnt)
{
	for (int i = 0; i < cnt; i++)
		hexprintw(p[i]);
	puts("");
}

void printstate(t_state s) // prints state
{
	hexprintw(s[0]);
	hexprintw(s[1]);
	hexprintw(s[2]);
	hexprintw(s[3]);
	puts("");
}

inline uint32_t word(uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3) // return whole word into uint32
{
	return a0 | (uint32_t)a1 << 8 | (uint32_t)a2 << 16 | (uint32_t)a3 << 24;
}

inline uint8_t wbyte(uint32_t w, int pos) // returns one byte out of word at pos
{
	return (w >> (pos * 8)) & 0xff;
}

// **************** AES  functions ****************
uint32_t subWord(uint32_t w)
{
	return word(SBOX[wbyte(w, 0)], SBOX[wbyte(w, 1)], SBOX[wbyte(w, 2)], SBOX[wbyte(w, 3)]);
}

uint32_t rotWord(uint32_t w)
{
	return word(wbyte(w, 1), wbyte(w, 2), wbyte(w, 3), wbyte(w, 0));
}

void subBytes(t_state s)
{
	for(unsigned int i = 0; i < 4; i++) 		// cycle trough words 
	{
		uint8_t bytes[4];
		for(unsigned int j = 0; j < 4; j++)		// cycle through bytes 
		{
			bytes[j] = wbyte(s[i], j);
			bytes[j] = SBOX[bytes[j]];
		}
		s[i] = word(bytes[0], bytes[1], bytes[2], bytes[3]);
	}
}

void shiftRows(t_state s)
{
	uint8_t tempArray[16];
	uint8_t tempArray1[16];
	tempArray[0] = wbyte(s[0], 0);
	tempArray[1] = wbyte(s[0], 1);
	tempArray[2] = wbyte(s[0], 2);
	tempArray[3] = wbyte(s[0], 3);
	
	tempArray[4] = wbyte(s[1], 0);
	tempArray[5] = wbyte(s[1], 1);
	tempArray[6] = wbyte(s[1], 2);
	tempArray[7] = wbyte(s[1], 3);

	tempArray[8] = wbyte(s[2], 0);
	tempArray[9] = wbyte(s[2], 1);
	tempArray[10] = wbyte(s[2], 2);
	tempArray[11] = wbyte(s[2], 3);

	tempArray[12] = wbyte(s[3], 0);
	tempArray[13] = wbyte(s[3], 1);
	tempArray[14] = wbyte(s[3], 2);
	tempArray[15] = wbyte(s[3], 3);

	tempArray1[0] = tempArray[0];
	tempArray1[1] = tempArray[5];
	tempArray1[2] = tempArray[10];
	tempArray1[3] = tempArray[15];

	tempArray1[4] = tempArray[4];
	tempArray1[5] = tempArray[9];
	tempArray1[6] = tempArray[14];
	tempArray1[7] = tempArray[3];

	tempArray1[8] = tempArray[8];
	tempArray1[9] = tempArray[13];
	tempArray1[10] = tempArray[2];
	tempArray1[11] = tempArray[7];

	tempArray1[12] = tempArray[12];
	tempArray1[13] = tempArray[1];
	tempArray1[14] = tempArray[6];
	tempArray1[15] = tempArray[11];

	s[0] = word(tempArray1[0], tempArray1[1], tempArray1[2], tempArray1[3]);
	s[1] = word(tempArray1[4], tempArray1[5], tempArray1[6], tempArray1[7]);
	s[2] = word(tempArray1[8], tempArray1[9], tempArray1[10], tempArray1[11]);
	s[3] = word(tempArray1[12], tempArray1[13], tempArray1[14], tempArray1[15]);
}

// source: https://groups.google.com/g/sci.crypt/c/Exrm5l0WePY?pli=1
uint8_t xtime(uint8_t a)
{
	return (a << 1) ^ (a & 0x80 ? 0x1b : 0);
}

// not mandatory - mix a single column
uint32_t mixColumn(uint32_t c) {
	return 0; /* ??? */
}

void mixColumns(t_state s)
{
	uint8_t tempArray[16];
	uint8_t tempArray1[16];
	tempArray[0] = wbyte(s[0], 0);
	tempArray[1] = wbyte(s[0], 1);
	tempArray[2] = wbyte(s[0], 2);
	tempArray[3] = wbyte(s[0], 3);
	
	tempArray[4] = wbyte(s[1], 0);
	tempArray[5] = wbyte(s[1], 1);
	tempArray[6] = wbyte(s[1], 2);
	tempArray[7] = wbyte(s[1], 3);

	tempArray[8] = wbyte(s[2], 0);
	tempArray[9] = wbyte(s[2], 1);
	tempArray[10] = wbyte(s[2], 2);
	tempArray[11] = wbyte(s[2], 3);

	tempArray[12] = wbyte(s[3], 0);
	tempArray[13] = wbyte(s[3], 1);
	tempArray[14] = wbyte(s[3], 2);
	tempArray[15] = wbyte(s[3], 3);

	tempArray1[0] = (uint8_t)(xtime(tempArray[0]) ^ (tempArray[1] ^ xtime(tempArray[1])) ^ tempArray[2] ^ tempArray[3]);
	tempArray1[1] = (uint8_t)(tempArray[0] ^ xtime(tempArray[1]) ^ (tempArray[2] ^ xtime(tempArray[2])) ^ tempArray[3]);
	tempArray1[2] = (uint8_t)(tempArray[0] ^ tempArray[1] ^ xtime(tempArray[2]) ^ (tempArray[3] ^ xtime(tempArray[3])));
	tempArray1[3] = (uint8_t)((tempArray[0] ^ xtime(tempArray[0])) ^ tempArray[1] ^ tempArray[2] ^ xtime(tempArray[3]));

	tempArray1[4] = (uint8_t)(xtime(tempArray[4]) ^ (tempArray[5] ^ xtime(tempArray[5])) ^ tempArray[6] ^ tempArray[7]);
	tempArray1[5] = (uint8_t)(tempArray[4] ^ xtime(tempArray[5]) ^ (tempArray[6] ^ xtime(tempArray[6])) ^ tempArray[7]);
	tempArray1[6] = (uint8_t)(tempArray[4] ^ tempArray[5] ^ xtime(tempArray[6]) ^ (tempArray[7] ^ xtime(tempArray[7])));
	tempArray1[7] = (uint8_t)((tempArray[4] ^ xtime(tempArray[4])) ^ tempArray[5] ^ tempArray[6] ^ xtime(tempArray[7]));

	tempArray1[8] = (uint8_t)(xtime(tempArray[8]) ^ (tempArray[9] ^ xtime(tempArray[9])) ^ tempArray[10] ^ tempArray[11]);
	tempArray1[9] = (uint8_t)(tempArray[8] ^ xtime(tempArray[9]) ^ (tempArray[10] ^ xtime(tempArray[10])) ^ tempArray[11]);
	tempArray1[10] = (uint8_t)(tempArray[8] ^ tempArray[9] ^ xtime(tempArray[10]) ^ (tempArray[11] ^ xtime(tempArray[11])));
	tempArray1[11] = (uint8_t)((tempArray[8] ^ xtime(tempArray[8])) ^ tempArray[9] ^ tempArray[10] ^ xtime(tempArray[11]));

	tempArray1[12] = (uint8_t)(xtime(tempArray[12]) ^ (tempArray[13] ^ xtime(tempArray[13])) ^ tempArray[14] ^ tempArray[15]);
	tempArray1[13] = (uint8_t)(tempArray[12] ^ xtime(tempArray[13]) ^ (tempArray[14] ^ xtime(tempArray[14])) ^ tempArray[15]);
	tempArray1[14] = (uint8_t)(tempArray[12] ^ tempArray[13] ^ xtime(tempArray[14]) ^ (tempArray[15] ^ xtime(tempArray[15])));
	tempArray1[15] = (uint8_t)((tempArray[12] ^ xtime(tempArray[12])) ^ tempArray[13] ^ tempArray[14] ^ xtime(tempArray[15]));

	s[0] = word(tempArray1[0], tempArray1[1], tempArray1[2], tempArray1[3]);
	s[1] = word(tempArray1[4], tempArray1[5], tempArray1[6], tempArray1[7]);
	s[2] = word(tempArray1[8], tempArray1[9], tempArray1[10], tempArray1[11]);
	s[3] = word(tempArray1[12], tempArray1[13], tempArray1[14], tempArray1[15]);
}

/*
* Key expansion from 128bits (4*32b)
* to 11 round keys (11*4*32b)
* each round key is 4*32b
*/

// source: https://www.brainkart.com/article/AES-Key-Expansion_8410/
void expandKey(uint8_t k[16], uint32_t ek[44])
{
	ek[0] = word(k[0], k[1], k[2], k[3]);
	ek[1] = word(k[4], k[5], k[6], k[7]);
	ek[2] = word(k[8], k[9], k[10], k[11]);
	ek[3] = word(k[12], k[13], k[14], k[15]);

	uint32_t tmp;
	for(int i = 4; i < 44; i++)
	{
		tmp = ek[i-1];
		if(i % 4 == 0)
			tmp = subWord(rotWord(tmp)) ^ rCon[i/4];
		
		ek[i] = ek[i - 4] ^ tmp;
	}
}

/* Adding expanded round key (prepared before) */
void addRoundKey(t_state s, uint32_t ek[], short index)
{
	s[0] ^= ek[index];
	s[1] ^= ek[index + 1];
	s[2] ^= ek[index + 2];
	s[3] ^= ek[index + 3]; 
}

// source: https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
void aes(uint8_t *in, uint8_t *out, uint32_t * expKey)
{

	t_state state;

	state[0] = word(in[0],  in[1],  in[2],  in[3]);
	state[1] = word(in[4],  in[5],  in[6],  in[7]);
	state[2] = word(in[8],  in[9],  in[10],  in[11]);
	state[3] = word(in[12],  in[13],  in[14],  in[15]);
	

	addRoundKey(state, expKey, 0);

	for(int i = 1; i <= 9 ; i++)
	{
		subBytes(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, expKey, 4*i);
	}

	subBytes(state);
	shiftRows(state);
	addRoundKey(state, expKey, 40);

	for (int i = 0; i < 16; i++)
	{
		if (i < 4) out[i] = wbyte(state[0], i % 4);
		else if (i < 8) out[i] = wbyte(state[1], i % 4);
		else if (i < 12) out[i] = wbyte(state[2], i % 4);
		else out[i] = wbyte(state[3], i % 4);
	}
}

//****************************
// MAIN function: AES testing
//****************************
int main(int argc, char* argv[])
{
	int cycles = 1000000;
	if(argc == 2)
		cycles = atoi(argv[1]);

	uint8_t key[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	uint8_t in[16] =  { 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89};
	uint32_t expKey[44];
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

	return  in[0];
}
