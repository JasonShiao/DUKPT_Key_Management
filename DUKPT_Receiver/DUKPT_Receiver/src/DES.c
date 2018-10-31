#include"DES.h"

#include<stdint.h>

//#define DEBUG_MSG

static const unsigned int SBox[8][4][16] = {
{
	{ 14, 4, 13, 1,  2, 15, 11, 8,  3, 10, 6, 12,   5, 9, 0, 7 },
	{ 0, 15, 7, 4,   14, 2, 13, 1,  10, 6, 12, 11,  9, 5, 3, 8 },
	{ 4, 1, 14, 8,   13, 6, 2, 11,  15, 12, 9, 7,   3, 10, 5, 0 },
	{ 15, 12, 8, 2,  4, 9, 1, 7,    5, 11, 3, 14,   10, 0, 6, 13 }
},

{
	{ 15, 1, 8, 14,  6, 11, 3, 4,   9, 7, 2, 13,  12, 0, 5, 10 },
	{ 3, 13, 4, 7,   15, 2, 8, 14,  12, 0, 1, 10,  6, 9, 11, 5 },
	{ 0, 14, 7, 11,  10, 4, 13, 1,  5, 8, 12, 6,   9, 3, 2, 15 },
	{ 13, 8, 10, 1,  3, 15, 4, 2,   11, 6, 7, 12,  0, 5, 14, 9 }
},

{
	{ 10, 0, 9, 14,  6, 3, 15, 5,  1, 13, 12, 7,  11, 4, 2, 8 },
	{ 13, 7, 0, 9,   3, 4, 6, 10,  2, 8, 5, 14,   12, 11, 15, 1 },
	{ 13, 6, 4, 9,   8, 15, 3, 0,  11, 1, 2, 12,  5, 10, 14, 7 },
	{ 1, 10, 13, 0,  6, 9, 8, 7,   4, 15, 14, 3,  11, 5, 2, 12 }
},

{
	{ 7, 13, 14, 3,  0, 6, 9, 10,    1, 2, 8, 5,    11, 12, 4, 15 },
	{ 13, 8, 11, 5,  6, 15, 0, 3,    4, 7, 2, 12,   1, 10, 14, 9 },
	{ 10, 6, 9, 0,   12, 11, 7, 13,  15, 1, 3, 14,  5, 2, 8, 4 },
	{ 3, 15, 0, 6,   10, 1, 13, 8,   9, 4, 5, 11,   12, 7, 2, 14 }
},

{
	{ 2, 12, 4, 1,    7, 10, 11, 6,  8, 5, 3, 15,   13, 0, 14, 9 },
	{ 14, 11, 2, 12,  4, 7, 13, 1,   5, 0, 15, 10,  3, 9, 8, 6 },
	{ 4, 2, 1, 11,    10, 13, 7, 8,  15, 9, 12, 5,  6, 3, 0, 14 },
	{ 11, 8, 12, 7,   1, 14, 2, 13,  6, 15, 0, 9,   10, 4, 5, 3 }
},

{
	{ 12, 1, 10, 15,  9, 2, 6, 8,   0, 13, 3, 4,   14, 7, 5, 11 },
	{ 10, 15, 4, 2,   7, 12, 9, 5,  6, 1, 13, 14,  0, 11, 3, 8 },
	{ 9, 14, 15, 5,   2, 8, 12, 3,  7, 0, 4, 10,   1, 13, 11, 6 },
	{ 4, 3, 2, 12,    9, 5, 15, 10, 11, 14, 1, 7,  6, 0, 8, 13 }
},

{
	{ 4, 11, 2, 14,  15, 0, 8, 13,  3, 12, 9, 7,   5, 10, 6, 1 },
	{ 13, 0, 11, 7,  4, 9, 1, 10,   14, 3, 5, 12,  2, 15, 8, 6 },
	{ 1, 4, 11, 13,  12, 3, 7, 14,  10, 15, 6, 8,  0, 5, 9, 2 },
	{ 6, 11, 13, 8,  1, 4, 10, 7,   9, 5, 0, 15,   14, 2, 3, 12 }
},

{
	{ 13, 2, 8, 4,   6, 15, 11, 1,  10, 9, 3, 14,  5, 0, 12, 7 },
	{ 1, 15, 13, 8,  10, 3, 7, 4,   12, 5, 6, 11,  0, 14, 9, 2 },
	{ 7, 11, 4, 1,   9, 12, 14, 2,  0, 6, 10, 13,  15, 3, 5, 8 },
	{ 2, 1, 14, 7,   4, 10, 8, 13,  15, 12, 9, 0,  3, 5, 6, 11 }
}
};


void GenSubkey(uint64_t key, uint64_t subkey[16])
{
	/* PC-1 */
	/* only the 56 bits of the 64 bits of key is used */
	/* (8, 16, 24, 32, 40, 48, 56, 64) bits were specified for use as parity bits */
	const int PC_1_table_left[28] = {	57, 49, 41, 33, 25, 17, 9,
										1, 58, 50, 42, 34, 26, 18,
										10, 2, 59, 51, 43, 35, 27,
										19, 11, 3, 60, 52, 44, 36 };

	const int PC_1_table_right[28] = {	63, 55, 47, 39, 31, 23, 15,
										7, 62, 54, 46, 38, 30, 22,
										14, 6, 61, 53, 45, 37, 29,
										21, 13, 5, 28, 20, 12, 4 };

	const int PC_2_table[48] = {14, 17, 11, 24, 1, 5,
								3, 28, 15, 6, 21, 10,
								23, 19, 12, 4, 26, 8,
								16, 7, 27, 20, 13, 2,
								41, 52, 31, 37, 47, 55,
								30, 40, 51, 45, 33, 48,
								44, 49, 39, 56, 34, 53,
								46, 42, 50, 36, 29, 32 };

	const int shift_table[16] = { 1, 1, 2, 2, 2, 2, 2, 2,
								  1, 2, 2, 2, 2, 2, 2, 1 };

	uint64_t left_half = 0x0;
	uint64_t right_half = 0x0;

	/* Left half 28 bits */
	for (int i = 0; i < 28; i++)
	{
		if (key & ((uint64_t)1U << (64 - PC_1_table_left[i])))
			left_half |= (uint64_t)1U << (27 - i);
	}
#ifdef DEBUG_MSG
	printf("Subkeys: CnDn\n");
	printf("C0: %016llx\n", left_half);
#endif

	/* Right half 28 bits*/
	for (int i = 0; i < 28; i++)
	{
		if (key & ((uint64_t)1U << (64 - PC_1_table_right[i])))
			right_half |= (uint64_t)1U << (27 - i);
	}
#ifdef DEBUG_MSG
	printf("D0: %016llx\n", right_half);
#endif

	/* 16 rounds for 16 subkeys */
	for (int i = 0; i < 16; i++)
	{
		/* Rotate left_half and right_half "n" bits left */
		for (int j = 0; j < shift_table[i]; j++)
		{
			left_half = (((left_half << 1) & (uint64_t)0xfffffff) | (left_half >> 27));
			right_half = (((right_half << 1) & (uint64_t)0xfffffff) | (right_half >> 27));
		}
#ifdef DEBUG_MSG
		printf("C%d: %016llx\n", i + 1, left_half);
		printf("D%d: %016llx\n", i + 1, right_half);
#endif
		/* merge and permute */
		uint64_t merge = (left_half << 28) | right_half;
		uint64_t result = 0x0;
		/* PC-2 */
		for (int j = 0; j < 48; j++)
		{
			if (merge & ((uint64_t)1U << (56 - PC_2_table[j])))
				result |= (uint64_t)1U << (47 - j);
		}
		subkey[i] = result;
	}

}

uint64_t DES_Encrypt(uint64_t text_block, uint64_t key)
{

	/* Subkey generation */
	uint64_t subkey[16];
	GenSubkey(key, subkey);


	/* Initial Permutation */
	uint64_t permuted_block = InitPermutation(text_block);

	/* initialize left and right half block*/
	uint32_t left_half = (uint32_t)(permuted_block >> 32);
	uint32_t right_half = (uint32_t)(permuted_block);
#ifdef DEBUG_MSG
	printf("Initial left_half: %x\n", left_half);
	printf("Initial right_half: %x\n", right_half);
#endif

	/* 16 rounds */
	for (int i = 0; i < 16; i++)
	{
		uint32_t temp = right_half;
#ifdef DEBUG_MSG
		printf("%d th round - subkey: %016llx\n", i + 1, subkey[i]);
#endif
		right_half = ( Feistel(right_half, subkey[i]) ^ left_half );
		left_half = temp;
#ifdef DEBUG_MSG
		printf("End of %d th round - left half of the next round: %x\n", i+1, left_half);
		printf("End of %d th round - right half of the next round: %x\n", i+1, right_half);
		printf("------------------------------------------------\n");
#endif
	}

	/* swap back right & left and merge into 64-bit */
	uint64_t temp = ( (uint64_t)right_half << 32 | (uint64_t)left_half );
#ifdef DEBUG_MSG
	printf("Before final permutation: %016llx\n", temp);
#endif

	/* Final Permutation */
	return FinalPermutation(temp);

}

uint64_t DES_Decrypt(uint64_t cypher_block, uint64_t key)
{
	/* Subkey generation */
	uint64_t subkey[16];
	GenSubkey(key, subkey);


	/* Initial Permutation */
	uint64_t permuted_block = InitPermutation(cypher_block);

	/* initialize left and right half block*/
	uint32_t left_half = (uint32_t)(permuted_block >> 32);
	uint32_t right_half = (uint32_t)(permuted_block);
#ifdef DEBUG_MSG
	printf("Initial left_half: %x\n", left_half);
	printf("Initial right_half: %x\n", right_half);
#endif

	/* 16 rounds */
	for (int i = 0; i < 16; i++)
	{
		uint32_t temp = right_half;
		right_half = (Feistel(right_half, subkey[15-i]) ^ left_half);
		left_half = temp;
#ifdef DEBUG_MSG
		printf("%d th round - left half: %x\n", i + 1, left_half);
		printf("%d th round - right half: %x\n", i + 1, right_half);
		printf("%d th round - subkey: %016llx\n", i + 1, subkey[i]);
#endif
	}

	/* swap back right & left and merge into 64-bit */
	uint64_t temp = ((uint64_t)right_half << 32 | (uint64_t)left_half);

	/* Final Permutation */
	return FinalPermutation(temp);

}

uint32_t Feistel(uint32_t half_block, uint64_t subkey)
{
	/* Assume subkey exists in the lower 48-bit of 64 bits*/
	uint64_t temp;
	uint32_t result = 0x0;

	temp = Expansion(half_block);
	temp ^= subkey;
#ifdef DEBUG_MSG
	printf("E(R)+K: %016llx\n", temp);
#endif

	for (int i = 0; i < 8; i++)
	{
#ifdef DEBUG_MSG
		printf("Result of S-Box%d: %x\n", i + 1, Substitution((temp >> (7 - i) * 6) & (uint64_t)0b111111, SBox[i]));
#endif
		result |= Substitution( (temp >> (7-i)*6) & (uint64_t)0b111111, SBox[i] ) << ((7-i)*4);
	}
#ifdef DEBUG_MSG
	printf("Result after S-Box: %x\n", result);
#endif

	result = Permutation(result);
#ifdef DEBUG_MSG
	printf("Result of Feistel (32-bit): %x\n", result);
#endif

	return result;
}

uint64_t Expansion(uint32_t half_block)
{
	// Assume data in the lower 32-bit of half_block
	// expanded result will be in the lower 48-bit of expanded_block
	uint64_t expanded_block = 0x0;

	const int expand_table[48] = {	32, 1, 2, 3, 4, 5,
									4, 5, 6, 7, 8, 9,
									8, 9, 10, 11, 12, 13,
									12, 13, 14, 15, 16, 17,
									16, 17, 18, 19, 20, 21,
									20, 21, 22, 23, 24, 25,
									24, 25, 26, 27, 28, 29,
									28, 29, 30, 31, 32, 1 };

	for (int i = 0; i < 48; i++)
	{
		if ( half_block & ( (uint32_t)1U << (32 - expand_table[i]) ) )
			expanded_block |= (uint64_t)1U << (47-i);
	}
#ifdef DEBUG_MSG
	printf("Result after expansion of right half (48-bit): %016llx\n", expanded_block);
#endif
	return expanded_block;
}

/* P-Box in Feistel function */
uint32_t Permutation(uint32_t half_block)
{
	uint32_t result = 0x0;

	const int PBox[32] = {	16, 7, 20, 21, 29, 12, 28, 17,
							1, 15, 23, 26, 5, 18, 31, 10,
							2, 8, 24, 14, 32, 27, 3, 9,
							19, 13, 30, 6, 22, 11, 4, 25 };

	for (int i = 0; i < 32; i++)
	{
		if( half_block & ((uint32_t)1U << (32 - PBox[i])) )
			result |= (uint32_t)1U << (31 - i);
	}

	return result;
}

/* S-Box in Feistel function */
uint32_t Substitution(uint64_t input, const unsigned int SBox[4][16])
{
	// Assume input only exists in the lowest 6-bit
	int row = 0;
	int col = 0;

	if (input & ((uint64_t)1U << 5))
		row += 2;
	if (input & (uint64_t)1U)
		row += 1;

	for (int i = 3; i >= 0; i--)
	{
		if (input & ((uint64_t)1U << (i + 1)))
			col += (1U << i);
	}

	return (uint32_t)(SBox[row][col]);

}


uint64_t InitPermutation(uint64_t input)
{
	const int IP_table[64] = {58, 50, 42, 34, 26, 18, 10, 2,
								60, 52, 44, 36, 28, 20, 12, 4,
								62, 54, 46, 38, 30, 22, 14, 6,
								64, 56, 48, 40, 32, 24, 16, 8,
								57, 49, 41, 33, 25, 17, 9, 1,
								59, 51, 43, 35, 27, 19, 11, 3,
								61, 53, 45, 37, 29, 21, 13, 5,
								63, 55, 47, 39, 31, 23, 15, 7 };
	
	uint64_t result = 0x0;

	for (int i = 0; i < 64; i++)
	{
		if (input & ((uint64_t)1U << (64 - IP_table[i])))
			result |= (uint64_t)1U << (63 - i);
	}

	return result;
}

uint64_t FinalPermutation(uint64_t input)
{
	const int FP_table[64] = {40, 8, 48, 16, 56, 24, 64, 32,
								39, 7, 47, 15, 55, 23, 63, 31,
								38, 6, 46, 14, 54, 22, 62, 30,
								37, 5, 45, 13, 53, 21, 61, 29,
								36, 4, 44, 12, 52, 20, 60, 28,
								35, 3, 43, 11, 51, 19, 59, 27,
								34, 2, 42, 10, 50, 18, 58, 26,
								33, 1, 41, 9, 49, 17, 57, 25 };

	uint64_t result = 0x0;

	for (int i = 0; i < 64; i++)
	{
		if (input & ((uint64_t)1U << (64 - FP_table[i])))
			result |= (uint64_t)1U << (63 - i);
	}

	return result;
}
