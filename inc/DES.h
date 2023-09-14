#ifndef DES_H
#define DES_H

#include<stdint.h>

void GenSubkey(uint64_t key, uint64_t subkey[16]);

uint64_t DES_Encrypt(uint64_t text_block, uint64_t key);
uint64_t DES_Decrypt(uint64_t cypher_block, uint64_t key);

uint64_t InitPermutation(uint64_t input);
uint64_t FinalPermutation(uint64_t input);

uint32_t Feistel(uint32_t half_block, uint64_t subkey);
uint64_t Expansion(uint32_t half_block);
uint32_t Permutation(uint32_t half_block);
uint32_t Substitution(uint64_t input, const unsigned int SBox[4][16]);

#endif
