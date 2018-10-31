#ifndef TDES_H
#define TDES_H

#include<stdint.h>

uint64_t TDES_Encrypt(uint64_t text_block, uint64_t key1, uint64_t key2, uint64_t key3);
uint64_t TDES_Decrypt(uint64_t cypher_block, uint64_t key1, uint64_t key2, uint64_t key3);

#endif
