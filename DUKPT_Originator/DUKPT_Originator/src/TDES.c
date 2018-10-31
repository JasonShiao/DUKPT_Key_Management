#include"TDES.h"

#include<stdint.h>
#include"DES.h"

uint64_t TDES_Encrypt(uint64_t text_block, uint64_t key1, uint64_t key2, uint64_t key3)
{
	uint64_t result_after_key1;
	uint64_t result_after_key2;
	uint64_t result_after_key3;

	/* For convenience to trace back */
	result_after_key1 = DES_Encrypt(text_block, key1);
	result_after_key2 = DES_Decrypt(result_after_key1, key2);
	result_after_key3 = DES_Encrypt(result_after_key2, key3);

	return result_after_key3;

	/* More compact */
	// return DES_Encrypt(DES_Decrypt(DES_Encrypt(text_block, key1), key2), key3);
	
}

uint64_t TDES_Decrypt(uint64_t cypher_block, uint64_t key1, uint64_t key2, uint64_t key3)
{
	uint64_t result_after_key1;
	uint64_t result_after_key2;
	uint64_t result_after_key3;

	/* For convenience to trace back */
	result_after_key3 = DES_Decrypt(cypher_block, key3);
	result_after_key2 = DES_Encrypt(result_after_key3, key2);
	result_after_key1 = DES_Decrypt(result_after_key2, key1);

	return result_after_key1;

	/* More compact */
	// return DES_Decrypt(DES_Encrypt(DES_Decrypt(cypher_block, key1), key2), key3);
	
}
