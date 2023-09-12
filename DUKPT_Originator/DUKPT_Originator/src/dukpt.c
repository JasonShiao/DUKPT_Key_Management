#include "dukpt.h"
#include "config.h"
#include <assert.h>

void GenerateLRC(FutureKey *FK)
{

	FK->LRC = 0;
	for (int i = 0; i < 4; i++)
	{
		FK->LRC = (FK->LRC + ((uint8_t)(FK->LeftHalf >> i * 8) & (uint8_t)0xFF) & (uint8_t)0xFF);
	}
	for (int i = 0; i < 4; i++)
	{
		FK->LRC = (FK->LRC + ((uint8_t)(FK->RightHalf >> i * 8) & (uint8_t)0xFF) & (uint8_t)0xFF);
	}
	FK->LRC = ((FK->LRC ^ 0xFF) + 1) & 0xFF;

}

int checkLRC(FutureKey *FK)
{
	//FK->LRC = 0;
	uint8_t tempLRC = 0;
	for (int i = 0; i < 4; i++)
	{
		tempLRC = (tempLRC + ((uint8_t)(FK->LeftHalf >> i * 8) & (uint8_t)0xFF) & (uint8_t)0xFF);
	}
	for (int i = 0; i < 4; i++)
	{
		tempLRC = (tempLRC + ((uint8_t)(FK->RightHalf >> i * 8) & (uint8_t)0xFF) & (uint8_t)0xFF);
	}
	tempLRC = ((tempLRC ^ 0xFF) + 1) & 0xFF;

	if (tempLRC == FK->LRC)
	{
		// check pass
		return 0;
	}
	else
	{
		// check fail
		return 1;
	}
}

void CalcIPEK(uint64_t BDK[2], uint8_t KSN[10], uint64_t IPEK[2])
{
#if ANSI_X_9_24_2009
	uint8_t IKSNmask[10] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0x00, 0x00};
	uint8_t maskedKSN[10];
	uint64_t IKSN = 0x0;

	for (int i = 0; i < 10; i++)
	{
		maskedKSN[i] = IKSNmask[i] & KSN[i];
	}

	for (int i = 0; i < 8; i++)
	{
		IKSN |= (uint64_t)(maskedKSN[i]) << (7 - i)*8;
	}
	printf("IKSN: %016llx\n", IKSN);

	IPEK[0] = DES_Encrypt(DES_Decrypt(DES_Encrypt(IKSN, BDK[0]), BDK[1]), BDK[0]);
	uint64_t BDKmask[2] = { 0xC0C0C0C000000000, 0xC0C0C0C000000000 };
	IPEK[1] = DES_Encrypt(DES_Decrypt(DES_Encrypt(IKSN, BDK[0]^BDKmask[0]), BDK[1]^BDKmask[1]), BDK[0]^BDKmask[0]);
#else
    printf("The Standard has not been supported yet");
    assert(false);
#endif
}

/* Generate "child key" with "parent key" + KSN (with counter information) */
void generateKey(uint64_t key[2], uint64_t baseKSN)
{
#if ANSI_X_9_24_2009
	uint64_t mask[2] = { 0xC0C0C0C000000000, 0xC0C0C0C000000000 };
	uint64_t maskedKey[2];
	maskedKey[0] = mask[0] ^ key[0];
	maskedKey[1] = mask[1] ^ key[1];

	printf("baseKSN: %016llx | maskedKey: %016llx %016llx\n", baseKSN, maskedKey[0], maskedKey[1]);
	printf("baseKSN: %016llx | key: %016llx %016llx\n", baseKSN, key[0], key[1]);
	uint64_t left = DES_Encrypt(baseKSN ^ maskedKey[1], maskedKey[0]) ^ maskedKey[1];
	uint64_t right = DES_Encrypt(baseKSN ^ key[1], key[0]) ^ key[1];
	
	key[0] = left;
	key[1] = right;
#else
    printf("The Standard has not been supported yet");
    assert(false);
#endif
}

/**
 * @brief Generate key based on current KSN (and ShiftReg) and current key,
 * 
 *        before calling this function,
 *        the KSN and ShiftReg should have been copied into CryptoReg[0] and
 *        the current key should have been copied into KeyReg[0] and KeyReg[1]
*/
void NonReversibleKeyGen(DUKPT_Reg* DUKPT_Instance)
{
#if ANSI_X_9_24_2009
	uint64_t mask[2] = { 0xC0C0C0C000000000, 0xC0C0C0C000000000 };
	uint64_t maskedKey[2];
	maskedKey[0] = mask[0] ^ DUKPT_Instance->KeyReg[0];
	maskedKey[1] = mask[1] ^ DUKPT_Instance->KeyReg[1];

	//printf("baseKSN: %016llx | key: %016llx %016llx\n", DUKPT_Instance->CryptoReg[0], DUKPT_Instance->KeyReg[0], DUKPT_Instance->KeyReg[1]);
	//printf("baseKSN: %016llx | maskedKey: %016llx %016llx\n", DUKPT_Instance->CryptoReg[0], maskedKey[0], maskedKey[1]);
	DUKPT_Instance->CryptoReg[1] = DES_Encrypt(DUKPT_Instance->CryptoReg[0] ^ DUKPT_Instance->KeyReg[1], DUKPT_Instance->KeyReg[0]);
	DUKPT_Instance->CryptoReg[1] ^= DUKPT_Instance->KeyReg[1];
	DUKPT_Instance->CryptoReg[0] = DES_Encrypt(DUKPT_Instance->CryptoReg[0] ^ maskedKey[1], maskedKey[0]);
	DUKPT_Instance->CryptoReg[0] ^= maskedKey[1];
#else
    printf("The Standard has not been supported yet");
    assert(false);
#endif
}

/**
 * @brief Used to generate some future keys from current key and erase the current key
 *        
 *        NOTE: The ANSI X9.24-1-2009 standard requires key with Hamming weight (count of non-zero bit) equal or larger than 10 to be ignored
 *        
*/
void NewKey(DUKPT_Reg *DUKPT_Instance)
{
    while (true) {
        // Calculate the hamming weight of encryption counter -> if >= 10, invalid
        int oneCount = 0; // Hamming weight
        uint32_t EncryptCounter = 0x0;
        EncryptCounter |= (uint32_t)(DUKPT_Instance->KSNReg[7] & 0x1F) << 16;
        EncryptCounter |= (uint32_t)(DUKPT_Instance->KSNReg[8]) << 8;
        EncryptCounter |= (uint32_t)(DUKPT_Instance->KSNReg[9]);
        // Count hamming weight of the counter value
        for (int i = 0; i < 21; i++) {
            if (EncryptCounter & (uint32_t)0x1U << i) {
                oneCount++;
            }
        }

        if (oneCount < 10) {
            // Normal case: valid encryption counter value -> generate new keys from the current key before discarding it
                NewKey_3(DUKPT_Instance);
        } else {   
            // Invalid encryption counter value -> not using the current key for generating new keys
            // Erase the current key
            //DUKPT_Instance->CurrentKeyPtr->LeftHalf = 0x0;
            //DUKPT_Instance->CurrentKeyPtr->RightHalf = 0x0;
            DUKPT_Instance->CurrentKeyPtr->LRC = DUKPT_Instance->CurrentKeyPtr->LRC + 1;

            // Update counter by adding ShiftReg to ignore the invalid value and store it back to KSN register
            // NOTE: This is a trick to jump instead of increment by 1 through all invalid counter values
            EncryptCounter += (uint32_t)DUKPT_Instance->ShiftReg;
            DUKPT_Instance->KSNReg[7] = (uint8_t)(EncryptCounter >> 16) & 0x1F;
            DUKPT_Instance->KSNReg[8] = (uint8_t)(EncryptCounter >> 8);
            DUKPT_Instance->KSNReg[9] = (uint8_t)(EncryptCounter);

            // TODO: Handle the result of NewKey_2
            NewKey_2(DUKPT_Instance);
            if (!DUKPT_Instance->operative) {
                // DUKPT End of life
                break;
            }

            // Not using invalid key to generate new keys
            break;
        }
    }
}

/**
 * @brief Generate all (at lower bits) future keys from the current key
*/
void NewKey_3(DUKPT_Reg *DUKPT_Instance)
{
    // Set the operative flag to true when loading the new initial key
    DUKPT_Instance->operative = true;

    while (true)
    {
        // 0. Right shift the ShiftReg by 1 bit and check if it is 0, if yes, end of new key(s) generation
	    DUKPT_Instance->ShiftReg >>= 1; // e.g. new key generation order: FK(n) -> FK(n+1) ... -> FK21
        if (DUKPT_Instance->ShiftReg == (uint64_t)0x0)
        {
            NewKey_4(DUKPT_Instance);
            NewKey_2(DUKPT_Instance);
            if (!DUKPT_Instance->operative) {
                // DUKPT End of life
                break;
            }
            // The end of NewKey_3
            break;
        }

        // 1. Right-justified ShiftReg "ORed" with the right-most 64 bits of KSNReg
        uint64_t KSN_right64 = (uint64_t)0x0;
        for (int i = 2; i < 10; i++)
        {
            KSN_right64 <<= 8;
            KSN_right64 |= (uint64_t)DUKPT_Instance->KSNReg[i];
        }
        DUKPT_Instance->CryptoReg[0] = DUKPT_Instance->ShiftReg | KSN_right64;

        // 2. Copy the current key into KeyReg
        DUKPT_Instance->KeyReg[0] = DUKPT_Instance->CurrentKeyPtr->LeftHalf;
        DUKPT_Instance->KeyReg[1] = DUKPT_Instance->CurrentKeyPtr->RightHalf;

        // 3. Generate the new key by the data in CryptoReg and the current key in KeyReg, and store the result in CryptoReg
        NonReversibleKeyGen(DUKPT_Instance);

        // 4. Store the new key (in CryptoReg) into the corresponding Future Key Register indicated by ShiftReg
        uint64_t mask = (uint64_t)0x1 << 20; // NOTE: Shift register bit map to #1 to #21 of FuturKeyReg from left to right, so it starts from bit-20
        for (int i = 0; i < 21; i++)
        {
            // Find the Future Key Register and store the new key
            if (DUKPT_Instance->ShiftReg & mask)
            {
                DUKPT_Instance->FKReg[i].LeftHalf = DUKPT_Instance->CryptoReg[0];
                DUKPT_Instance->FKReg[i].RightHalf = DUKPT_Instance->CryptoReg[1];
                GenerateLRC(&DUKPT_Instance->FKReg[i]);
                break;
            }
            mask >>= 1;
        }
    }
}

/**
 * @brief Do nothing but check if the counter is overflowed
 *        If any bit in the counter is 1, then the counter is not overflowed
 * @return 0 if counter is not overflowed (successful)
 *         1 if counter is overflowed (DUKPT is end-of-life, must load a new initial key)
*/
int NewKey_2(DUKPT_Reg *DUKPT_Instance)
{
	if (DUKPT_Instance->KSNReg[7] & 0x1f | DUKPT_Instance->KSNReg[8] & 0xff | DUKPT_Instance->KSNReg[9] & 0xff)
	{
		/* Do nothing */
		//printf("Counter hasn't overflowed\n");
		return 0;
	}
	else
	{
		/* Cease operation. */
		DUKPT_Instance->operative = false;
		printf("The PIN Entry Device is now inoperative, having encrypted more than 1 million PINs\n");
		return 1;
	}

}

/**
 * @brief Erase (Discard) the current key,
 *        Increment the Counter and then
 *        Check if the counter is overflowed
*/
void NewKey_4(DUKPT_Reg *DUKPT_Instance)
{
	// 1. Erase the current key (NOTE: The key has been extracted and store in Key Register)
	//DUKPT_Instance->CurrentKeyPtr->LeftHalf = 0x0;
	//DUKPT_Instance->CurrentKeyPtr->RightHalf = 0x0;
	// 2. Set the LRC into an invalid state: e.g. increment the LRC by 1
	DUKPT_Instance->CurrentKeyPtr->LRC = DUKPT_Instance->CurrentKeyPtr->LRC + 1;

	// 3. Add 1 to the Encryption Counter and handle overflow
	uint32_t tempEncryptCounter = 0x0;
	tempEncryptCounter += (DUKPT_Instance->KSNReg[7] & (uint8_t)0x1F) << 16;
	tempEncryptCounter += DUKPT_Instance->KSNReg[8] << 8;
	tempEncryptCounter += DUKPT_Instance->KSNReg[9];

	tempEncryptCounter += 1; // Increment by 1
	tempEncryptCounter &= (uint32_t)0x1FFFFF; // Discard overflow bit

	DUKPT_Instance->KSNReg[7] &= (uint8_t)0xE0; // clear counter bits and preserve other bits
	DUKPT_Instance->KSNReg[7] |= (uint8_t)(tempEncryptCounter >> 16); // extract the bit-16 to bit-20 of the temp counter and assign to KSNReg[7]
	DUKPT_Instance->KSNReg[8] = (uint8_t)(tempEncryptCounter >> 8);   // extract the bit-8 to bit-15 of the temp counter and assign to KSNReg[8]
	DUKPT_Instance->KSNReg[9] = (uint8_t)tempEncryptCounter;          // extract the bit-0 to bit-7 of the temp counter and assign to KSNReg[9]
}

/**
 * @brief Update ShiftReg with the lowest non-zero bit in Counter 
 *        e.g. 0b000100011101011100000 -> 0b000000000000000100000
 *                  Counter (21 bits)        ShiftReg (21 bits)
 *        NOTE: The ShiftReg can be used to determine which key in FKReg pointed by the current key 
 *              e.g. For the example above, the bit-5 of ShiftReg is set, so the current key is the 5th key in FKReg is FK16 (NOTE: bit-0 = FK21, bit-20 = FK1)
*/
void SetBit(DUKPT_Reg* DUKPT_Instance)
{
	DUKPT_Instance->ShiftReg = (uint64_t)0x0;
	uint32_t EncryptCounter = 0x0;
	EncryptCounter += (DUKPT_Instance->KSNReg[7] & (uint8_t)0x1F) << 16;
	EncryptCounter += DUKPT_Instance->KSNReg[8] << 8;
	EncryptCounter += DUKPT_Instance->KSNReg[9];
	for (int i = 0; i < 21; i++)
	{
		if (EncryptCounter & ((uint32_t)0x1U << i))
		{
			DUKPT_Instance->ShiftReg |= (uint32_t)0x1U << i;
			break;
		}
	}
}

void printDUKPTStateSummary(DUKPT_Reg *DUKPT_Instance)
{
	printf("=======================================================\n");
	printf("                       State Summary                   \n");
	printf("=======================================================\n");
	for (int i = 0; i < 21; i++)
	{
        if (checkLRC(&DUKPT_Instance->FKReg[i]) == 0) {
		    printf("Future Key #%d: %016llx %016llx | LRC: 0x%02x Valid\n", i + 1, DUKPT_Instance->FKReg[i].LeftHalf, DUKPT_Instance->FKReg[i].RightHalf, DUKPT_Instance->FKReg[i].LRC);
        } else {
            printf("Future Key #%d: %016llx %016llx | LRC: 0x%02x Invalid\n", i + 1, DUKPT_Instance->FKReg[i].LeftHalf, DUKPT_Instance->FKReg[i].RightHalf, DUKPT_Instance->FKReg[i].LRC);
        }
	}
	printf("Key Register: %016llx %016llx\n", DUKPT_Instance->KeyReg[0], DUKPT_Instance->KeyReg[1]);
	printf("Encryption Counter: 0x%02x%02x%02x\n", DUKPT_Instance->KSNReg[7] & 0x1F, DUKPT_Instance->KSNReg[8], DUKPT_Instance->KSNReg[9]);
	//printf("Shift Register: 0x%016llx\n", DUKPT_Instance->ShiftReg);
}