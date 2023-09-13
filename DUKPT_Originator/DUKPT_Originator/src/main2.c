
#include "config.h"
#include "dukpt.h"


// TODO: Generate PIN Block from input PIN instead of hard-coded value for test
uint64_t PIN_Block = 0x041274EDCBA9876F;


void loadInitialKey(DUKPT_Reg* DUKPT_Instance, uint64_t BDK[2], uint8_t KSN[10])
{
	// 0. Calculate IPEK from BDK and KSN
    uint64_t IPEK[2];
    CalcIPEK(BDK, KSN, IPEK);
    
    // 1. Store the initial PIN encryption key (IPEK) in the Future Key Register #21 (FK21) (correspond to the left-most bit of ShiftReg)
	DUKPT_Instance->FKReg[20].LeftHalf = IPEK[0];
	DUKPT_Instance->FKReg[20].RightHalf = IPEK[1];
	// 2. Generate and store LRC for FK21
	GenerateLRC(&(DUKPT_Instance->FKReg[20]));

	// 3. Write the address of FK21 into Current Key Pointer
	DUKPT_Instance->CurrentKeyPtr = &DUKPT_Instance->FKReg[20];

	// 4. Store the Key Serial Number into Key Serial Number Register
	for (int i = 0; i < 10; i++)
		DUKPT_Instance->KSNReg[i] = KSN[i];

	// 5. Clear Encryption Counter (right-most 21 bits of KSNReg)
	DUKPT_Instance->KSNReg[9] = DUKPT_Instance->KSNReg[9] & (uint8_t)0x0;
	DUKPT_Instance->KSNReg[8] = DUKPT_Instance->KSNReg[8] & (uint8_t)0x0;
	DUKPT_Instance->KSNReg[7] = DUKPT_Instance->KSNReg[7] & (uint8_t)0xE0;

	// 6. Set the left-most bit (corresponding to FK21) of ShiftReg to 1, and all other bits to 0
	DUKPT_Instance->ShiftReg = (uint64_t)(0x1) << 20;

    printDUKPTStateSummary(DUKPT_Instance);

	// 7. go to NewKey-3 subprocess
	NewKey_3(DUKPT_Instance, true);
}

/**
 *
 * @return 0: encrypted PIN sent
 *         1: canceled
 *         2: DUKPT End of life
 *         3: message without PIN related info sent
 */
int Request_PIN_Entry(DUKPT_Reg* DUKPT_Instance, uint8_t PAN[12+1])
{
    // TODO: Wait for Cancel or PIN entry

    //
    //while (true)
    //{
    //    // TODO: polling request
    //    // ...
    //
    //    // Handle request
    //    if (canceled) {
    //        return 1;
    //    }
    //
    //    if (entered) {
    //        if (!pin) {
    //            // TODO: Send message without PIN related info
    //            return 3;
    //        } else {
    //            break;
    //        }
    //    } 
    //}

    // Search until the next valid key for PIN encryption
    while (true) {
        SetBit(DUKPT_Instance); // Update ShiftReg with the current Encryption Counter (the lowest one bit position)
        int FKReg_idx = 20; // NOTE: #21 is the first future key = right-most bit of ShiftReg
	    for (int i = 0; i < 21; i++) {
	    	if (DUKPT_Instance->ShiftReg & (uint64_t)0x1 << i) {
	    		break;
	    	}
	    	FKReg_idx--;
	    }
	    DUKPT_Instance->CurrentKeyPtr = &(DUKPT_Instance->FKReg[FKReg_idx]);

        if (checkLRC(DUKPT_Instance->CurrentKeyPtr) == 0) {
            // Found a valid key
            //printf("Valid key at FK#: %d, counter: 0x%02x%02x%02x\n", FKReg_idx + 1, DUKPT_Instance->KSNReg[7] & 0x1F, DUKPT_Instance->KSNReg[8], DUKPT_Instance->KSNReg[9]);
            break;
        }

        //printf("Invalid key at FK#: %d, counter: 0x%02x%02x%02x\n", FKReg_idx + 1, DUKPT_Instance->KSNReg[7] & 0x1F, DUKPT_Instance->KSNReg[8], DUKPT_Instance->KSNReg[9]);
        // LRC check fail, update the counter by adding ShiftReg (and handle overflow) -> skip over the invalid key
		uint32_t EncryptCounter = 0x0;
		EncryptCounter |= (uint32_t)(DUKPT_Instance->KSNReg[7] & 0x1F) << 16;
		EncryptCounter |= (uint32_t)(DUKPT_Instance->KSNReg[8]) << 8;
		EncryptCounter |= (uint32_t)(DUKPT_Instance->KSNReg[9]);

		EncryptCounter = EncryptCounter + DUKPT_Instance->ShiftReg;
		EncryptCounter &= (uint32_t)0x1FFFFF;

		DUKPT_Instance->KSNReg[9] = (uint8_t)EncryptCounter;
		DUKPT_Instance->KSNReg[8] = (uint8_t)(EncryptCounter >> 8);
		DUKPT_Instance->KSNReg[7] &= (uint8_t)0xE0; // clear counter bits
		DUKPT_Instance->KSNReg[7] |= (uint8_t)(EncryptCounter >> 16); // assign new counter bits

        // If encryption counter contains all 0 -> DUKPT End of life
        NewKey_2(DUKPT_Instance);
        if (DUKPT_Instance->operative == false) {
            return 2;
        }

        // New keys generated, back to the start of loop to check if the new key is valid
    }

    if (!DUKPT_Instance->operative) {
        // DUKPT End of life -> cease operation
        return 2;
    }

    // Use the key to encrypt PIN and send message, then generate new keys before discarding the current key
    // Mask the key with variant constant for different purposes:
    //   1. PIN Encryption Key:             0x00000000000000FF 0x00000000000000FF
    //   2. MAC Request Key:                0x000000000000FF00 0x000000000000FF00   
    //   3. MAC Response Key:               0x00000000FF000000 0x00000000FF000000
    //   4. Data Encryption Key (Request):  0x0000000000FF0000 0x0000000000FF0000
    //   5. Data Entrypction Key (Response):0x000000FF00000000 0x000000FF00000000

    // Encrypt the message (Format and encrypt PIN Block)
#if ANSI_X_9_24_2009
    DUKPT_Instance->CryptoReg[0] = PIN_Block;
    DUKPT_Instance->KeyReg[0] = (*(DUKPT_Instance->CurrentKeyPtr)).LeftHalf;
	DUKPT_Instance->KeyReg[1] = (*(DUKPT_Instance->CurrentKeyPtr)).RightHalf;

	uint64_t PIN_variant_const[2] = { 0x00000000000000FF, 0x00000000000000FF };
	DUKPT_Instance->KeyReg[0] ^= PIN_variant_const[0];
	DUKPT_Instance->KeyReg[1] ^= PIN_variant_const[1];

	DUKPT_Instance->CryptoReg[0] = DES_Encrypt(DUKPT_Instance->CryptoReg[0], DUKPT_Instance->KeyReg[0]);
	DUKPT_Instance->CryptoReg[0] = DES_Decrypt(DUKPT_Instance->CryptoReg[0], DUKPT_Instance->KeyReg[1]);
	DUKPT_Instance->CryptoReg[0] = DES_Encrypt(DUKPT_Instance->CryptoReg[0], DUKPT_Instance->KeyReg[0]);
#else
    printf("The Standard has not been supported yet");
    assert(false);
#endif
    // Send the message
    //printf("=======================================================\n");
	//printf("                   Transaction Message                 \n");
	//printf("=======================================================\n");
	//printf("KSN = %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", 
	//	DUKPT_Instance->KSNReg[0], DUKPT_Instance->KSNReg[1], DUKPT_Instance->KSNReg[2], DUKPT_Instance->KSNReg[3], DUKPT_Instance->KSNReg[4], 
	//	DUKPT_Instance->KSNReg[5], DUKPT_Instance->KSNReg[6], DUKPT_Instance->KSNReg[7], DUKPT_Instance->KSNReg[8], DUKPT_Instance->KSNReg[9]);
	//printf("Encrypted PIN Block: %016llx\n", DUKPT_Instance->CryptoReg[0]);
    // TODO: PAN block?
    
    // Generate new keys and discard the current key
    NewKey(DUKPT_Instance);

    return 0;
}

int main()
{
    // 0. Create DUKPT Instance
    DUKPT_Reg* DUKPT_Instance = (DUKPT_Reg*)malloc(sizeof(DUKPT_Reg));
    // 1. Load initial key
    uint64_t BDK[2];
    BDK[0] = 0x0123456789ABCDEF;
	BDK[1] = 0xFEDCBA9876543210;
    //uint64_t IPEK[2];
    //IPEK[0] = 0x6AC292FAA1315B4D;
	//IPEK[1] = 0x858AB3A3D7D5933A;
    uint8_t KSN[10];
    KSN[0] = 0xFF; KSN[1] = 0xFF; KSN[2] = 0x98; KSN[3] = 0x76;
	KSN[4] = 0x54; KSN[5] = 0x32; KSN[6] = 0x10; KSN[7] = 0xE0;
	KSN[8] = 0x00; KSN[9] = 0x00;

    loadInitialKey(DUKPT_Instance, BDK, KSN);
    printDUKPTStateSummary(DUKPT_Instance);

    //DUKPT_Instance->KSNReg[7] = 0xEF;
    //DUKPT_Instance->KSNReg[8] = 0xF8;
    //DUKPT_Instance->KSNReg[9] = 0x01;

    // 2. Request PIN entry for n times
    for (int i = 0; i < 2000000; i++) {
        uint8_t PAN[12+1];
        Request_PIN_Entry(DUKPT_Instance, PAN);
        //printDUKPTStateSummary(DUKPT_Instance);
        //printf("Encryption counter: %02x %02x %02x\n", DUKPT_Instance->KSNReg[7] & 0x1F, DUKPT_Instance->KSNReg[8], DUKPT_Instance->KSNReg[9]);
        if (i % 5000 == 0) {
            printf(">");
        }
        if (i % 50000 == 0) {
            printf("\n");
        }
        if (DUKPT_Instance->operative == false) {
            printf("\n");
            printf("i = %d\n", i);
            printf("DUKPT End of life\n");
            break;
        }
    }

    printDUKPTStateSummary(DUKPT_Instance);

    return 0;
}