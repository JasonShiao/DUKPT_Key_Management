/********************************************************
 *                                                      *
 *    Implementation of DUKPT PIN Block Encryption      *
 *    based on ANSI_X9.24-1-2009                        *
 *                                                      *
 *    Originater (device) Side                          *
 *                                                      *
 *                            By Jason Shiao, Oct 2018  *
 *                                                      *
*********************************************************/

#include<stdio.h>
#include<stdint.h>
#include<string.h>
#include<stdlib.h>

#include"DES.h"

#define ANSI_X_9_24

#define DUKPT_STRUCT


typedef struct
{
	uint64_t LeftHalf;
	uint64_t RightHalf;
	uint8_t LRC;

}FutureKey;

typedef struct
{

	uint8_t KSNReg[10];		// Key Serial Number Register
	FutureKey FKReg[21];	// Future Key Register 
	uint64_t KeyReg[2];		// Key Register
	uint64_t CryptoReg[2];	// Crypto Register
	uint64_t ShiftReg;		// only right-most 21-bit should be used
	FutureKey *CurrentKeyPtr;	// Current Key Pointer (Point to element of Future Key Register)

}DUKPT_Reg;



/*   Function Prototype   */
uint64_t PINField_format0(char PIN[14+1]);
uint64_t PANField_format0(char PAN[12+1]);

void Query_PIN(char PIN[14 + 1]);
void Query_PAN(char PIN[12 + 1]);
void Query_TDES_Key(char c_TDES_Key[48 + 1]);

void Separate_TDES_Keys(char Key[48 + 1], uint64_t TDES_Key[3]);
void GenerateLRC(FutureKey *FK);
int checkLRC(FutureKey *FK);

void CalcIPEK(uint64_t BDK[2], uint8_t KSN[10], uint64_t IPEK[2]);
void generateKey(uint64_t key[2], uint64_t baseKSN);
void NonReversibleKeyGen(DUKPT_Reg* DUKPT_Instance);

void NewKey_3(DUKPT_Reg* DUKPT_Instance);
void NewKey_1(DUKPT_Reg* DUKPT_Instance);
void NewKey_4(DUKPT_Reg* DUKPT_Instance);
int NewKey_2(DUKPT_Reg* DUKPT_Instance);

void Request_PIN_Entry_1(DUKPT_Reg* DUKPT_Instance);
void Request_PIN_Entry_2(DUKPT_Reg* DUKPT_Instance);

void SetBit(DUKPT_Reg* DUKPT_Instance);

void printDUKPTStateSummary(DUKPT_Reg* DUKPT_Instance);




int main(int argc, char* argv[])
{

#ifdef ANSI_X_9_24

	uint8_t KSN[10]; // Key Serial Number
	uint64_t BDK[2]; // Base Derivation Key
	uint64_t IPEK[2]; // Initial PIN encryption Key

	//DUKPT_Reg DUKPT_Instance;

	DUKPT_Reg* DUKPT_Instance = malloc(sizeof(DUKPT_Reg));

	/* Directly assign in program (for test) */
	KSN[0] = 0xFF; KSN[1] = 0xFF; KSN[2] = 0x98; KSN[3] = 0x76;
	KSN[4] = 0x54; KSN[5] = 0x32; KSN[6] = 0x10; KSN[7] = 0xE0;
	KSN[8] = 0x00; KSN[9] = 0x00;

	BDK[0] = 0x0123456789ABCDEF;
	BDK[1] = 0xFEDCBA9876543210;

	IPEK[0] = 0x6AC292FAA1315B4D;
	IPEK[1] = 0x858AB3A3D7D5933A;
	// or use CalcIPEK(BDK, KSN, IPEK);

	printf("-------------------------------------------------\n");
	printf("KSN = %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", KSN[0], KSN[1], KSN[2], KSN[3], KSN[4], KSN[5], KSN[6], KSN[7], KSN[8], KSN[9]);
	printf("IPEK = %016llx %016llx\n", IPEK[0], IPEK[1]);
	printf("-------------------------------------------------\n");

	/* End of sample data assignment */


	/* Load Initial Key */
	DUKPT_Instance->FKReg[20].LeftHalf = IPEK[0];
	DUKPT_Instance->FKReg[20].RightHalf = IPEK[1];

	GenerateLRC(&(DUKPT_Instance->FKReg[20]));
	DUKPT_Instance->CurrentKeyPtr = &DUKPT_Instance->FKReg[20];



	/* Set Key Serial Number Register */
	for (int i = 0; i < 10; i++)
		DUKPT_Instance->KSNReg[i] = KSN[i];


	/* Clear Encryption Counter (right-most 21 bits) */
	DUKPT_Instance->KSNReg[9] = DUKPT_Instance->KSNReg[9] & (uint8_t)0x0;
	DUKPT_Instance->KSNReg[8] = DUKPT_Instance->KSNReg[8] & (uint8_t)0x0;
	DUKPT_Instance->KSNReg[7] = DUKPT_Instance->KSNReg[7] & (uint8_t)0xE0;


	/* Set #1 bit (leftmost bit) of ShiftReg to 1 */
	DUKPT_Instance->ShiftReg = (uint64_t)(0x1) << 20;


	NewKey_3(DUKPT_Instance);

	printDUKPTStateSummary(DUKPT_Instance);

	/* Initialization Finished */


	/* Start PIN entry and Transaction */
	
	/* Assign PIN Block Directly instead of calling Request PIN Entry */
	uint64_t PIN_Block = 0x041274EDCBA9876F;

	/* n transactions */
	for (int n = 0; n < 10; n++)
	{
		/* Store PIN Block into Crypto Register 1 */
		DUKPT_Instance->CryptoReg[0] = PIN_Block;

		/* Request PIN Entry 1 */
		Request_PIN_Entry_1(DUKPT_Instance);
	}


#endif

	/*
	char PIN[14 + 1];
	char PAN[12 + 1];
	char c_TDES_Key[48 + 1];
	uint64_t PIN_Field;
	uint64_t PAN_Field;
	uint64_t PIN_Block;
	uint64_t TDES_Keys[3] = { 0x0, 0x0, 0x0 };
	uint64_t encrypted_PIN_Block;

	Query_PIN(PIN);
	Query_PAN(PAN);
	Query_TDES_Key(c_TDES_Key);

	PIN_Field = PINField_format0(PIN);
	PAN_Field = PANField_format0(PAN);
	PIN_Block = PIN_Field ^ PAN_Field;

	Separate_TDES_Keys(c_TDES_Key, TDES_Keys);
			
	encrypted_PIN_Block = TDES_Encrypt(PIN_Block, TDES_Keys[0], TDES_Keys[1], TDES_Keys[2]);

	printf("PIN Field: 0x%016llx\n", PIN_Field);
	printf("PAN Field: 0x%016llx\n", PAN_Field);
	printf("PIN Block: 0x%016llx\n", PIN_Block);
	printf("Key 1: 0x%016llx\n", TDES_Keys[0]);
	printf("Key 2: 0x%016llx\n", TDES_Keys[1]);
	printf("Key 3: 0x%016llx\n", TDES_Keys[2]);
	printf("Cypher Block: 0x%016llx\n", encrypted_PIN_Block);

	*/

	free(DUKPT_Instance);

	system("pause");
	return 0;
}



uint64_t PINField_format0(char PIN[14+1])
{
	uint64_t PINField = 0x0;
	/* 2nd nibble: PIN length */
	PINField |= (uint64_t)(strlen(PIN)) << 56;

	/* 3rd to 3+n nibbles: PIN */
	uint64_t PIN_digit;
	for (int i = 0; i < strlen(PIN); i++)
	{
		PIN_digit = (uint64_t)(PIN[i] - '0');
		PINField |= PIN_digit << (4 * (13 - i));
	}

	/* right padding with 0xF */
	for (int i = 0; i < 14 - strlen(PIN); i++)
	{
		PINField |= (uint64_t)0xF << 4 * i;
	}

	return PINField;
}

uint64_t PANField_format0(char PAN[12+1])
{
	uint64_t PANField = 0x0;
	uint64_t PAN_digit;
	for (int i = 0; i < strlen(PAN); i++)
	{
		PAN_digit = (uint64_t)(PAN[i] - '0');
		PANField |= PAN_digit << (4 * (11 - i));
	}

	return PANField;
}



void Query_PIN(char PIN[14+1])
{
	while (1)
	{
		printf("Please enter a PIN(4-14 digits): ");
		scanf_s("%s", PIN, 15);
		printf("length: %d\n", strlen(PIN));
		if (strlen(PIN) >= 4 && strlen(PIN) <= 14)
			break;
		else
			printf("Invalid PIN length.\n");
	}
}

void Query_PAN(char PAN[12 + 1])
{
	while (1)
	{
		printf("Please enter the PAN(12 digits): ");
		scanf_s("%s", PAN, 13);
		if (strlen(PAN) == 12)
			break;
		else
			printf("Invalid PAN length.\n");
	}
}

void Query_TDES_Key(char TDES_Key[48+1])
{
	while (1)
	{
		printf("Please enter a 48-digit hex number (0-9, A-F): ");
		scanf_s("%s", TDES_Key, 49);

		if (strlen(TDES_Key) == 48)
			break;
		else
			printf("Invalid Key length.\n");
	}

}

void Separate_TDES_Keys(char Key[48 + 1], uint64_t TDES_Keys[3])
{
	char c_Keys[3][17];
	for (int i = 0; i < 3; i++)
	{
		strncpy_s(c_Keys[i], 17, Key + 16 * i, 16);
		c_Keys[i][16] = '\0';

		TDES_Keys[i] = 0x0;
		for (int j = 0; j < strlen(c_Keys[i]); j++)
		{
			TDES_Keys[i] = TDES_Keys[i] << 0x4;
			if (c_Keys[i][j] >= '0' && c_Keys[i][j] <= '9')
			{
				TDES_Keys[i] += (uint64_t)(c_Keys[i][j] - '0');
			}
			else if (c_Keys[i][j] >= 'a' && c_Keys[i][j] <= 'f')
			{
				TDES_Keys[i] += (uint64_t)(c_Keys[i][j] - 'a' + 10);
			}
			else if (c_Keys[i][j] >= 'A' && c_Keys[i][j] <= 'F')
			{
				TDES_Keys[i] += (uint64_t)(c_Keys[i][j] - 'A' + 10);
			}
		}
	}
}

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

}

/* Generate "child key" with "parent key" + KSN (with counter information) */
void generateKey(uint64_t key[2], uint64_t baseKSN)
{

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

}
void NonReversibleKeyGen(DUKPT_Reg* DUKPT_Instance)
{
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

}


void NewKey(DUKPT_Reg *DUKPT_Instance)
{
	int oneCount = 0;
	uint32_t EncryptCounter = 0x0;

	EncryptCounter |= (uint32_t)(DUKPT_Instance->KSNReg[7] & 0x1F) << 16;
	EncryptCounter |= (uint32_t)(DUKPT_Instance->KSNReg[8]) << 8;
	EncryptCounter |= (uint32_t)(DUKPT_Instance->KSNReg[9]);

	for (int i = 0; i < 21; i++)
	{
		if (EncryptCounter & (uint32_t)0x1U << i)
		{
			oneCount++;
		}
	}

	if (oneCount < 10)
	{
		NewKey_1(DUKPT_Instance);
	}
	else
	{
		/* Erase the current key */
		DUKPT_Instance->CurrentKeyPtr->LeftHalf = 0x0;
		DUKPT_Instance->CurrentKeyPtr->RightHalf = 0x0;
		DUKPT_Instance->CurrentKeyPtr->LRC = DUKPT_Instance->CurrentKeyPtr->LRC + 1;

		EncryptCounter += (uint32_t)DUKPT_Instance->ShiftReg;

		DUKPT_Instance->KSNReg[7] = (uint8_t)(EncryptCounter >> 16) & 0x1F;
		DUKPT_Instance->KSNReg[8] = (uint8_t)(EncryptCounter >> 8);
		DUKPT_Instance->KSNReg[9] = (uint8_t)(EncryptCounter);

		NewKey_2(DUKPT_Instance);
	}

}

void NewKey_3(DUKPT_Reg *DUKPT_Instance)
{

	uint64_t KSN_right64 = (uint64_t)0x0;
	for (int i = 2; i < 10; i++)
	{
		KSN_right64 <<= 8;
		KSN_right64 |= (uint64_t)DUKPT_Instance->KSNReg[i];
	}

	DUKPT_Instance->CryptoReg[0] = DUKPT_Instance->ShiftReg | KSN_right64;
	DUKPT_Instance->KeyReg[0] = DUKPT_Instance->CurrentKeyPtr->LeftHalf;
	DUKPT_Instance->KeyReg[1] = DUKPT_Instance->CurrentKeyPtr->RightHalf;

	NonReversibleKeyGen(DUKPT_Instance);

	uint64_t mask = (uint64_t)0x1 << 20;
	for (int i = 0; i < 21; i++)
	{
		// NOTE: Shift register from lowest# to highest# from left to right
		if (DUKPT_Instance->ShiftReg & mask)
		{
			DUKPT_Instance->FKReg[i].LeftHalf = DUKPT_Instance->CryptoReg[0];
			DUKPT_Instance->FKReg[i].RightHalf = DUKPT_Instance->CryptoReg[1];
			GenerateLRC(&DUKPT_Instance->FKReg[i]);
			break;
		}
		mask >>= 1;
	}

	NewKey_1(DUKPT_Instance);

}

void NewKey_1(DUKPT_Reg *DUKPT_Instance)
{

	DUKPT_Instance->ShiftReg >>= 1;
	if (DUKPT_Instance->ShiftReg == (uint64_t)0x0)
	{
		/* go to NewKey-4 */
		NewKey_4(DUKPT_Instance);
	}
	else
	{
		/* go to NewKey-3 again */
		NewKey_3(DUKPT_Instance);
	}
}

int NewKey_2(DUKPT_Reg *DUKPT_Instance)
{

	if (DUKPT_Instance->KSNReg[9] & 0xff | DUKPT_Instance->KSNReg[8] & 0xff | DUKPT_Instance->KSNReg[7] & 0x1f)
	{
		/* Exit */
		printf("Exit successfully\n");
		return 0;
	}
	else
	{
		/* Cease operation. */
		printf("The PIN Entry Device is now inoperative, having encrypted more than 1 million PINs\n");
		return 1;
	}

}

void NewKey_4(DUKPT_Reg *DUKPT_Instance)
{
	/* Erase the current key (NOTE: The key has been extracted and store in Key Register) */
	DUKPT_Instance->CurrentKeyPtr->LeftHalf = 0x0;
	DUKPT_Instance->CurrentKeyPtr->RightHalf = 0x0;
	DUKPT_Instance->CurrentKeyPtr->LRC = DUKPT_Instance->CurrentKeyPtr->LRC + 1;

	uint32_t tempEncryptCounter = 0x0;
	tempEncryptCounter += DUKPT_Instance->KSNReg[9];
	tempEncryptCounter += DUKPT_Instance->KSNReg[8] << 8;
	tempEncryptCounter += (DUKPT_Instance->KSNReg[7] & (uint8_t)0x1F) << 16;

	tempEncryptCounter += 1; // Increment by 1
	tempEncryptCounter &= (uint32_t)0x1FFFFF; // Discard overflow bit

	DUKPT_Instance->KSNReg[9] = (uint8_t)tempEncryptCounter;
	DUKPT_Instance->KSNReg[8] = (uint8_t)(tempEncryptCounter >> 8);
	DUKPT_Instance->KSNReg[7] &= (uint8_t)0xE0; // clear counter bits
	DUKPT_Instance->KSNReg[7] |= (uint8_t)(tempEncryptCounter >> 16); // assign new counter bits

	NewKey_2(DUKPT_Instance);
}

void Request_PIN_Entry_1(DUKPT_Reg* DUKPT_Instance)
{
	
	SetBit(DUKPT_Instance);
	int positionShiftReg = 0;
	for (int i = 0; i < 21; i++)
	{
		if (DUKPT_Instance->ShiftReg & (uint64_t)0x100000 >> i)
		{
			break;
		}
		positionShiftReg++;
	}
	DUKPT_Instance->CurrentKeyPtr = &(DUKPT_Instance->FKReg[positionShiftReg]);

	if (checkLRC(DUKPT_Instance->CurrentKeyPtr) == 0)
	{
		// LRC check pass
		/* Request PIN Entry 2 */
		Request_PIN_Entry_2(DUKPT_Instance);
	}
	else
	{
		// LRC check fail
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


		if (EncryptCounter == 0)
		{
			/* Cease Operation: more than 1 million PINs have been encrypted */
			return;
		}
		else 
		{
			Request_PIN_Entry_1(DUKPT_Instance); // Recursive
		}
	}

}

void Request_PIN_Entry_2(DUKPT_Reg* DUKPT_Instance)
{
	DUKPT_Instance->KeyReg[0] = (*(DUKPT_Instance->CurrentKeyPtr)).LeftHalf;
	DUKPT_Instance->KeyReg[1] = (*(DUKPT_Instance->CurrentKeyPtr)).RightHalf;

	uint64_t PIN_variant_const[2] = { 0x00000000000000FF, 0x00000000000000FF };
	DUKPT_Instance->KeyReg[0] ^= PIN_variant_const[0];
	DUKPT_Instance->KeyReg[1] ^= PIN_variant_const[1];

	DUKPT_Instance->CryptoReg[0] = DES_Encrypt(DUKPT_Instance->CryptoReg[0], DUKPT_Instance->KeyReg[0]);
	DUKPT_Instance->CryptoReg[0] = DES_Decrypt(DUKPT_Instance->CryptoReg[0], DUKPT_Instance->KeyReg[1]);
	DUKPT_Instance->CryptoReg[0] = DES_Encrypt(DUKPT_Instance->CryptoReg[0], DUKPT_Instance->KeyReg[0]);

	/* Format and transmit encrypted PIN Block */
	printf("=======================================================\n");
	printf("                   Transaction Message                 \n");
	printf("=======================================================\n");
	printf("KSN = %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", 
		DUKPT_Instance->KSNReg[0], DUKPT_Instance->KSNReg[1], DUKPT_Instance->KSNReg[2], DUKPT_Instance->KSNReg[3], DUKPT_Instance->KSNReg[4], 
		DUKPT_Instance->KSNReg[5], DUKPT_Instance->KSNReg[6], DUKPT_Instance->KSNReg[7], DUKPT_Instance->KSNReg[8], DUKPT_Instance->KSNReg[9]);
	printf("Encrypted PIN Block: %016llx\n", DUKPT_Instance->CryptoReg[0]);

	/* New Key */
	NewKey(DUKPT_Instance);

	printDUKPTStateSummary(DUKPT_Instance);
}


void SetBit(DUKPT_Reg* DUKPT_Instance)
{
	DUKPT_Instance->ShiftReg = (uint64_t)0x0;
	uint32_t EncryptCounter = 0x0;
	EncryptCounter += DUKPT_Instance->KSNReg[9];
	EncryptCounter += DUKPT_Instance->KSNReg[8] << 8;
	EncryptCounter += (DUKPT_Instance->KSNReg[7] & (uint8_t)0x1F) << 16;
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
		printf("Future Key #%d: %016llx %016llx | LRC: 0x%02x \n", i + 1, DUKPT_Instance->FKReg[i].LeftHalf, DUKPT_Instance->FKReg[i].RightHalf, DUKPT_Instance->FKReg[i].LRC);
	}
	printf("Key Register: %016llx %016llx\n", DUKPT_Instance->KeyReg[0], DUKPT_Instance->KeyReg[1]);
	printf("Encryption Counter: 0x%02x%02x%02x\n", DUKPT_Instance->KSNReg[7] & 0x1F, DUKPT_Instance->KSNReg[8], DUKPT_Instance->KSNReg[9]);
	printf("Shift Register: 0x%016llx\n", DUKPT_Instance->ShiftReg);
}