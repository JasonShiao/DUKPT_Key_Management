/********************************************************
*                                                      *
*    Implementation of DUKPT PIN Block Encryption      *
*    based on ANSI_X9.24-1-2009                        *
*                                                      *
*    Receiver (server) Side                            *
*                                                      *
*                            By Jason Shiao, Oct 2018  *
*                                                      *
*********************************************************/

#include<stdio.h>
#include<stdint.h>
#include<string.h>
#include<stdlib.h>

#include"DES.h"
#include"DUKPT.h"


typedef struct
{

	uint64_t LeftHalf;
	uint64_t RightHalf;
	uint8_t LRC;

}FutureKey;

/*   Function Prototype   */
uint64_t PINField_format0(char PIN[14+1]);
uint64_t PANField_format0(char PAN[12+1]);

void Query_PIN(char PIN[14 + 1]);
void Query_PAN(char PIN[12 + 1]);
void Query_TDES_Key(char c_TDES_Key[48 + 1]);

void Separate_TDES_Keys(char Key[48 + 1], uint64_t TDES_Key[3]);
void GenerateLRC(FutureKey *FK);

void CalcIPEK(uint64_t BDK[2], uint8_t KSN[10], uint64_t IPEK[2]);
void generateKey(uint64_t key[2], uint64_t baseKSN);


int main(int argc, char* argv[])
{

	/************************************************************************************/
	/*                                                                                  */
	/* Receiver(Acquirer) regenerates the IPEK and derives keys to decrypt PIN and Data */
	/*                                                                                  */
	/************************************************************************************/

	/* BDK from internal TRSM */
	uint64_t BDK[2] = { 0x0123456789ABCDEF, 0xFEDCBA9876543210 };  

	/* KSN and encrypted PIN Block from device */
	uint8_t KSN[10] = { 0xff, 0xff, 0x98, 0x76, 0x54, 
						0x32, 0x10, 0xe0, 0x00, 0x05};
	uint64_t test_encrypted_PIN_Block = 0x5BC0AF22AD87B327;

	printf("Received KSN: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
		KSN[0], KSN[1], KSN[2], KSN[3], KSN[4],
		KSN[5], KSN[6], KSN[7], KSN[8], KSN[9]);
	printf("Received encrypted PIN Block: %016llx\n", test_encrypted_PIN_Block);
	printf("Internal BDK: %016llx %016llx \n", BDK[0], BDK[1]);




	uint64_t IPEK[2];

	CalcIPEK(BDK, KSN, IPEK);
	printf("IPEK: %016llx %016llx\n", IPEK[0], IPEK[1]);


	/* Derive Key */
	uint64_t curKey[2];
	
	uint64_t baseKSN_mask = 0xFFFFFFFFFFE00000;
	uint64_t baseKSN = 0x0;
	/* baseKSN = rightmost 64 bits of KSN with counter=0 */
	for (int i = 2; i < 10; i++)
	{
		baseKSN |= (uint64_t)(KSN[i]) << (9 - i) * 8;
	}
	baseKSN &= baseKSN_mask;

	uint32_t counter = 0x0;
	uint32_t counter_mask = 0x1FFFFF;
	/* Bottom 3 bytes */
	for (int i = 7; i < 10; i++)
	{
		counter |= (uint32_t)(KSN[i]) << (9 - i)*8;
	}
	/* bottom 21 bits*/
	counter &= counter_mask;
	printf("Encryption Counter: %x\n", counter);

	curKey[0] = IPEK[0];
	curKey[1] = IPEK[1];

	for (uint32_t shiftReg = 0x100000; shiftReg > 0; shiftReg >>= 1)
	{
		if (shiftReg & counter)
		{
			baseKSN |= shiftReg;
			//printf("baseKSN: %016llx\n", baseKSN);
			generateKey(curKey, baseKSN);
			//printf("curKey: %016llx %016llx\n", curKey[0], curKey[1]);
		}
	}

	printf("---------------------------------------------------\n");
	printf("Regenerated Key: %016llx  %016llx\n", curKey[0], curKey[1]);

	uint64_t PIN_variant_const[2] = { 0x00000000000000FF, 0x00000000000000FF };
	uint64_t PIN_encryption_key[2];
	PIN_encryption_key[0] = curKey[0] ^ PIN_variant_const[0];
	PIN_encryption_key[1] = curKey[1] ^ PIN_variant_const[1];
	printf("PIN encryption Key: %016llx  %016llx\n", PIN_encryption_key[0], PIN_encryption_key[1]);

	uint64_t clean_PIN_Block = DES_Decrypt(DES_Encrypt(DES_Decrypt(test_encrypted_PIN_Block, PIN_encryption_key[0]), PIN_encryption_key[1]), PIN_encryption_key[0]);
	printf("Decrypted PIN Block: %016llx\n", clean_PIN_Block);

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

void generateKey(uint64_t key[2], uint64_t baseKSN)
{

	uint64_t mask[2] = { 0xC0C0C0C000000000, 0xC0C0C0C000000000 };
	uint64_t maskedKey[2];
	maskedKey[0] = mask[0] ^ key[0];
	maskedKey[1] = mask[1] ^ key[1];
	
	//printf("baseKSN: %016llx | maskedKey: %016llx %016llx\n", baseKSN, maskedKey[0], maskedKey[1]);
	//printf("baseKSN: %016llx | key: %016llx %016llx\n", baseKSN, key[0], key[1]);
	uint64_t left = DES_Encrypt(baseKSN ^ maskedKey[1], maskedKey[0]) ^ maskedKey[1];
	uint64_t right = DES_Encrypt(baseKSN ^ key[1], key[0]) ^ key[1];
	
	key[0] = left;
	key[1] = right;

}