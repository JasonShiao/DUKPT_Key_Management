#include"DUKPT.h"

#include<stdint.h>
#include"DES.h"



void SetBit(uint64_t *ShiftReg, uint64_t EncryptCounter)
{
	uint64_t temp = 0x1U;
	for (int i = 0; i < 21; i++)
	{
		if (temp & EncryptCounter)
		{
			*ShiftReg = temp;
			break;
		}
		temp <<= 1;
	}
}

void NonReversibleKeyGen(uint64_t KeyReg[2], uint64_t CryptoReg[2])
{
	CryptoReg[1] = CryptoReg[0] ^ KeyReg[1];
	CryptoReg[1] = DES_Encrypt(CryptoReg[1], KeyReg[0]);
	CryptoReg[1] = CryptoReg[1] ^ KeyReg[1];
	KeyReg[0] ^= (uint64_t)0xC0C0C0C000000000;
	KeyReg[1] ^= (uint64_t)0xC0C0C0C000000000;

	CryptoReg[0] ^= KeyReg[1];
	CryptoReg[0] = DES_Encrypt(CryptoReg[0], KeyReg[0]);
	CryptoReg[0] ^= KeyReg[1];
}

void TripleDEA_Encrypt(uint64_t KeyReg[2], uint64_t CryptoReg[2])
{
	CryptoReg[0] = DES_Encrypt(CryptoReg[0], KeyReg[0]);
	CryptoReg[0] = DES_Decrypt(CryptoReg[0], KeyReg[1]);
	CryptoReg[0] = DES_Encrypt(CryptoReg[0], KeyReg[0]);
}