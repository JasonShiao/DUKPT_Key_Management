#ifndef DUKPT_H
#define DUKPT_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include "config.h"

#if ANSI_X_9_24_2009
#include"DES.h"
#endif

typedef struct
{
	uint64_t LeftHalf;
	uint64_t RightHalf;
	uint8_t LRC;
} FutureKey;

typedef struct
{
	bool operative;			   // Operative Flag
	uint8_t KSNReg[10];		   // Key Serial Number Register, including Initial Key Serial Number (59 bits) and Encryption Counter (21 bits)
	FutureKey FKReg[21];	   // Future Key Register: FK[20] = FK21 = the bit-0 Future Key
	uint64_t KeyReg[2];		   // Key Register:    Store the key to be used in encryption process
	uint64_t CryptoReg[2];	   // Crypto Register: Store the data to be encrypted and the result of encryption)
	uint64_t ShiftReg;		   // Shift Register:  At any point in time, only one bit in ShiftReg is set. (and only the right-most 21-bit should be used), and #1 is the left-most bit in the 21 bits, ...
	FutureKey *CurrentKeyPtr;  // Current Key Pointer (Point to element of Future Key Register)
} DUKPT_Reg;

void GenerateLRC(FutureKey *FK);
int checkLRC(FutureKey *FK);

void CalcIPEK(uint64_t BDK[2], uint8_t KSN[10], uint64_t IPEK[2]);
void generateKey(uint64_t key[2], uint64_t baseKSN);
void NonReversibleKeyGen(DUKPT_Reg* DUKPT_Instance);

void NewKey_3(DUKPT_Reg* DUKPT_Instance, bool firstKey);
void NewKey_1(DUKPT_Reg* DUKPT_Instance);
void NewKey_4(DUKPT_Reg* DUKPT_Instance);
int NewKey_2(DUKPT_Reg* DUKPT_Instance);

void NewKey(DUKPT_Reg* DUKPT_Instance);

void SetBit(DUKPT_Reg* DUKPT_Instance);

void printDUKPTStateSummary(DUKPT_Reg* DUKPT_Instance);




#endif // DUKPT_H