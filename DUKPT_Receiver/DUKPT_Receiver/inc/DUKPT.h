#ifndef DUKPT_H
#define DUKPT_H

#include<stdint.h>

void SetBit(uint64_t *ShiftReg, uint64_t EncryptCounter);
void NonReversibleKeyGen(uint64_t KeyReg[2], uint64_t CryptoReg[2]);
void TripleDEA_Encrypt(uint64_t KeyReg[2], uint64_t CryptoReg[2]);


#endif
