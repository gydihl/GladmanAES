#include "GladmanAES.h"
#include <memory.h>
#include <algorithm>


void aes_cycles(volatile unsigned __int64 *rtn)    
{   
#if defined(_MSC_VER)
	__asm   // read the Pentium Time Stamp Counter
	{   cpuid
		rdtsc
		mov     ecx,rtn
		mov     [ecx],eax
		mov     [ecx+4],edx
		cpuid
	}
#else
#include <time.h>
	time_t tt;
	tt     = time(NULL);
	rtn[0] = tt;
	rtn[1] = tt & -36969l;
	return;
#endif
}

#define AES_RAND(a,b) (((a = 36969 * (a & 65535) + (a >> 16)) << 16) + \
	(b = 18000 * (b & 65535) + (b >> 16))  )

void aes_fillrand(char *buf, const int len)
{
	static unsigned long aes_a[2], aes_mt = 1, aes_count = 4;
	static char          aes_r[4];
	int                  i;

	if(aes_mt) { aes_mt = 0; aes_cycles((unsigned __int64 *)aes_a); }

	for(i = 0; i < len; ++i)
	{
		if(aes_count == 4)
		{
			*(unsigned long*)aes_r = AES_RAND(aes_a[0], aes_a[1]);
			aes_count = 0;
		}

		buf[i] = aes_r[aes_count++];
// 		aes_r[aes_count++];
// 		buf[i] = 0;
	}
}

GladmanAES::GladmanAES()
{
	_nKeyLength = 0;
	memset(_key, 0, sizeof(unsigned char)*KEY_LENGTH);
// 	memset(&_encCtx, 0, sizeof(_encCtx));
// 	memset(&_decCtx, 0, sizeof(_decCtx));
}

GladmanAES::~GladmanAES()
{

}

void GladmanAES::setkey(const unsigned char *key, int length)
{
	if (!key || length > 2 * KEY_LENGTH)
		return;
	memset(_hexKey, 0, 2 * KEY_LENGTH);
	memcpy(_hexKey, key, length);
	int index = 0;
	// temp data
	char ch = 0;
	int by = 0;
	while (index < length)
	{
		// all to upper
		ch = toupper(_hexKey[index]);
		if (ch >= '0' && ch <= '9')
			by = (by << 4) + ch - '0';
		else if (ch >= 'A' && ch <= 'F')
			by = (by << 4) + ch - 'A' + 10;
		else
		{
			printf("key must be in hexadecimal notation\n");
			return;
		}
		// store a key byte for each pair of hexadecimal digits
		if (index++ & 1)
			_key[index / 2 - 1] = by & 0xFF;
	}
	_nKeyLength = length / 2;
	// encode aes ctx
	aes_enc_key(_key, _nKeyLength, _encCtx);
	// decode aes ctx
	aes_dec_key(_key, _nKeyLength, _decCtx);
}

// pInBuf is data buffer + fill 0 size buff + BLOCK_SIZE*0 buffer
// inLength is buffer data length + 0 length + BLOCK_SIZE
// pOutBuf is encode data buffer + IV
unsigned long GladmanAES::encode(unsigned char *pInBuf, unsigned long inLength, unsigned char *pOutBuf)
{
	if (!pInBuf || !pOutBuf || inLength < 2 * BLOCK_SIZE)
		return inLength;
	unsigned char *pIV = pOutBuf + inLength - BLOCK_SIZE;
	// rand iv
	aes_fillrand((char*)pIV, BLOCK_SIZE);

	unsigned long enBegin = 0;
	while (enBegin < inLength - BLOCK_SIZE)
	{
		// xor the buffer bytes with the IV bytes
		for (int i = 0; i < BLOCK_SIZE; ++i)
		{
			pInBuf[enBegin+i] ^= pIV[i];
		}

		// encrypt the 16 bytes of the buffers
		aes_enc_blk(pInBuf+enBegin, pOutBuf+enBegin, _encCtx);

		// change IV to encode buffer
		pIV = pOutBuf + enBegin;

		enBegin += BLOCK_SIZE;
	}
	return inLength;
}

// pInBuf is org data buffer + IV buffer
// inLength is buffer data length + BLOCK_SIZE
// pOutBuf is encode data buffer
unsigned long GladmanAES::decode(unsigned char *pInBuf, unsigned long inLength, unsigned char *pOutBuf)
{
	if (!pInBuf || !pOutBuf || inLength < 2 * BLOCK_SIZE)
		return inLength;
	unsigned char pIV[BLOCK_SIZE] = {0};
	unsigned char pTmpIV[BLOCK_SIZE] = {0};

	memcpy(pIV, pInBuf + inLength - BLOCK_SIZE, BLOCK_SIZE);

	unsigned long deBegin = 0;
	while (deBegin < inLength - BLOCK_SIZE)
	{
		memcpy(pTmpIV, pInBuf + deBegin, BLOCK_SIZE);
		// decrypt 
		aes_dec_blk(pInBuf+deBegin, pOutBuf+deBegin, _decCtx);
		// unchain cbc 
		for (int i = 0; i < BLOCK_SIZE; ++i)
		{
			pOutBuf[deBegin+i] ^= pIV[i];
		}

		memcpy(pIV, pTmpIV, BLOCK_SIZE);

		deBegin += BLOCK_SIZE;
	}

	return inLength - BLOCK_SIZE;
}

// pInBuf is data buffer + BLOCK_SIZE*0 buffer
// inLength is buffer data length + BLOCK_SIZE
// pOutBuf is encode data buffer + IV
unsigned long GladmanAES::encode_error(unsigned char *pInBuf, unsigned long inLength, unsigned char *pOutBuf)
{
	if (!pInBuf || !pOutBuf || 0 == inLength)
		return inLength;

	// set a random IV	
	unsigned char iv[BLOCK_SIZE] = {0};
	aes_fillrand((char*)iv, BLOCK_SIZE);

	unsigned char dataBuffer[BLOCK_SIZE] = {0};

	if (inLength - BLOCK_SIZE <= BLOCK_SIZE)
	{
		memset(dataBuffer, 0, BLOCK_SIZE);
		// copy data
		memcpy(dataBuffer, pInBuf, inLength-BLOCK_SIZE);
		// xor the byte with zeors
		for (int i = 0; i < BLOCK_SIZE; ++i)
		{
			dataBuffer[i] ^= iv[i];
		}
		// encrypt 
		aes_enc_blk(dataBuffer, pOutBuf, _encCtx);
		// iv to output buff
		memcpy(pOutBuf+BLOCK_SIZE, iv, inLength-BLOCK_SIZE);
	}
	else
	{

// 		unsigned long enBegin = 0;
// 		while (enBegin < inLength - BLOCK_SIZE)
// 		{
// 			// xor the buffer bytes with the IV bytes
// 			for (int i = 0; i < BLOCK_SIZE; ++i)
// 			{
// 				pInBuf[enBegin+i] ^= pIV[i];
// 			}
// 
// 			// encrypt the 16 bytes of the buffers
// 			aes_enc_blk(pInBuf+enBegin, pOutBuf+enBegin, _encCtx);
// 
// 			// change IV to encode buffer
// 			pIV = pOutBuf + enBegin;
// 
// 			enBegin += BLOCK_SIZE;
// 		}
	}

	return inLength;
}

// pInBuf is org data buffer + IV buffer
// inLength is buffer data length + BLOCK_SIZE
// pOutBuf is encode data buffer + IV
unsigned long GladmanAES::decode_error(unsigned char *pInBuf, unsigned long inLength, unsigned char *pOutBuf)
{
	if (!pInBuf || !pOutBuf || inLength < BLOCK_SIZE)
		return inLength;
	// get IV
	unsigned char iv[BLOCK_SIZE] = {0};

	unsigned char dataBuffer[BLOCK_SIZE] = {0};

	if (inLength - BLOCK_SIZE <= BLOCK_SIZE)
	{
		// copy iv
		memcpy(iv, pInBuf+inLength-BLOCK_SIZE, BLOCK_SIZE);
		memset(dataBuffer, 0, BLOCK_SIZE);
		// copy data
		memcpy(dataBuffer, pInBuf, inLength-BLOCK_SIZE);
		// decode
		aes_dec_blk(dataBuffer, pOutBuf, _decCtx);
		// undo cbc chaining
		for (int i = 0; i < inLength-BLOCK_SIZE; ++i)
		{
			pOutBuf[i] = iv[i];
		}
	}
	else
	{
// 		unsigned long deBegin = 0;
// 		while (deBegin < inLength - BLOCK_SIZE)
// 		{
// 			// decrypt input buffer
// 			aes_dec_blk(pInBuf+deBegin, pOutBuf+deBegin, _decCtx);
// 
// 			for (int i = 0; i < BLOCK_SIZE; ++i)
// 			{
// 				pOutBuf[deBegin+i] ^= pIV[i];
// 			}
// 
// 			// change IV to encode buffer
// 			pIV = pInBuf[deBegin+BLOCK_SIZE];
// 
// 			deBegin += BLOCK_SIZE;
// 		}
	}

	return inLength-BLOCK_SIZE;
}