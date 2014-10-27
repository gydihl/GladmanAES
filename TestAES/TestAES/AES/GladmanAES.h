/********************************************************************
	created:	2014/10/24
	filename: 	GladmanAES.h
	author:		dihl
	purpose:	gladman AES class
	http://brgladman.org/oldsite/cryptography_technology/index.php

*********************************************************************/

#pragma once

#include "aes.h"
#include <string>

class GladmanAES
{
public:
	GladmanAES();
	virtual ~GladmanAES();

public:
	// set hexadecimal key	max 64
	void setkey(const unsigned char *key, int length);

	// iv back
	unsigned long encode(unsigned char *pInBuf, unsigned long inLength, unsigned char *pOutBuf);
	unsigned long decode(unsigned char *pInBuf, unsigned long inLength, unsigned char *pOutBuf);


	unsigned long encode_error(unsigned char *pInBuf, unsigned long inLength, unsigned char *pOutBuf);
	unsigned long decode_error(unsigned char *pInBuf, unsigned long inLength, unsigned char *pOutBuf);

protected:
	static const int KEY_LENGTH			= 32;
	int _nKeyLength;
	unsigned char _key[KEY_LENGTH];// the maximum key length is 32 bytes
	unsigned char _hexKey[2*KEY_LENGTH];		// hence at most 64 hexadecimal digits process a hexadecimal digit
	aes_ctx _encCtx[1];			// encode ctx
	aes_ctx _decCtx[1];			// decode ctx
};
