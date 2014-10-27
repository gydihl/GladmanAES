// TestAES.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <memory.h>

#include "AES/aes.h"
#include <string>

#define BLOCK_LEN   16
#define READ_ERROR  -7
#define WRITE_ERROR -8

#ifdef LINUX
#define file_len(x) (unsigned long)x.__pos
#else
#define file_len(x) (unsigned long)x
#endif

void cycles(volatile unsigned __int64 *rtn)    
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

#define RAND(a,b) (((a = 36969 * (a & 65535) + (a >> 16)) << 16) + \
	(b = 18000 * (b & 65535) + (b >> 16))  )

void fillrand(char *buf, const int len)
{
	static unsigned long a[2], mt = 1, count = 4;
	static char          r[4];
	int                  i;

	if(mt) { mt = 0; cycles((unsigned __int64 *)a); }

	for(i = 0; i < len; ++i)
	{
		if(count == 4)
		{
			*(unsigned long*)r = RAND(a[0], a[1]);
			count = 0;
		}

		buf[i] = r[count++];
	}
}

int encfile(FILE *fin, FILE *fout, aes_ctx *ctx, const char *ifn, const char *ofn)
{
	char buf[BLOCK_LEN], dbuf[2 * BLOCK_LEN];
	fpos_t          flen;
	unsigned long   i, len, rlen;

	// set a random IV

	fillrand(dbuf, BLOCK_LEN);

	// find the file length

	fseek(fin, 0, SEEK_END);
	fgetpos(fin, &flen); 
	rlen = file_len(flen);
	// reset to start
	fseek(fin, 0, SEEK_SET);

	if(rlen <= BLOCK_LEN)               
	{   // if the file length is less than or equal to 16 bytes

		// read the bytes of the file into the buffer and verify length
		len = (unsigned long) fread(dbuf + BLOCK_LEN, 1, BLOCK_LEN, fin);
		rlen -= len;        
		if(rlen > 0) 
			return READ_ERROR;

		// pad the file bytes with zeroes
		for(i = len; i < BLOCK_LEN; ++i)
			dbuf[i + BLOCK_LEN] = 0;

		// xor the file bytes with the IV bytes
		for(i = 0; i < BLOCK_LEN; ++i)
			dbuf[i + BLOCK_LEN] ^= dbuf[i];

		// encrypt the top 16 bytes of the buffer
		aes_enc_blk((unsigned char*)(dbuf + BLOCK_LEN), (unsigned char*)(dbuf + len), ctx);

		len += BLOCK_LEN;
		// write the IV and the encrypted file bytes
		if(fwrite(dbuf, 1, len, fout) != len)
			return WRITE_ERROR;
	}
	else
	{   // if the file length is more 16 bytes

		// write the IV
		if(fwrite(dbuf, 1, BLOCK_LEN, fout) != BLOCK_LEN)
			return WRITE_ERROR;

		// read the file a block at a time 
		while(rlen > 0 && !feof(fin))
		{  
			// read a block and reduce the remaining byte count
			len = (unsigned long)fread(buf, 1, BLOCK_LEN, fin);
			rlen -= len;

			// verify length of block 
			if(len != BLOCK_LEN) 
				return READ_ERROR;

			// do CBC chaining prior to encryption
			for(i = 0; i < BLOCK_LEN; ++i)
				buf[i] ^= dbuf[i];

			// encrypt the block
			aes_enc_blk((unsigned char*)buf, (unsigned char*)dbuf, ctx);

			// if there is only one more block do ciphertext stealing
			if(rlen > 0 && rlen < BLOCK_LEN)
			{
				// move the previous ciphertext to top half of double buffer
				// since rlen bytes of this are output last
				for(i = 0; i < BLOCK_LEN; ++i)
					dbuf[i + BLOCK_LEN] = dbuf[i];

				// read last part of plaintext into bottom half of buffer
				if(fread(dbuf, 1, rlen, fin) != rlen)
					return READ_ERROR;

				// clear the remainder of the bottom half of buffer
				for(i = 0; i < BLOCK_LEN - rlen; ++i)
					dbuf[rlen + i] = 0;

				// do CBC chaining from previous ciphertext
				for(i = 0; i < BLOCK_LEN; ++i)
					dbuf[i] ^= dbuf[i + BLOCK_LEN];

				// encrypt the final block
				aes_enc_blk((unsigned char*)dbuf, (unsigned char*)dbuf, ctx);

				// set the length of the final write
				len = rlen + BLOCK_LEN; rlen = 0;
			}

			// write the encrypted block
			if(fwrite(dbuf, 1, len, fout) != len)
				return WRITE_ERROR;
		}
	}

	return 0;
}

int decfile(FILE *fin, FILE *fout, aes_ctx *ctx, const char* ifn, const char* ofn)
{
	char            buf1[BLOCK_LEN], buf2[BLOCK_LEN], dbuf[2 * BLOCK_LEN];
	char            *b1, *b2, *bt;
	fpos_t          flen;
	unsigned long   i, len, rlen;

	// find the file length

	fseek(fin, 0, SEEK_END);
	fgetpos(fin, &flen); 
	rlen = file_len(flen);
	// reset to start
	fseek(fin, 0, SEEK_SET);

	if(rlen <= 2 * BLOCK_LEN)
	{   // if the original file length is less than or equal to 16 bytes

		// read the bytes of the file and verify length
		len = (unsigned long)fread(dbuf, 1, 2 * BLOCK_LEN, fin);
		rlen -= len;
		if(rlen > 0)
			return READ_ERROR;

		// set the original file length
		len -= BLOCK_LEN;

		// decrypt from position len to position len + BLOCK_LEN
		aes_dec_blk((unsigned char*)(dbuf + len), (unsigned char*)(dbuf + BLOCK_LEN), ctx);

		// undo CBC chaining
		for(i = 0; i < len; ++i)
			dbuf[i] ^= dbuf[i + BLOCK_LEN];

		// output decrypted bytes
		if(fwrite(dbuf, 1, len, fout) != len)
			return WRITE_ERROR; 
	}
	else
	{   // we need two input buffers because we have to keep the previous
		// ciphertext block - the pointers b1 and b2 are swapped once per
		// loop so that b2 points to new ciphertext block and b1 to the
		// last ciphertext block

		rlen -= BLOCK_LEN; b1 = buf1; b2 = buf2;

		// input the IV
		if(fread(b1, 1, BLOCK_LEN, fin) != BLOCK_LEN)
			return READ_ERROR;

		// read the encrypted file a block at a time
		while(rlen > 0 && !feof(fin))
		{
			// input a block and reduce the remaining byte count
			len = (unsigned long)fread(b2, 1, BLOCK_LEN, fin);
			rlen -= len;

			// verify the length of the read operation
			if(len != BLOCK_LEN)
				return READ_ERROR;

			// decrypt input buffer
			aes_dec_blk((unsigned char*)b2, (unsigned char*)dbuf, ctx);

			// if there is only one more block do ciphertext stealing
			if(rlen > 0 && rlen < BLOCK_LEN)
			{
				// read last ciphertext block
				if(fread(b2, 1, rlen, fin) != rlen)
					return READ_ERROR;

				// append high part of last decrypted block
				for(i = rlen; i < BLOCK_LEN; ++i)
					b2[i] = dbuf[i];

				// decrypt last block of plaintext
				for(i = 0; i < rlen; ++i)
					dbuf[i + BLOCK_LEN] = dbuf[i] ^ b2[i];

				// decrypt last but one block of plaintext
				aes_dec_blk((unsigned char*)b2, (unsigned char*)dbuf, ctx);

				// adjust length of last output block
				len = rlen + BLOCK_LEN; rlen = 0;
			}

			// unchain CBC using the last ciphertext block
			for(i = 0; i < BLOCK_LEN; ++i)
				dbuf[i] ^= b1[i];

			// write decrypted block
			if(fwrite(dbuf, 1, len, fout) != len)
				return WRITE_ERROR;

			// swap the buffer pointers
			bt = b1, b1 = b2, b2 = bt;
		}
	}

	return 0;
}

#include "AES/GladmanAES.h"

void testEncodeDecode(GladmanAES aes)
{
	FILE *fp = fopen("D:\\gameloading.json", "rb");
	fpos_t pos = 0;
	fgetpos(fp, &pos);
	fseek(fp, 0L, SEEK_END);
	long lFilelength = ftell(fp);
	fsetpos(fp, &pos);

	long bufSize = lFilelength;
	if (lFilelength % 16 > 0)
	{
		bufSize = 16 * (lFilelength / 16 + 1);
	}
	bufSize += 16;
	unsigned char *buf = new unsigned char[bufSize];
	memset(buf, 0, bufSize);
	fread(buf, sizeof(char), lFilelength, fp);
	fclose(fp);
	printf("%s\n", buf);

	aes.encode(buf, bufSize, buf);
	FILE *fpSave = fopen("D:\\gameloading_cpp_1.json", "wb");
	fwrite(buf, sizeof(char), bufSize, fpSave);
	fclose(fpSave);

	bufSize = aes.decode(buf, bufSize, buf);
	FILE *fpInv = fopen("D:\\gameloading_cpp_2.json", "wb");
	fwrite(buf, sizeof(char), lFilelength, fpInv);
	fclose(fpInv);
}

void testDecode(GladmanAES aes)
{
	FILE *fpEncode = fopen("D:\\gameloading_1.json", "rb");
	if (!fpEncode)
		return;

	fpos_t pos = 0;
	fgetpos(fpEncode, &pos);
	fseek(fpEncode, 0L, SEEK_END);
	long lFilelength = ftell(fpEncode);
	fsetpos(fpEncode, &pos);

	unsigned char *buf = new unsigned char[lFilelength];
	memset(buf, 0, lFilelength);

	fread(buf, sizeof(unsigned char), lFilelength, fpEncode);
	fclose(fpEncode);

	lFilelength = aes.decode(buf, lFilelength, buf);

	while (0 == buf[lFilelength-1])
	{
		--lFilelength;
	}

	FILE *fpDecode = fopen("D:\\gameloading_1_cpp.json", "wb");
	fwrite(buf, sizeof(unsigned char), lFilelength, fpDecode);
	fclose(fpDecode);
}

int _tmain(int argc, _TCHAR* argv[])
{
	char *cp = new char[64];
	char *keystore = new char[16];
	keystore = "0123456789ABCDEF";
	for (int i = 0; i < 64; ++i)
	{
		cp[i] = keystore[i % 16];
	}

	char tpcp[65] = "7d72e6035fd27ebcd25f1a4daec1bef67d72e6035fd27ebcd25f1a4daec1bef6";

// 	unsigned char *buffer = new unsigned char[32];
// 	buffer = (unsigned char*)"animation";
	unsigned char buffer[32+16] = "animation GladmanAES";
	GladmanAES aes;
//	aes.setkey((unsigned char*)cp, 64);
	aes.setkey((unsigned char*)tpcp, 64);
	testEncodeDecode(aes);
	testDecode(aes);

// 	aes.encode(buffer, 32+16, buffer);
// 	aes.decode(buffer, 32+16, buffer);
//	aes.encode(buffer, 32, buffer);
	int i = 0;
	i = 5;

/*	FILE        *fin = 0, *fout = 0, *fdecout = 0;
	char        *cp, ch, key[32];
	int         i, by, key_len, err = 0;
	aes_ctx     ctx[1];

	std::string strfin = "D:\\fin.txt";
	std::string strfout = "D:\\fout.txt";
	std::string strfdecout = "D:\\fdecout.txt";

	fin = fopen(strfin.c_str(), "rb");
//	fout = fopen(strfout.c_str(), "wb");
	fout = fopen(strfout.c_str(), "wb+");
	fdecout = fopen(strfdecout.c_str(), "wb");

	cp = new char[64];
	by = 0;
	by * 0xff;
	char *keystore = new char[16];
	keystore = "0123456789ABCDEF";
	for (i = 0; i < 64; ++i)
	{
		ch = cp[i] = keystore[i % 16];
		if (ch >= '0' && ch <= '9')
			by = (by << 4) + ch - '0';
		else if (ch >= 'A' && ch <= 'F')
			by = (by << 4) + ch - 'A' + 10;
		else
		{
			printf("key must by in hexadecimal notation\n");
		}
		if (i & 1)
			key[(i+1)/2-1] = by * 0xff;
	}

	key_len = 64 / 2;

	aes_enc_key((unsigned char*)key, key_len, ctx);
	err = encfile(fin, fout, ctx, strfin.c_str(), strfout.c_str());
	
	aes_dec_key((unsigned char*)key, key_len, ctx);
	err = decfile(fout, fdecout, ctx, strfout.c_str(), strfdecout.c_str());

	fclose(fin);
	fclose(fout);
	fclose(fdecout);
	*/
	return 0;
}

