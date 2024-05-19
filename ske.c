#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+----------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(IV|C) (32 bytes for SHA256) |
 * +------------+--------------------+----------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */

	/*
	unsigned char *HMAC(
						const EVP_MD *evp_md,
						const void *key,
						int key_len,
						const unsigned char *d,
						size_t n,
						unsigned char *md,
						unsigned int *md_len
	);
	HMAC() computes the message authentication code of the n bytes at d using the hash function evp_md and the key key which is key_len bytes long. It places the result in md (which must have space for the output of the hash function, which is no more than EVP_MAX_MD_SIZE bytes). If md is NULL, the digest is placed in a static array. The size of the output is placed in md_len, unless it is NULL.
	Note: passing a NULL value for md to use the static array is not thread safe.
	*/

	unsigned char memalloc = 0;
	if(entropy == NULL)
	{
		entLen = 32;
		entropy = calloc(entLen, 1);
		++memalloc;
		randBytes(entropy, entLen);
	}

	unsigned int md_len = -1;
	HMAC(
		EVP_sha256(),
		KDF_KEY,
		strlen(KDF_KEY),
		entropy,
		entLen,
		K->hmacKey,
		&md_len
	);

	memcpy(K->aesKey, K->hmacKey, HM_LEN);

// 	printf("md_len: 	%u\n", md_len);
// 	printf("K->hmacKey: %.32s\n", K->hmacKey);
//
// 	printf("md_len: 	%u\n", md_len);
// 	printf("K->aesKey:  %.32s\n", K->aesKey);

	if(memalloc) free(entropy);

	return 0;
}

size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}

size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len, SKE_KEY* K, unsigned char* IV)
{
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */

	if(inBuf == NULL)
	{
		fprintf(stderr, "Input buffer is NULL. Nothing to encrypt.\n");
		return 0;
	}

	if(outBuf == NULL)
	{
		fprintf(stderr, "Output buffer is NULL. Encryption stopped.\n");
		return 0;
	}

	unsigned char iv[16];
	if(IV == NULL)
		for (size_t i = 0; i < 16; i++)	iv[i] = i;
	else
		memcpy(iv, IV, 16);

	/* encrypt: */
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, iv))
		ERR_print_errors_fp(stderr);

	memcpy(outBuf, iv, sizeof iv);
	outBuf += sizeof iv;

	int nWritten = 0;
	if (1 != EVP_EncryptUpdate(ctx, outBuf, &nWritten, inBuf, len))
		ERR_print_errors_fp(stderr);

	EVP_CIPHER_CTX_free(ctx);

	unsigned int md_len = 0;
	outBuf -= sizeof iv;
	HMAC(
		EVP_sha256(),
		K->hmacKey,
		sizeof K->hmacKey,
		outBuf,
		sizeof iv + len,
		outBuf + sizeof iv + len ,
		&md_len
	);

	/* TODO: should return number of bytes written, which
	   hopefully matches ske_getOutputLen(...). */
	return ske_getOutputLen(len);
}

size_t ske_encrypt_file(const char* fnout, const char* fnin, SKE_KEY* K, unsigned char* IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */




	return 0;
}

size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len, SKE_KEY* K)
{
	/* TODO: write this.  Make sure you check the mac before decrypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */

	/* now decrypt.  NOTE: in counter mode, encryption and decryption are
	 * actually identical, so doing the above again would work. */

	if(inBuf == NULL)
	{
		fprintf(stderr, "Input buffer is NULL. Nothing to encrypt.\n");
		return 0;
	}

	if(outBuf == NULL)
	{
		fprintf(stderr, "Output buffer is NULL. Decryption stopped.\n");
		return 0;
	}

	unsigned int md_len = 0;
	unsigned char mac[HM_LEN] = { [HM_LEN - 1] = '\0'};
	HMAC(
		EVP_sha256(),
		K->hmacKey,
		sizeof K->hmacKey,
		inBuf,
		len - HM_LEN,
		mac,
		&md_len
	);

	/* check the mac before decrypting */
	if(memcmp(mac, inBuf + len - HM_LEN, HM_LEN) != 0)
		return -1;

	/* if MAC test success begin decryption */
	puts("MAC TEST SUCCESS .....");

	int nWritten = 0;
	unsigned char iv[16];
	for (size_t i = 0; i < 16; i++) iv[i] = i;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, iv))
		ERR_print_errors_fp(stderr);
	if (1 != EVP_DecryptUpdate(ctx, outBuf, &nWritten, inBuf + sizeof iv, len - HM_LEN - sizeof iv))
		ERR_print_errors_fp(stderr);

	return nWritten;
}

size_t ske_decrypt_file(const char* fnout, const char* fnin, SKE_KEY* K, size_t offset_in)
{
	/* TODO: write this. */
	return 0;
}
