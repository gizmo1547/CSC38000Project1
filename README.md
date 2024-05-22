# Project1: Secure Encryption 

## Synopsis
`project1` is a simple encryption utility that provides CCA2 security based on the KEM/DEM hybrid model. The project includes a set of programs and libraries to encrypt and decrypt data using RSA and AES encryption.

## Important Notes
- Ensure you have OpenSSL installed on your system.
- The utility supports encryption and decryption of files and key generation.
- The project uses RSA for key encapsulation and AES for symmetric encryption.

## Details

### Encryption Utility (`kem-enc.c`)
The `kem-enc.c` file provides a command-line utility for encrypting and decrypting data using a combination of RSA and AES. It supports various options for input/output files, key management, and encryption/decryption modes.

#### Key Functions:
- `kem_encrypt`: Encapsulates a random symmetric key (SK) using RSA and SHA256, encrypts the input file with SK, and writes the encapsulation and ciphertext to the output file.
- `kem_decrypt`: Recovers the symmetric key from the encapsulation, checks its validity, and decrypts the input file using the recovered key.

### Pseudo-Random Function (`prf.c` and `prf.h`)
The `prf.c` and `prf.h` files provide a simple pseudo-random function based on HMAC-SHA512. It is used for generating random bytes and seeding cryptographic operations.

#### Key Functions:
- `setSeed`: Initializes the PRF state with a given entropy.
- `randBytes`: Generates random bytes using the PRF.

### RSA Encryption (`rsa.c` and `rsa.h`)
The `rsa.c` and `rsa.h` files implement RSA encryption and decryption functions. They also provide utilities for key generation and key management.

#### Key Functions:
- `rsa_keyGen`: Generates RSA public and private keys.
- `rsa_encrypt`: Encrypts data using RSA.
- `rsa_decrypt`: Decrypts data using RSA.
- `rsa_initKey`: Initializes an RSA key structure.
- `rsa_writePublic`: Writes an RSA public key to a file.
- `rsa_writePrivate`: Writes an RSA private key to a file.
- `rsa_readPublic`: Reads an RSA public key from a file.
- `rsa_readPrivate`: Reads an RSA private key from a file.

### Symmetric Key Encryption (`ske.c` and `ske.h`)
The `ske.c` and `ske.h` files implement CCA2 symmetric key encryption using AES in counter mode and HMAC for message authentication.

#### Key Functions:
- `ske_keyGen`: Generates a symmetric key from a given entropy.
- `ske_encrypt`: Encrypts data using AES-CTR and appends an HMAC for integrity.
- `ske_decrypt`: Decrypts data using AES-CTR and verifies the HMAC.
- `ske_encrypt_file`: Encrypts a file using AES-CTR and HMAC.
- `ske_decrypt_file`: Decrypts a file using AES-CTR and verifies the HMAC.

## Compiling the Skeleton
To compile the project, ensure you have gcc and OpenSSL development libraries installed. Use the following commands:

```bash
gcc -o kem-enc kem-enc.c ske.c rsa.c prf.c -lssl -lcrypto -lgmp
