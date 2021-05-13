//Copyright (c) 2018-2019, ARM Limited. All rights reserved.
//
//SPDX-License-Identifier:        BSD-3-Clause

#define NDEBUG
#include <assert.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <stdint.h>


#define MAX_LINE_LEN 128
#ifndef TEST_DEBUG
#define TEST_DEBUG_PRINTF 0
#else
#define TEST_DEBUG_PRINTF 1
#endif

#define aescbc_debug_printf(...) \
    do { if (TEST_DEBUG_PRINTF) printf(__VA_ARGS__); } while (0)

uint8_t hextobyte(uint8_t top, uint8_t bot);
inline uint8_t hextobyte(uint8_t top, uint8_t bot) {
    assert(('0' <= top && top <= '9') || ('A' <= top && top <= 'F') || ('a' <= top && top <= 'f'));
    assert(('0' <= bot && bot <= '9') || ('A' <= bot && bot <= 'F') || ('a' <= bot && bot <= 'f'));
    uint8_t t = top & 0xf;
    uint8_t b = bot & 0xf;
    t += top & 0x40 ? 9 : 0;
    b += bot & 0x40 ? 9 : 0;
    return (t<<4) + b;
}

//// Called once a reference state is set up, runs encrypt/decrypt
//// and checks the outputs match the expected outputs
bool __attribute__ ((noinline)) test_reference(uint64_t block_byte_length,
                    uint8_t * key, uint8_t * iv,
                    uint8_t * reference_plaintext,
                    uint8_t * reference_ciphertext,
                    bool is_encrypt,
                    bool verbose)
{
    bool success = true;
    uint8_t key_expanded[256] = {0};
    uint8_t * output;
    uint8_t * auth;
    int outlen = 0;
	EVP_CIPHER_CTX *ctx;

    output = (uint8_t *)malloc(block_byte_length);

    //// Dummy auth data to feed cipher function.
    auth = (uint8_t *)malloc(block_byte_length);

    if (is_encrypt) {
        //// ENCRYPTION TEST
        //// Encrypt reference plaintext and check output with reference ciphertext and tag
        if(verbose) printf("\n\nENCRYPTION TEST\n");

		//加密
    	
    	ctx = EVP_CIPHER_CTX_new();    
    	EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, 1);
    	EVP_CipherUpdate(ctx, output, &outlen, reference_plaintext, block_byte_length);
    	EVP_CIPHER_CTX_free(ctx);
       
        if(verbose)
        {
            if(outlen == 0) {
                printf("Compute failure!\n");
            }else if(output != NULL) {
                printf("Computed ciphertext: 0x");
                for(uint64_t i=0; i<block_byte_length; ++i) {
                    printf("%02x", output[i]);
                }
                printf("\n");

                printf("Computed digest: 0x");
                for(uint64_t i=0; i<block_byte_length; ++i) {
                    printf("%02x", auth[i]);
                }
                printf("\n");
            } else {
                printf("Computed ciphertext: NULL\n");
            }
        }

        bool ref_ciphertext_match = true;
        for(int i=0; i<block_byte_length; ++i) {
            if( output[i] != reference_ciphertext[i] ) ref_ciphertext_match = false;
        }

        if(verbose) printf("Reference ciphertext match %s!\n", ref_ciphertext_match ? "success" : "failure");

        if(!ref_ciphertext_match || (outlen == 0)) {
            if(verbose) printf("Encryption failure!\n");
            success = false;
        }
    } else {
        //// DECRYPTION TEST
        //// Decrypt reference ciphertext and check output with reference plaintext and tag
        if(verbose) printf("\n\nDECRYPTION TEST\n");

		ctx = EVP_CIPHER_CTX_new();
   		EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, 0);
    	EVP_CipherUpdate(ctx, output, &outlen, reference_ciphertext, block_byte_length);
    	EVP_CIPHER_CTX_free(ctx);

        if(verbose)
        {
            if(outlen == 0) {
                printf("Compute failure!\n");
            }else if(output != NULL) {
                printf("Computed plaintext: 0x");
                for(uint64_t i=0; i<block_byte_length; ++i) {
                    printf("%02x", output[i]);
                }
                printf("\n");

                printf("Computed digest: 0x");
                for(uint64_t i=0; i<block_byte_length; ++i) {
                    printf("%02x", auth[i]);
                }
                printf("\n");
            } else {
                printf("Computed plaintext: NULL\n");
            }
        }

        bool ref_plaintext_match = true;
        for(int i=0; i<block_byte_length; ++i) {
            if( output[i] != reference_plaintext[i] ) ref_plaintext_match = false;
        }

        if(verbose) printf("Reference plaintext match %s!\n", ref_plaintext_match ? "success" : "failure");

        if(!ref_plaintext_match || (output == 0)) {
            if(verbose) printf("Decryption failure!\n");
            success = false;
        }
    }

    free(output);
    free(auth);

    return success;
}

//// Read a reference file and check that encrypt/decrypt operations are
//// producing the correct outputs without errors
void process_test_file(FILE * fin)
{
    //// Initialise/Default values
    uint64_t block_byte_length = 16;

    char * input_buff = (char *)malloc(MAX_LINE_LEN);
    fpos_t last_line;

    uint8_t *key = NULL;
    uint8_t *iv = NULL;
    uint8_t *pt = NULL;
    uint8_t *ct = NULL;
    bool acceptable = true;
    bool new_reference = false;
    bool dir_encrypt = true;
    uint64_t passes = 0;
    uint64_t skips = 0;

    key = malloc(block_byte_length);
    iv = malloc(block_byte_length);
    pt = malloc(block_byte_length);
    ct = malloc(block_byte_length);

    while(!feof(fin)) {
        fgetpos(fin, &last_line);
        if(fgets(input_buff, MAX_LINE_LEN, fin)) {
            if (input_buff[0]!='#' && input_buff[0]!='\0') {
                if(input_buff[0] == '\n' || (input_buff[0] == '\r' && input_buff[1] == '\n')) {
                    if(new_reference)
                    {
                        if(acceptable)
                        {
                            bool pass;
                            pass = test_reference(block_byte_length,
                                        key, iv, pt, ct, dir_encrypt,
                                        false);

                            if (!pass)
                            {
                                printf("Keylen = %lu\n",
                                        block_byte_length<<3);
                                printf("Key 0x");
                                for(uint64_t i=0; i<block_byte_length; ++i) {
                                    printf("%02x", key[i]);
                                }
                                printf("\n");
                                printf("IV  0x");
                                for(uint64_t i=0; i<block_byte_length; ++i) {
                                    printf("%02x", iv[i]);
                                }
                                printf("\n");
                                printf("PT  0x");
                                for(uint64_t i=0; i<block_byte_length; ++i) {
                                    printf("%02x", pt[i]);
                                }
                                printf("\n");
                                printf("CT  0x");
                                for(uint64_t i=0; i<block_byte_length; ++i) {
                                    printf("%02x", ct[i]);
                                }
                                printf("\n");

                                pass = test_reference(block_byte_length,
                                            key, iv, pt, ct, dir_encrypt,
                                            true);
                                exit(1);
                            }
                            passes++;
                        }
                        else
                        {
                            skips++;
                        }
                    }
                    new_reference = false;
                }
                else if(strncmp(input_buff, "[ENCRYPT", 8) == 0) {
                    //set the cipher direction
                    dir_encrypt = true;
                }
                else if(strncmp(input_buff, "[DECRYPT", 8) == 0) {
                    //set the cipher direction
                    dir_encrypt = false;
                }
                else if(strncmp(input_buff, "COUNT", 5) == 0) {
                    //start of new reference
                    aescbc_debug_printf("New reference: %s\n", input_buff);
                    new_reference = true;
                }
                else if(strncmp(input_buff, "KEY", 3) == 0) {
                    //set the AES key
                    fsetpos(fin, &last_line);
                    fseek(fin, 6, SEEK_CUR);
                    for(uint64_t i=0; i<block_byte_length; ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        key[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}

                    //FIXME: I think this makes sense on BE systems, need to check
                    aescbc_debug_printf("Key set to %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                            key[0], key[1], key[2],  key[3],  key[4],  key[5],  key[6],  key[7],
                            key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15]);
                    aescbc_debug_printf("\n");
                }
                else if(strncmp(input_buff, "IV", 2) == 0) {
                    //set the nonce
                    fsetpos(fin, &last_line);
                    fseek(fin, 5, SEEK_CUR);
                    for(uint64_t i=0; i<block_byte_length; ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        iv[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}

                    aescbc_debug_printf("Set nonce - length %lu Bytes 0x", block_byte_length);
                    for(uint64_t i=0; i<block_byte_length; ++i) {
                        aescbc_debug_printf("%02x", iv[i]);
                    }
                    aescbc_debug_printf("\n");
                }
                else if(strncmp(input_buff, "PLAINTEXT", 9) == 0) {
                    //set the reference plaintext
                    fsetpos(fin, &last_line);
                    fseek(fin, 12, SEEK_CUR);
                    for(uint64_t i=0; i<block_byte_length; ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        pt[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}

                    aescbc_debug_printf("Set reference plaintext - length %lu Bytes 0x", block_byte_length);
                    for(uint64_t i=0; i<block_byte_length; ++i) {
                        aescbc_debug_printf("%02x", pt[i]);
                    }
                    aescbc_debug_printf("\n");
                }
                else if(strncmp(input_buff, "CIPHERTEXT", 10) == 0) {
                    //set the reference ciphertext
                    fsetpos(fin, &last_line);
                    fseek(fin, 13, SEEK_CUR);
                    for(uint64_t i=0; i<block_byte_length; ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        ct[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}

                    aescbc_debug_printf("Set reference ciphertext - length %lu Bytes 0x", block_byte_length);
                    for(uint64_t i=0; i<block_byte_length; ++i) {
                        aescbc_debug_printf("%02x", ct[i]);
                    }
                    aescbc_debug_printf("\n");
                }
            }
            else if(strncmp(input_buff, "# Key Length :", 14) == 0) {
                    //Check key length
                    if(strncmp (input_buff+15, "128", 3) != 0) {
                    printf("ERROR: Currently only key length 128 is supported.\n");
                    exit(1);
                }
            }
        }
    }
    free(key);
    free(iv);
    free(pt);
    free(ct);
    free(input_buff);

    printf("Successfully processed %lu inputs:\nPASS:\t%lu\nSKIP:\t%lu\n\n", passes+skips, passes, skips);
}

int main(int argc, char* argv[]) {
    //// Get reference input file name
    char reference_filename[100];
    if(argc==2) {
        strcpy(reference_filename, argv[1]);
    } else {
        strcpy(reference_filename, "ref_default");
    }
    printf("Using reference file %s\n", reference_filename);
    FILE * fin = fopen(reference_filename,"rb");
    if(fin == NULL) {
        printf("Could not open reference file\n");
        exit(1);
    }

    process_test_file(fin);
    fclose(fin);

    return 0;
}
