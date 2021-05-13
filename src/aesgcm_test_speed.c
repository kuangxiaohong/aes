//Copyright (c) 2018-2019, ARM Limited. All rights reserved.
//
//SPDX-License-Identifier:        BSD-3-Clause

#define NDEBUG
#include <assert.h>

#include <stdbool.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <sys/time.h>
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

#define aesgcm_debug_printf(...) \
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
char reference_filename[100];

//// Read a reference file and check that encrypt/decrypt operations are
//// producing the correct outputs without errors
void process_test_file(FILE * fin, uint64_t test_count, bool encrypt, bool IPsec,
                       bool overwrite_buffer_length, uint64_t overwritten_buffer_length)
{
    //// Initialise/Default values
    uint8_t * aad = NULL;
    uint64_t aad_length = 0;
    uint64_t aad_byte_length = 0;

	uint8_t * key = NULL;
    uint8_t key_length = 16;

    uint8_t * reference_plaintext = NULL;
    uint8_t * plaintext = NULL;
    uint64_t plaintext_length = 0;
    uint64_t plaintext_byte_length = 0;

    uint8_t reference_tag[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    uint8_t tag[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	uint8_t tag_byte_length;

    uint8_t * reference_ciphertext = NULL;
    uint8_t * ciphertext = NULL;

    uint8_t * nonce = NULL;
    uint64_t nonce_length = 96;
    uint64_t nonce_byte_length = 12;

    char * input_buff = (char *)malloc(MAX_LINE_LEN);
    fpos_t last_line;    

	const EVP_CIPHER *cipher;

    bool new_reference = false;
	struct timeval start,end;
	memset(&start,0,sizeof(start));	
	memset(&end,0,sizeof(end));

    //set up PT/CT variables if we're overwriting the buffer length
    if(overwrite_buffer_length) {
        plaintext_length = overwritten_buffer_length<<3;
        plaintext_byte_length = (overwritten_buffer_length+15)&~15;
        free(reference_plaintext);
        reference_plaintext = (uint8_t *)malloc(plaintext_byte_length);
        free(plaintext);
        plaintext = (uint8_t *)malloc(plaintext_byte_length);
        free(reference_ciphertext);
        reference_ciphertext = (uint8_t *)malloc(plaintext_byte_length);
        free(ciphertext);
        ciphertext = (uint8_t *)malloc(plaintext_byte_length);
    }

    while(!feof(fin)) {
        fgetpos(fin, &last_line);
        if(fgets(input_buff, MAX_LINE_LEN, fin)) {
            if (input_buff[0]!='#' && input_buff[0]!='\0') {
                if(input_buff[0] == '\n' || (input_buff[0] == '\r' && input_buff[1] == '\n')) {
                    if(new_reference)
                    {
                        bool bSuccess = true;
                        if(encrypt)
                        {
                        	gettimeofday(&start,NULL);
                            for(uint64_t i=0; i<test_count; ++i) {
								int len, encLen;
								EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
								EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);
								EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce_byte_length, NULL);
								EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
  								EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_byte_length);
  								len = 0;
  								/*while(len + 16 < plaintext_byte_length)
  								{
     								EVP_EncryptUpdate (ctx, ciphertext + len, &encLen, reference_plaintext + len, 16);
     								len += 16;
  								}
								EVP_EncryptUpdate(ctx, ciphertext + len, &encLen, reference_plaintext + len, plaintext_byte_length - len);*/
								EVP_EncryptUpdate(ctx, ciphertext + len, &encLen, reference_plaintext + len, plaintext_byte_length);
  								EVP_EncryptFinal(ctx, tag, &len);
  								EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_byte_length, tag);  
  								EVP_CIPHER_CTX_free(ctx);

								/*printf("%lu\t%lu\t%lu\n", plaintext_length, aad_byte_length, nonce_byte_length);
								for(int i = 0; i < (plaintext_length>>3); i++){
    								printf("%02x", reference_plaintext[i]);
  								}
  								printf("\n");
								for(int i = 0; i < nonce_byte_length; i++){
    								printf("%02x", nonce[i]);
  								}
  								printf("\n");
								for(int i = 0; i < key_length; i++){
    								printf("%02x", key[i]);
  								}
  								printf("\n");
								for(int i = 0; i < aad_byte_length; i++){
    								printf("%02x", aad[i]);
  								}
  								printf("\n");
								for(int i = 0; i < (plaintext_length>>3); i++){
    								printf("%02x", ciphertext[i]);
  								}
  								printf("\n");*/

								/*for(int i = 0; i < tag_byte_length; i++){
    								printf("%02x", tag[i]);
  								}
  								printf("\n");*/

								/*bool ref_ciphertext_match = true;
    							for(int i=0; i<(plaintext_length>>3); ++i) {
        							if( ciphertext[i] != reference_ciphertext[i] ) ref_ciphertext_match = false;
    							}
								bool reference_tag_match = true;
    							for(int i=0; i<tag_byte_length; ++i) {
        							if( tag[i] != reference_tag[i] ) reference_tag_match = false;
    							}

								bSuccess = bSuccess && ref_ciphertext_match && reference_tag_match;*/
                            }

							gettimeofday(&end,NULL);
							unsigned long interval = 1000ull*(end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)/1000;
							printf("file:%s time:%ld(ms)\n",reference_filename,interval);
							
                        } else {
                        
							gettimeofday(&start,NULL);
                            for(uint64_t i=0; i<test_count; ++i) {
								int len, decLen;
								EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
								EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);
								EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce_byte_length, NULL);
								EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
  								EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_byte_length);
  								len = 0;
  								while(len + 16 < plaintext_byte_length)
  								{
     								EVP_DecryptUpdate (ctx, plaintext + len, &decLen, reference_ciphertext + len, 16);
     								len += 16;
  								}
								EVP_DecryptUpdate (ctx, plaintext + len, &decLen, reference_ciphertext + len, plaintext_byte_length - len);
  								EVP_DecryptFinal(ctx, tag, &len);
  								EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_byte_length, tag);  
  								EVP_CIPHER_CTX_free(ctx);

								/*bool ref_plaintext_match = true;
    							for(int i=0; i<(plaintext_length>>3); ++i) {
        							if( plaintext[i] != reference_plaintext[i] ) ref_plaintext_match = false;
    							}
								bool reference_tag_match = true;
    							for(int i=0; i<tag_byte_length; ++i) {
        							if( tag[i] != reference_tag[i] ) reference_tag_match = false;
    							}
								bSuccess = bSuccess && ref_plaintext_match && reference_tag_match;*/
                            }
							gettimeofday(&end,NULL);
							unsigned long interval = 1000ull*(end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)/1000;
							printf("file:%s time:%ld(ms)\n",reference_filename,interval);
                        }
                       // printf("%s - %s\n%lu runs\n%lu bytes\nResult is %s\n%s",
                        //encrypt ? "Encrypt" : "Decrypt", IPsec ? "IPsec" : "Generic",
                        //test_count, plaintext_byte_length, bSuccess ? "Success" : "Failure",
                        //encrypt ? "" : "(only should be Success with 1 run - need to reset counter and tag between each call)\n");
                    }
                    new_reference = false;
                }
                else if(strncmp(input_buff, "[Keylen", 7) == 0) {
                    //set the cipher mode
                    if(strncmp (input_buff+10, "128", 3) == 0) {
                        cipher  = EVP_aes_128_gcm();
                        key_length = 16;
                        aesgcm_debug_printf("Cipher mode set to AES_GCM_128\n");
                    } else if(strncmp (input_buff+10, "192", 3) == 0) {
                        cipher  = EVP_aes_192_gcm();
                        key_length = 24;
                        aesgcm_debug_printf("Cipher mode set to AES_GCM_192\n");
                    } else if(strncmp (input_buff+10, "256", 3) == 0) {
                        cipher  = EVP_aes_256_gcm();
                        key_length = 32;
                        aesgcm_debug_printf("Cipher mode set to AES_GCM_256\n");
                    } else {
                        aesgcm_debug_printf("Cipher mode not recognised - keeping previous value\n");
                    }
					key = (uint8_t *)malloc(key_length);
                }
                else if(strncmp(input_buff, "[IVlen", 6) == 0) {
                    //set the nonce length
                    nonce_length = strtoul(input_buff+9, NULL, 10);
                    //nonce_byte_length = ((nonce_length+127)&~127ul)>>3; //pad to block size
					nonce_byte_length = nonce_length >> 3;
                    free(nonce);
                    nonce = (uint8_t *)malloc(nonce_byte_length);
                    aesgcm_debug_printf("Nonce length set to %lu\n", nonce_length);
                }
                else if(strncmp(input_buff, "[PTlen", 6) == 0 && !overwrite_buffer_length) {
                    //set the plaintext length
                    plaintext_length = strtoul(input_buff+9, NULL, 10);
                    plaintext_byte_length = ((plaintext_length+127)&~127ul)>>3; //pad to block size
                    free(reference_plaintext);
                    reference_plaintext = (uint8_t *)malloc(plaintext_byte_length);
                    free(plaintext);
                    plaintext = (uint8_t *)malloc(plaintext_byte_length);
                    free(reference_ciphertext);
                    reference_ciphertext = (uint8_t *)malloc(plaintext_byte_length);
                    free(ciphertext);
                    ciphertext = (uint8_t *)malloc(plaintext_byte_length);
                    aesgcm_debug_printf("Plaintext length set to %lu\n", plaintext_length);
                }
                else if(strncmp(input_buff, "[AADlen", 7) == 0) {
                    //set the aad length
                    aad_length = strtoul(input_buff+10, NULL, 10);
                    //aad_byte_length = ((aad_length+127)&~127ul)>>3; //pad to block size
					aad_byte_length = aad_length >> 3;
                    free(aad);
                    aad = (uint8_t *)malloc(aad_byte_length);
                    aesgcm_debug_printf("AAD length set to %lu\n", aad_byte_length);
                }
                else if(strncmp(input_buff, "[Taglen", 7) == 0) {
                    //set the tag length
                    tag_byte_length = (uint8_t) strtoul(input_buff+10, NULL, 10)>>3;
                    aesgcm_debug_printf("Tag length set to %u\n\n", tag_byte_length<<3);
                }
                else if(strncmp(input_buff, "Count", 5) == 0) {
                    //start of new reference
                    if( test_count == 0) {
                        test_count = strtoul(input_buff+8, NULL, 10);
                    }
                    aesgcm_debug_printf("New reference: %s\n", input_buff);
                    new_reference = true;
                }
                else if(strncmp(input_buff, "Key", 3) == 0) {
                    //set the AES key and associated precomputation
                    //needs the cipher mode to be set already
                    fsetpos(fin, &last_line);
                    fseek(fin, 6, SEEK_CUR);
                    for(uint64_t i=0; i<key_length; ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        key[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}
                }
                else if(strncmp(input_buff, "IV", 2) == 0 ) {
                    //set the nonce
                    fsetpos(fin, &last_line);
                    fseek(fin, 5, SEEK_CUR);
                    for(uint64_t i=0; i<((nonce_length+7)>>3); ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        nonce[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}
                    for(uint64_t i=(nonce_length+7)>>3; i<nonce_byte_length; ++i) {
                        nonce[i] = 0;
                    }

                    aesgcm_debug_printf("Set nonce - length %lu (%lu) 0x", nonce_length, nonce_byte_length);
                    for(uint64_t i=0; i<nonce_byte_length; ++i) {
                        aesgcm_debug_printf("%02x", nonce[i]);
                    }
                    aesgcm_debug_printf("\n");
                }
                else if(strncmp(input_buff, "PT", 2) == 0  && !overwrite_buffer_length) {
                    //set the reference plaintext
                    fsetpos(fin, &last_line);
                    fseek(fin, 5, SEEK_CUR);
                    for(uint64_t i=0; i<((plaintext_length+7)>>3); ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        reference_plaintext[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}
                    for(uint64_t i=(plaintext_length+7)>>3; i<plaintext_byte_length; ++i) {
                        reference_plaintext[i] = 0;
                    }
                    aesgcm_debug_printf("Set reference plaintext - length %lu (%lu) 0x", plaintext_length, plaintext_byte_length);
                    for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                        aesgcm_debug_printf("%02x", reference_plaintext[i]);
                    }
                    aesgcm_debug_printf("\n");
                }
                else if(strncmp(input_buff, "AAD", 3) == 0) {
                    //set the additional authentication data
                    fsetpos(fin, &last_line);
                    fseek(fin, 6, SEEK_CUR);
                    for(uint64_t i=0; i<((aad_length+7)>>3); ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        aad[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}
                    for(uint64_t i=(aad_length+7)>>3; i<aad_byte_length; ++i) {
                        aad[i] = 0;
                    }
                    aesgcm_debug_printf("Set aad - length %lu (%lu) 0x", aad_length, aad_byte_length);
                    for(uint64_t i=0; i<aad_byte_length; ++i) {
                        aesgcm_debug_printf("%02x", aad[i]);
                    }
                    aesgcm_debug_printf("\n");
                }
                else if(strncmp(input_buff, "CT", 2) == 0  && !overwrite_buffer_length) {
                    //set the reference ciphertext
                    fsetpos(fin, &last_line);
                    fseek(fin, 5, SEEK_CUR);
                    for(uint64_t i=0; i<((plaintext_length+7)>>3); ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        reference_ciphertext[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}
                    for(uint64_t i=(plaintext_length+7)>>3; i<plaintext_byte_length; ++i) {
                        reference_ciphertext[i] = 0;
                    }
                    aesgcm_debug_printf("Set reference ciphertext - length %lu (%lu) 0x", plaintext_length, plaintext_byte_length);
                    for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                        aesgcm_debug_printf("%02x", reference_ciphertext[i]);
                    }
                    aesgcm_debug_printf("\n");
                }
                else if(strncmp(input_buff, "Tag", 3) == 0) {
                    //set the authentication tag
                    // quadword_t temp_tag;
                    for(int i=0; i<16; ++i) {
                        reference_tag[i] = hextobyte(input_buff[6+(2*i)], input_buff[7+(2*i)]);
                    }
                    aesgcm_debug_printf("Reference tag set to %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                            reference_tag[0], reference_tag[1], reference_tag[2], reference_tag[3], reference_tag[4], reference_tag[5], reference_tag[6], reference_tag[7],
                            reference_tag[8], reference_tag[9], reference_tag[10], reference_tag[11], reference_tag[12], reference_tag[13], reference_tag[14], reference_tag[15] );
                }
            }
        }
    }
    free(input_buff);

    free(aad);
    free(reference_plaintext);
    free(reference_ciphertext);
}

int main(int argc, char* argv[]) {
    //// Get input cipher size
    uint64_t test_count = 0;
    bool encrypt = true;
    bool IPsec = true;
    bool overwrite_buffer_length = false;
    uint64_t overwritten_buffer_length = 0;
    if(argc>=2) {
        strcpy(reference_filename, argv[1]);
    } else {
        strcpy(reference_filename, "ref_default");
    }
    if(argc>=3) {
        test_count = strtoul(argv[2], NULL, 10);
    }
    if(argc>=4) {
        encrypt = (bool) strtoul(argv[3], NULL, 10);
    }
    if(argc>=5) {
        IPsec = (bool) strtoul(argv[4], NULL, 10);
    }
    if(argc>=6) {
        overwrite_buffer_length = true;
        overwritten_buffer_length = strtoul(argv[5], NULL, 10);
    }
    FILE * fin = fopen(reference_filename,"rb");
    if(fin == NULL) {
        printf("Could not open reference file\n");
        exit(1);
    }

    process_test_file(fin, test_count, encrypt, IPsec, overwrite_buffer_length, overwritten_buffer_length);
    fclose(fin);

    return 0;
}
