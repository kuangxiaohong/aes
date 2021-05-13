//Copyright (c) 2018-2019, ARM Limited. All rights reserved.
//
//SPDX-License-Identifier:        BSD-3-Clause

#define NDEBUG
#include <assert.h>

#include <stdbool.h>
#include <stdio.h>
#include <math.h>
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

//// Called once a reference state is set up, runs encrypt/decrypt
//// and checks the outputs match the expected outputs
bool __attribute__ ((noinline)) test_reference(
					uint8_t tag_byte_length,
					uint8_t * key, uint8_t key_byte_length,
					uint8_t * nonce, uint64_t nonce_byte_length,
					uint8_t * aad, uint64_t aad_length,
                    uint8_t * reference_plaintext,
                    uint64_t plaintext_length,
                    uint64_t plaintext_byte_length,
                    uint8_t * reference_tag,
                    uint8_t * reference_ciphertext,
                    uint64_t reference_checksum, bool check_checksum,
                    bool verbose)
{
    bool success = true;    

    uint8_t * tag;

    uint8_t * output = (uint8_t *)malloc(plaintext_byte_length+16);

    tag = (uint8_t *)malloc(tag_byte_length);

	const EVP_CIPHER *cipher;
  	switch(key_byte_length)
  	{
  	case 16: cipher  = EVP_aes_128_gcm ();break;
  	case 24: cipher  = EVP_aes_192_gcm ();break;
  	case 32: cipher  = EVP_aes_256_gcm ();break;
  	default:break;
  	}
	int len = 0,ret = 0;
	int encLen, decLen;

	//char Encry[6] = "Encry";
	//char Decry[6] = "Decry";

	//char *is_encry = NULL;

	//is_encry = strstr(reference_filename,Encry);

	//printf("file:%s is_encry:%p\n",reference_filename,is_encry);
	//if (is_encry)
	if(1)
	{
	
	    //// ENCRYPTION TEST
	    //// Encrypt reference plaintext and check output with reference ciphertext and tag
		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
		ret = EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);
		if(ret != 1)
		{
			printf("1\n");			
			EVP_CIPHER_CTX_free(ctx);
			goto failed;
		}
		ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce_byte_length, NULL);
		
		if(ret != 1)
		{
			printf("2\n");			
			EVP_CIPHER_CTX_free(ctx);
			goto failed;
		}

		ret = EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
		
		if(ret != 1)
		{
			printf("4\n");			
			EVP_CIPHER_CTX_free(ctx);
			goto failed;
		}
	  	ret = EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_length);
		
		if(ret != 1)
		{
			printf("5\n");			
			EVP_CIPHER_CTX_free(ctx);
			goto failed;
		}
	  	len = 0;
	  	while(len + 16 < plaintext_byte_length)
	  	{
	     	ret = EVP_EncryptUpdate (ctx, output + len, &encLen, reference_plaintext + len, 16);
			
			if(ret != 1)
			{
				printf("6\n");				
				EVP_CIPHER_CTX_free(ctx);
				goto failed;
			}
	     	len += 16;
	  	}
		ret = EVP_EncryptUpdate(ctx, output + len, &encLen, reference_plaintext + len, plaintext_byte_length - len);
		if(ret != 1)
		{
			printf("7\n");			
			EVP_CIPHER_CTX_free(ctx);
			goto failed;
		}

		EVP_EncryptFinal_ex(ctx, output, &len);
	  	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_byte_length, tag);  
	  	EVP_CIPHER_CTX_free(ctx);

	    if(verbose)
	    {
	        if(output != NULL) {
	            printf("Computed ciphertext: 0x");
	            for(uint64_t i=0; i<plaintext_byte_length; ++i) {
	                printf("%02x", output[i]);
	            }
	            printf("\n");
	        } else {
	            printf("Computed ciphertext: NULL\n");
	        }
	    }
		
		//printf("11111111111111:%d\n",plaintext_length);
	    bool ref_ciphertext_match = true;
	    for(int i=0; i< plaintext_byte_length; ++i) {
	        if( (uint8_t)output[i] != (uint8_t)reference_ciphertext[i] )
	        {
	        	printf("reference_ciphertext error\n");
				for(int i = 0; i < plaintext_length; i++){
		printf("offset:%d reference_ciphertext:%02x output:%02x",i, reference_ciphertext[i],output[i]);
				printf("\n");
				}
				
				ref_ciphertext_match = false;
				break;
	        }
			//printf("%d %d len:%d\n",output[i],reference_ciphertext[i],plaintext_length);
	    }
		/*printf("%lu\n", nonce_byte_length);
		for(int i = 0; i < nonce_byte_length; i++){
	    	printf("%02x", nonce[i]);
	  	}
	  	printf("\n");*/
	    bool reference_tag_match = true;
	    for(int i=0; i< tag_byte_length; ++i) {
	        if( (uint8_t)tag[i] != (uint8_t)reference_tag[i] ) 
			{
				printf("tag error %u %u\n",tag[i],reference_tag[i]);

				for(int i = 0; i < tag_byte_length; i++){
	  	  			printf("reference_tag:%02x  tag:%02x", reference_tag[i],tag[i]);
				printf("\n");
	  		}
				reference_tag_match = false;
				break;
	        }
	    }
		//printf("%u\t%lu\n", tag_byte_length, aad_length);
		//for(int i = 0; i < tag_byte_length; i++){
	    //	printf("out:%02x  ori:%02x", reference_tag[i],tag[i]);
	  	//}
	  	//printf("\n");
	    if(verbose) 
			printf("Reference ciphertext match %s!\nReference tag match %s!\n", ref_ciphertext_match ? "success" : "failure", reference_tag_match ? "success" : "failure");

	    if(!ref_ciphertext_match || !reference_tag_match) {
			printf("Encryption failure!\n");
	        success = false;
		}
		
		//free(output);
		//free(tag);	
		//return success;
	}
	
#if 0
	printf("11\n");
	ctx = EVP_CIPHER_CTX_new();      
  	EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce_byte_length, NULL);
	EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);  	
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_byte_length, reference_tag);	
  	EVP_DecryptUpdate (ctx, NULL, &len, aad, aad_length);
  	len = 0;
  	while(len + 16 < plaintext_byte_length)
  	{
     	EVP_EncryptUpdate (ctx, output + len, &decLen, reference_ciphertext + len, 16);
     	len += 16;
  	}
	EVP_EncryptUpdate(ctx, output + len, &decLen, reference_ciphertext + len, plaintext_byte_length - len);
  	EVP_DecryptFinal(ctx, tag, &len);
  	EVP_CIPHER_CTX_free(ctx);
	printf("22\n");

    if(verbose)
    {
        if(output != NULL) {
            printf("Computed plaintext: 0x");
            for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                printf("%02x", output[i]);
            }
            printf("\n");
        } else {
            printf("Computed plaintext: NULL\n");
        }
    }

    bool ref_plaintext_match = true;
    for(int i=0; i<(plaintext_length>>3); ++i) {
        if( output[i] != reference_plaintext[i] ) ref_plaintext_match = false;
    }

	/*printf("%lu\n", nonce_byte_length);
	for(int i = 0; i < nonce_byte_length; i++){
    	printf("%02x", nonce[i]);
  	}
  	printf("\n");*/

    for(int i=0; i<tag_byte_length; ++i) {
        if( tag[i] != reference_tag[i] ) reference_tag_match = false;
    }
	/*for(int i = 0; i < tag_byte_length; i++){
    	printf("%02x", tag[i]);
  	}
  	printf("\n");*/
   
    if(verbose) printf("Reference plaintext match %s!\nReference tag match %s!\n", ref_plaintext_match ? "success" : "failure", reference_tag_match ? "success" : "failure");

    free(output);
    free(tag);

    if(!ref_plaintext_match || !reference_tag_match) {
        if(verbose) printf("Decryption failure!\n");
        success = false;
    }
    else
    {
        if(verbose) printf("Decryption authenticated\n");
    }
#endif
    //// DECRYPTION TEST
    //// Decrypt reference ciphertext and check output with reference plaintext and tag
	//else
	if (1)
	{
		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
		/* Select cipher */
		ret = EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);
		if(ret != 1)
		{
			printf("11\n");			
			EVP_CIPHER_CTX_free(ctx);
			goto failed;
		}

		ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce_byte_length, NULL);
		
		if(ret != 1)
		{
			printf("2\n");			
			EVP_CIPHER_CTX_free(ctx);
			goto failed;
		}

		ret = EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
		
		if(ret != 1)
		{
			printf("4\n");			
			EVP_CIPHER_CTX_free(ctx);
			goto failed;
		}


#if 0
		ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_byte_length, reference_tag); 
		
			
		if(ret != 1)
		{
			printf("3\n");			
			EVP_CIPHER_CTX_free(ctx);
			goto failed;
		}

#endif
		
	  	ret = EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_length);
		
		if(ret != 1)
		{
			printf("5\n");			
			EVP_CIPHER_CTX_free(ctx);
			goto failed;
		}
	  	len = 0;
	  	while(len + 16 < plaintext_byte_length)
	  	{
	     	ret = EVP_DecryptUpdate (ctx, output + len, &decLen, reference_ciphertext + len, 16);
			
			if(ret != 1)
			{
				printf("6\n");				
				EVP_CIPHER_CTX_free(ctx);
				goto failed;
			}
	     	len += 16;
	  	}

		if(plaintext_byte_length - len)
		{
			ret = EVP_DecryptUpdate(ctx, output + len, &decLen, reference_ciphertext + len, plaintext_byte_length - len);
			if(ret != 1)
			{
				printf("7\n");			
				EVP_CIPHER_CTX_free(ctx);
				goto failed;
			}
		}
		EVP_DecryptFinal_ex(ctx, output, &len);
	  	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_byte_length, tag);  
	  	EVP_CIPHER_CTX_free(ctx);


		bool ref_plaintext_match = true;
	 	for(int i=0; i< plaintext_byte_length; ++i) {
		   if( output[i] != reference_plaintext[i] ) 
		   {
	        	printf("reference_plaintext error\n");
				for(int i = 0; i < plaintext_length; i++)
				{
					printf("offset:%d reference_ciphertext:%02x output:%02x",i, reference_ciphertext[i],output[i]);
					printf("\n");
		        }	
				ref_plaintext_match = false;
				break;
	       }
	   }

	   bool reference_tag_match = true;
	   for(int i=0; i< tag_byte_length; ++i) 
	   {
        	if( tag[i] != reference_tag[i] ) 
			{
				printf("tag error %u %u\n",tag[i],reference_tag[i]);
	
				for(int i = 0; i < tag_byte_length; i++)
				{
		  	  		printf("reference_tag:%02x  tag:%02x", reference_tag[i],tag[i]);
					printf("\n");
		  		}
				reference_tag_match = false;
				break;
	      	}
   	   }
	   
	   if(!ref_plaintext_match || !reference_tag_match) 
	   {
			printf("Decryption failure!\n");
	        success = false;
	   }
		
		free(output);
		free(tag);	
		return success;

	}

	failed:
		free(output);
		free(tag);	
		success = false;
    return success;
}

//// Called once a reference state is set up and we expect it to fail authentication runs decryption
//// and checks the result is an authentication failure
bool test_reference_invalid_auth(
					uint8_t tag_byte_length,
					uint8_t * key, uint8_t key_byte_length,
					uint8_t * nonce, uint64_t nonce_byte_length,
					uint8_t * aad, uint64_t aad_length,
                    uint8_t * reference_plaintext,
                    uint64_t plaintext_length,
                    uint64_t plaintext_byte_length,
                    uint8_t * reference_tag,
                    uint8_t * reference_ciphertext,
                    bool verbose)
{
    bool success = true;

	//printf("33333333333333333333333333\n");
    uint8_t * tag;

    uint8_t * output = (uint8_t *)malloc(plaintext_byte_length+16);

    tag = (uint8_t *)malloc(tag_byte_length);

	const EVP_CIPHER *cipher;
  	switch(key_byte_length)
  	{
  	case 16: cipher  = EVP_aes_128_gcm ();break;
  	case 24: cipher  = EVP_aes_192_gcm ();break;
  	case 32: cipher  = EVP_aes_256_gcm ();break;
  	default:break;
  	}
	int len = 0;
	int encLen, decLen;


    //// DECRYPTION TEST
    //// Decrypt reference ciphertext and check output with reference plaintext and tag
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();      
  	EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce_byte_length, NULL);
	EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);  	
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_byte_length, reference_tag);	
  	EVP_DecryptUpdate (ctx, NULL, &len, aad, aad_length);
  	len = 0;
  	while(len + 16 < plaintext_byte_length)
  	{
     	EVP_DecryptUpdate (ctx, output + len, &decLen, reference_ciphertext + len, 16);
     	len += 16;
  	}
	EVP_DecryptUpdate(ctx, output + len, &decLen, reference_ciphertext + len, plaintext_byte_length - len);
  	EVP_DecryptFinal(ctx, tag, &len);
  	EVP_CIPHER_CTX_free(ctx);

    if(verbose)
    {
        if(output != NULL) {
            printf("Computed plaintext: 0x");
            for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                printf("%02x", output[i]);
            }
            printf("\n");
        } else {
            printf("Computed plaintext: NULL\n");
        }
    }

    bool ref_plaintext_match = true;
    for(int i=0; i<(plaintext_length>>3); ++i) {
        if( output[i] != reference_plaintext[i] ) ref_plaintext_match = false;
    }
	/*printf("%lu\t%lu\n", plaintext_length, aad_length);
	for(int i = 0; i < (plaintext_length>>3); i++){
    	printf("%02x", output[i]);
  	}
  	printf("\n");*/
    bool reference_tag_match = true;
    for(int i=0; i<tag_byte_length; ++i) {
        if( tag[i] != reference_tag[i] ) reference_tag_match = false;
    }
	/*printf("%u\n", tag_byte_length);
	for(int i = 0; i < tag_byte_length; i++){
    	printf("%02x", tag[i]);
  	}
  	printf("\n");*/
    if(verbose) printf("Reference plaintext match %s!\nReference tag match %s!\n", ref_plaintext_match ? "success" : "failure", reference_tag_match ? "success" : "failure");

    free(output);
    free(tag);
    if(ref_plaintext_match && reference_tag_match) {
        if(verbose) printf("Decryption didn't cause authentication failure!\n");
        success = false;
    }
    else
    {
        if(verbose) printf("Decryption failed authentication correctly\n");
    }

    return success;
}

//// Read a reference file and check that encrypt/decrypt operations are
//// producing the correct outputs without errors
void process_test_file(FILE * fin)
{
    //// Initialise/Default values
    uint8_t * aad = NULL;
    uint64_t aad_length = 0;
    uint64_t aad_byte_length = 0;

	uint8_t * key = NULL;
    uint8_t key_byte_length = 16;

    uint8_t * reference_plaintext = NULL;
    uint64_t plaintext_length = 0;
    uint64_t plaintext_byte_length = 0;

    uint8_t reference_checksum[8] = { 0 };
    bool checksum_set = false;

	uint8_t tag_byte_length = 16;
    uint8_t reference_tag[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

    uint8_t * reference_ciphertext = NULL;

    uint8_t * nonce = NULL;
    uint64_t nonce_length = 96;
    uint64_t nonce_byte_length = 12;

    char * input_buff = (char *)malloc(MAX_LINE_LEN);
    fpos_t last_line;

    bool acceptable = true;
    bool new_reference = false;
    bool expect_valid_auth = true;
    uint64_t passes = 0;
    uint64_t skips = 0;

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
                            if(expect_valid_auth) {
                                pass = test_reference(tag_byte_length,
											key, key_byte_length,
											nonce, nonce_byte_length,
											aad, aad_byte_length,
                                            reference_plaintext,
                                            plaintext_length,
                                            plaintext_byte_length,
                                            reference_tag,
                                            reference_ciphertext,
                                            *((uint64_t *) reference_checksum), checksum_set,
                                            false);
                            } else {
                                pass = test_reference_invalid_auth(tag_byte_length,
											key, key_byte_length,
											nonce, nonce_byte_length,
											aad, aad_byte_length,
                                            reference_plaintext,
                                            plaintext_length,
                                            plaintext_byte_length,
                                            reference_tag,
                                            reference_ciphertext,
                                            false);
                            }

                            if (!pass)
                            {
                                printf("Keylen = %u\nIVlen = %lu\nPTlen = %lu\nAADlen = %lu\nTaglen = %u\n",
                                        key_byte_length<<3,nonce_length, plaintext_length, aad_length, tag_byte_length<<3);
                                printf("Key 0x");
                                for(uint64_t i=0; i<key_byte_length; ++i) {
                                    printf("%02x", key[i]);
                                }
                                printf("\n");
                                printf("IV  0x");
                                for(uint64_t i=0; i<((nonce_length+7)>>3); ++i) {
                                    printf("%02x", nonce[i]);
                                }
                                printf("\n");
                                printf("PT  0x");
                                for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                                    printf("%02x", reference_plaintext[i]);
                                }
                                printf("\n");
                                printf("CS  0x");
                                for(uint64_t i=0; i<8; ++i) {
                                    printf("%02x", reference_checksum[i]);
                                }
                                printf("\n");
                                printf("AAD 0x");
                                for(uint64_t i=0; i<aad_byte_length; ++i) {
                                    printf("%02x", aad[i]);
                                }
                                printf("\n");
                                printf("CT  0x");
                                for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                                    printf("%02x", reference_ciphertext[i]);
                                }
                                printf("\n");
                                printf("Tag 0x");
                                for(uint64_t i=0; i< tag_byte_length; ++i) {
                                    printf("%02x", reference_tag[i]);
                                }
                                printf("\n");

                                if(expect_valid_auth) {
                                    pass = test_reference(tag_byte_length,
												key, key_byte_length,
												nonce, nonce_byte_length,
												aad, aad_byte_length,
                                                reference_plaintext,
                                                plaintext_length,
                                                plaintext_byte_length,
                                                reference_tag,
                                                reference_ciphertext,
                                                *((uint64_t *) reference_checksum), checksum_set,
                                                true);
                                } else {
                                    pass = test_reference_invalid_auth(tag_byte_length,
												key, key_byte_length,
												nonce, nonce_byte_length,
												aad, aad_byte_length,
                                                reference_plaintext,
                                                plaintext_length,
                                                plaintext_byte_length,
                                                reference_tag,
                                                reference_ciphertext,
                                                true);
                                }
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
                    checksum_set = false;
                    expect_valid_auth = true;
                }
                else if(strncmp(input_buff, "[Keylen", 7) == 0) {
                    //set the cipher mode
                    if(strncmp (input_buff+10, "128", 3) == 0) {
                        key_byte_length = 16;
                        aesgcm_debug_printf("Cipher mode set to AES_GCM_128\n");
                    } else if(strncmp (input_buff+10, "192", 3) == 0) {
                        key_byte_length = 24;
                        aesgcm_debug_printf("Cipher mode set to AES_GCM_192\n");
                    } else if(strncmp (input_buff+10, "256", 3) == 0) {
                        key_byte_length = 32;
                        aesgcm_debug_printf("Cipher mode set to AES_GCM_256\n");
                    } else {
                        aesgcm_debug_printf("Cipher mode not recognised - keeping previous value\n");
                    }
					key = (uint8_t *)malloc(key_byte_length);
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
                else if(strncmp(input_buff, "[PTlen", 6) == 0) {
                    //set the plaintext length
                    plaintext_length = strtoul(input_buff+9, NULL, 10);
                    //plaintext_byte_length = ((plaintext_length+127)&~127ul)>>3; //pad to block size
					plaintext_byte_length = plaintext_length >> 3;
                    aesgcm_debug_printf("1 addr %lx len %lu bitlen %lu\n", (uint64_t) reference_plaintext, plaintext_length, plaintext_byte_length);
                    free(reference_plaintext);
                    free(reference_ciphertext);
                    if( plaintext_byte_length ) {
                        reference_plaintext = (uint8_t *)malloc(plaintext_byte_length);
                        reference_ciphertext = (uint8_t *)malloc(plaintext_byte_length);
                    } else {
                        reference_plaintext = NULL;
                        reference_ciphertext = NULL;
                    }
                    aesgcm_debug_printf("Plaintext length set to %lu\n", plaintext_length);
                }
                else if(strncmp(input_buff, "[AADlen", 7) == 0) {
                    //set the aad length
                    aad_length = strtoul(input_buff+10, NULL, 10);
                    //aad_byte_length = ((aad_length+127)&~127ul)>>3; //pad to block size
					aad_byte_length = aad_length >> 3;
                    free(aad);
                    aad = (uint8_t *)malloc(aad_byte_length);
                    aesgcm_debug_printf("AAD length set to %lu\n", aad_length);
                }
                else if(strncmp(input_buff, "[Taglen", 7) == 0) {
                    //set the tag length
                    tag_byte_length = (uint8_t) strtoul(input_buff+10, NULL, 10)>>3;
                    aesgcm_debug_printf("Tag length set to %u\n\n", tag_byte_length<<3);
                }
                else if(strncmp(input_buff, "Count", 5) == 0) {
                    //start of new reference
                    aesgcm_debug_printf("New reference: %s\n", input_buff);
                    new_reference = true;
                }
                else if(strncmp(input_buff, "Key", 3) == 0) {
                    //set the AES key and associated precomputation
                    //needs the cipher mode to be set already
                    fsetpos(fin, &last_line);
                    fseek(fin, 6, SEEK_CUR);
                    for(uint64_t i=0; i<key_byte_length; ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        key[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}
                    aesgcm_debug_printf("\n");
                }
                else if(strncmp(input_buff, "IV", 2) == 0) {
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
                        nonce[i] = 0xde; //ensure that reading beyond end will be caught
                    }
                    aesgcm_debug_printf("Set nonce - length %lu (%lu) 0x", nonce_length, nonce_byte_length);
                    for(uint64_t i=0; i<nonce_byte_length; ++i) {
                        aesgcm_debug_printf("%02x", nonce[i]);
                    }
                    aesgcm_debug_printf("\n");
                }
                else if(strncmp(input_buff, "PT", 2) == 0) {
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
                        reference_plaintext[i] = 0xde; //ensure that reading beyond end will be caught
                    }
                    aesgcm_debug_printf("Set reference plaintext - length %lu (%lu) 0x", plaintext_length, plaintext_byte_length);
                    for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                        aesgcm_debug_printf("%02x", reference_plaintext[i]);
                    }
                    aesgcm_debug_printf("\n");
                }
                else if(strncmp(input_buff, "CS", 2) == 0) {
                    //set the reference plaintext
                    fsetpos(fin, &last_line);
                    fseek(fin, 5, SEEK_CUR);
                    for(uint64_t i=0; i<8; ++i) {
                        uint8_t top = fgetc(fin);
                        uint8_t bot = fgetc(fin);
                        reference_checksum[i] = hextobyte(top, bot);
                    }
                    while( fgetc(fin) != '\n' ) {}
                    checksum_set = true;
                    aesgcm_debug_printf("Set reference checksum - length %lu (%lu) 0x", 8ul, 8ul);
                    for(uint64_t i=0; i<8; ++i) {
                        aesgcm_debug_printf("%02x", reference_checksum[i]);
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
                        aad[i] = 0xde; //ensure that reading beyond end will be caught
                    }
                    aesgcm_debug_printf("Set aad - length %lu (%lu) 0x", aad_length, aad_byte_length);
                    for(uint64_t i=0; i<aad_byte_length; ++i) {
                        aesgcm_debug_printf("%02x", aad[i]);
                    }
                    aesgcm_debug_printf("\n");
                }
                else if(strncmp(input_buff, "CT", 2) == 0) {
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
                        reference_ciphertext[i] = 0xde; //ensure that reading beyond end will be caught
                    }
                    aesgcm_debug_printf("Set reference ciphertext - length %lu (%lu) 0x", plaintext_length, plaintext_byte_length);
                    for(uint64_t i=0; i<plaintext_byte_length; ++i) {
                        aesgcm_debug_printf("%02x", reference_ciphertext[i]);
                    }
                    aesgcm_debug_printf("\n");
                }
                else if(strncmp(input_buff, "Tag", 3) == 0) {
                    //set the authentication tag
                    for(int i=0; i<16; ++i) {
                        reference_tag[i] = hextobyte(input_buff[6+(2*i)], input_buff[7+(2*i)]);
                    }
                    aesgcm_debug_printf("Set reference tag - length %u (%u) 0x", tag_byte_length<<3, tag_byte_length);
                    for (uint64_t i=0; i<tag_byte_length; ++i) {
                        aesgcm_debug_printf("%02x", reference_tag[i]);
                    }
                    aesgcm_debug_printf("\n");
                }
                else if(strncmp(input_buff, "FAIL", 4) == 0) {
                    //Expect this reference to fail
                    expect_valid_auth = false;
                    aesgcm_debug_printf("Expect this reference to fail\n");
                }
            }
        }
    }
    free(input_buff);

    printf("Successfully processed %lu inputs:\nPASS:\t%lu\nSKIP:\t%lu\n\n", passes+skips, passes, skips);

    free(aad);
    free(reference_plaintext);
    free(reference_ciphertext);
}

int main(int argc, char* argv[]) {
    //// Get reference input file name
    if(argc==2) {
        strcpy(reference_filename, argv[1]);
    } else {
        strcpy(reference_filename, "ref_default");
    }
   // printf("Using reference file %s\n", reference_filename);
    FILE * fin = fopen(reference_filename,"rb");
    if(fin == NULL) {
        printf("Could not open reference file\n");
        exit(1);
    }

    process_test_file(fin);
    fclose(fin);

    return 0;
}
