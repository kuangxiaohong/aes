PWD=$(shell pwd)
all:aescbc_test_speed aescbc_test_speed_soft aescbc_test_functional_soft aescbc_test_functional aesgcm_test_functional_soft aesgcm_test_functional aesgcm_test_speed_soft aesgcm_test_speed
aescbc_test_speed_soft:
	gcc -g aescbc_test_speed_soft.c -o aescbc_test_speed_soft -ldl -lpthread ${PWD}/../lib/libcrypto_aes_cbc_soft.a

aescbc_test_speed:
	gcc -g aescbc_test_speed.c -o aescbc_test_speed -ldl -lpthread ${PWD}/../lib/libcrypto_aes_cbc_hw.a

aescbc_test_functional_soft:
	gcc -g aescbc_test_functional_soft.c -o aescbc_test_functional_soft -ldl -lpthread ${PWD}/../lib/libcrypto_aes_cbc_soft.a

aescbc_test_functional:
	gcc -g aescbc_test_functional.c -o aescbc_test_functional -ldl -lpthread ${PWD}/../lib/libcrypto_aes_cbc_hw.a


aesgcm_test_speed_soft:
	gcc -g aesgcm_test_speed_soft.c -o aesgcm_test_speed_soft -ldl -lpthread ${PWD}/../lib/libcrypto_aes_gcm_soft.a

aesgcm_test_speed:
	gcc -g aesgcm_test_speed.c -o aesgcm_test_speed -ldl -lpthread ${PWD}/../lib/libcrypto_aes_gcm_hw.a

aesgcm_test_functional_soft:
	gcc -g aesgcm_test_functional_soft.c -o aesgcm_test_functional_soft -ldl -lpthread ${PWD}/../lib/libcrypto_aes_gcm_soft.a

aesgcm_test_functional:
	gcc -g aesgcm_test_functional.c -o aesgcm_test_functional -ldl -lpthread ${PWD}/../lib/libcrypto_aes_gcm_hw.a

clean:
	rm -rf *.o aescbc_test_speed aescbc_test_speed_soft aescbc_test_functional_soft aescbc_test_functional aesgcm_test_functional_soft aesgcm_test_functional aesgcm_test_speed_soft aesgcm_test_speed
