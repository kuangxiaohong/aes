#!/bin/bash
echo "##########################################"
echo "# functional test                        #"
echo "# aes cbc                                #"
echo "##########################################"

REPEAT=10000
PWD=`pwd`
for ref in `ls data\/testvectors__NIST_aescbc/*128.rsp`
do
	old_path=${LD_LIBRARY_PATH}
	export LD_LIBRARY_PATH=LD_LIBRAY_PATH:${PWD}/../lib
	taskset -c 1 ./bin/aescbc_test_functional $ref
	export LD_LIBRARY_PATH=LD_LIBRAY_PATH:${old_path}
done

echo "##########################################"
echo "# functional test                        #"
echo "# aes gcm                                #"
echo "##########################################"

for ref in `ls data\/testvectors__NIST_aesgcm`
do
	old_path=${LD_LIBRARY_PATH}
	export LD_LIBRARY_PATH=LD_LIBRAY_PATH:${PWD}/../lib
	taskset -c 1 ./bin/aesgcm_test_functional data/testvectors__NIST_aesgcm/$ref
	export LD_LIBRARY_PATH=LD_LIBRAY_PATH:${old_path}
done


echo "##########################################"
echo "# speed test                             #"
echo "# aes cbc                                #"
echo "##########################################"

for size in 16 32 48 64 128 256 512 1024 2048 4096 8192 16384
do
	old_path=${LD_LIBRARY_PATH}
	export LD_LIBRARY_PATH=LD_LIBRAY_PATH:${PWD}/../lib
	taskset -c 1  ./bin/aescbc_test_speed data/testvectors__speed_aescbc/speedtest128_$size.rsp $REPEAT 1 
	export LD_LIBRARY_PATH=LD_LIBRAY_PATH:${old_path}
done

for size in 32768 65536 131072 262144 524288 1048576
do
	old_path=${LD_LIBRARY_PATH}
	export LD_LIBRARY_PATH=LD_LIBRAY_PATH:${PWD}/../lib
	echo "overwrite size :${size}"
	taskset -c 1  ./bin/aescbc_test_speed data/testvectors__speed_aescbc/speedtest128_16384.rsp $REPEAT 1 $size
	export LD_LIBRARY_PATH=LD_LIBRAY_PATH:${old_path}
done

echo "##########################################"
echo "# speed test                             #"
echo "# aes gcm                                #"
echo "##########################################"

for size in 16 32 48 64 128 256 512 1024 2048 4096 8192 16384
do
		old_path=${LD_LIBRARY_PATH}
		export LD_LIBRARY_PATH=LD_LIBRAY_PATH:${PWD}/../lib
        taskset -c 1 ./bin/aesgcm_test_speed data/testvectors__speed_aesgcm/speedtest128_$size.rsp $REPEAT 1 0 
		export LD_LIBRARY_PATH=LD_LIBRAY_PATH:${old_path}

done

for size in 32768 65536 131072 262144 524288 1048576
do
		old_path=${LD_LIBRARY_PATH}
		export LD_LIBRARY_PATH=LD_LIBRAY_PATH:${PWD}/../lib
		echo "overwrite size :${size}"
        taskset -c 1 ./bin/aesgcm_test_speed data/testvectors__speed_aesgcm/speedtest128_16384.rsp $REPEAT 1 0 $size
		export LD_LIBRARY_PATH=LD_LIBRAY_PATH:${old_path}

done

old_path=${LD_LIBRARY_PATH}
export LD_LIBRARY_PATH=LD_LIBRAY_PATH:${PWD}/../lib
taskset -c 1  ./bin/aesgcm_test_speed data/testvectors__speed_aesgcm/speedtest192_16384.rsp $REPEAT 1 0 
export LD_LIBRARY_PATH=LD_LIBRAY_PATH:${old_path}


for size in 16 32 48 64 128 256 512 1024 2048 4096 8192 16384
do
	old_path=${LD_LIBRARY_PATH}
	export LD_LIBRARY_PATH=LD_LIBRAY_PATH:${PWD}/../lib
	taskset -c 1 ./bin/aesgcm_test_speed data/testvectors__speed_aesgcm/speedtest256_$size.rsp $REPEAT 1 0 
	export LD_LIBRARY_PATH=LD_LIBRAY_PATH:${old_path}	
done

for size in 32768 65536 131072 262144 524288 1048576
do
	old_path=${LD_LIBRARY_PATH}
	export LD_LIBRARY_PATH=LD_LIBRAY_PATH:${PWD}/../lib
	echo "overwrite size :${size}"
	taskset -c 1 ./bin/aesgcm_test_speed data/testvectors__speed_aesgcm/speedtest256_16384.rsp $REPEAT 1 0 $size
	export LD_LIBRARY_PATH=LD_LIBRAY_PATH:${old_path}
	
done

