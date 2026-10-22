all:
	gcc -o benchmark-ibs-schnorr main-schnorr.c utils.c common.c ibsschnorr.c -O2 -lssl -lcrypto -Wno-deprecated-declarations
	gcc -o benchmark-ibs-ecdsa main-ecdsa.c utils.c common.c ibsecdsa.c -O2 -lssl -lcrypto -Wno-deprecated-declarations
	gcc -o benchmark-ibs-ecdsa-v1 main-ecdsa.c utils.c common.c ibsecdsav1.c -O2 -lssl -lcrypto -Wno-deprecated-declarations
	gcc -o benchmark-ibs-ecdsa-v2 main-ecdsa.c utils.c common.c ibsecdsav2.c -O2 -lssl -lcrypto -Wno-deprecated-declarations
	gcc -o benchmark-ibs-ecdsa-v3 main-ecdsa.c utils.c common.c ibsecdsav3.c -O2 -lssl -lcrypto -Wno-deprecated-declarations
	gcc -o benchmark-ds-schnorr schnorr.c utils.c common.c -O2 -lssl -lcrypto -Wno-deprecated-declarations
	gcc -o benchmark-ds-ecdsa ecdsa.c utils.c common.c -O2 -lssl -lcrypto -Wno-deprecated-declarations

optimized:
	gcc -o benchmark-ibs-schnorr-O3 main-schnorr.c utils.c common.c ibsschnorr.c -O3 -lssl -lcrypto -Wno-deprecated-declarations
	gcc -o benchmark-ibs-ecdsa-O3 main-ecdsa.c utils.c common.c ibsecdsa.c -O3 -lssl -lcrypto -Wno-deprecated-declarations
	gcc -o benchmark-ibs-ecdsa-v1-O3 main-ecdsa.c utils.c common.c ibsecdsav1.c -O3 -lssl -lcrypto -Wno-deprecated-declarations
	gcc -o benchmark-ibs-ecdsa-v2-O3 main-ecdsa.c utils.c common.c ibsecdsav2.c -O3 -lssl -lcrypto -Wno-deprecated-declarations
	gcc -o benchmark-ibs-ecdsa-v3-O3 main-ecdsa.c utils.c common.c ibsecdsav3.c -O3 -lssl -lcrypto -Wno-deprecated-declarations
	gcc -o benchmark-ds-schnorr-O3 schnorr.c utils.c common.c -O3 -lssl -lcrypto -Wno-deprecated-declarations
	gcc -o benchmark-ds-ecdsa-O3 ecdsa.c utils.c common.c -O3 -lssl -lcrypto -Wno-deprecated-declarations

native:
	gcc -o benchmark-ibs-schnorr-O3-native main-schnorr.c utils.c common.c ibsschnorr.c -O3 -march=native -lssl -lcrypto -Wno-deprecated-declarations
	gcc -o benchmark-ibs-ecdsa-O3-native main-ecdsa.c utils.c common.c ibsecdsa.c -O3 -march=native -lssl -lcrypto -Wno-deprecated-declarations
	gcc -o benchmark-ibs-ecdsa-v1-O3-native main-ecdsa.c utils.c common.c ibsecdsav1.c -march=native -O3 -lssl -lcrypto -Wno-deprecated-declarations
	gcc -o benchmark-ibs-ecdsa-v2-O3-native main-ecdsa.c utils.c common.c ibsecdsav2.c -O3 -march=native -lssl -lcrypto -Wno-deprecated-declarations
	gcc -o benchmark-ibs-ecdsa-v3-O3-native main-ecdsa.c utils.c common.c ibsecdsav3.c -O3 -march=native -lssl -lcrypto -Wno-deprecated-declarations
	gcc -o benchmark-ds-schnorr-O3-native schnorr.c utils.c common.c -O3 -march=native -lssl -lcrypto -Wno-deprecated-declarations
	gcc -o benchmark-ds-ecdsa-O3-native ecdsa.c utils.c common.c -O3 -march=native -lssl -lcrypto -Wno-deprecated-declarations
	
libraries:
	gcc -x c -c utils.h
	gcc -x c -c common.h
	gcc -x c -c ibsecdsa.h
	gcc -x c -c ibsschnorr.h

run_bench_native:
	mkdir ibs-schnorr-native 		&& ./benchmark-ibs-schnorr-O3-native 		&& mv *.csv ibs-schnorr-native/
	mkdir ibs-ecdsa-native 	 		&& ./benchmark-ibs-ecdsa-O3-native 			&& mv *.csv ibs-ecdsa-native/
	mkdir ibs-ecdsa-v1-native 	&& ./benchmark-ibs-ecdsa-v1-O3-native 	&& mv *.csv ibs-ecdsa-v1-native/
	mkdir ibs-ecdsa-v2-native 	&& ./benchmark-ibs-ecdsa-v2-O3-native 	&& mv *.csv ibs-ecdsa-v2-native/
	mkdir ibs-ecdsa-v3-native 	&& ./benchmark-ibs-ecdsa-v3-O3-native 	&& mv *.csv ibs-ecdsa-v3-native/
	mkdir ds-schnorr-native 		&& ./benchmark-ds-schnorr-O3-native 		&& mv *.csv ds-schnorr-native/
	mkdir ds-ecdsa-native 			&& ./benchmark-ds-ecdsa-O3-native 			&& mv *.csv ds-ecdsa-native/
	mkdir experiments-native		&& mv ds-* ibs-* experiments-native/


run_bench:
	mkdir ibs-schnorr 		&& ./benchmark-ibs-schnorr 			&& mv *.csv ibs-schnorr/
	mkdir ibs-schnorr-O3	&& ./benchmark-ibs-schnorr-O3 	&& mv *.csv ibs-schnorr-O3/
	mkdir ibs-ecdsa 			&& ./benchmark-ibs-ecdsa 				&& mv *.csv ibs-ecdsa/
	mkdir ibs-ecdsa-O3 		&& ./benchmark-ibs-ecdsa-O3 		&& mv *.csv ibs-ecdsa-O3/
	mkdir ibs-ecdsa-v1 		&& ./benchmark-ibs-ecdsa-v1 		&& mv *.csv ibs-ecdsa-v1/
	mkdir ibs-ecdsa-v1-O3 && ./benchmark-ibs-ecdsa-v1-O3	&& mv *.csv ibs-ecdsa-v1-O3/
	mkdir ibs-ecdsa-v2 		&& ./benchmark-ibs-ecdsa-v2 		&& mv *.csv ibs-ecdsa-v2/
	mkdir ibs-ecdsa-v2-O3 && ./benchmark-ibs-ecdsa-v2-O3 	&& mv *.csv ibs-ecdsa-v2-O3/
	mkdir ibs-ecdsa-v3 		&& ./benchmark-ibs-ecdsa-v3 		&& mv *.csv ibs-ecdsa-v3/
	mkdir ibs-ecdsa-v3-O3 && ./benchmark-ibs-ecdsa-v3-O3 	&& mv *.csv ibs-ecdsa-v3-O3/
	mkdir ds-schnorr		 	&& ./benchmark-ds-schnorr 			&& mv *.csv ds-schnorr/
	mkdir ds-schnorr-O3		&& ./benchmark-ds-schnorr-O3 		&& mv *.csv ds-schnorr-O3/
	mkdir ds-ecdsa 			 	&& ./benchmark-ds-ecdsa 				&& mv *.csv ds-ecdsa/
	mkdir ds-ecdsa-O3			&& ./benchmark-ds-ecdsa-O3 			&& mv *.csv ds-ecdsa-O3/
	mkdir experiments 		&& mv ds-* ibs-* experiments/

clean:
	rm -rf experiments/
