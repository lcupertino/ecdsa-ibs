/*
 *
 *
 * Description: common functions to all IBS schemes.
 *
 * Contents:
 *  - CLOCKS_TO_MS: macro for converting from clocks to
 *  ms.
 *  - setup: master key pair generation function.
 *  - hash_message: computes the digest of a message
 *  - print_hash: print digest value
 */

#ifndef COMMON_IMPLEMENTATION

#include "utils.h"

#define DEBUG 0
#define WARMUP 1000
#define NUMROUNDS 10 * WARMUP
#define NUMCURVES sizeof(curves) / sizeof(int)
#define BASE_NAME_ECDSA       "-benchmark-ds-ecdsa.csv"
#define BASE_NAME_SCHNORR     "-benchmark-ds-schnorr.csv"
#define BASE_NAME_IBS_ECDSA   "-benchmark-ibs-ecdsa.csv"
#define BASE_NAME_IBS_SCHNORR "-benchmark-ibs-schnorr.csv"

#define CLOCKS_TO_MS(c) ((((float)c) / CLOCKS_PER_SEC) * 1000.0)

EVP_PKEY *setup(int curve);

void hash_message(const unsigned char *msg, size_t msg_len,
                  unsigned char *digest);

#endif
