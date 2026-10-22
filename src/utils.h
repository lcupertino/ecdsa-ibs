/*
 *
 *
 * Description: common utility and helper functions
 * for debugging purpose.
 *
 * Contents:
 *  - handle_errors: error handling
 *  - print_bignum: print bignum style numbers
 *  - print_point: print elliptic curve point
 *  - print_hash: print digest value
 */
#ifndef UTILS_IMPLEMENTATION

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void handle_errors(void);

void print_bn(const char* label, const BIGNUM* x);

void print_point(const char* label, const EC_GROUP* group,
                 const EC_POINT* point, BN_CTX* ctx);

void print_hash(const char* label, const unsigned char* hash, size_t len);

#endif
