#ifndef IBSSCHNORR_IMPLEMENTATION

#include <openssl/rand.h>
#include <openssl/sha.h>

#include "utils.h"
#include "common.h"

typedef struct {
  EC_POINT *R;
  BIGNUM *s;
} user_sk_schnorr;

typedef struct {
  EC_POINT *A;
  BIGNUM *b;
  EC_POINT *R;
} ibs_schnorr;

int modified_keyderiv(EVP_PKEY *pkey, const unsigned char *id, BIGNUM **c, BIGNUM **y, EC_POINT **R_out, BN_CTX *ctx);

int keyderiv(const EC_GROUP* group, const BIGNUM* priv_key,
             const unsigned char* msg, size_t msg_len, BIGNUM** r, BIGNUM** s,
             EC_POINT** R_out);

int schnorr_verify(const EC_GROUP* group, const EC_POINT* pub_key,
                   const unsigned char* msg, size_t msg_len, const BIGNUM* r,
                   const BIGNUM* s);

int modified_sign(EVP_PKEY *pkey, const BIGNUM *y, const EC_POINT *R,
          const unsigned char *id, const unsigned char *m,
          EC_POINT **A, BIGNUM **b, BN_CTX *ctx);

int sign(const EC_GROUP* group, const BIGNUM* s, const unsigned char* msg,
         size_t msg_len, const unsigned char* msg_prime, size_t msg_prime_len,
         const EC_POINT* R, EC_POINT** A, BIGNUM** b);

int modified_verify(EVP_PKEY *pkey, const unsigned char *id, const unsigned char *m, 
          const EC_POINT *A, const BIGNUM *b, const EC_POINT *R, BN_CTX *ctx);

int verify(const EC_GROUP* group, const EC_POINT* Z, const unsigned char* msg,
           size_t msg_len, const unsigned char* msg_prime, size_t msg_prime_len,
           const EC_POINT* A, const BIGNUM* b, const EC_POINT* R);

int simulate_ibs_schnorr(int curve, FILE *file);
int simulate_ibs_schnorr_modified(int curve, FILE *file);

#endif
