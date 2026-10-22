#ifndef IBSECDSA_IMPLEMENTATION

#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include "utils.h"
#include "common.h"

typedef struct {
  BIGNUM *uid;
  BIGNUM *tid;
} user_sk_ecdsa;

typedef struct {
  BIGNUM *s;
  BIGNUM *t;
  EC_POINT *R;
} ibs_ecdsa;

int keyderiv(const EVP_PKEY *pkey, const char *id, BIGNUM **uid, BIGNUM **tid,
             EC_POINT **R_out, BN_CTX *ctx);

int ecdsa_verify(void);

void sign(EVP_PKEY *pkey, const BIGNUM *uid, const BIGNUM *tid, const EC_POINT *R,
          const unsigned char *id, const unsigned char *m,
          BIGNUM **s, BIGNUM **t,
          EC_POINT **R_out, BN_CTX *ctx);

int verify(EVP_PKEY *pkey, const BIGNUM *u_prime, const BIGNUM *t_prime,
           const EC_POINT *R, const unsigned char *m,
           const unsigned char *m_prime, BN_CTX *ctx);

void simulate_ibs_ecdsa(int curve, FILE *file);

#endif
