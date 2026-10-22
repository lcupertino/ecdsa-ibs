#include "ibsschnorr.h"

#define DEBUG 0

int modified_keyderiv(EVP_PKEY *pkey,
             const unsigned char *id, BIGNUM **c, BIGNUM **y,
             EC_POINT **R_out, BN_CTX *ctx) {
  int ret = 0;
  unsigned char *hash = NULL;
  unsigned char *data = NULL;
  size_t data_len;

  const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
  const EC_GROUP *group = EC_KEY_get0_group(ec_key);
  const BIGNUM *order = EC_GROUP_get0_order(group);
  const BIGNUM *msk   = EC_KEY_get0_private_key(ec_key);

  EC_POINT *R = EC_POINT_new(group);
  BIGNUM *r = BN_CTX_get(ctx);
  if (!R || !r) goto err;

  do {
    BN_rand_range(r, order);
  } while(BN_is_zero(r));

  if (!EC_POINT_mul(group, R, r, NULL, NULL, ctx)) goto err;

  data_len =
      EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
  data = malloc(data_len);
  if (!data) goto err;
  EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, data, data_len,
                     ctx);

  hash = malloc(SHA256_DIGEST_LENGTH);
  if (!hash) goto err;
  SHA256_CTX sha_ctx;
  SHA256_Init(&sha_ctx);
  SHA256_Update(&sha_ctx, data, data_len);
  SHA256_Update(&sha_ctx, id, strlen(id));
  SHA256_Final(hash, &sha_ctx);

  *c = BN_new();
  if (!*c) goto err;
  BN_bin2bn(hash, SHA256_DIGEST_LENGTH, *c);

  *y = BN_new();
  if (!*y) goto err;
  if (!BN_mod_mul(*y, *c, msk, order, ctx)) goto err;
  if (!BN_mod_add(*y, r, *y, order, ctx)) goto err;

  *R_out = EC_POINT_new(group);
  if (!EC_POINT_copy(*R_out, R)) goto err;

  ret = 1;

err:
  if (R) EC_POINT_free(R);
  if (data) free(data);
  if (hash) free(hash);
  return ret;
}

int schnorr_verify(const EC_GROUP* group, const EC_POINT* pub_key,
                   const unsigned char* msg, size_t msg_len, const BIGNUM* r,
                   const BIGNUM* s) {
  int ret = 0;
  EC_POINT* R = NULL;
  unsigned char* hash = NULL;
  unsigned char* data = NULL;
  size_t data_len;
  BN_CTX* ctx = BN_CTX_new();

  if (!ctx) goto err;

  R = EC_POINT_new(group);
  if (!R) goto err;

  EC_POINT* temp = EC_POINT_new(group);
  if (!temp) goto err;
  if (!EC_POINT_mul(group, temp, s, NULL, NULL, ctx)) goto err;
  if (!EC_POINT_mul(group, R, NULL, pub_key, r, ctx)) goto err;
  if (!EC_POINT_invert(group, R, ctx)) goto err;
  if (!EC_POINT_add(group, R, temp, R, ctx)) goto err;

  data_len =
      EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
  data = malloc(data_len);
  if (!data) goto err;
  EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, data, data_len,
                     ctx);

  hash = malloc(SHA256_DIGEST_LENGTH);
  if (!hash) goto err;
  SHA256_CTX sha_ctx;
  SHA256_Init(&sha_ctx);
  SHA256_Update(&sha_ctx, data, data_len);
  SHA256_Update(&sha_ctx, msg, msg_len);
  SHA256_Final(hash, &sha_ctx);

  BIGNUM* computed_r = BN_new();
  if (!computed_r) goto err;
  BN_bin2bn(hash, SHA256_DIGEST_LENGTH, computed_r);

  if (BN_cmp(computed_r, r) == 0) ret = 1;

err:
  if (R) EC_POINT_free(R);
  if (temp) EC_POINT_free(temp);
  if (data) free(data);
  if (hash) free(hash);
  BN_CTX_free(ctx);
  return ret;
}

int modified_sign(EVP_PKEY *pkey, const BIGNUM *y, const EC_POINT *R,
         const unsigned char *id, const unsigned char *m,
         EC_POINT **A, BIGNUM **b, BN_CTX *ctx) {
  int ret = 0;

  unsigned char* hash = NULL;
  unsigned char* A_bytes = NULL;
  unsigned char* combined_msg = NULL;
  size_t A_bytes_len, combined_msg_len;

  const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
  const EC_GROUP *group = EC_KEY_get0_group(ec_key);
  const BIGNUM *order = EC_GROUP_get0_order(group);


  *A = EC_POINT_new(group);
  BIGNUM *a = BN_CTX_get(ctx);
  if (!*A || !a) goto err;

  do {
    BN_rand_range(a, order);
  } while(BN_is_zero(a));

  if (!EC_POINT_mul(group, *A, a, NULL, NULL, ctx)) goto err;

  A_bytes_len =
      EC_POINT_point2oct(group, *A, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
  A_bytes = malloc(A_bytes_len);
  if (!A_bytes) goto err;
  EC_POINT_point2oct(group, *A, POINT_CONVERSION_COMPRESSED, A_bytes,
                     A_bytes_len, ctx);

  combined_msg_len = A_bytes_len + strlen(id) + strlen(m);
  combined_msg = malloc(combined_msg_len);
  if (!combined_msg) goto err;

  memcpy(combined_msg, A_bytes, A_bytes_len);
  memcpy(combined_msg + A_bytes_len, id, strlen(id));
  memcpy(combined_msg + A_bytes_len + strlen(id), m, strlen(m));

  hash = malloc(SHA256_DIGEST_LENGTH);
  if (!hash) goto err;
  SHA256(combined_msg, combined_msg_len, hash);

  BIGNUM *d = BN_CTX_get(ctx);
  if (!d) goto err;
  BN_bin2bn(hash, SHA256_DIGEST_LENGTH, d);

  *b = BN_new();
  if (!*b) goto err;
  if (!BN_mod_mul(*b, d, y, order, ctx)) goto err;
  if (!BN_mod_add(*b, a, *b, order, ctx)) goto err;

  ret = 1;

err:
  if (a) BN_free(a);
  if (A_bytes) free(A_bytes);
  if (combined_msg) free(combined_msg);
  if (hash) free(hash);
  return ret;
}

int modified_verify(EVP_PKEY *pkey, const unsigned char *id,
          const unsigned char *m, const EC_POINT *A, 
          const BIGNUM *b, const EC_POINT *R, BN_CTX *ctx) {
  int ret = 0;
  EC_POINT *lhs = NULL, *rhs = NULL;
  EC_POINT *temp1 = NULL, *temp2 = NULL;
  unsigned char* hash_d = NULL;
  unsigned char* hash_c = NULL;
  unsigned char* A_bytes = NULL;
  unsigned char* R_bytes = NULL;
  unsigned char* combined_msg = NULL;
  size_t A_bytes_len, R_bytes_len, combined_msg_len;

  const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
  const EC_GROUP *group = EC_KEY_get0_group(ec_key);
  const EC_POINT *mpk = EC_KEY_get0_public_key(ec_key);
  const BIGNUM *order = EC_GROUP_get0_order(group);

  R_bytes_len =
      EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
  R_bytes = malloc(R_bytes_len);
  if (!R_bytes) goto err;
  EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, R_bytes,
                     R_bytes_len, ctx);

  hash_c = malloc(SHA256_DIGEST_LENGTH);
  if (!hash_c) goto err;
  SHA256_CTX sha_ctx;
  SHA256_Init(&sha_ctx);
  SHA256_Update(&sha_ctx, R_bytes, R_bytes_len);
  SHA256_Update(&sha_ctx, id, strlen(id));
  SHA256_Final(hash_c, &sha_ctx);

  BIGNUM *c = BN_CTX_get(ctx);
  if (!c) goto err;
  BN_bin2bn(hash_c, SHA256_DIGEST_LENGTH, c);

  A_bytes_len =
      EC_POINT_point2oct(group, A, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
  A_bytes = malloc(A_bytes_len);
  if (!A_bytes) goto err;
  EC_POINT_point2oct(group, A, POINT_CONVERSION_COMPRESSED, A_bytes,
                     A_bytes_len, ctx);

  combined_msg_len = A_bytes_len + strlen(id) + strlen(m);
  combined_msg = malloc(combined_msg_len);
  if (!combined_msg) goto err;

  memcpy(combined_msg, A_bytes, A_bytes_len);
  memcpy(combined_msg + A_bytes_len, id, strlen(id));
  memcpy(combined_msg + A_bytes_len + strlen(id), m, strlen(m));

  hash_d = malloc(SHA256_DIGEST_LENGTH);
  if (!hash_d) goto err;
  SHA256(combined_msg, combined_msg_len, hash_d);

  BIGNUM *d = BN_CTX_get(ctx);
  if (!d) goto err;
  BN_bin2bn(hash_d, SHA256_DIGEST_LENGTH, d);

  lhs = EC_POINT_new(group);
  if (!lhs) goto err;
  if (!EC_POINT_mul(group, lhs, b, NULL, NULL, ctx)) goto err;

  rhs = EC_POINT_new(group);
  temp1 = EC_POINT_new(group);
  temp2 = EC_POINT_new(group);
  if (!rhs || !temp1 || !temp2) goto err;

  if (!EC_POINT_mul(group, temp1, NULL, mpk, c, ctx)) goto err;
  if (!EC_POINT_add(group, temp2, R, temp1, ctx)) goto err;
  if (!EC_POINT_mul(group, temp1, NULL, temp2, d, ctx)) goto err;
  if (!EC_POINT_add(group, rhs, A, temp1, ctx)) goto err;

  if (EC_POINT_cmp(group, lhs, rhs, ctx) == 0) ret = 1;

err:
  if (lhs) EC_POINT_free(lhs);
  if (rhs) EC_POINT_free(rhs);
  if (temp1) EC_POINT_free(temp1);
  if (temp2) EC_POINT_free(temp2);
  if (A_bytes) free(A_bytes);
  if (R_bytes) free(R_bytes);
  if (combined_msg) free(combined_msg);
  if (hash_c) free(hash_c);
  if (hash_d) free(hash_d);
  return ret;
}

int simulate_ibs_schnorr_modified(int curve, FILE *file) {
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  /* Time-related variables */
  clock_t start, end;
  BN_CTX *ctx = BN_CTX_new();
  BN_CTX_start(ctx);

  start = clock();
  EVP_PKEY *pkey = setup(curve);
  end = clock();
  fprintf(file, "%.3f", CLOCKS_TO_MS(end - start));

  /* Common parameters */
  const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
  const EC_GROUP *group = EC_KEY_get0_group(ec_key);
  const BIGNUM *order = EC_GROUP_get0_order(group);

  /* Messages */
  const unsigned char *id = "id";
  const unsigned char *m  = "message";

  /* Key derivation */
  start = clock();
  BIGNUM *c = BN_CTX_get(ctx);
  BIGNUM *y = BN_CTX_get(ctx);
  EC_POINT *R = EC_POINT_new(group);

  if (!modified_keyderiv(pkey, id, &c, &y, &R, ctx)) {
    fprintf(stderr, "Failed to sign message\n");
    return 1;
  }
  end = clock();
  fprintf(file, ",%.3f", CLOCKS_TO_MS(end - start));

/*
#if DEBUG
  start = clock();
  if (!schnorr_verify(group, pub_key, (const unsigned char*)msg, msg_len, r,
                      s)) {
    fprintf(stderr, "First signature verification failed\n");
    return 1;
  }
  end = clock();
  printf("First signature verification,%f\n", CLOCKS_TO_MS(end - start));
#endif
*/

  /* Sign */
  start = clock();
  EC_POINT *A = EC_POINT_new(group);
  BIGNUM *b = BN_CTX_get(ctx);
  if (!modified_sign(pkey, y, R, id, m, &A, &b, ctx)) {
    fprintf(stderr, "Failed to create second signature\n");
    return 1;
  }
  end = clock();
  fprintf(file, ",%.3f", CLOCKS_TO_MS(end - start));

  /* Verify */
  start = clock();
  if (!modified_verify(pkey, id, m, A, b, R, ctx)) {
    fprintf(stderr, "Second signature verification failed\n");
    return 1;
  }
  end = clock();
  fprintf(file, ",%.3f\n", CLOCKS_TO_MS(end - start));

  BN_free(c);
  BN_free(y);
  EC_POINT_free(R);
  EC_POINT_free(A);
  BN_free(b);
  EVP_cleanup();
}
