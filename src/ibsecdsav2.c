#include "ibsecdsa.h"

#define RECOVER_R 0
#define DEBUG 0

int keyderiv(const EVP_PKEY *pkey, const char *id, BIGNUM **uid, BIGNUM **tid,
             EC_POINT **R_out, BN_CTX *ctx) {
  int ret = 1;

  BIGNUM *u = BN_CTX_get(ctx);
  BIGNUM *t = BN_CTX_get(ctx);
  const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
  const EC_GROUP *group = EC_KEY_get0_group(ec_key);
  const BIGNUM *order = EC_GROUP_get0_order(group);
  const BIGNUM *msk = EC_KEY_get0_private_key(ec_key);

  BIGNUM *r = BN_CTX_get(ctx);
  do {
    BN_rand_range(r, order);
  } while (BN_is_zero(r));

  EC_POINT *R = EC_POINT_new(group);
  if (!EC_POINT_mul(group, R, r, NULL, NULL, ctx)) handle_errors();

  BIGNUM *x_R = BN_CTX_get(ctx);
  BIGNUM *y_R = BN_CTX_get(ctx);
  if (!EC_POINT_get_affine_coordinates(group, R, x_R, y_R, ctx))
    handle_errors();
  if (!BN_nnmod(t, x_R, order, ctx)) handle_errors();

  BIGNUM *c = BN_CTX_get(ctx);
  unsigned char digest[SHA256_DIGEST_LENGTH];
  hash_message(id, strlen(id), digest);
  BN_bin2bn(digest, SHA256_DIGEST_LENGTH, c);

  BIGNUM *tmp = BN_CTX_get(ctx);
  if (!BN_mod_mul(tmp, t, msk, order, ctx)) handle_errors();
  if (!BN_mod_add(tmp, c, tmp, order, ctx)) handle_errors();

  BIGNUM *r_inv = BN_CTX_get(ctx);
  if (!BN_mod_inverse(r_inv, r, order, ctx)) handle_errors();
  if (!BN_mod_mul(u, r_inv, tmp, order, ctx)) handle_errors();

  *uid = BN_CTX_get(ctx);
  *uid = BN_dup((const BIGNUM *)u);
  *tid = BN_CTX_get(ctx);
  *tid = BN_dup((const BIGNUM *)t);
  *R_out = EC_POINT_new(group);

  if (!uid || !tid || !EC_POINT_copy(*R_out, R)) ret = 0;

  EC_POINT_free(R);
  return ret;
}

void sign(EVP_PKEY *pkey, const BIGNUM *uid, const BIGNUM *tid,
          const EC_POINT *R, const unsigned char *id, const unsigned char *m,
          BIGNUM **s, BIGNUM **t, EC_POINT **R_out, BN_CTX *ctx) {
  const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
  const EC_GROUP *group = EC_KEY_get0_group(ec_key);
  const BIGNUM *order = EC_GROUP_get0_order(group);

#if RECOVER_R
  const EC_POINT *mpk = EC_KEY_get0_public_key(ec_key);
#endif

#if DEBUG
  printf("\n=== Computing Second Signature ===\n");
  print_bn("Input uid", uid);
  print_bn("Input tid", tid);
#endif

#if RECOVER_R
  BIGNUM *c = BN_CTX_get(ctx);
  BIGNUM *inv_uid = BN_CTX_get(ctx);
  EC_POINT *cG = EC_POINT_new(group);
  EC_POINT *tMPK = EC_POINT_new(group);
  EC_POINT *U = EC_POINT_new(group);
#endif

  unsigned char digest[SHA256_DIGEST_LENGTH];
  hash_message(id, strlen(id), digest);

#if RECOVER_R
  BN_bin2bn(digest, SHA256_DIGEST_LENGTH, c);
  BN_mod_inverse(inv_uid, uid, order, ctx);
  EC_POINT_mul(group, cG, c, NULL, NULL, ctx);
  EC_POINT_mul(group, tMPK, NULL, mpk, tid, ctx);
  EC_POINT_add(group, U, cG, tMPK, ctx);
  EC_POINT_mul(group, U, NULL, U, inv_uid, ctx);
#endif

#if DEBUG
  BIGNUM *x_R = BN_CTX_get(ctx);
  BIGNUM *y_R = BN_CTX_get(ctx);
  EC_POINT_get_affine_coordinates(group, U, x_R, y_R, ctx);
  BN_nnmod(x_R, x_R, order, ctx);
  printf("\nVerifying recovered R matches original t...\n");
  print_bn("x(R) mod n", x_R);
  print_bn("Original tid", tid);
  printf("Match: %s\n", BN_cmp(x_R, tid) == 0 ? "YES" : "NO");
#endif

  BIGNUM *a = BN_CTX_get(ctx);
  EC_POINT *A = EC_POINT_new(group);
  BN_rand_range(a, order);

  EC_POINT_mul(group, A, NULL, R, a, ctx);

  BIGNUM *x = BN_CTX_get(ctx);
  BIGNUM *y = BN_CTX_get(ctx);
  EC_POINT_get_affine_coordinates(group, A, x, y, ctx);
  *t = BN_CTX_get(ctx);
  BN_nnmod(*t, x, order, ctx);

  BIGNUM *d = BN_CTX_get(ctx);
  BIGNUM *t_uid = BN_CTX_get(ctx);
  BIGNUM *inv_a = BN_CTX_get(ctx);
  *s = BN_CTX_get(ctx);

  unsigned char m_concat[strlen(id) + strlen(m)];
  memcpy(m_concat, id, strlen(id));
  memcpy(m_concat + strlen(id), m, strlen(m));
  hash_message(m_concat, strlen(id) + strlen(m), digest);
  BN_bin2bn(digest, SHA256_DIGEST_LENGTH, d);

  BN_mod_mul(t_uid, *t, uid, order, ctx);
  BN_mod_add(*s, d, t_uid, order, ctx);
  BN_mod_inverse(inv_a, a, order, ctx);
  BN_mod_mul(*s, *s, inv_a, order, ctx);
  *R_out = EC_POINT_dup(R, group);

#if DEBUG
  printf("\n=== Final Second Signature ===\n");
  print_bn("s", *s);
  print_bn("t", *t);
  print_point("R", group, *R_out, ctx);
  printf("=== End of Second Signature Computation ===\n\n");
#endif

#if RECOVER_R
  EC_POINT_free(cG);
  EC_POINT_free(tMPK);
  EC_POINT_free(U);
#endif

  EC_POINT_free(A);
}

int verify(EVP_PKEY *pkey, const BIGNUM *s, const BIGNUM *t, const EC_POINT *R,
           const unsigned char *id, const unsigned char *m, BN_CTX *ctx) {
#if DEBUG
  printf("\n=== Verifying Second Signature ===\n");
  print_bn("Input s", s);
  print_bn("Input t", t);
  print_point("Input R", EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey)), R, ctx);
#endif

  const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
  const EC_GROUP *group = EC_KEY_get0_group(ec_key);
  const BIGNUM *order = EC_GROUP_get0_order(group);
  const EC_POINT *mpk = EC_KEY_get0_public_key(ec_key);
  size_t id_len = strlen(id);
  size_t m_len = strlen(m);

  BIGNUM *tid = BN_CTX_get(ctx);
  BIGNUM *y = BN_CTX_get(ctx);
  EC_POINT_get_affine_coordinates(group, R, tid, y, ctx);
  BN_nnmod(tid, tid, order, ctx);

  BIGNUM *c = BN_CTX_get(ctx);
  BIGNUM *d = BN_CTX_get(ctx);
  BIGNUM *inv_s = BN_CTX_get(ctx);
  EC_POINT *cG = EC_POINT_new(group);
  EC_POINT *tMPK = EC_POINT_new(group);
  EC_POINT *term1 = EC_POINT_new(group);
  EC_POINT *term2 = EC_POINT_new(group);
  EC_POINT *sum = EC_POINT_new(group);
  EC_POINT *A_prime = EC_POINT_new(group);

  unsigned char digest[SHA256_DIGEST_LENGTH];
  hash_message(id, id_len, digest);
  BN_bin2bn(digest, SHA256_DIGEST_LENGTH, c);

  unsigned char m_concat[id_len + m_len];
  memcpy(m_concat, id, id_len);
  memcpy(m_concat + id_len, m, m_len);
  hash_message(m_concat, id_len + m_len, digest);
  BN_bin2bn(digest, SHA256_DIGEST_LENGTH, d);

  BN_mod_inverse(inv_s, s, order, ctx);
  EC_POINT_mul(group, cG, c, NULL, NULL, ctx);
  EC_POINT_mul(group, tMPK, NULL, mpk, tid, ctx);
  EC_POINT_add(group, term1, cG, tMPK, ctx);
  EC_POINT_mul(group, term2, NULL, term1, t, ctx);
  EC_POINT_mul(group, term1, NULL, R, d, ctx);
  EC_POINT_add(group, sum, term1, term2, ctx);
  EC_POINT_mul(group, A_prime, NULL, sum, inv_s, ctx);

  BIGNUM *x = BN_CTX_get(ctx);
  EC_POINT_get_affine_coordinates(group, A_prime, x, NULL, ctx);
  BN_nnmod(x, x, order, ctx);

  int result = BN_cmp(x, t) == 0;

#if DEBUG
  printf("\nVerification %s\n", result ? "SUCCEEDED" : "FAILED");
  printf("=== End of Verification ===\n\n");
#endif

  EC_POINT_free(cG);
  EC_POINT_free(tMPK);
  EC_POINT_free(term1);
  EC_POINT_free(term2);
  EC_POINT_free(sum);
  EC_POINT_free(A_prime);

  return result;
}

void simulate_ibs_ecdsa(int curve, FILE *file) {
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  /* Time related variables */
  clock_t start, end;
  BN_CTX *ctx = BN_CTX_new();
  BN_CTX_start(ctx);

  /* Setup */
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
  const unsigned char *m = "message";

  /* Key derivation */
  start = clock();
  BIGNUM *uid = BN_CTX_get(ctx);
  BIGNUM *tid = BN_CTX_get(ctx);
  EC_POINT *R = EC_POINT_new(group);
  int ret = keyderiv(pkey, id, &uid, &tid, &R, ctx);
#if DEBUG
  printf("KEYDERIV %s\n", ret == 1 ? "SUCCESS" : "FAILED");
#endif
  end = clock();
  fprintf(file, ",%.3f", CLOCKS_TO_MS(end - start));

  /* Sign */
  BIGNUM *s = BN_CTX_get(ctx);
  BIGNUM *t = BN_CTX_get(ctx);
  EC_POINT *R_for_second_sig = EC_POINT_dup(R, group);
  start = clock();
  sign(pkey, uid, tid, R, id, m, &s, &t, &R_for_second_sig, ctx);
  end = clock();
  fprintf(file, ",%.3f", CLOCKS_TO_MS(end - start));

  /* Verify */
  start = clock();
  int is_valid = verify(pkey, s, t, R_for_second_sig, id, m, ctx);
  end = clock();
  fprintf(file, ",%.3f\n", CLOCKS_TO_MS(end - start));

#if DEBUG
  printf("\nSignature is %s\n", is_valid == 1 ? "VALID" : "INVALID");
#endif

  EC_POINT_free(R);
  EC_POINT_free(R_for_second_sig);
  EVP_PKEY_free(pkey);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  EVP_cleanup();
  ERR_free_strings();
}
