#include "common.h"

EVP_PKEY *setup(int curve) {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  if (!ctx) handle_errors();

  if (EVP_PKEY_keygen_init(ctx) <= 0) handle_errors();
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve) <= 0) handle_errors();

  EVP_PKEY* pkey = NULL;
  if (EVP_PKEY_keygen(ctx, &pkey) <= 0) handle_errors();

  EVP_PKEY_CTX_free(ctx);
  return pkey;
}

void hash_message(const unsigned char* msg, size_t msg_len,
                  unsigned char* digest) {
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) handle_errors();

  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) <= 0) handle_errors();
  if (EVP_DigestUpdate(mdctx, msg, msg_len) <= 0) handle_errors();

  unsigned int digest_len;
  if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) <= 0) handle_errors();

  EVP_MD_CTX_free(mdctx);
}
