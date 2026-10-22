#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "utils.h"
#include "common.h"

const int curves[] = {
    NID_brainpoolP224r1, NID_brainpoolP256r1, NID_brainpoolP320r1,
    NID_brainpoolP384r1, NID_brainpoolP512r1, NID_secp224r1,
    NID_secp256k1,       NID_secp384r1,       NID_secp521r1};

const char *algorithms[] = {
    "brainpoolP224r1", "brainpoolP256r1", "brainpoolP320r1",
    "brainpoolP384r1", "brainpoolP512r1", "secp224r1",
    "secp256k1",       "secp384r1",       "secp521r1"};

EVP_PKEY *keygen(int curve) {
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) handle_errors();
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve) <= 0) handle_errors();
  if (EVP_PKEY_keygen(ctx, &pkey) <= 0) handle_errors();
  EVP_PKEY_CTX_free(ctx);
  return pkey;
}

int sign(EVP_PKEY *pkey, const unsigned char *msg, size_t msg_len,
                 unsigned char **sig, size_t *sig_len) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) handle_errors();
  if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0)
    handle_errors();
  if (EVP_DigestSign(ctx, NULL, sig_len, msg, msg_len) <= 0) handle_errors();
  *sig = (unsigned char*) malloc(*sig_len);
  if (!*sig) handle_errors();
  if (EVP_DigestSign(ctx, *sig, sig_len, msg, msg_len) <= 0)
    handle_errors();
  EVP_MD_CTX_free(ctx);
  return 1;
}

int verify(EVP_PKEY *pkey, const unsigned char *msg, size_t msg_len,
                     const unsigned char *sig, size_t sig_len) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) handle_errors();
  if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0)
    handle_errors();
  int result = EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len);
  EVP_MD_CTX_free(ctx);
  return result;
}

int simulate_ecdsa(int curve, FILE *file) {
  clock_t start, end;
  double elapsed;

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  /* Keygen */
  start = clock();
  EVP_PKEY* pkey = keygen(curve);
  end = clock();
  fprintf(file, "%.3f", CLOCKS_TO_MS(end - start));

  /* Sign */
  start = clock();
  const char* message = "message";
  size_t message_len = strlen(message);
  unsigned char* signature = NULL;
  size_t signature_len;
  if (!sign(pkey, (unsigned char*)message, message_len, &signature,
                   &signature_len))
    handle_errors();
  end = clock();
  fprintf(file, ",%.3f", CLOCKS_TO_MS(end - start));

  /* Verify */
  start = clock();
  if (!verify(pkey, (unsigned char*) message, message_len, signature,
                       signature_len))
    handle_errors();
  end = clock();
  fprintf(file, ",%.3f\n", CLOCKS_TO_MS(end - start));

  free(signature);
  EVP_PKEY_free(pkey);
  EVP_cleanup();
  ERR_free_strings();

  return 0;
}

int main() {
  for (int j = 0; j < NUMCURVES; j++) {
    /*
     * Creating file
     *
     */
    const char *extra_buffer = "extra";
    size_t SIZE = strlen(algorithms[j]) + strlen(BASE_NAME_ECDSA) + strlen(extra_buffer);
    char *buffer = malloc(sizeof(*buffer) * SIZE);
    char *filename;
    filename = buffer;
    filename = strcpy(filename, algorithms[j]);
    filename = strcat(filename, BASE_NAME_ECDSA);
    printf("Filename %s\n", filename);

#if !DEBUG
    FILE *file;
    file = fopen(filename, "w");
    if (!file) return 0;

    for (int i = 0; i < NUMROUNDS; i++) {
      int ret = simulate_ecdsa(curves[j], file);
    }
    fclose(file);
#endif
  }

  return 0;
}
