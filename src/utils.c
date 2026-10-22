#include "utils.h"

void handle_errors() {
  ERR_print_errors_fp(stderr);
  abort();
}

void print_bn(const char* label, const BIGNUM* bn) {
  char* str = BN_bn2hex(bn);
  printf("%s: %s\n", label, str);
  OPENSSL_free(str);
}

void print_point(const char* label, const EC_GROUP* group,
                 const EC_POINT* point, BN_CTX* ctx) {
  BIGNUM* x = BN_new();
  BIGNUM* y = BN_new();
  EC_POINT_get_affine_coordinates(group, point, x, y, ctx);
  char* x_str = BN_bn2hex(x);
  char* y_str = BN_bn2hex(y);
  printf("%s:\n  x: %s\n  y: %s\n", label, x_str, y_str);
  OPENSSL_free(x_str);
  OPENSSL_free(y_str);
  BN_free(x);
  BN_free(y);
}

void print_hash(const char* label, const unsigned char* hash, size_t len) {
  printf("%s: ", label);
  for (size_t i = 0; i < len; i++) {
    printf("%02x", hash[i]);
  }
  printf("\n");
}
