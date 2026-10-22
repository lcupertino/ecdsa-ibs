#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CLOCKS_TO_MS(c) (((double)(c) * 1000) / CLOCKS_PER_SEC)

int schnorr_sign(const EC_GROUP* group, const BIGNUM* priv_key,
                const unsigned char* msg, size_t msg_len,
                BIGNUM** r, BIGNUM** s, EC_POINT** R_out) {
    int ret = 0;
    BIGNUM* k = NULL;
    EC_POINT* R = NULL;
    unsigned char* hash = NULL;
    unsigned char* data = NULL;
    size_t data_len;
    const BIGNUM* order = EC_GROUP_get0_order(group);
    BN_CTX* ctx = BN_CTX_new();

    if (!ctx) goto err;

    R = EC_POINT_new(group);
    k = BN_new();
    if (!R || !k) goto err;

    if (!BN_rand_range(k, order)) goto err;
    if (!EC_POINT_mul(group, R, k, NULL, NULL, ctx)) goto err;

    data_len = EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    data = malloc(data_len);
    if (!data) goto err;
    EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, data, data_len, ctx);

    hash = malloc(SHA256_DIGEST_LENGTH);
    if (!hash) goto err;
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, data, data_len);
    SHA256_Update(&sha_ctx, msg, msg_len);
    SHA256_Final(hash, &sha_ctx);

    *r = BN_new();
    if (!*r) goto err;
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, *r);

    *s = BN_new();
    if (!*s) goto err;
    if (!BN_mod_mul(*s, *r, priv_key, order, ctx)) goto err;
    if (!BN_mod_add(*s, k, *s, order, ctx)) goto err;

    *R_out = EC_POINT_new(group);
    if (!EC_POINT_copy(*R_out, R)) goto err;

    ret = 1;

err:
    if (R) EC_POINT_free(R);
    if (k) BN_free(k);
    if (data) free(data);
    if (hash) free(hash);
    BN_CTX_free(ctx);
    return ret;
}

int schnorr_verify(const EC_GROUP* group, const EC_POINT* pub_key,
                  const unsigned char* msg, size_t msg_len,
                  const BIGNUM* r, const BIGNUM* s) {
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

    data_len = EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    data = malloc(data_len);
    if (!data) goto err;
    EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, data, data_len, ctx);

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

int second_sign(const EC_GROUP* group, const BIGNUM* s,
               const unsigned char* msg, size_t msg_len,
               const unsigned char* msg_prime, size_t msg_prime_len,
               const EC_POINT* R, EC_POINT** A, BIGNUM** b) {
    int ret = 0;
    BIGNUM* a = NULL;
    unsigned char* hash = NULL;
    unsigned char* A_bytes = NULL;
    unsigned char* combined_msg = NULL;
    size_t A_bytes_len, combined_msg_len;
    const BIGNUM* order = EC_GROUP_get0_order(group);
    BN_CTX* ctx = BN_CTX_new();

    if (!ctx) goto err;

    *A = EC_POINT_new(group);
    a = BN_new();
    if (!*A || !a) goto err;

    if (!BN_rand_range(a, order)) goto err;
    if (!EC_POINT_mul(group, *A, a, NULL, NULL, ctx)) goto err;

    A_bytes_len = EC_POINT_point2oct(group, *A, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    A_bytes = malloc(A_bytes_len);
    if (!A_bytes) goto err;
    EC_POINT_point2oct(group, *A, POINT_CONVERSION_COMPRESSED, A_bytes, A_bytes_len, ctx);

    combined_msg_len = A_bytes_len + msg_len + msg_prime_len;
    combined_msg = malloc(combined_msg_len);
    if (!combined_msg) goto err;
    
    memcpy(combined_msg, A_bytes, A_bytes_len);
    memcpy(combined_msg + A_bytes_len, msg, msg_len);
    memcpy(combined_msg + A_bytes_len + msg_len, msg_prime, msg_prime_len);

    hash = malloc(SHA256_DIGEST_LENGTH);
    if (!hash) goto err;
    SHA256(combined_msg, combined_msg_len, hash);

    BIGNUM* e_prime = BN_new();
    if (!e_prime) goto err;
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, e_prime);

    *b = BN_new();
    if (!*b) goto err;
    if (!BN_mod_mul(*b, e_prime, s, order, ctx)) goto err;
    if (!BN_mod_add(*b, a, *b, order, ctx)) goto err;

    ret = 1;

err:
    if (a) BN_free(a);
    if (A_bytes) free(A_bytes);
    if (combined_msg) free(combined_msg);
    if (hash) free(hash);
    BN_CTX_free(ctx);
    return ret;
}

int second_verify(const EC_GROUP* group, const EC_POINT* Z,
                 const unsigned char* msg, size_t msg_len,
                 const unsigned char* msg_prime, size_t msg_prime_len,
                 const EC_POINT* A, const BIGNUM* b, const EC_POINT* R) {
    int ret = 0;
    EC_POINT* lhs = NULL, *rhs = NULL;
    EC_POINT* temp1 = NULL, *temp2 = NULL;
    unsigned char* hash_e_prime = NULL;
    unsigned char* hash_e = NULL;
    unsigned char* A_bytes = NULL;
    unsigned char* R_bytes = NULL;
    unsigned char* combined_msg = NULL;
    size_t A_bytes_len, R_bytes_len, combined_msg_len;
    BN_CTX* ctx = BN_CTX_new();

    if (!ctx) goto err;

    // Compute e = H(R||m)
    R_bytes_len = EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    R_bytes = malloc(R_bytes_len);
    if (!R_bytes) goto err;
    EC_POINT_point2oct(group, R, POINT_CONVERSION_COMPRESSED, R_bytes, R_bytes_len, ctx);

    hash_e = malloc(SHA256_DIGEST_LENGTH);
    if (!hash_e) goto err;
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, R_bytes, R_bytes_len);
    SHA256_Update(&sha_ctx, msg, msg_len);
    SHA256_Final(hash_e, &sha_ctx);

    BIGNUM* e = BN_new();
    if (!e) goto err;
    BN_bin2bn(hash_e, SHA256_DIGEST_LENGTH, e);

    // Compute e' = H(A||m||m')
    A_bytes_len = EC_POINT_point2oct(group, A, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    A_bytes = malloc(A_bytes_len);
    if (!A_bytes) goto err;
    EC_POINT_point2oct(group, A, POINT_CONVERSION_COMPRESSED, A_bytes, A_bytes_len, ctx);

    combined_msg_len = A_bytes_len + msg_len + msg_prime_len;
    combined_msg = malloc(combined_msg_len);
    if (!combined_msg) goto err;
    
    memcpy(combined_msg, A_bytes, A_bytes_len);
    memcpy(combined_msg + A_bytes_len, msg, msg_len);
    memcpy(combined_msg + A_bytes_len + msg_len, msg_prime, msg_prime_len);

    hash_e_prime = malloc(SHA256_DIGEST_LENGTH);
    if (!hash_e_prime) goto err;
    SHA256(combined_msg, combined_msg_len, hash_e_prime);

    BIGNUM* e_prime = BN_new();
    if (!e_prime) goto err;
    BN_bin2bn(hash_e_prime, SHA256_DIGEST_LENGTH, e_prime);

    // Compute lhs = b*G
    lhs = EC_POINT_new(group);
    if (!lhs) goto err;
    if (!EC_POINT_mul(group, lhs, b, NULL, NULL, ctx)) goto err;

    // Compute rhs = A + e'*(R + e*Z)
    rhs = EC_POINT_new(group);
    temp1 = EC_POINT_new(group);
    temp2 = EC_POINT_new(group);
    if (!rhs || !temp1 || !temp2) goto err;

    if (!EC_POINT_mul(group, temp1, NULL, Z, e, ctx)) goto err;
    if (!EC_POINT_add(group, temp2, R, temp1, ctx)) goto err;
    if (!EC_POINT_mul(group, temp1, NULL, temp2, e_prime, ctx)) goto err;
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
    if (hash_e_prime) free(hash_e_prime);
    if (hash_e) free(hash_e);
    BN_CTX_free(ctx);
    return ret;
}

int main() {
    clock_t start, end;
    
    OpenSSL_add_all_algorithms();

    // Print CSV header
    printf("Operation,Time (ms)\n");

    // ===== Key Generation =====
    start = clock();
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) {
        fprintf(stderr, "Failed to create EC group\n");
        return 1;
    }

    BIGNUM* priv_key = BN_new();
    if (!BN_rand_range(priv_key, EC_GROUP_get0_order(group))) {
        fprintf(stderr, "Failed to generate private key\n");
        return 1;
    }

    EC_POINT* pub_key = EC_POINT_new(group);
    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, NULL)) {
        fprintf(stderr, "Failed to derive public key\n");
        return 1;
    }
    end = clock();
    printf("Key generation,%f\n", CLOCKS_TO_MS(end - start));

    // ===== First Signature =====
    const char* msg = "First message";
    const char* msg_prime = "Second message";
    size_t msg_len = strlen(msg);
    size_t msg_prime_len = strlen(msg_prime);

    // Sign first message
    start = clock();
    BIGNUM* r = NULL, *s = NULL;
    EC_POINT* R = NULL;
    if (!schnorr_sign(group, priv_key, (const unsigned char*)msg, msg_len, &r, &s, &R)) {
        fprintf(stderr, "Failed to sign message\n");
        return 1;
    }
    end = clock();
    printf("First signature creation,%f\n", CLOCKS_TO_MS(end - start));

    // Verify first signature
    start = clock();
    if (!schnorr_verify(group, pub_key, (const unsigned char*)msg, msg_len, r, s)) {
        fprintf(stderr, "First signature verification failed\n");
        return 1;
    }
    end = clock();
    printf("First signature verification,%f\n", CLOCKS_TO_MS(end - start));

    // ===== Second Signature =====
    start = clock();
    EC_POINT* A = NULL;
    BIGNUM* b = NULL;
    if (!second_sign(group, s, (const unsigned char*)msg, msg_len,
                   (const unsigned char*)msg_prime, msg_prime_len, R, &A, &b)) {
        fprintf(stderr, "Failed to create second signature\n");
        return 1;
    }
    end = clock();
    printf("Second signature creation,%f\n", CLOCKS_TO_MS(end - start));

    // Verify second signature
    start = clock();
    if (!second_verify(group, pub_key, (const unsigned char*)msg, msg_len,
                     (const unsigned char*)msg_prime, msg_prime_len, A, b, R)) {
        fprintf(stderr, "Second signature verification failed\n");
        return 1;
    }
    end = clock();
    printf("Second signature verification,%f\n", CLOCKS_TO_MS(end - start));

    // ===== Cleanup =====
    EC_GROUP_free(group);
    BN_free(priv_key);
    EC_POINT_free(pub_key);
    BN_free(r);
    BN_free(s);
    EC_POINT_free(R);
    EC_POINT_free(A);
    BN_free(b);
    EVP_cleanup();

    return 0;
}