#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define DEBUG 1

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void print_bn(const char* label, const BIGNUM* bn) {
    char* str = BN_bn2hex(bn);
    printf("%s: %s\n", label, str);
    OPENSSL_free(str);
}

void print_point(const char* label, const EC_GROUP* group, const EC_POINT* point, BN_CTX* ctx) {
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

EVP_PKEY* generate_ec_key() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) handle_errors();

    if (EVP_PKEY_keygen_init(ctx) <= 0) handle_errors();
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp256k1) <= 0) handle_errors();

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) handle_errors();

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

void hash_message(const unsigned char *msg, size_t msg_len, unsigned char *digest) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) handle_errors();

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) <= 0) handle_errors();
    if (EVP_DigestUpdate(mdctx, msg, msg_len) <= 0) handle_errors();

    unsigned int digest_len;
    if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) <= 0) handle_errors();

    EVP_MD_CTX_free(mdctx);
}

void compute_second_signature(
    EVP_PKEY *pkey,
    const BIGNUM *u, const BIGNUM *t,
    const unsigned char *m, size_t m_len,
    const unsigned char *m_prime, size_t m_prime_len,
    BIGNUM **u_prime, BIGNUM **t_prime,
    EC_POINT **R_out,
    BN_CTX *ctx
) {
    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    const EC_POINT *Z = EC_KEY_get0_public_key(ec_key);

    printf("\n=== Computing Second Signature ===\n");
    print_bn("Input u", u);
    print_bn("Input t", t);
    print_point("Public Key Z", group, Z, ctx);

    // Step 1: Compute R = u⁻¹(H(m)*G + t*Z)
    BIGNUM *Hm = BN_CTX_get(ctx);
    BIGNUM *inv_u = BN_CTX_get(ctx);
    EC_POINT *HmG = EC_POINT_new(group);
    EC_POINT *tZ = EC_POINT_new(group);
    EC_POINT *R = EC_POINT_new(group);

    // Compute H(m)
    unsigned char digest[SHA256_DIGEST_LENGTH];
    hash_message(m, m_len, digest);
    print_hash("H(m)", digest, SHA256_DIGEST_LENGTH);
    BN_bin2bn(digest, SHA256_DIGEST_LENGTH, Hm);
    print_bn("H(m) as BN", Hm);

    // Compute u⁻¹ mod n
    BN_mod_inverse(inv_u, u, order, ctx);
    print_bn("u⁻¹", inv_u);

    // Compute H(m)*G
    EC_POINT_mul(group, HmG, Hm, NULL, NULL, ctx);
    print_point("H(m)*G", group, HmG, ctx);

    // Compute t*Z
    EC_POINT_mul(group, tZ, NULL, Z, t, ctx);
    print_point("t*Z", group, tZ, ctx);

    // R = H(m)*G + t*Z
    EC_POINT_add(group, R, HmG, tZ, ctx);
    print_point("H(m)*G + t*Z", group, R, ctx);

    // R = u⁻¹ * (H(m)*G + t*Z)
    EC_POINT_mul(group, R, NULL, R, inv_u, ctx);
    print_point("Recovered R", group, R, ctx);

    // Verify recovered R matches original t
    BIGNUM *x_R = BN_new();
    BIGNUM *y_R = BN_new();
    EC_POINT_get_affine_coordinates(group, R, x_R, y_R, ctx);
    BN_nnmod(x_R, x_R, order, ctx);
    printf("\nVerifying recovered R matches original t...\n");
    print_bn("x(R) mod n", x_R);
    print_bn("Original t", t);
    printf("Match: %s\n", BN_cmp(x_R, t) == 0 ? "YES" : "NO");
    BN_free(x_R);
    BN_free(y_R);

    // Step 3: Sample r' and compute R' = r'*R
    BIGNUM *r_prime = BN_CTX_get(ctx);
    EC_POINT *R_prime = EC_POINT_new(group);
    BN_rand_range(r_prime, order);
    print_bn("\nNew nonce r'", r_prime);
    
    EC_POINT_mul(group, R_prime, NULL, R, r_prime, ctx);
    print_point("R' = r'*R", group, R_prime, ctx);

    // Step 4: Extract t' = x-coord(R') mod n
    BIGNUM *x = BN_CTX_get(ctx);
    BIGNUM *y = BN_CTX_get(ctx);
    EC_POINT_get_affine_coordinates(group, R_prime, x, y, ctx);
    *t_prime = BN_new();
    BN_nnmod(*t_prime, x, order, ctx);
    print_bn("t' (x-coord of R' mod n)", *t_prime);

    // Step 5: Compute u' = r'⁻¹(H(m||m') + t'*u)
    BIGNUM *Hmm = BN_CTX_get(ctx);
    BIGNUM *t_prime_u = BN_CTX_get(ctx);
    BIGNUM *inv_r_prime = BN_CTX_get(ctx);
    *u_prime = BN_new();
    
    unsigned char m_concat[m_len + m_prime_len];
    memcpy(m_concat, m, m_len);
    memcpy(m_concat + m_len, m_prime, m_prime_len);
    hash_message(m_concat, m_len + m_prime_len, digest);
    print_hash("\nH(m||m')", digest, SHA256_DIGEST_LENGTH);
    BN_bin2bn(digest, SHA256_DIGEST_LENGTH, Hmm);
    print_bn("H(m||m') as BN", Hmm);

    BN_mod_mul(t_prime_u, *t_prime, u, order, ctx);
    print_bn("t'*u", t_prime_u);

    BN_mod_add(*u_prime, Hmm, t_prime_u, order, ctx);
    print_bn("H(m||m') + t'*u", *u_prime);

    BN_mod_inverse(inv_r_prime, r_prime, order, ctx);
    print_bn("r'⁻¹", inv_r_prime);

    BN_mod_mul(*u_prime, *u_prime, inv_r_prime, order, ctx);
    print_bn("u' = r'⁻¹*(H(m||m') + t'*u)", *u_prime);

    // Return R (needed for verification)
    *R_out = EC_POINT_dup(R, group);

    printf("\n=== Final Second Signature ===\n");
    print_bn("u'", *u_prime);
    print_bn("t'", *t_prime);
    print_point("R", group, *R_out, ctx);
    printf("=== End of Second Signature Computation ===\n\n");

    // Cleanup temporary points
    EC_POINT_free(HmG);
    EC_POINT_free(tZ);
    EC_POINT_free(R_prime);
}

int verify_second_signature(
    EVP_PKEY *pkey,
    const BIGNUM *u_prime, const BIGNUM *t_prime, const EC_POINT *R,
    const unsigned char *m, size_t m_len,
    const unsigned char *m_prime, size_t m_prime_len,
    BN_CTX *ctx
) {
    printf("\n=== Verifying Second Signature ===\n");
    print_bn("Input u'", u_prime);
    print_bn("Input t'", t_prime);
    print_point("Input R", EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey)), R, ctx);

    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    const EC_POINT *Z = EC_KEY_get0_public_key(ec_key);

    // Step 1: Compute t = x-coord(R) mod n
    BIGNUM *t = BN_CTX_get(ctx);
    BIGNUM *y = BN_CTX_get(ctx);
    EC_POINT_get_affine_coordinates(group, R, t, y, ctx);
    BN_nnmod(t, t, order, ctx);
    print_bn("\nt (x-coord of R mod n)", t);

    // Step 2: Compute R'' = u'⁻¹ * [H(m||m')*R + t'*(H(m)*G + t*Z)]
    BIGNUM *Hm = BN_CTX_get(ctx);
    BIGNUM *Hmm = BN_CTX_get(ctx);
    BIGNUM *inv_u_prime = BN_CTX_get(ctx);
    EC_POINT *HmG = EC_POINT_new(group);
    EC_POINT *tZ = EC_POINT_new(group);
    EC_POINT *term1 = EC_POINT_new(group);
    EC_POINT *term2 = EC_POINT_new(group);
    EC_POINT *sum = EC_POINT_new(group);
    EC_POINT *R_double_prime = EC_POINT_new(group);

    // Compute H(m) and H(m||m')
    unsigned char digest[SHA256_DIGEST_LENGTH];
    hash_message(m, m_len, digest);
    print_hash("\nH(m)", digest, SHA256_DIGEST_LENGTH);
    BN_bin2bn(digest, SHA256_DIGEST_LENGTH, Hm);
    print_bn("H(m) as BN", Hm);

    unsigned char m_concat[m_len + m_prime_len];
    memcpy(m_concat, m, m_len);
    memcpy(m_concat + m_len, m_prime, m_prime_len);
    hash_message(m_concat, m_len + m_prime_len, digest);
    print_hash("H(m||m')", digest, SHA256_DIGEST_LENGTH);
    BN_bin2bn(digest, SHA256_DIGEST_LENGTH, Hmm);
    print_bn("H(m||m') as BN", Hmm);

    // Compute u'⁻¹ mod n
    BN_mod_inverse(inv_u_prime, u_prime, order, ctx);
    print_bn("\nu'⁻¹", inv_u_prime);

    // Compute H(m)*G
    EC_POINT_mul(group, HmG, Hm, NULL, NULL, ctx);
    print_point("H(m)*G", group, HmG, ctx);

    // Compute t*Z
    EC_POINT_mul(group, tZ, NULL, Z, t, ctx);
    print_point("t*Z", group, tZ, ctx);

    // Compute H(m)*G + t*Z
    EC_POINT_add(group, term1, HmG, tZ, ctx);
    print_point("H(m)*G + t*Z", group, term1, ctx);

    // Compute t'*(H(m)*G + t*Z)
    EC_POINT_mul(group, term2, NULL, term1, t_prime, ctx);
    print_point("t'*(H(m)*G + t*Z)", group, term2, ctx);

    // Compute H(m||m')*R
    EC_POINT_mul(group, term1, NULL, R, Hmm, ctx);
    print_point("H(m||m')*R", group, term1, ctx);

    // Compute H(m||m')*R + t'*(H(m)*G + t*Z)
    EC_POINT_add(group, sum, term1, term2, ctx);
    print_point("H(m||m')*R + t'*(H(m)*G + t*Z)", group, sum, ctx);

    // Compute R'' = u'⁻¹ * [H(m||m')*R + t'*(H(m)*G + t*Z)]
    EC_POINT_mul(group, R_double_prime, NULL, sum, inv_u_prime, ctx);
    print_point("\nR'' (final verification point)", group, R_double_prime, ctx);

    // Step 3: Verify x-coord(R'') == t'
    BIGNUM *x = BN_CTX_get(ctx);
    EC_POINT_get_affine_coordinates(group, R_double_prime, x, NULL, ctx);
    BN_nnmod(x, x, order, ctx);
    print_bn("x-coord of R''", x);
    print_bn("t' (expected)", t_prime);

    int result = BN_cmp(x, t_prime) == 0;

    printf("\nVerification %s\n", result ? "SUCCEEDED" : "FAILED");
    printf("=== End of Verification ===\n\n");

    // Cleanup
    EC_POINT_free(HmG);
    EC_POINT_free(tZ);
    EC_POINT_free(term1);
    EC_POINT_free(term2);
    EC_POINT_free(sum);
    EC_POINT_free(R_double_prime);

    return result;
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Time measurement variables
    clock_t start, end;
    double cpu_time_used;
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    // Generate key pair
    start = clock();
    EVP_PKEY *pkey = generate_ec_key();
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
    printf("Key generation time: %.2f ms\n", cpu_time_used);

    // Messages
    const char *m = "Hello, ECDSA!";
    const char *m_prime = "Second message!";
    size_t m_len = strlen(m);
    size_t m_prime_len = strlen(m_prime);

    // Simulate first signature (u, t)
    start = clock();
    BIGNUM *u = BN_new();
    BIGNUM *t = BN_new();
    const EC_GROUP *group = EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey));
    const BIGNUM *order = EC_GROUP_get0_order(group);
    
    // Generate random k for first signature
    BIGNUM *k = BN_new();
    BN_rand_range(k, order);
    
    // Compute R = k*G
    EC_POINT *R = EC_POINT_new(group);
    EC_POINT_mul(group, R, k, NULL, NULL, ctx);
    
    // Get x-coordinate of R for t
    BIGNUM *x_R = BN_new();
    BIGNUM *y_R = BN_new();
    EC_POINT_get_affine_coordinates(group, R, x_R, y_R, ctx);
    BN_nnmod(t, x_R, order, ctx);
    
    // Compute u = k⁻¹(H(m) + t*z) mod n
    const BIGNUM *z = EC_KEY_get0_private_key(EVP_PKEY_get0_EC_KEY(pkey));
    BIGNUM *Hm = BN_new();
    unsigned char digest[SHA256_DIGEST_LENGTH];
    hash_message(m, m_len, digest);
    BN_bin2bn(digest, SHA256_DIGEST_LENGTH, Hm);
    
    BIGNUM *tmp = BN_new();
    BN_mod_mul(tmp, t, z, order, ctx);
    BN_mod_add(tmp, Hm, tmp, order, ctx);
    
    BIGNUM *k_inv = BN_new();
    BN_mod_inverse(k_inv, k, order, ctx);
    BN_mod_mul(u, k_inv, tmp, order, ctx);
    end = clock();
    double elapsed = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
    printf("Time for first signature (ms): %0.2f\n", elapsed);
    printf("\nFirst Signature (u, t):\n");
    print_bn("u", u);
    print_bn("t", t);
    print_point("R", group, R, ctx);
    
    // Verify x(R) mod n == t
    printf("\nVerifying x(R) mod n == t...\n");
    print_bn("x(R) mod n", t);
    print_bn("t", t);
    printf("Match: %s\n", BN_cmp(t, t) == 0 ? "YES" : "NO");

    // Compute second signature (u', t', R)
    BIGNUM *u_prime = NULL;
    BIGNUM *t_prime = NULL;
    EC_POINT *R_for_second_sig = EC_POINT_dup(R, group);
    start = clock();
    compute_second_signature(pkey, u, t, (unsigned char *)m, m_len, 
                           (unsigned char *)m_prime, m_prime_len, 
                           &u_prime, &t_prime, &R_for_second_sig, ctx);
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
    printf("Second signature computation time: %.2f ms\n", cpu_time_used);

    // Verify second signature
    start = clock();
    int is_valid = verify_second_signature(pkey, u_prime, t_prime, R_for_second_sig, 
                                         (unsigned char *)m, m_len, 
                                         (unsigned char *)m_prime, m_prime_len, ctx);
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
    printf("Verification time: %.2f ms\n", cpu_time_used);
  

    printf("\nSignature is %s\n", is_valid == 1? "VALID" : "INVALID");

    // Cleanup
    BN_free(u);
    BN_free(t);
    BN_free(u_prime);
    BN_free(t_prime);
    BN_free(k);
    BN_free(x_R);
    BN_free(y_R);
    BN_free(Hm);
    BN_free(tmp);
    BN_free(k_inv);
    EC_POINT_free(R);
    EC_POINT_free(R_for_second_sig);
    EVP_PKEY_free(pkey);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
