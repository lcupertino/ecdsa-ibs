#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int schnorr_sign(const EC_GROUP *group, const BIGNUM *priv_key, const EC_POINT *pub_key, const unsigned char *msg, size_t msg_len, BIGNUM **r, BIGNUM **s, EC_POINT **R) {
    int ret = 0;
    BIGNUM *k = NULL;
    unsigned char *hash = NULL;
    unsigned char *data = NULL;
    unsigned char *pub_key_data = NULL;
    size_t data_len, pub_key_len;
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BN_CTX *ctx = BN_CTX_new();

    if (!ctx) goto err;

    *R = EC_POINT_new(group);
    k = BN_new();
    if (!*R || !k) goto err;

    if (!BN_rand_range(k, order)) goto err;

    if (!EC_POINT_mul(group, *R, k, NULL, NULL, ctx)) goto err;

    data_len = EC_POINT_point2oct(group, *R, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    data = malloc(data_len);
    if (!data) goto err;
    EC_POINT_point2oct(group, *R, POINT_CONVERSION_COMPRESSED, data, data_len, ctx);

    pub_key_len = EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
    pub_key_data = malloc(pub_key_len);
    if (!pub_key_data) goto err;
    EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_COMPRESSED, pub_key_data, pub_key_len, ctx);

    hash = malloc(SHA256_DIGEST_LENGTH);
    if (!hash) goto err;
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, data, data_len);
    SHA256_Update(&sha_ctx, pub_key_data, pub_key_len);
    SHA256_Update(&sha_ctx, msg, msg_len);
    SHA256_Final(hash, &sha_ctx);

    *r = BN_new();
    if (!*r) goto err;
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, *r);

    *s = BN_new();
    if (!*s) goto err;
    if (!BN_mod_mul(*s, *r, priv_key, order, ctx)) goto err;
    if (!BN_mod_add(*s, k, *s, order, ctx)) goto err;

    ret = 1;

err:
    if (k) BN_free(k);
    if (data) free(data);
    if (pub_key_data) free(pub_key_data);
    if (hash) free(hash);
    BN_CTX_free(ctx);
    return ret;
}

int schnorr_sign_second_message(const EC_GROUP *group, const BIGNUM *s_priv_key, const EC_POINT *pub_key, const unsigned char *msg1, size_t msg1_len, const unsigned char *msg2, size_t msg2_len, BIGNUM **r, BIGNUM **s, EC_POINT **R) {
    int ret = 0;
    unsigned char *combined_msg = NULL;
    size_t combined_msg_len = msg1_len + msg2_len;

    combined_msg = malloc(combined_msg_len);
    if (!combined_msg) goto err;
    memcpy(combined_msg, msg1, msg1_len);
    memcpy(combined_msg + msg1_len, msg2, msg2_len);

    if (!schnorr_sign(group, s_priv_key, pub_key, combined_msg, combined_msg_len, r, s, R)) goto err;

    ret = 1;

err:
    if (combined_msg) free(combined_msg);
    return ret;
}

void print_ec_point(const EC_GROUP *group, const EC_POINT *point) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    if (!ctx || !x || !y) {
        fprintf(stderr, "Failed to allocate memory for printing EC_POINT\n");
        return;
    }

    if (!EC_POINT_get_affine_coordinates(group, point, x, y, ctx)) {
        fprintf(stderr, "Failed to get affine coordinates\n");
        return;
    }

    printf("EC_POINT (x, y):\n");
    printf("x: ");
    BN_print_fp(stdout, x);
    printf("\n");
    printf("y: ");
    BN_print_fp(stdout, y);
    printf("\n");

    BN_free(x);
    BN_free(y);
    BN_CTX_free(ctx);
}

int main() {
	clock_t ts;
	double elapsed;

    OpenSSL_add_all_algorithms();

    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) {
        fprintf(stderr, "Failed to create EC group\n");
        return 1;
    }

    ts = clock();
    BIGNUM *priv_key = BN_new();
    if (!BN_rand_range(priv_key, EC_GROUP_get0_order(group))) {
        fprintf(stderr, "Failed to generate private key\n");
        return 1;
    }
    ts = clock() - ts;
	elapsed = ((double) ts)/CLOCKS_PER_SEC;
	printf("%f,", elapsed);
		
    ts = clock();
    EC_POINT *pub_key = EC_POINT_new(group);
    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, NULL)) {
        fprintf(stderr, "Failed to derive public key\n");
        return 1;
    }
	
    const char *msg1 = "Original message";
    size_t msg1_len = strlen(msg1);

    BIGNUM *r1 = NULL, *s1 = NULL;
    EC_POINT *R1 = NULL;
    if (!schnorr_sign(group, priv_key, pub_key, (const unsigned char *)msg1, msg1_len, &r1, &s1, &R1)) {
        fprintf(stderr, "Failed to sign first message\n");
        return 1;
    }
	ts = clock() - ts;
	elapsed = ((double) ts)/CLOCKS_PER_SEC;
	printf(" %f,", elapsed);

    ts = clock();
    const char *msg2 = "New message";
    size_t msg2_len = strlen(msg2);

    BIGNUM *r2 = NULL, *s2 = NULL;
    EC_POINT *R2 = NULL;
    if (!schnorr_sign_second_message(group, s1, pub_key, (const unsigned char *)msg1, msg1_len, (const unsigned char *)msg2, msg2_len, &r2, &s2, &R2)) {
        fprintf(stderr, "Failed to sign second message\n");
        return 1;
    }
	ts = clock() - ts;
	elapsed = ((double) ts)/CLOCKS_PER_SEC;
	printf(" %f\n", elapsed);

    EC_GROUP_free(group);
    BN_free(priv_key);
    EC_POINT_free(pub_key);
    BN_free(r1);
    BN_free(s1);
    EC_POINT_free(R1);
    BN_free(r2);
    BN_free(s2);
    EC_POINT_free(R2);
    EVP_cleanup();

    return 0;
}
