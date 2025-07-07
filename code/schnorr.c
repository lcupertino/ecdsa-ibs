#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int schnorr_sign(const EC_GROUP *group, const BIGNUM *priv_key, const unsigned char *msg, size_t msg_len, BIGNUM **r, BIGNUM **s) {
    int ret = 0;
    BIGNUM *k = NULL;
    EC_POINT *R = NULL;
    unsigned char *hash = NULL;
    unsigned char *data = NULL;
    size_t data_len;
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BN_CTX *ctx = BN_CTX_new();

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

    ret = 1;

err:
    if (R) EC_POINT_free(R);
    if (k) BN_free(k);
    if (data) free(data);
    if (hash) free(hash);
    BN_CTX_free(ctx);
    return ret;
}

int schnorr_verify(const EC_GROUP *group, const EC_POINT *pub_key, const unsigned char *msg, size_t msg_len, const BIGNUM *r, const BIGNUM *s) {
    int ret = 0;
    EC_POINT *R = NULL;
    unsigned char *hash = NULL;
    unsigned char *data = NULL;
    size_t data_len;
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BN_CTX *ctx = BN_CTX_new();

    if (!ctx) goto err;

    R = EC_POINT_new(group);
    if (!R) goto err;

    EC_POINT *temp = EC_POINT_new(group);
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

    BIGNUM *computed_r = BN_new();
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

    EC_POINT *pub_key = EC_POINT_new(group);
    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, NULL)) {
        fprintf(stderr, "Failed to derive public key\n");
        return 1;
    }
    
    ts = clock() - ts;
    elapsed = ((double) ts)/CLOCKS_PER_SEC;
	printf("%f", elapsed);

    ts = clock();
    const char *msg = "Hello, Schnorr!";
    size_t msg_len = strlen(msg);

    BIGNUM *r = NULL, *s = NULL;
    if (!schnorr_sign(group, priv_key, (const unsigned char *)msg, msg_len, &r, &s)) {
        fprintf(stderr, "Failed to sign message\n");
        return 1;
    }
	
    ts = clock() - ts;
	elapsed = ((double) ts)/CLOCKS_PER_SEC;
	printf(",%f", elapsed);
    ts = clock();
    
    if (schnorr_verify(group, pub_key, (const unsigned char *)msg, msg_len, r, s)) {
        //printf("Signature is valid!\n");
    } else {
        //printf("Signature is invalid!\n");
    }
    ts = clock() - ts;
	elapsed = ((double) ts)/CLOCKS_PER_SEC;
	printf(",%f\n", elapsed);
    
    EC_GROUP_free(group);
    BN_free(priv_key);
    EC_POINT_free(pub_key);
    BN_free(r);
    BN_free(s);
    EVP_cleanup();

    return 0;
}
