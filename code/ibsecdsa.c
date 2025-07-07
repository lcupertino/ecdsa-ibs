#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

EC_KEY* generate_ecdsa_key() {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) {
        fprintf(stderr, "Failed to create EC key\n");
        return NULL;
    }

    if (!EC_KEY_generate_key(key)) {
        fprintf(stderr, "Failed to generate EC key pair\n");
        EC_KEY_free(key);
        return NULL;
    }

    return key;
}

int ecdsa_sign_extract_rs(const EC_KEY *key, const unsigned char *msg, size_t msg_len, BIGNUM **r, BIGNUM **s) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha_ctx;

    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, msg, msg_len);
    SHA256_Final(hash, &sha_ctx);

    ECDSA_SIG *sig = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, key);
    if (!sig) {
        fprintf(stderr, "Failed to generate ECDSA signature\n");
        return 0;
    }

    const BIGNUM *sig_r, *sig_s;
    ECDSA_SIG_get0(sig, &sig_r, &sig_s);
    if (!sig_r || !sig_s) {
        fprintf(stderr, "Failed to extract r and s from ECDSA signature\n");
        ECDSA_SIG_free(sig);
        return 0;
    }

    *r = BN_dup(sig_r);
    *s = BN_dup(sig_s);
    if (!*r || !*s) {
        fprintf(stderr, "Failed to allocate memory for r and s\n");
        ECDSA_SIG_free(sig);
        return 0;
    }

    ECDSA_SIG_free(sig);
    return 1;
}

int ecdsa_sign_second_message(const EC_KEY *key, const BIGNUM *s_priv_key, const unsigned char *msg1, size_t msg1_len, const unsigned char *msg2, size_t msg2_len, BIGNUM **t, BIGNUM **s_new, const BIGNUM *r1) {
    int ret = 0;
    unsigned char *combined_msg = NULL;
    size_t combined_msg_len = msg1_len + msg2_len;

    combined_msg = malloc(combined_msg_len);
    if (!combined_msg) goto err;
    memcpy(combined_msg, msg1, msg1_len);
    memcpy(combined_msg + msg1_len, msg2, msg2_len);

    if (!ecdsa_sign_extract_rs(key, combined_msg, combined_msg_len, t, s_new)) goto err;

    ret = 1;

err:
    if (combined_msg) free(combined_msg);
    return ret;
}

void print_bignum(const char *label, const BIGNUM *bn) {
    printf("%s: ", label);
    BN_print_fp(stdout, bn);
    printf("\n");
}

int main() {
	 clock_t ts;
	 double elapsed;

    OpenSSL_add_all_algorithms();

	ts = clock();
    EC_KEY *key = generate_ecdsa_key();
    if (!key) {
        fprintf(stderr, "Failed to generate ECDSA key pair\n");
        return 1;
    }
	
    ts = clock() - ts;
	elapsed = ((double) ts)/CLOCKS_PER_SEC;
    printf("%f", elapsed);
    
    const char *msg1 = "Original message";
    size_t msg1_len = strlen(msg1);

    ts = clock();

    BIGNUM *r1 = NULL, *s1 = NULL;
    if (!ecdsa_sign_extract_rs(key, (const unsigned char *)msg1, msg1_len, &r1, &s1)) {
        fprintf(stderr, "Failed to sign first message\n");
        EC_KEY_free(key);
        return 1;
    }

	ts = clock() - ts;
	elapsed = ((double) ts)/CLOCKS_PER_SEC;
	printf(",%f", elapsed);

    const char *msg2 = "New message";
    size_t msg2_len = strlen(msg2);

    ts = clock();
    BIGNUM *t = NULL, *s_new = NULL;
    if (!ecdsa_sign_second_message(key, s1, (const unsigned char *)msg1, msg1_len, (const unsigned char *)msg2, msg2_len, &t, &s_new, r1)) {
        fprintf(stderr, "Failed to sign second message\n");
        BN_free(r1);
        BN_free(s1);
        EC_KEY_free(key);
        return 1;
    }
	ts = clock() - ts;
	elapsed = ((double) ts)/CLOCKS_PER_SEC;
	printf(",%f\n", elapsed);

    BN_free(r1);
    BN_free(s1);
    BN_free(t);
    BN_free(s_new);
    EC_KEY_free(key);
    EVP_cleanup();

    return 0;
}
