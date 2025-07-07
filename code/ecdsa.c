#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

EVP_PKEY* generate_ecdsa_key() {
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) {
        handle_errors();
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp256k1) <= 0) {
        handle_errors();
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        handle_errors();
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

int sign_message(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len, unsigned char** sig, size_t* sig_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        handle_errors();
    }

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        handle_errors();
    }

    if (EVP_DigestSign(ctx, NULL, sig_len, msg, msg_len) <= 0) {
        handle_errors();
    }

    *sig = (unsigned char*)malloc(*sig_len);
    if (!*sig) {
        handle_errors();
    }

    if (EVP_DigestSign(ctx, *sig, sig_len, msg, msg_len) <= 0) {
        handle_errors();
    }

    EVP_MD_CTX_free(ctx);
    return 1;
}

int verify_signature(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len, const unsigned char* sig, size_t sig_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        handle_errors();
    }

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        handle_errors();
    }

    int result = EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len);
    EVP_MD_CTX_free(ctx);

    if (result == 1) {
        return 1;
    } else if (result == 0) {
        return 0;
    } else {
        handle_errors();
    }
}

int main() {
	 clock_t ts;
	 double elapsed;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    ts = clock();
    EVP_PKEY* pkey = generate_ecdsa_key();
    ts = clock() - ts;
	elapsed = ((double) ts)/CLOCKS_PER_SEC;
	printf("%f", elapsed);

    ts = clock();
    const char* message = "Hello, ECDSA!";
    size_t message_len = strlen(message);

    unsigned char* signature = NULL;
    size_t signature_len;
    if (sign_message(pkey, (unsigned char*)message, message_len, &signature, &signature_len)) {
        //printf("Message signed successfully.\n");
    }
	 ts = clock() - ts;
	 elapsed = ((double) ts)/CLOCKS_PER_SEC;
	 printf(",%f", elapsed);

    ts = clock();
    if (verify_signature(pkey, (unsigned char*)message, message_len, signature, signature_len)) {
        // printf("Signature is valid.\n");
    } else {
        // printf("Signature is invalid.\n");
    }
	 ts = clock() - ts;
	 elapsed = ((double) ts)/CLOCKS_PER_SEC;
	 printf(",%f\n", elapsed);

    free(signature);
    EVP_PKEY_free(pkey);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
