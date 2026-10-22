#include "utils.h"
#include "common.h"
#include "ibsschnorr.h"

const int curves[] = {
    NID_brainpoolP224r1, NID_brainpoolP256r1, NID_brainpoolP320r1,
    NID_brainpoolP384r1, NID_brainpoolP512r1, NID_secp224r1,
    NID_secp256k1,       NID_secp384r1,       NID_secp521r1};

const char *algorithms[] = {
    "brainpoolP224r1", "brainpoolP256r1", "brainpoolP320r1",
    "brainpoolP384r1", "brainpoolP512r1", "secp224r1",
    "secp256k1",       "secp384r1",       "secp521r1"};

int main() {
  for (int j = 0; j < NUMCURVES; j++) {
    /*
     * Creating file
     *
     */
    const char *extra_buffer = "extra";
    size_t SIZE = strlen(algorithms[j]) + strlen(BASE_NAME_IBS_SCHNORR) + strlen(extra_buffer);
    char *buffer = malloc(sizeof(*buffer) * SIZE);
    char *filename;
    filename = buffer;
    filename = strcpy(filename, algorithms[j]);
    filename = strcat(filename, BASE_NAME_IBS_SCHNORR);
    printf("Filename %s\n", filename);

#if !DEBUG
    FILE *file;
    file = fopen(filename, "w");
    if (!file) return 0;

    for (int i = 0; i < NUMROUNDS; i++) {
      int ret = simulate_ibs_schnorr_modified(curves[j], file);
    }
    fclose(file);
#endif
  }

  return 0;
}
