#include "bftvmhors.h"
#include "bits.h"
#include "debug.h"
#include <stdlib.h>
#include <sys/time.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 5) {
        debug("Usage:  ./hors T K L LPK P M SEED_FILE_PATH", DEBUG_ERR);
        return 1;
    }

    /* Hyper parameters and keys */
    bftvmhors_hp_t hp;
    bftvmhors_keys_t keys;

    FILE *fp = fopen(argv[7], "r");
    fseek(fp, 0L, SEEK_END);
    int seed_len = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    keys.seed = malloc(seed_len);
    keys.seed_len = seed_len;
    hp.state = 0;
    fread(keys.seed, seed_len, 1, fp);


    hp.t = atoi(argv[1]);
    hp.k = atoi(argv[2]);
    hp.l = atoi(argv[3]);
    hp.lpk = atoi(argv[4]);


    hp.ohbf_hp.num_of_mod_operations = atoi(argv[5]);
    hp.ohbf_hp.required_size = atoi(argv[6]);


    /* Signer */
    debug("New signer is created", DEBUG_INF);


    bftvmhors_signer_t signer;
    bftvmhors_new_signer(&signer, &hp, &keys);
    bftvmhors_signature_t signature;
    signature.signature = malloc(signer.hp->k * BITS_2_BYTES(signer.hp->lpk));


    /* Verifier */
    debug("New verifier is created", DEBUG_INF);
    double signer_time = 0;
    double verifier_time = 0;


#define ITER 100000
    for (int i = 0; i < ITER; i++) {
        u8 *message = "kiarash";
        constexpr u32 message_len = 7;

        printf("\rSigning Message: %d", hp.state);
        fflush(stdout);

        bftvmhors_sign(&signature, &signer, message, message_len);


        if (bftvmhors_verify(&keys, &hp, &signature, message, message_len) != BFTVMHORS_SIGNATURE_ACCEPTED) {
            debug("\nVerification: Signature is (not) valid", DEBUG_INF);
            break;
        }

        hp.state++;


#ifdef TIMEKEEPING
        signer_time += BFTVMHORS_SIGN_TIME;
        verifier_time += BFTVMHORS_VERIFY_TIME;
#endif
    }

#ifdef TIMEKEEPING
    printf("\nKeygen time: %0.12f\n", BFTVMHORS_KEYGEN_TIME / ITER * 1000000);
    printf("\nSign time: %0.12f\n", signer_time / ITER * 1000000);
    printf("Verify time: %0.12f\n", verifier_time / ITER * 1000000);
#endif
}
