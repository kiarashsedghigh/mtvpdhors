#include "hors.h"
#include "bits.h"
#include "debug.h"
#include <stdlib.h>
#include <sys/time.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc<5){
        debug("Usage:  ./hors T K L LPK SEED_FILE_PATH", DEBUG_ERR);
        return 1;
    }

    /* Hyper parameters and keys */
    hors_hp_t hp;
    hors_keys_t keys;

    FILE *fp = fopen(argv[5], "r");
    fseek(fp, 0L, SEEK_END);
    int seed_len = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    hp.seed = malloc(seed_len);
    hp.seed_len = seed_len;
    hp.state = 0;
    fread(hp.seed, seed_len, 1, fp);


    hp.t = atoi(argv[1]);
    hp.k = atoi(argv[2]);
    hp.l = atoi(argv[3]);
    hp.lpk = atoi(argv[4]);


    /* Signer */
    debug("New signer is created", DEBUG_INF);


    hors_signer_t signer;
    hors_new_signer(&signer, &hp, &keys);
    hors_signature_t signature;
    signature.signature = malloc(signer.hp->k * BITS_2_BYTES(signer.hp->lpk));

    /* Reading the message */


    /* Verifier */
    debug("New verifier is created", DEBUG_INF);
    double signer_time = 0;
    double verifier_time = 0;


#define ITER 10000000
    for(int i=0; i<ITER;i++) {
        u8 * message = "kiarash";
        constexpr u32 message_len = 7;

        printf("\rSigning Message: %d", hp.state);
        fflush(stdout);

        hors_sign(&signature, &signer, message, message_len);

        if (hors_verify(&hp, &signature, message, message_len) != HORS_SIGNATURE_ACCEPTED) {
            debug("\nVerification: Signature is (not) valid", DEBUG_INF);
            break;
        }

#ifdef TIMEKEEPING
        signer_time+=HORS_SIGN_TIME;
        verifier_time+=HORS_VERIFY_TIME;
#endif
    }

#ifdef TIMEKEEPING
    printf("\nSign time: %0.12f\n", signer_time/ITER * 1000000);
    printf("Verify time: %0.12f\n", verifier_time/ITER * 1000000);
#endif

    hors_destroy_hp(&hp);
}


