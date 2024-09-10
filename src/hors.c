#include "hash.h"
#include "bits.h"
#include "hors.h"
#include <sys/time.h>
#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_FILE_MAX_LENGTH 300

/* Time information variables/functions for HORS */
#ifdef TIMEKEEPING
struct timeval start_time, end_time;

static double hors_keygen_time = 0;
static double hors_sign_time = 0;
static double hors_verify_time = 0;

double hors_get_keygen_time() { return hors_keygen_time; }
double hors_get_sign_time() { return hors_sign_time; }
double hors_get_verify_time() { return hors_verify_time; }
#endif

/// Struct for the parameters needed to be passed to the running thread of the keygen
typedef struct hors_keygen_thread_argument {
    hors_keys_t *keys; // Keys
    hors_hp_t *hp; // Hyper parameters
    u32 private_key_start; // Index of the first private key
    u32 private_key_end; // Index of the last private key
} hors_keygen_thread_argument_t;


u32 hors_pk_keygen(hors_keys_t *keys, hors_hp_t *hp) {
    /* Generate the PK */
    keys->pk = malloc(BITS_2_BYTES(hp->lpk) * hp->t);

    unsigned char *new_seed = malloc(hp->seed_len + 4 + 4);

#ifdef TIMEKEEPING
    gettimeofday(&start_time, NULL);
#endif

    /* Compute OWF of privates as public key */
    for (u32 i = 0; i < hp->t; i++) {
        u8 sk[HASH_MAX_LENGTH_THRESHOLD];

        memcpy(new_seed, hp->seed, hp->seed_len);
        memcpy(new_seed + hp->seed_len, &hp->state, 4);
        memcpy(new_seed + hp->seed_len + 4, &i, 4);
        blake2b_256(sk, new_seed, hp->seed_len + 4 + 4);
        blake2b_256(sk, sk, 32);

        memcpy(keys->pk + i * BITS_2_BYTES(hp->lpk), sk, BITS_2_BYTES(hp->lpk));
    }

#ifdef TIMEKEEPING
    gettimeofday(&end_time, NULL);
    hors_keygen_time = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1.0e6;
#endif

    free(new_seed);
    return HORS_KEYGEN_SUCCESS;
}

void hors_destroy_keys(hors_keys_t *keys) {
    free(keys->pk);
}


// static int check_if_indices_are_distinct(const unsigned char *value, int k, int chunk, int *message_indices,
//                                          int **sorted_indices) {
//     int *new_indices = malloc(sizeof(int) * k);
//     *sorted_indices = new_indices;
//
//     for (int i = 0; i < k; i++) {
//         new_indices[i] = read_bits_as_4bytes(value, i + 1, chunk);
//         message_indices[i] = new_indices[i];
//     }
//
//     array_sort_desc(new_indices, k);
//
//     for (int i = 1; i < k; i++) {
//         if (new_indices[i] == new_indices[i - 1]) {
//             return 0;
//         }
//     }
//     return 1;
// }
//
// static int perform_rejection_sampling(const unsigned char *message, int message_len, int k, int t,
//                                       int *message_indices, int **sorted_indices) {
//     unsigned char pads[3][32] = {
//         {
//             0x6b, 0x8f, 0x34, 0x1a, 0xdf, 0x21, 0x5e, 0xa3, 0x79, 0x2d, 0xe7, 0xc1, 0x5b, 0x6a, 0x1b, 0x3f, 0x5c, 0xe0,
//             0x1d, 0x8b, 0x3d, 0xf2, 0x7e, 0x4a, 0xe8, 0xb1, 0x5d, 0x9c, 0x6f, 0x43, 0x84, 0x2e
//         },
//         {
//             0xab, 0xf9, 0x27, 0xcd, 0x12, 0xe3, 0x89, 0x45, 0xd8, 0x66, 0x97, 0xa4, 0xbc, 0x8d, 0x5e, 0xf1, 0x4c, 0x32,
//             0x7a, 0x90, 0x8f, 0xb3, 0xd9, 0xe6, 0x1e, 0xac, 0x74, 0x91, 0x5b, 0xdf, 0x2c, 0xe5
//         },
//         {
//             0x59, 0x9f, 0x4b, 0x8a, 0x36, 0xf4, 0xa7, 0x28, 0x91, 0x6e, 0x2b, 0x5d, 0xc9, 0x72, 0xf2, 0x13, 0x46, 0x8e,
//             0x93, 0xb4, 0xd7, 0x6a, 0xe1, 0x5f, 0x0b, 0xc4, 0x89, 0x71, 0x3d, 0x2a, 0x94, 0xfc
//         },
//     };
//
//     /* Hash one time */
//     unsigned char hash_ctr_buffer[SHA256_OUTPUT_LEN + 4];
//     blake2b_256(hash_ctr_buffer, message, message_len);
//
//     if (check_if_indices_are_distinct(hash_ctr_buffer, k, (int) log2(t), message_indices, sorted_indices))
//         return 0;
//
//
//     /* XOR with pads 1-3 and try again */
//     for (int j = 0; j < 3; j++) {
//         for (int i = 0; i < 32; i++)
//             hash_ctr_buffer[i] ^= pads[j][i];
//         if (check_if_indices_are_distinct(hash_ctr_buffer, k, (int) log2(t), message_indices, sorted_indices))
//             return 0;
//     }
//
//     /* Use Ctr to resolve */
//     unsigned int ctr = 1;
//     while (1) {
//         unsigned char hash_result[SHA256_OUTPUT_LEN];
//         mempcpy(hash_ctr_buffer + SHA256_OUTPUT_LEN, &ctr, sizeof(ctr));
//         blake2b_256(hash_result, hash_ctr_buffer, SHA256_OUTPUT_LEN + sizeof(ctr));
//
//         if (check_if_indices_are_distinct(hash_result, k, (int) log2(t), message_indices, sorted_indices))
//             return ctr;
//         ctr++;
//
//         /* Overflow the unsigned counter variable*/
//         if (ctr == 0)
//             assert(ctr != 0);
//     }
//
//     return ctr;
// }
//
// static int check_rejection_sampling(const unsigned char *message, int message_len, int k, int t, int *indices,
//                                     unsigned int ctr, int **sorted_indices) {
//     unsigned char pads[3][32] = {
//         {
//             0x6b, 0x8f, 0x34, 0x1a, 0xdf, 0x21, 0x5e, 0xa3, 0x79, 0x2d, 0xe7, 0xc1, 0x5b, 0x6a, 0x1b, 0x3f, 0x5c, 0xe0,
//             0x1d, 0x8b, 0x3d, 0xf2, 0x7e, 0x4a, 0xe8, 0xb1, 0x5d, 0x9c, 0x6f, 0x43, 0x84, 0x2e
//         },
//         {
//             0xab, 0xf9, 0x27, 0xcd, 0x12, 0xe3, 0x89, 0x45, 0xd8, 0x66, 0x97, 0xa4, 0xbc, 0x8d, 0x5e, 0xf1, 0x4c, 0x32,
//             0x7a, 0x90, 0x8f, 0xb3, 0xd9, 0xe6, 0x1e, 0xac, 0x74, 0x91, 0x5b, 0xdf, 0x2c, 0xe5
//         },
//         {
//             0x59, 0x9f, 0x4b, 0x8a, 0x36, 0xf4, 0xa7, 0x28, 0x91, 0x6e, 0x2b, 0x5d, 0xc9, 0x72, 0xf2, 0x13, 0x46, 0x8e,
//             0x93, 0xb4, 0xd7, 0x6a, 0xe1, 0x5f, 0x0b, 0xc4, 0x89, 0x71, 0x3d, 0x2a, 0x94, 0xfc
//         },
//     };
//
//     /* Hash one time */
//     unsigned char hash_ctr_buffer[SHA256_OUTPUT_LEN + 4];
//     blake2b_256(hash_ctr_buffer, message, message_len);
//
//     if (check_if_indices_are_distinct(hash_ctr_buffer, k, (int) log2(t), indices, sorted_indices))
//         return 1;
//
//
//     /* XOR with pads 1-3 and try again */
//     for (int j = 0; j < 3; j++) {
//         for (int i = 0; i < 32; i++)
//             hash_ctr_buffer[i] ^= pads[j][i];
//         if (check_if_indices_are_distinct(hash_ctr_buffer, k, (int) log2(t), indices, sorted_indices))
//             return 1;
//     }
//
//     /* Use Ctr to resolve */
//     unsigned char target_hash[SHA256_OUTPUT_LEN];
//     mempcpy(hash_ctr_buffer + SHA256_OUTPUT_LEN, &ctr, sizeof(ctr));
//     blake2b_256(target_hash, hash_ctr_buffer, SHA256_OUTPUT_LEN + sizeof(ctr));
//
//     if (check_if_indices_are_distinct(target_hash, k, (int) log2(t), indices, sorted_indices))
//         return 1;
//
//     return 0;
// }
//


/// Passing the HORS hyper parameters and the keys it creates a HORS signer
/// \param hp HORS hyper parameter
/// \param keys HORS keys
/// \return HORS signer
u32 hors_new_signer(hors_signer_t *signer, hors_hp_t *hp, hors_keys_t *keys) {
    /* State has not been set as this is a one-time HORS */
    signer->keys = keys;
    signer->hp = hp;
    return HORS_NEW_SIGNER_SUCCESS;
}


u32 hors_sign(const hors_signature_t *signature, hors_signer_t *signer, u8 *message, u64 message_len) {
    u8 message_hash[HASH_MAX_LENGTH_THRESHOLD];

#ifdef TIMEKEEPING
    gettimeofday(&start_time, NULL);
#endif
    // /* Perform rejection sampling */
    // if (signer->hp->do_rejection_sampling) {
    //     if (rejection_sampling(signer->hp->k, signer->hp->t,
    //                            &signature->rejection_sampling_counter, message_hash,
    //                            message,
    //                            message_len) == HORS_REJECTION_SAMPLING_FAILED)
    //         return HORS_SIGNING_FAILED;
    // } else

    /* Hashing the message without rejection sampling */
    openssl_hash_sha2_256(message_hash, message, message_len);

    /* HORS log(t), defining size of the bit slices */
    u32 bit_slice_len = log2(signer->hp->t);

    unsigned char *new_seed = malloc(signer->hp->l + 4 + 4);


    /* Extract the portions from the private key and write to the signature */
    for (u32 i = 0; i < signer->hp->k; i++) {
        u32 portion_value = read_bits_as_4bytes(message_hash, i + 1, bit_slice_len);

        u8 sk[HASH_MAX_LENGTH_THRESHOLD];

        memcpy(new_seed, signer->hp->seed, signer->hp->seed_len);
        memcpy(new_seed + signer->hp->seed_len, &signer->hp->state, 4);
        memcpy(new_seed + signer->hp->seed_len + 4, &portion_value, 4);
        blake2b_256(sk, new_seed, signer->hp->seed_len + 4 + 4);
        memcpy(&signature->signature[i * BITS_2_BYTES(signer->hp->l)], sk, BITS_2_BYTES(signer->hp->l));
    }

#ifdef TIMEKEEPING
    gettimeofday(&end_time, NULL);
    hors_sign_time = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1.0e6;
#endif

    free(new_seed);
    return HORS_SIGNING_SUCCESS;
}


u32 hors_verify(hors_hp_t *hp, hors_signature_t *signature, u8 *message, u64 message_len) {
    u8 message_hash[HASH_MAX_LENGTH_THRESHOLD];

    hors_keys_t keys;
    hors_pk_keygen(&keys, hp);

#ifdef TIMEKEEPING
    gettimeofday(&start_time, NULL);
#endif
    // /* Perform rejection sampling */
    // if (hp->do_rejection_sampling) {
    //     if (rejection_sampling_status(hp->k, hp->t,
    //                                   signature->rejection_sampling_counter, message_hash,
    //                                   message, message_len) == HORS_REJECTION_SAMPLING_NOT_DONE)
    //         return HORS_SIGNATURE_REJECTED;
    // } else

    /* Hashing the message without rejection sampling */
    openssl_hash_sha2_256(message_hash, message, message_len);

    /* HORS log(t), defining size of the bit slices */
    u32 bit_slice_len = log2(hp->t);

    for (u32 i = 0; i < hp->k; i++) {
        u32 portion_value = read_bits_as_4bytes(message_hash, i + 1, bit_slice_len);

        /* Current signature element (sk) */
        u8 *current_signature_portion = &signature->signature[i * BITS_2_BYTES(hp->l)];

        /* Hash the current signature element (sk) for further comparison */
        u8 sk_hash[HASH_MAX_LENGTH_THRESHOLD];

        blake2b_256(sk_hash, current_signature_portion, BITS_2_BYTES(hp->l));

        /* Compare the hashed current signature element (sk) with public key indexed
         * by portion_value */
        if (memcmp(sk_hash, &keys.pk[portion_value * BITS_2_BYTES(hp->lpk)], BITS_2_BYTES(hp->lpk)) != 0) {
#ifdef TIMEKEEPING
            gettimeofday(&end_time, NULL);
            hors_verify_time = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1.0e6;
#endif
            hp->state++;
            return HORS_SIGNATURE_REJECTED;
        }
    }

#ifdef TIMEKEEPING
    gettimeofday(&end_time, NULL);
    hors_verify_time = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1.0e6;
#endif
    hors_destroy_keys(&keys);
    hp->state++;
    return HORS_SIGNATURE_ACCEPTED;
}

void hors_destroy_hp(hors_hp_t *hp) {
    free(hp->seed);
}
