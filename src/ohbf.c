#include "ohbf.h"
#include "hash.h"
#include "bits.h"
#include <openssl/bn.h>
#include <stdlib.h>
#include <string.h>


//TODO check with paper
/// Determining the length of the partitions based on the Algorithm 1 of "One-Hashing Bloom Filter" paper
/// \param partitions Pointer to the array of partition sizes
/// \param required_size Required length for summing all the partition sizes
/// \param num_of_partitions Number of partitions
/// \return Actual sum of the partition sizes
static u32 ohbf_create_partitions(u32 ** partitions, u32 required_size, u32 num_of_partitions){
    /* Allocate partition size table */
    *partitions = (u32 *) malloc(sizeof(u32)*(num_of_partitions+2));

    /* Find the closest prime to the required_size/num_of_partitions */
    int closest_prime_dist = INT_MAX;
    int closest_prime_idx = 0;

    for (int i=0; i<OHBF_PRIME_COUNT; i++){
        if (abs(ohbf_primes[i] - required_size/num_of_partitions) < closest_prime_dist){
            closest_prime_dist = abs(ohbf_primes[i] - required_size/num_of_partitions);
            closest_prime_idx = i;
        }
    }

    int sum = 0, diff = 0, actual_size=0;

    for (int i=closest_prime_idx-num_of_partitions; i<closest_prime_idx; i++) {

        int j = i;
        if (j<0)
            j+=100000;
        sum += ohbf_primes[j];
    }

    int min = abs(sum - required_size);
    int j = closest_prime_idx ;

    while(1){
        int idx = j-num_of_partitions;
        if(idx<0)
            idx+=100000;

        sum += ohbf_primes[j] - ohbf_primes[idx];

        diff = abs(sum-required_size);
        if (diff >= min)
            break;
        min = diff;
        j++;
    }

    for (int i=0; i<num_of_partitions; i++){
        int idx = j-num_of_partitions;
        if (idx<0)
            idx+=100000;

        (*partitions)[i] = ohbf_primes[idx+i];
        actual_size += (*partitions)[i];
    }

    return actual_size;
}

// u32 ohbf_new_hp(ohbf_hp_t * ohbf_hp, u32 required_size, u32 num_of_mod_operations, const u8 *hash_family) {
//     ohbf_hp->required_size = required_size;
//
//     ohbf_hp->actual_size = ohbf_create_partitions(&ohbf_hp->partitions, required_size, num_of_mod_operations);
//     ohbf_hp->num_of_mod_operations = num_of_mod_operations;
//     ohbf_hp->hash_family = hash_family;
//     return OHBF_NEW_HP_SUCCESS;
// }

u32 ohbf_create(ohbf_t *ohbf, const ohbf_hp_t *ohbf_hp){
    // ohbf->size = ohbf_hp->required_size;
    ohbf->num_of_mod_operations = ohbf_hp->num_of_mod_operations;
    ohbf->size = ohbf_create_partitions(&ohbf->partitions, ohbf_hp->required_size, ohbf->num_of_mod_operations);
    ohbf->bv = malloc(ohbf->size / 8);

    /* Zero out the bit vector */
    for (u32 i = 0; i < ohbf->size / 8; i++) ohbf->bv[i] = 0;

    return OHBF_CREATE_SUCCESS;

}

void ohbf_destroy(const ohbf_t *ohbf) {
    // free(ohbf->bv);
    // free(ohbf->partitions);
}


void ohbf_insert(const ohbf_t *ohbf, const u8 *input, u64 length) {
    u8 hash_buffer[HASH_MAX_LENGTH_THRESHOLD];

    xxhash3_128(hash_buffer, input, length);


    for (u32 i = 0; i < ohbf->num_of_mod_operations; i++) {

        /* Convert the hash value to BigNum for further evaluations.
         *
         * We aim to compute the following to get an index for the OHBF:
         *              target_idx = hash % m_i,  where m_i is the length of each partition
         * */
        unsigned __int128 target_idx = *(unsigned __int128 *)hash_buffer % ohbf->partitions[i];

        /* Read the target byte from the target partition and set the appropriate bit and write back */
        u8 * target_partition = &ohbf->bv[ohbf->partitions[i]/8];
        u8 ohbf_target_byte = target_partition[BITS_2_BYTES(target_idx)];
        ohbf_target_byte |= 1 << (8 - BITS_MOD_BYTES(target_idx) - 1);
        target_partition[BITS_2_BYTES(target_idx)] = ohbf_target_byte;

    }
}


u32 ohbf_check(const ohbf_t *ohbf, const u8 *input, u64 length) {
    u8 hash_buffer[HASH_MAX_LENGTH_THRESHOLD];

    xxhash3_128(hash_buffer, input, length);

    for (u32 i = 0; i < ohbf->num_of_mod_operations; i++) {

        /* Convert the hash value to BigNum for further evaluations.
         *
         * We aim to compute the following to get an index for the OHBF:
         *              target_idx = hash % m_i,  where m_i is the length of each partition
         * */
        unsigned __int128 target_idx = *(unsigned __int128 *)hash_buffer % ohbf->partitions[i];


        /* Read the target byte from the target partition and check for the set/unset state of the desired bit */
        u8 * target_partition = &ohbf->bv[ohbf->partitions[i]/8];
        u8 ohbf_target_byte = target_partition[BITS_2_BYTES(target_idx)];
        if (!(ohbf_target_byte & (1 << (8 - BITS_MOD_BYTES(target_idx) - 1)))) {
            return OHBF_ELEMENT_ABSENTS;
        }
    }
    return OHBF_ELEMENT_EXISTS;
}

