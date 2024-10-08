#ifndef TVBFMHORS_OHBF_H
#define TVBFMHORS_OHBF_H

#include "types.h"
#include "ohbf_primes.h"


#define OHBF_ELEMENT_EXISTS 0
#define OHBF_ELEMENT_ABSENTS 1

#define OHBF_NEW_HP_SUCCESS 0
#define OHBF_NEW_HP_FAILED 1

typedef struct ohbf_hp {
    u32 required_size;         // Required size of the OHBF
    u32 actual_size;            // Actual size of the OHBF
    u32 num_of_mod_operations;  // Number of modulo operations to be used
    u32 *partitions;    // Size of each partition in the OHBF
    u8 *hash_family;  // Family of the functions to be used for hashing.
}ohbf_hp_t;

#define OHBF_CREATE_SUCCESS 0
#define OHBF_CREATE_FAILED 1

/// One-time Hash Bloom Filter (OHBF) implementation
typedef struct ohbf {
    u8 *bv;                                         // The OHBF bit vector
    u32 size;                                       // Size of the OHBF
    u32 num_of_mod_operations;  // Number of modulo operations to be used
    u32 *partitions;    // Size of each partition in the OHBF
} ohbf_t;

/// Creates a new OHBF with the given hyper parameters
/// \param ohbf The OHBF struct
/// \param ohbf_hp The OHBF hyper parameters
u32 ohbf_create(ohbf_t *ohbf, const ohbf_hp_t *ohbf_hp);

/// Destroys the given OHBF
/// \param ohbf Target OHBF to be destroyed
void ohbf_destroy(const ohbf_t *ohbf);

#define OHBF_ELEMENT_EXISTS 0
#define OHBF_ELEMENT_ABSENTS 1

/// Insert the input to the passed OHBF
/// \param ohbf The OHBF we want to insert into
/// \param input The input to be inserted into the OHBF
/// \param length The length of the input
void ohbf_insert(const ohbf_t *ohbf, const u8 *input, u64 length);

/// Checks if an element is in the OHBF
/// \param ohbf The OHBF we want to check the element existence in
/// \param input The input to be inserted into the OHBF
/// \param length The length of the input
/// \return Returns OHBF_ELEMENT_EXISTS , OHBF_ELEMENT_ABSENTS
u32 ohbf_check(const ohbf_t *ohbf, const u8 *input, u64 length);


#endif
