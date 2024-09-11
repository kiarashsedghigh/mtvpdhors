#ifndef BFTVMHORS_BFTVMHORS_H
#define BFTVMHORS_BFTVMHORS_H

#include "ohbf.h"
#include "types.h"


double bftvmhors_get_keygen_time();
double bftvmhors_get_sign_time();
double bftvmhors_get_verify_time();


#define BFTVMHORS_KEYGEN_TIME bftvmhors_get_keygen_time()
#define BFTVMHORS_SIGN_TIME bftvmhors_get_sign_time()
#define BFTVMHORS_VERIFY_TIME bftvmhors_get_verify_time()


#define BFTVMHORS_NEW_HP_SUCCESS 0
#define BFTVMHORS_NEW_HP_FAILED 1

#define BFTVMHORS_NEW_SIGNER_SUCCESS 0
#define BFTVMHORS_NEW_SIGNER_FAILED 1

#define BFTVMHORS_NEW_VERIFIER_SUCCESS 0
#define BFTVMHORS_NEW_VERIFIER_FAILED 1

#define BFTVMHORS_KEYGEN_SUCCESS 0
#define BFTVMHORS_KEYGEN_FAILED 1

#define BFTVMHORS_SIGNATURE_ACCEPTED 0
#define BFTVMHORS_SIGNATURE_REJECTED 1

#define BFTVMHORS_SIGNING_SUCCESS 0
#define BFTVMHORS_SIGNING_FAILED 1

#define BFTVMHORS_REJECTION_SAMPLING_SUCCESS 0
#define BFTVMHORS_REJECTION_SAMPLING_FAILED 1

#define BFTVMHORS_REJECTION_SAMPLING_DONE 0
#define BFTVMHORS_REJECTION_SAMPLING_NOT_DONE 1

/// Implements the hyper parameters of BFTVMHORS
typedef struct bftvmhors_hp {
  u32 N;                     /* Number of messages to be signed */
  u32 k;                     /* k parameter of the HORS signature */
  u32 t;                     /* t parameter of the HORS signature */
  u32 l;                     /* l parameter of the HORS signature */
  u32 lpk;                    /* Size of the public key portion */
  u32 state; /* State number*/
  ohbf_hp_t ohbf_hp;           /* Hyper parameters of the underlying Standard Bloom Filter (OHBF) */
} bftvmhors_hp_t;

/// Implements the BFTVMHORS keys
typedef struct bftvmhors_keys {
  u8 *seed; /* Pointer to the seed */
  u32 seed_len; /* Length of the seed in bytes */
  ohbf_t pk; /* OHBF Public key */
} bftvmhors_keys_t;

/// Implements the BFTVMHORS signature
typedef struct bftvmhors_signature {
  u8 *signature;
  u32 rejection_sampling_counter;
} bftvmhors_signature_t;

/// Implements the BFTVMHORS signer
typedef struct bftvmhors_signer {
  u32 state;
  bftvmhors_keys_t *keys;
  bftvmhors_hp_t *hp;
} bftvmhors_signer_t;

/// Creates hyper parameters for the BFTVMHORS
/// \param new_hp Pointer to the hyper parameter variable
/// \param config_file Name/Path of the config_sample file
/// \return 0 if parsing the config_sample file is successful, 1 otherwise
u32 bftvmhors_new_hp(bftvmhors_hp_t *new_hp, const u8 *config_file);

/// Destroys the hyper parameter struct
/// \param hp Pointer to the hyper parameter struct
void bftvmhors_destroy_hp(bftvmhors_hp_t* hp);

/// Destroys the keys struct
/// \param keys Pointer to the keys struct
void bftvmhors_destroy_keys(bftvmhors_keys_t* keys);

/// Passing the BFTVMHORS hyper parameters and the keys it creates a BFTVMHORS signer
/// \param signer Pointer to the signer struct
/// \param hp BFTVMHORS hyper parameter
/// \param keys BFTVMHORS keys
/// \return BFTVMHORS_NEW_SIGNER_SUCCESS and BFTVMHORS_NEW_SIGNER_FAILED
u32 bftvmhors_new_signer(bftvmhors_signer_t * signer, bftvmhors_hp_t* hp, bftvmhors_keys_t* keys);

/// BFTVMHORS signer
/// \param signature Pointer to the output signature struct
/// \param signer Pointer to the BFTVMHORS signer struct
/// \param message  Pointer to the message to check signature on
/// \param message_len  Length of the input message
/// \return BFTVMHORS_SIGNING_SUCCESS, BFTVMHORS_SIGNING_FAILED
u32 bftvmhors_sign(bftvmhors_signature_t* signature, bftvmhors_signer_t* signer, u8* message,
                   u64 message_len);


/// BFTVMHORS verifier
/// \param hp Pointer to the BFTVMHORS hyper parameter struct
/// \param signature Pointer to the BFTVMHORS signature struct
/// \param message  Pointer to the message to check signature on
/// \param message_len Length of the input message
/// \return BFTVMHORS_SIGNATURE_VERIFIED and BFTVMHORS_SIGNATURE_REJECTED
u32 bftvmhors_verify(bftvmhors_keys_t* keys, bftvmhors_hp_t* hp,
                     bftvmhors_signature_t * signature, u8* message, u64 message_len);

#endif