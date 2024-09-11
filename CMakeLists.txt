cmake_minimum_required(VERSION 3.28)
project(mtvpdhors C)

set(CMAKE_C_STANDARD 23)




add_compile_options(-DTIMEKEEPING -O3 -w -DOHBF)
include_directories(src/ src/crypto src/utils)
link_libraries(tomcrypt m ssl crypto xxhash)



set(COMMON_SRCS
        src/bf.c src/bf.h
        src/hash.h
        src/mht.c src/mht.h

        src/prng.h
        src/tv_params.h
        src/types.h
        src/utils/bits.c src/utils/bits.h
        src/utils/debug.c src/utils/debug.h
        src/utils/file.c src/utils/file.h
        src/utils/format.c src/utils/format.h
        src/utils/stack.c src/utils/stack.h
        src/crypto/hash/sha2-256.c
        src/crypto/prng/chacha20.c
        src/crypto/hash/blake/blake2b.c
        src/crypto/hash/blake/blake2s.c
        src/crypto/hash/blake/tomcrypt.h
        src/crypto/hash/blake/tomcrypt_argchk.h
        src/crypto/hash/blake/tomcrypt_cfg.h
        src/crypto/hash/blake/tomcrypt_cipher.h
        src/crypto/hash/blake/tomcrypt_custom.h
        src/crypto/hash/blake/tomcrypt_hash.h
        src/crypto/hash/blake/tomcrypt_mac.h
        src/crypto/hash/blake/tomcrypt_macros.h
        src/crypto/hash/blake/tomcrypt_math.h
        src/crypto/hash/blake/tomcrypt_misc.h
        src/crypto/hash/blake/tomcrypt_pk.h
        src/crypto/hash/blake/tomcrypt_pkcs.h
        src/crypto/hash/blake/tomcrypt_prng.h
)

add_executable(hors
        test/hors_example.c
        src/hors.c src/hors.h
        ${COMMON_SRCS}
)

add_executable(mtvpdhors
        test/mtvpdhors_example.c
        src/bftvmhors.c src/bftvmhors.h
        ${COMMON_SRCS}
        src/crypto/hash/xxhash/xxhash.c
        src/ohbf.c src/ohbf.h
        src/ohbf_primes.h
)



