# MTVPD-HORS
<p>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT License-%23ffb243?style=flat-square"></a>
<a href="CMAKE"><img src="https://img.shields.io/badge/cmake-3.22%2B-blue.svg">
</p>



## Requirements
Before you begin, ensure you have met the following requirements:
- **Openssl**
- **CMake**: 3.22 or higher


# Dependencies
We use xxHash3 for our bloom filter. Build it as follows:
```
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh
./vcpkg integrate install
./vcpkg install xxhash
cp ./installed/TARGET/include/*.h /usr/inlude
cp ./installed/TARGET/lib/*.a /usr/lib
```

# Building
To install first:
```
git clone https://github.com/kiarashsedghigh/mtvpdhors.git
```
To build the binary:
```
mkdir build
cd buid
cmake  -S .. -B . -DCMAKE_C_FLAGS="-O3 -w" 
make [hors | mtvpdhors]
```
Add `-DTIMEKEEPING` to get timing report.

# Running
To run the program:
```
$ ./mtvpdhors T K L LPK P M SEED_FILE 
```
where `T`, `K`, `L` are HORS parameters, `LPK` denotes the output size of the
one-way function, `P` is the number of partitions, `M` is OHBF size in bits, and `SEED_FILE` is the path to the seed file. Create a
seed file manually if no exists.

# Example
## Build
```
cmake  -S .. -B . -DCMAKE_C_FLAGS="-O3 -w -DTIMEKEEPING"
make mtvpdhors
```

## Run
We can set parameters
as `t=64`, `k=16`, `l=32`, `lpk=128`, `p=8`, `m=7954`:
```
$ ./mtvpdhors 64 16 32 128 8 7954 ./seedfile
```

