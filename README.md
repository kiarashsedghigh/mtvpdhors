# MTVPD-HORS
<p>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT License-%23ffb243?style=flat-square"></a>
<a href="CMAKE"><img src="https://img.shields.io/badge/cmake-3.22%2B-blue.svg">
</p>



## Requirements
Before you begin, ensure you have met the following requirements:
- **Openssl**
- **CMake**: 3.22 or higher


# Building
To install first:
```
git clone https://github.com/kiarashsedghigh/mtvpdhors.git
```
To build the binary:
```
mkdir build
cd buid
cmake -S .. -B . -DCMAKE_C_FLAGS="-O3 -w"
make
```
Add `-DTIMEKEEPING` to get timing report.

# Running
To run the program:
```
$ ./mtvpdhors T K L LPK SEED_FILE 
```
where `T`, `K`, `L` are HORS parameters, `LPK` denotes the output size of the
one-way function, and `SEED_FILE` is the path to the seed file. Create a
seed file manually if no exists.

# Example
## Build
```
cmake -S .. -B . -DCMAKE_C_FLAGS="-O3 -w -DTIMEKEEPING"
make
```

## Run
We can set parameters
as `t=1024`, `k=25`, `l=256`, `r=25601`, `rt=11`, `tests=1048576`:
```
$ ./mtvpdhors 256 32 256 256 ./seed_file
```

