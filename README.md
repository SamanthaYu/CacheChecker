# CacheChecker
- This Clang static analyzer detects cache-based use-after-frees within systemd
- In this repo, we demonstrate how to create a custom Clang static analyzer checker

## Setup
- Before building Clang, make sure that you have plenty of space to build it (e.g. 60 GB)
- Clone the LLVM repository: https://github.com/llvm/llvm-project.git
- Save this CacheChecker in 

## How to Build Clang
- There's two ways to build Clang: Use CMake or use Ninja
- We recommend building with Ninja, because it will only build the changed files
  - Compared to CMake which takes 2 hours for every build, Ninja can compile a checker within 5 minutes

### Approach 1: Use CMake
<details>
  
- Create a build directory inside llvm-project: `mkdir build`
- Execute inside the build directory: `cmake -DLLVM_ENABLE_PROJECTS=clang -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" -DLLVM_USE_LINKER=gold ../llvm`
    - `-DLLVM_ENABLE_PROJECTS=clang`: To build Clang
    - `-DCMAKE_BUILD_TYPE=Release`: To build in release mode instead of debug mode (much faster)
    - `-DLLVM_USE_LINKER=gold`: To use the gold linker, which is much faster than ld
- Run: `make`
    - This step takes about 2 hours
    - Every time that we make a change to a Clang checker, we would have to re-build the whole project again
</details>

### Approach 2: Use Ninja
<details open>
  
- Create a build directory inside llvm-project: `mkdir build`
- Execute inside the build directory: `cmake -G Ninja -DLLVM_ENABLE_PROJECTS=clang -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Release ../llvm`
  - Unlike the CMake attempt, we don’t recommend using the gold linker, because we ran into an internal error towards the end of compilation
- `ninja`
  - Like CMake, this step initially takes about 2 hours
  - While building, users should be careful that their CPU will not run out of memory as Ninja can easily consume all available memory
  - Since Ninja builds incrementally, users can stop the build process at any time and resume it
</details>

### Environment Variables
- Add the following environment variables:
  - `/llvm-project/build/bin`
  - `/llvm-project/clang/include`
  - `/llvm-project/llvm/include`

## Tests
We created tests for this checker in https://github.com/SamanthaYu/systemd/pull/1
![Cache checker detecting a use-after-free in an example scenario](cmpt416_CacheChecker.jpg)
