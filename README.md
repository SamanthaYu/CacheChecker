# CacheChecker
- CacheChecker detects cache-based use-after-frees within [systemd](https://github.com/systemd/systemd)
- In this repo, we demonstrate how to create a custom Clang static analyzer checker

## Setup
- Before building Clang, make sure that you have plenty of space to build it (e.g. 60 GB)
- Clone the LLVM repository: https://github.com/llvm/llvm-project.git

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

## How to Use a Custom Clang Checker
- Pull this CacheChecker repo into `/llvm-project/clang` and re-build Clang
- There's two ways to use a Clang custom checker: Use LLVM's `load-plugin` argument or use CodeChecker
- For our cache checker, we need a static analysis that can perform CTU (cross-translation unit) analysis
  - We decided to use CodeChecker as recommended by the [Clang documentation](https://clang.llvm.org/docs/analyzer/user-docs/CrossTranslationUnit.html)

### Register the Checker
- Our custom checker must be registered within the Clang static analyzer, so this repo modified these two files:
  - [include/clang/StaticAnalyzer/Checkers/Checkers.td](include/clang/StaticAnalyzer/Checkers/Checkers.td)
  - [lib/StaticAnalyzer/Checkers/CMakeLists.txt](lib/StaticAnalyzer/Checkers/CMakeLists.txt)
  
### Approach 1: Use LLVM's load-plugin Argument
<details>
  
- The Clang documentation usually describes creating a custom checker within the source build only
- It’s possible to use an out-of-source checker by using the `load-plugin` argument:
  - e.g. If `SimpleStreamChecker` is our out-of-source checker, we can execute inside systemd's build directory: `scan-build -load-plugin SimpleStreamChecker/libSimpleStreamChecker.so -enable-checker alpha.SimpleStreamChecker ninja -C build`
- With the `load-plugin` argument, users must still register the checker in `clang/include/clang/StaticAnalyzer/Checkers/Checkers.td`
- The reasoning behind using the `load-plugin` argument is to avoid having to rebuild Clang every time that we want to build the checker
  - With Ninja, we would only be incrementally building our changes, so placing the checker in the LLVM source tree is still reasonable
</details>

### Approach 2: Use CodeChecker
<details open>
  
- CodeChecker passes arguments back to the Clang static analyzer
  - However, CodeChecker does not currently support the `load-plugin` argument, so we build the custom checker in the source tree
- Collect the cross-translation units: `CodeChecker analyze compile_commands.json -o /systemd-csa -ctu-collect -analyzers clangsa`
  - `compile_commands.json` is the compilation database for [systemd](https://github.com/systemd/systemd) generated by `meson build`, because CacheChecker is designed to analyze systemd
  - We write the files to the directory `/systemd-csa`
- Run Clang checkers: `CodeChecker analyze compile_commands.json -o /systemd-csa -ctu-analyze -analyzers clangsa -enable alpha -disable alpha.security.taint`
  - To reduce the amount of time spent analyzing the source code, we can use a `compile_commands.json` that only includes the translation units that we want to analyze
  - `-enable alpha`: Alpha checkers are disabled by default. We registered our cache checker as an alpha checker, so we have to enable all the alpha checkers
  - `-disable alpha.security.taint`: To run our checker on systemd, we had to disable the alpha.security.taint checker
- Parse the results: `CodeChecker parse /systemd-csa -e html -o /systemd-csa/reports_html`
  - `-o /systemd-csa/reports_html`: Write the files to `/systemd-csa/reports_html`
</details>

## Results
- This CacheChecker was designed to detect the asynchronous use-after-free in [CVE-2020-1712](https://bugzilla.redhat.com/show_bug.cgi?id=1794578)
- We created an example schedule of CVE-2020-1712 in https://github.com/SamanthaYu/systemd/pull/1
- Unfortunately, CVE-2020-1712 requires value taint analysis, but the Clang static analyzer does not support this [feature](http://clang-developers.42468.n3.nabble.com/Clear-taint-mark-static-analyzer-checker-td4044933.html)

## Tests
We created tests for this custom checker in https://github.com/SamanthaYu/systemd/pull/1
<br/>
<img src="cmpt416_CacheChecker.jpg" alt="Cache checker detecting a use-after-free in an example scenario" width="650">

