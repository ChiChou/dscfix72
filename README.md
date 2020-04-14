# dscfix72

Requires IDA Pro >= 7.2

**Only tested on iOS 13 firmware**

The name of this project is to salute [dsc_fix](https://github.com/deepinstinct/dsc_fix). **Nothing is broken**. Full cache analysis works perfect, but it takes like one week to finish, and the user experience is below standard. Even "single module plus dependencies" is too slow. We don't really need so many functions to be analyzed once.

Since IDA 7.2, `dscu` is exposed to IDAPython so you can control the loader more flexibly. This project only load one module, then try to resolve the references to classes and symbol stubs. It tries its best to avoid unnecessary disassembly action (but it will anyways) to improve performance. For example, the official document suggests loading `CoreFoundation` just to get some class references. We don't do this at all.

## Usage:

1. `cd helper; make` to build symbol extractor, works on WSL, Linux and macOS
2. `python3 headless.py dyld_shared_cache_arm64 /System/Library/ControlCenter/Bundles/DisplayModule.bundle/DisplayModule`

References:

* [IDA: IDA 7.2 – The Mac Rundown](https://www.hex-rays.com/products/ida/7_2/the_mac_rundown/)
* https://gist.github.com/Siguza/3cc8021cb4a029affc536279f7648211
* https://github.com/deepinstinct/dsc_fix

## Known Issue:

Each `objc_autoreleaseReturnValue` at the end of the function body will become a `JUMPOUT()` in decompiler and I don't know why
