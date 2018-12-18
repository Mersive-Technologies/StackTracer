# StackTracer
This is a simple tool for getting native stack traces from processes running on Linux/x86_64 or Android/ARM.  It uses ptrace to attach to each thread of the specified process and generate a stack trace using libunwind.  Finally, it determines the function name for each stack trace element using the ELF symbol data, if available.

## Motivation
We needed a lightweight, minimally-intrusive way to get native stack traces (i.e. at the C/C++/Rust level) from Linux and Android processes on systems where it's not practical or desirable to install a full-fledged debugger.  This allows us to gather forensic data from deployed applications with minimal fuss.

## Building
First, install [rustup and cargo](http://rustup.rs) if you don't already have them.  Then, ensure that you have the appropriate toolchains for whichever target you wish to build:
```
rustup target add x86_64-unknown-linux-gnu
rustup target add arm-linux-androideabi
```

To build for Linux, first install libunwind using e.g. `sudo apt-get install libunwind-dev`, then the following at the base of this repository:
```
cargo build --target=x86_64-unknown-linux-gnu --release
```

To cross-compile for Android, install the [Android NDK](https://developer.android.com/ndk/downloads/) and build a standalone toolchain:

```
~/Android/Sdk/ndk-bundle/build/tools/make_standalone_toolchain.py \
  --api 22 --arch arm --install-dir ~/android-toolchain --stl libc++
```

Now this is the weird part.  Since we link against libunwind.so and libunwind-ptrace.so, which are part of Android but not part of the NDK, we need to copy them off an Android device and add them to our toolchain, replacing the unrelated libunwind.a that does is included in the NDK:

```
adb pull /system/lib/libunwind-ptrace.so /system/lib/libunwind.so ~/android-toolchain/sysroot/usr/lib/
rm ~/android-toolchain/arm-linux-androideabi/lib/armv7-a/thumb/libunwind.a \
  ~/android-toolchain/arm-linux-androideabi/lib/armv7-a/libunwind.a
```

Note that you may need to deploy those .so files as part of your application on newer Android versions where linking against non-public system libraries is disallowed.

Finally, build for Android using the toolchain you created above:
```
PATH=${HOME}/android-toolchain/bin:${PATH} cargo build --target=arm-linux-androideabi --release
```

## TODOs
 * Use DWARF debug info to get line numbers
 * Find a cleaner way to link against libunwind.so and libunwind-ptrace.so that doesn't require having access to an Android system at build time
 * Support using this tool as a library
