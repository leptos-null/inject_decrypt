## inject_decrypt

Decrypt Mach-O executables using injection. 

iOS (and watchOS, and probably tvOS) binaries acquired through the App Store have an encrypted section. When a binary is loaded into memory, and is ready for execution, the section that's encypted on disk is decrypted in memory. This dynamic library can be injected into a process to dump the image with it's decrypted section to a new file on disk. The resulting file has an invalid code signature. 
The App Store typically only serves "thinned" binaries, however I've added support for "fat" (multiple architectures in one file) images just in case. In the case where an image on disk is fat, the entire file is copied, however only the slice loaded in memory is decrypted. 

A binary must be decrypted before meaningful static analysis may be performed on it. 

### Usage

```
DYLD_INSERT_LIBRARIES=inject_decrypt.dylib <executable> [-avvv] <out_path>
  -a    all images (out_path should be a non-existant directory)
  -v    verbose mode, multiple increases verbosity
```

### Compile

Using Xcode: `xcodebuild` should create `build/Release-iphoneos/libinject_decrypt.a`, an unsigned dynamic library. Sign with `ldid -S` or similar if needed.

Using Theos: `make DEBUG=0` should create `.theos/obj/inject_decrypt.dylib`, a pseudo-signed dynamic library.

Independent, macOS: `$(xcrun --sdk iphoneos --find clang) -isysroot $(xcrun --sdk iphoneos --show-sdk-path) -arch armv7 -arch arm64 -Os -dynamiclib inject_decrypt/inject_decrypt.c -o inject_decrypt.dylib` should create `inject_decrypt.dylib`, an unsigned dynamic library. Sign with `ldid -S` or similar if needed.

Independent, other (substitute the path to your iOS SDK, and your C compiler, if needed): `$CC -isysroot IOS_SDK_PATH -arch armv7 -arch arm64 -Os -dynamiclib inject_decrypt/inject_decrypt.c -o inject_decrypt.dylib` should create `inject_decrypt.dylib`, an unsigned dynamic library. Sign with `ldid -S` or similar if needed.

### Known Similar Tools

- [dumpdecrypted](https://github.com/stefanesser/dumpdecrypted) uses injection, and only dumps the main image

- [decrypt](https://bitbucket.org/lordscotland/objctools/src/master/decrypt.c) uses injection, and dumps all loaded images

- [Clutch](https://github.com/KJCracks/Clutch) uses spawning, and supports dumping all images
