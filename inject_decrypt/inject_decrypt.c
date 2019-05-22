//
//  inject_decrypt.c
//
//  Created by Leptos on 5/19/19.
//  Copyright 2019 Leptos. All rights reserved.
//
//  compile:
//    $(xcrun --sdk iphoneos --find clang) -isysroot $(xcrun --sdk iphoneos --show-sdk-path) -arch armv7 -arch arm64 -Os -dynamiclib
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <copyfile.h>
#include <mach-o/fat.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

/* from Libc/Libc-1272.200.26/sys/crt_externs.c */
#if !(__DYNAMIC__)
#   warning ProgramVars may not be defined for this target
#endif
struct ProgramVars {
    struct mach_header *mh;
    int *NXArgcPtr;
    const char ***NXArgvPtr;
    const char ***environPtr;
    const char **__prognamePtr;
};
/* end Libc/Libc-1272.200.26/sys/crt_externs.c */

static const char __used
_whatMsg[] = "@(#) inject_decrypt: decrypt Mach-O executables using injection",
_whatUsg[] = "@(#) Usage: DYLD_INSERT_LIBRARIES=inject_decrypt.dylib <executable> <out_path>";

__attribute__((constructor, noreturn))
static void dump(int argc, const char *argv[], const char *envp[], const char *apple[], const struct ProgramVars *vars) {
    struct mach_header *mh = vars->mh;
    if (mh == NULL) {
        /*
         * should this be used instead?
         *
         * mh = _dyld_get_image_header(0);
         */
        puts("Could not find mach header of loaded image");
        exit(EXIT_FAILURE);
    }
    
    struct load_command *lc = NULL;
    if (mh->magic == MH_MAGIC_64) {
        lc = (void *)mh + sizeof(struct mach_header_64);
    } else if (mh->magic == MH_MAGIC) {
        lc = (void *)mh + sizeof(struct mach_header);
    } else {
        printf("Unknown magic: %#x\n", mh->magic);
        exit(EXIT_FAILURE);
    }
    
    const char *readPath = argv[0], *outPath = argv[1];
    if (readPath == NULL) {
        /*
         * should this be used instead?
         *
         * while (*apple) {
         *     const char *param = *apple++;
         *     const char exec_path_key[] = "executable_path=";
         *     const size_t exec_path_key_length = strlen(exec_path_key);
         *     if (strncmp(param, exec_path_key, exec_path_key_length) == 0) {
         *         readPath = param + exec_path_key_length;
         *     }
         * }
         *
         * or
         *
         * readPath = _dyld_get_image_name(0);
         */
        puts("Could not find executable path");
        exit(EXIT_FAILURE);
    }
    if (outPath == NULL) {
        puts("Output path required");
        exit(EXIT_FAILURE);
    }
    
    int read_fd = open(readPath, O_RDONLY);
    if (read_fd < 0) {
        perror(readPath);
        exit(EXIT_FAILURE);
    }
    
    int write_fd = open(outPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (write_fd < 0) {
        perror(outPath);
        exit(EXIT_FAILURE);
    }
    
    struct fat_header fh;
    if (read(read_fd, &fh, sizeof(fh)) != sizeof(fh)) {
        perror("read fat_header");
        exit(EXIT_FAILURE);
    }
    off_t write_offset = 0;
    if (OSSwapBigToHostInt32(fh.magic) == FAT_MAGIC) {
        struct fat_arch fa;
        __typeof(*mh) mhl;
        for (__typeof(fh.nfat_arch) i = 0; i < OSSwapBigToHostInt32(fh.nfat_arch); i++) {
            if (read(read_fd, &fa, sizeof(fa)) != sizeof(fa)) {
                perror("read fat_arch");
                exit(EXIT_FAILURE);
            }
            off_t mh_offset = OSSwapBigToHostInt32(fa.offset);
            if (pread(read_fd, &mhl, sizeof(mhl), mh_offset) != sizeof(mhl)) {
                perror("read mach_header");
                exit(EXIT_FAILURE);
            }
            
            if (memcmp(&mhl, mh, sizeof(mhl)) == 0) {
                write_offset = mh_offset;
                break;
            }
        }
        if (write_offset == 0) {
            puts("Header magic is FAT_MAGIC, but could not find loaded slice in disk image");
            exit(EXIT_FAILURE);
        }
    } else if (OSSwapBigToHostInt32(fh.magic) == FAT_MAGIC_64) {
        struct fat_arch_64 fa;
        __typeof(*mh) mhl;
        for (__typeof(fh.nfat_arch) i = 0; i < OSSwapBigToHostInt32(fh.nfat_arch); i++) {
            if (read(read_fd, &fa, sizeof(fa)) != sizeof(fa)) {
                perror("read fat_arch_64");
                exit(EXIT_FAILURE);
            }
            off_t mh_offset = OSSwapBigToHostInt64(fa.offset);
            if (pread(read_fd, &mhl, sizeof(mhl), mh_offset) != sizeof(mhl)) {
                perror("read mach_header");
                exit(EXIT_FAILURE);
            }
            
            if (memcmp(&mhl, mh, sizeof(mhl)) == 0) {
                write_offset = mh_offset;
                break;
            }
        }
        if (write_offset == 0) {
            puts("Header magic is FAT_MAGIC_64, but could not find loaded slice in disk image");
            exit(EXIT_FAILURE);
        }
    } else if (fh.magic == MH_MAGIC) {
        
    } else if (fh.magic == MH_MAGIC_64) {
        
    } else {
        printf("Unknown magic: %x\n", fh.magic);
        exit(EXIT_FAILURE);
    }
    if (lseek(read_fd, 0, SEEK_SET) != 0) {
        perror("lseek start of file");
        exit(EXIT_FAILURE);
    }
    if (fcopyfile(read_fd, write_fd, NULL, COPYFILE_DATA) < 0) {
        perror("fcopyfile");
        exit(EXIT_FAILURE);
    }
    
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        // encryption_info_command and encryption_info_command_64 are the same except for some bottom padding
        // similar to how mach_header and mach_header_64 are the same
        if (lc->cmd == LC_ENCRYPTION_INFO || lc->cmd == LC_ENCRYPTION_INFO_64) {
            struct encryption_info_command *eic = (__typeof(eic))lc;
            
            if (eic->cryptid != 0) {
                if (pwrite(write_fd, (void *)mh + eic->cryptoff, eic->cryptsize, eic->cryptoff + write_offset) != eic->cryptsize) {
                    perror("pwrite crypt section");
                }
                
                __typeof(eic->cryptid) const zero = 0;
                if (pwrite(write_fd, &zero, sizeof(zero), (void *)&eic->cryptid - (void *)mh + write_offset) != sizeof(zero)) {
                    perror("pwrite clearing encryption_info_command->cryptid");
                }
            }
            
        }
        lc = (void *)lc + lc->cmdsize;
    }
    
    exit(EXIT_SUCCESS);
}
