//
//  inject_decrypt.c
//
//  Created by Leptos on 5/19/19.
//  Copyright 2019 Leptos. All rights reserved.
//
//  compile:
//    $(xcrun --sdk iphoneos --find clang) -isysroot $(xcrun --sdk iphoneos --show-sdk-path) -arch armv7 -arch arm64 -Os -dynamiclib
//  most likely, the library will need to be signed in order to be injected (sign with `ldid -S` or similar)
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <copyfile.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <mach-o/fat.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

static const char __used
_whatMsg[] = "@(#) inject_decrypt: decrypt Mach-O executables using injection",
_whatUsg[] = "@(#) Usage: DYLD_INSERT_LIBRARIES=inject_decrypt.dylib <executable> [-a] <out_path>";

__attribute__((constructor, noreturn))
static void dump(int argc, char *argv[]) {
    const char *__restrict usageMessageFormat =
    "Usage: DYLD_INSERT_LIBRARIES=inject_decrypt.dylib %s [-a] <out_path>\n"
    "  -a    all images (out_path should be a non-existant directory)";
    char usageMessage[strlen(usageMessageFormat) - 2 + strlen(argv[0]) + 1]; /* %s is -2, null term is +1 */
    snprintf(usageMessage, sizeof(usageMessage), usageMessageFormat, argv[0]);
    
    if (argc < 2) {
        puts(usageMessage);
        exit(EXIT_FAILURE);
    }
    const char *outPath = argv[--argc];
    
    bool wantsFrameworks = false;
    
    int optc;
    while ((optc = getopt(argc, argv, ":a")) >= 0) {
        switch (optc) {
            case 'a':
                wantsFrameworks = true;
                break;
                
            default:
                puts(usageMessage);
                exit(EXIT_FAILURE);
                break;
        }
    }
    
    if (wantsFrameworks) {
        if (mkdir(outPath, 0755) != 0) {
            perror(outPath);
            exit(EXIT_FAILURE);
        }
    }
    
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        
        const struct load_command *lc = NULL;
        if (mh->magic == MH_MAGIC_64) {
            lc = (void *)mh + sizeof(struct mach_header_64);
        } else if (mh->magic == MH_MAGIC) {
            lc = (void *)mh + sizeof(struct mach_header);
        } else {
            printf("Unknown magic: %#x\n", mh->magic);
            exit(EXIT_FAILURE);
        }
        
        const char *readPath = _dyld_get_image_name(i);
        struct stat statInfo;
        if (stat(readPath, &statInfo) != 0) {
            if (errno == ENOENT) {
                errno = 0;
                continue;
            } else {
                perror(readPath);
                exit(EXIT_FAILURE);
            }
        }
        
        int read_fd = open(readPath, O_RDONLY);
        if (read_fd < 0) {
            perror(readPath);
            exit(EXIT_FAILURE);
        }
        
        const char *imageBase = basename((char *)readPath);
        char writePath[strlen(outPath) + 1 + strlen(imageBase) + 1];
        strcpy(writePath, outPath);
        
        if (wantsFrameworks) {
            writePath[strlen(outPath)] = '/';
            strcpy(writePath + strlen(outPath) + 1, imageBase);
        } else {
            writePath[strlen(outPath)] = 0;
        }
        
        int write_fd = open(writePath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (write_fd < 0) {
            perror(outPath);
            exit(EXIT_FAILURE);
        }
        /**** start of FAT file support ****/
        struct fat_header fh;
        if (read(read_fd, &fh, sizeof(fh)) != sizeof(fh)) {
            perror("read fat_header");
            exit(EXIT_FAILURE);
        }
        uint64_t write_offset = 0;
        if (OSSwapBigToHostInt32(fh.magic) == FAT_MAGIC) {
            struct fat_arch fa;
            struct mach_header mhl;
            for (__typeof(fh.nfat_arch) arch = 0; arch < OSSwapBigToHostInt32(fh.nfat_arch); arch++) {
                if (read(read_fd, &fa, sizeof(fa)) != sizeof(fa)) {
                    perror("read fat_arch");
                    exit(EXIT_FAILURE);
                }
                uint32_t mh_offset = OSSwapBigToHostInt32(fa.offset);
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
            struct mach_header mhl;
            for (__typeof(fh.nfat_arch) arch = 0; arch < OSSwapBigToHostInt32(fh.nfat_arch); arch++) {
                if (read(read_fd, &fa, sizeof(fa)) != sizeof(fa)) {
                    perror("read fat_arch_64");
                    exit(EXIT_FAILURE);
                }
                uint64_t mh_offset = OSSwapBigToHostInt64(fa.offset);
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
            printf("Unknown magic: 0x%x\n", fh.magic);
            exit(EXIT_FAILURE);
        }
        
        if (lseek(read_fd, 0, SEEK_SET) != 0) {
            perror("lseek start of file");
            exit(EXIT_FAILURE);
        }
        /**** end of FAT file support ****/
        
        if (fcopyfile(read_fd, write_fd, NULL, COPYFILE_DATA) < 0) {
            perror("fcopyfile");
            exit(EXIT_FAILURE);
        }
        
        for (uint32_t cmd = 0; cmd < mh->ncmds; cmd++) {
            // encryption_info_command and encryption_info_command_64 are the same except for some bottom padding
            // similar to how mach_header and mach_header_64 are the same
            if (lc->cmd == LC_ENCRYPTION_INFO || lc->cmd == LC_ENCRYPTION_INFO_64) {
                const struct encryption_info_command *eic = (__typeof(eic))lc;
                
                if (eic->cryptid != 0) {
                    if (pwrite(write_fd, (void *)mh + eic->cryptoff, eic->cryptsize, eic->cryptoff + write_offset) != eic->cryptsize) {
                        perror("pwrite crypt section");
                    }
                    
                    __typeof(eic->cryptid) zero = 0;
                    if (pwrite(write_fd, &zero, sizeof(zero), (void *)&eic->cryptid - (void *)mh + write_offset) != sizeof(zero)) {
                        perror("pwrite clearing encryption_info_command->cryptid");
                    }
                }
                
            }
            lc = (void *)lc + lc->cmdsize;
        }
        close(read_fd);
        close(write_fd);
        
        if (!wantsFrameworks) {
            break;
        }
    }
    exit(EXIT_SUCCESS);
}
