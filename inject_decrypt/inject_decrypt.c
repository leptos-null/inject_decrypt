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

#define VerboseLog(_lvl, ...) if (verboseLevel >= _lvl) printf(__VA_ARGS__)

static const char __used
_whatMsg[] = "@(#) inject_decrypt: decrypt Mach-O executables using injection",
_whatUsg[] = "@(#) Usage: DYLD_INSERT_LIBRARIES=inject_decrypt.dylib <executable> [-avvv] <out_path>";

__attribute__((constructor, noreturn))
static void dump(int argc, char *argv[]) {
    const char *__restrict usageMessageFormat =
    "Usage: DYLD_INSERT_LIBRARIES=inject_decrypt.dylib %s [-avvv] <out_path>\n"
    "  -a    all images (out_path should be a non-existant directory)\n"
    "  -v    verbose mode, multiple increases verbosity";
    char usageMessage[strlen(usageMessageFormat) - 2 + strlen(argv[0]) + 1]; /* %s is -2, null term is +1 */
    snprintf(usageMessage, sizeof(usageMessage), usageMessageFormat, argv[0]);
    
    if (argc < 2) {
        puts(usageMessage);
        exit(EXIT_FAILURE);
    }
    const char *outPath = argv[--argc];
    
    bool wantsFrameworks = false;
    uint16_t verboseLevel = 0;
    
    int optc;
    while ((optc = getopt(argc, argv, ":av")) >= 0) {
        switch (optc) {
            case 'a':
                wantsFrameworks = true;
                break;
            case 'v':
                verboseLevel++;
                break;
                
            default:
                puts(usageMessage);
                exit(EXIT_FAILURE);
                break;
        }
    }
    
    VerboseLog(1, "[Config] Verbose level: %u\n", verboseLevel);
    if (wantsFrameworks) {
        VerboseLog(1, "[Config] Decrypt all loaded images\n");
    } else {
        VerboseLog(1, "[Config] Decrypt main executable only\n");
    }
    
    if (wantsFrameworks) {
        VerboseLog(2, "Creating folder %s\n", outPath);
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
                VerboseLog(3, "%s doesn't exist on disk, skipping\n", readPath);
                continue;
            } else {
                perror(readPath);
                exit(EXIT_FAILURE);
            }
        }
        VerboseLog(1, "Decrypting %s\n", readPath);
        
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
        VerboseLog(2, "Output file is %s\n", writePath);
        
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
            VerboseLog(2, "%s is a FAT image, scanning for loaded slice\n", readPath);
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
                VerboseLog(3, "Trying slice %u (magic = 0x%x)\n", arch, mhl.magic);
                if (memcmp(&mhl, mh, sizeof(mhl)) == 0) {
                    VerboseLog(2, "Found slice at %u\n", mh_offset);
                    write_offset = mh_offset;
                    break;
                }
            }
            if (write_offset == 0) {
                puts("Header magic is FAT_MAGIC, but could not find loaded slice in disk image");
                exit(EXIT_FAILURE);
            }
        } else if (OSSwapBigToHostInt32(fh.magic) == FAT_MAGIC_64) {
            VerboseLog(2, "%s is a FAT_64 image, scanning for loaded slice\n", readPath);
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
                VerboseLog(3, "Trying slice %u (magic = 0x%x)\n", arch, mhl.magic);
                if (memcmp(&mhl, mh, sizeof(mhl)) == 0) {
                    VerboseLog(2, "Found slice at %llu\n", mh_offset);
                    write_offset = mh_offset;
                    break;
                }
            }
            if (write_offset == 0) {
                puts("Header magic is FAT_MAGIC_64, but could not find loaded slice in disk image");
                exit(EXIT_FAILURE);
            }
        } else if (fh.magic == MH_MAGIC) {
            VerboseLog(2, "%s is a Mach image\n", readPath);
        } else if (fh.magic == MH_MAGIC_64) {
            VerboseLog(2, "%s is a Mach_64 image\n", readPath);
        } else {
            printf("Unknown magic: 0x%x\n", fh.magic);
            exit(EXIT_FAILURE);
        }
        
        if (lseek(read_fd, 0, SEEK_SET) != 0) {
            perror("lseek start of file");
            exit(EXIT_FAILURE);
        }
        /**** end of FAT file support ****/
        VerboseLog(3, "Copying %s to %s\n", readPath, writePath);
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
                    VerboseLog(2, "Writing decrypted data %llu -> %llu\n", eic->cryptoff + write_offset, eic->cryptoff + write_offset + eic->cryptsize);
                    if (pwrite(write_fd, (void *)mh + eic->cryptoff, eic->cryptsize, eic->cryptoff + write_offset) != eic->cryptsize) {
                        perror("pwrite crypt section");
                    }
                    
                    __typeof(eic->cryptid) zero = 0;
                    if (pwrite(write_fd, &zero, sizeof(zero), (void *)&eic->cryptid - (void *)mh + write_offset) != sizeof(zero)) {
                        perror("pwrite clearing encryption_info_command->cryptid");
                    }
                } else {
                    VerboseLog(2, "%s is not encrypted\n", readPath);
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
