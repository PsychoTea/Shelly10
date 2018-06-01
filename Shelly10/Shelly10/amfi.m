//
//  amfi.m
//  Meridian
//
//  Created by Ben Sparkes on 19/12/2017.
//  Copyright © 2017 Ben Sparkes. All rights reserved.
//

#import "patchfinder64.h"
#import "kernel.h"
#import "amfi.h"
#import "helpers.h"
#import "ViewController.h"
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <mach-o/loader.h>
#import <mach-o/dyld_images.h>
#import <mach-o/fat.h>
#import <mach-o/swap.h>
#import <sys/stat.h>
#import <sys/event.h>
#import <dlfcn.h>
#import <pthread.h>
#import <sys/spawn.h>

uint64_t trust_cache;
uint64_t amficache;

int init_amfi() {
    trust_cache = find_trustcache();
    amficache = find_amficache();
    
    NSLog(@"[amfi] trust_cache = 0x%llx \n", trust_cache);
    NSLog(@"[amfi] amficache = 0x%llx \n", amficache);
    
    if (trust_cache == 0 ||
        amficache == 0) {
        return -1;
    }
    
    return 0;
}

// creds to stek29(?)
int inject_trust(const char *path) {
    if (file_exists(path) != 0) {
        NSLog(@"[amfi] you wanka, %s doesn't exist!", path);
        return -1;
    }
    
    typedef char hash_t[20];
    
    struct trust_chain {
        uint64_t next;
        unsigned char uuid[16];
        unsigned int count;
        hash_t hash[1];
    };
    
    struct trust_chain fake_chain;
    
    fake_chain.next = rk64(trust_cache);
    *(uint64_t *)&fake_chain.uuid[0] = 0xabadbabeabadbabe;
    *(uint64_t *)&fake_chain.uuid[8] = 0xabadbabeabadbabe;
    fake_chain.count = 1;
    
    uint8_t *codeDir = get_code_directory(path, 0);
    if (codeDir == NULL) {
        NSLog(@"[amfi] was given null code dir for %s!", path);
        return -2;
    }
    
    uint8_t *hash = get_sha1(codeDir);
    memmove(fake_chain.hash[0], hash, 20);
    
    free(hash);
    
    uint64_t kernel_trust = 0;
    mach_vm_allocate(tfp0, &kernel_trust, sizeof(fake_chain), VM_FLAGS_ANYWHERE);
    
    kwrite(kernel_trust, &fake_chain, sizeof(fake_chain));
    wk64(trust_cache, kernel_trust);
    
    NSLog(@"[amfi] signed %s \n", path);
    return 0;
}

uint8_t *get_code_directory(const char* file_path, uint64_t file_off) {
    FILE* fd = fopen(file_path, "r");
    
    if (fd == NULL) {
        NSLog(@"[amfi] couldn't open file %s", file_path);
        fclose(fd);
        return NULL;
    }
    
    fseek(fd, 0L, SEEK_END);
    uint64_t file_len = ftell(fd);
    fseek(fd, 0L, SEEK_SET);
    
    if (file_off > file_len){
        NSLog(@"[amfi] file offset greater than length");
        fclose(fd);
        return NULL;
    }
    
    uint32_t magic;
    fread(&magic, sizeof(magic), 1, fd);
    fseek(fd, 0, SEEK_SET);
    
    int is_swap = (magic == MH_CIGAM || magic == MH_CIGAM_64 || magic == FAT_CIGAM);
    
    uint64_t off = file_off;
    int ncmds = 0;
    
    if (magic == MH_MAGIC_64) {
        struct mach_header_64 mh64;
        fread(&mh64, sizeof(mh64), 1, fd);
        off += sizeof(mh64);
        ncmds = mh64.ncmds;
    } else if (magic == MH_MAGIC) {
        struct mach_header mh;
        fread(&mh, sizeof(mh), 1, fd);
        off += sizeof(mh);
        ncmds = mh.ncmds;
    } else if (magic == FAT_CIGAM || magic == FAT_CIGAM_64) {
        struct fat_header header;
        fread(&header, sizeof(header), 1, fd);
        if (is_swap) swap_fat_header(&header, 0);
        
        int arch_offset = sizeof(header);
        for (int i = 0; i < header.nfat_arch; i++) {
            struct fat_arch arch;
            fseek(fd, arch_offset, 0);
            fread(&arch, sizeof(struct fat_arch), 1, fd);
            if (is_swap) swap_fat_arch(&arch, 1, 0);
            
            if (arch.cputype != CPU_TYPE_ARM64) continue;
            
            fseek(fd, arch.offset, 0);
            
            uint32_t magic;
            fread(&magic, sizeof(magic), 1, fd);
            
            if (magic == MH_MAGIC) {
                struct mach_header mh;
                fread(&mh, sizeof(mh), 1, fd);
                off += arch.offset + sizeof(mh);
                ncmds = mh.ncmds;
            } else if (magic == MH_MAGIC_64) {
                struct mach_header_64 mh64;
                fread(&mh64, sizeof(mh64), 1, fd);
                off += arch.offset + sizeof(mh64);
                ncmds = mh64.ncmds;
            }
            
            arch_offset += sizeof(arch);
        }
    } else {
        NSLog(@"[amfi] your magic is not valid in these lands! %ux", magic);
        fclose(fd);
        return NULL;
    }
    
    if (off > file_len) {
        NSLog(@"[amfi] unexpected end of file");
        fclose(fd);
        return NULL;
    }
    
    fseek(fd, off, SEEK_SET);
    
    for (int i = 0; i < ncmds; i++) {
        if (off + sizeof(struct load_command) > file_len) {
            NSLog(@"[amfi] unexpected end of file");
            fclose(fd);
            return NULL;
        }
        
        const struct load_command cmd;
        fseek(fd, off, SEEK_SET);
        fread((void*)&cmd, sizeof(struct load_command), 1, fd);
        if (cmd.cmd == LC_CODE_SIGNATURE) {
            uint32_t off_cs;
            fread(&off_cs, sizeof(uint32_t), 1, fd);
            uint32_t size_cs;
            fread(&size_cs, sizeof(uint32_t), 1, fd);
            
            if (off_cs + file_off + size_cs > file_len) {
                NSLog(@"[amfi] unexpected end of file");
                fclose(fd);
                return NULL;
            }
            
            uint8_t *cd = malloc(size_cs);
            fseek(fd, off_cs + file_off, SEEK_SET);
            fread(cd, size_cs, 1, fd);
            return cd;
        } else {
            off += cmd.cmdsize;
            if (off > file_len) {
                NSLog(@"[amfi] unexpected end of file");
                fclose(fd);
                return NULL;
            }
        }
    }
    
    NSLog(@"[amfi] couldn't find the code sig for %s", file_path);
    fclose(fd);
    return NULL;
}

// creds to nullpixel
uint8_t *get_sha1(uint8_t* code_dir) {
    uint8_t *out = malloc(CC_SHA1_DIGEST_LENGTH);
    
    uint32_t* code_dir_int = (uint32_t*)code_dir;
    
    uint32_t realsize = 0;
    for (int j = 0; j < 10; j++) {
        if (swap_uint32(code_dir_int[j]) == 0xfade0c02) {
            realsize = swap_uint32(code_dir_int[j+1]);
            code_dir += 4*j;
        }
    }
    
    CC_SHA1(code_dir, realsize, out);
    
    return out;
}

uint32_t swap_uint32(uint32_t val) {
    val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
    return (val << 16) | (val >> 16);
}
