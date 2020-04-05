// forked from https://gist.github.com/Siguza/3cc8021cb4a029affc536279f7648211

#include <errno.h>
#include <fcntl.h> // open
#include <stdint.h>
#include <stdio.h>    // printf, fprintf, stderr
#include <stdlib.h>   // exit
#include <string.h>   // strerror, strncmp
#include <sys/mman.h> // mmap
#include <sys/stat.h> // fstat

#include "macho.h"

#define LOG(str, args...)                                                                                              \
  do {                                                                                                                 \
    fprintf(stderr, "\x1b[93m" str "\x1b[0m\n", ##args);                                                               \
  } while (0)

typedef struct {
  char magic[16];
  uint32_t mappingOffset;
  uint32_t mappingCount;
  uint32_t imagesOffset;
  uint32_t imagesCount;
  uint64_t dyldBaseAddress;
  uint64_t codeSignatureOffset;
  uint64_t codeSignatureSize;
  uint64_t slideInfoOffset;
  uint64_t slideInfoSize;
  uint64_t localSymbolsOffset;
  uint64_t localSymbolsSize;
  uint8_t uuid[16];
  uint64_t cacheType;
  uint32_t branchPoolsOffset;
  uint32_t branchPoolsCount;
  uint64_t accelerateInfoAddr;
  uint64_t accelerateInfoSize;
  uint64_t imagesTextOffset;
  uint64_t imagesTextCount;
} cache_hdr_t;

typedef struct {
  uint64_t address;
  uint64_t size;
  uint64_t fileOffset;
  uint32_t maxProt;
  uint32_t initProt;
} cache_map_t;

typedef struct {
  uint64_t address;
  uint64_t modTime;
  uint64_t inode;
  uint32_t pathFileOffset;
  uint32_t pad;
} cache_img_t;

typedef struct mach_header mach_hdr32_t;
typedef struct mach_header_64 mach_hdr64_t;
typedef struct load_command mach_lc_t;
typedef struct symtab_command mach_stab_t;
typedef struct segment_command segment_32_t;
typedef struct segment_command_64 segment_64_t;
typedef struct section section_32_t;
typedef struct section_64 section_64_t;
typedef struct nlist nlist32_t;
typedef struct nlist_64 nlist64_t;

static void *addr2ptr(uint64_t addr, void *cache) {
  cache_hdr_t *hdr = cache;
  cache_map_t *map = (cache_map_t *)((uintptr_t)cache + hdr->mappingOffset);
  for (uint32_t i = 0; i < hdr->mappingCount; ++i) {
    if (addr >= map[i].address && addr < map[i].address + map[i].size) {
      return (void *)((uintptr_t)cache + map[i].fileOffset + (addr - map[i].address));
    }
  }
  LOG("Failed to translate address 0x%llx", addr);
  exit(-1);
}

static void *addr2file(uint64_t addr, void *cache) {
  cache_hdr_t *hdr = cache;
  cache_map_t *map = (cache_map_t *)((uintptr_t)cache + hdr->mappingOffset);
  for (uint32_t i = 0; i < hdr->mappingCount; ++i) {
    if (addr >= map[i].address && addr < map[i].address + map[i].size) {
      return (void *)((uintptr_t)map[i].fileOffset + (addr - map[i].address));
    }
  }
  LOG("Failed to translate address 0x%llx", addr);
  exit(-1);
}

static void readable_prot(vm_prot_t prot, char out[4]) {
  int i = 0;

#define CHECK(val, str)                                                                                                \
  if (prot & val) {                                                                                                    \
    out[i] = str;                                                                                                      \
    i++;                                                                                                               \
  }

  CHECK(VM_PROT_READ, 'R');
  CHECK(VM_PROT_WRITE, 'W');
  CHECK(VM_PROT_EXECUTE, 'X');
  out[i] = 0;
}

#define SUFFIX ".symbol"

int main(int argc, const char **argv) {
  if (argc < 2) {
    fprintf(stderr,
            "Usage:\n"
            "    %s file\n",
            argv[0]);
    return -1;
  }
  int fd = open(argv[1], O_RDONLY);
  if (fd == -1) {
    LOG("open(%s): %s", argv[1], strerror(errno));
    return -1;
  }

  char *output = NULL;
  if (argc == 3) {
    output = (char *)argv[2];
  } else {
    size_t len = strlen(argv[1]) + sizeof(SUFFIX);
    output = malloc(len);
    if (!output) {
      LOG("wtf?");
      exit(0);
    }
    snprintf(output, len, "%s%s", argv[1], SUFFIX);
  }

  FILE *fout = fopen(output, "w");
  struct stat s;
  if (fstat(fd, &s) != 0) {
    LOG("fstat(%s): %s", argv[1], strerror(errno));
    return -1;
  }
  if (s.st_size < sizeof(cache_hdr_t)) {
    LOG("File is too short to be a cache.");
    return -1;
  }
  void *cache = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (cache == MAP_FAILED) {
    LOG("mmap(%s): %s", argv[1], strerror(errno));
    return -1;
  }
  cache_hdr_t *hdr = cache;
  if (strncmp(hdr->magic, "dyld_v1 ", 8) != 0) {
    LOG("Bad magic: %s", hdr->magic);
    return -1;
  }

  cache_img_t *img = (cache_img_t *)((uintptr_t)cache + hdr->imagesOffset);
  char prot[4];
  for (uint32_t i = 0; i < hdr->imagesCount; ++i) {
    void *ptr = addr2ptr(img[i].address, cache);
    fprintf(fout, "file %s\n", (const char *)(cache + img[i].pathFileOffset));
    if (*(uint32_t *)ptr == MH_MAGIC) {
      mach_hdr32_t *h32 = ptr;
      for (mach_lc_t *cmd = (mach_lc_t *)(h32 + 1), *end = (mach_lc_t *)((uintptr_t)cmd + h32->sizeofcmds); cmd < end;
           cmd = (mach_lc_t *)((uintptr_t)cmd + cmd->cmdsize)) {
        if (cmd->cmd == LC_SEGMENT) {
          segment_32_t *seg = (segment_32_t *)cmd;
          unsigned long ceil = seg->vmaddr + seg->vmsize - 1;
          readable_prot(seg->maxprot, prot);
          fprintf(fout, "segment %s 0x%lx 0x%lx 0x%lx 0x%lx %s\n", seg->segname, seg->vmaddr,
                  addr2file(seg->vmaddr, cache), seg->vmsize, prot);
        } else if (cmd->cmd == LC_SYMTAB) {
          mach_stab_t *stab = (mach_stab_t *)cmd;
          nlist32_t *syms = (nlist32_t *)((uintptr_t)cache + stab->symoff);
          char *strs = (char *)((uintptr_t)cache + stab->stroff);
          for (size_t n = 0; n < stab->nsyms; ++n) {
            if ((syms[n].n_type & N_TYPE) != N_UNDF && (syms[n].n_type & N_EXT)) {
              if (strs[syms[n].n_un.n_strx] != '_') {
                LOG("Not a C symbol: %s", &strs[syms[n].n_un.n_strx]);
              } else {
                fprintf(fout, "symbol %s 0x%x\n", &strs[syms[n].n_un.n_strx + 1], syms[n].n_value);
              }
            }
          }
        }
      }
    } else if (*(uint32_t *)ptr == MH_MAGIC_64) {
      mach_hdr64_t *h64 = ptr;
      for (mach_lc_t *cmd = (mach_lc_t *)(h64 + 1), *end = (mach_lc_t *)((uintptr_t)cmd + h64->sizeofcmds); cmd < end;
           cmd = (mach_lc_t *)((uintptr_t)cmd + cmd->cmdsize)) {
        if (cmd->cmd == LC_SEGMENT_64) {
          segment_64_t *seg = (segment_64_t *)cmd;
          readable_prot(seg->initprot, prot);
          fprintf(fout, "segment %s 0x%llx 0x%llx 0x%llx 0x%llx %s\n", seg->segname, seg->vmaddr,
                  seg->vmaddr + seg->vmsize - 1, addr2file(seg->vmaddr, cache), seg->filesize, prot);
          for (uint j = 0; j < seg->nsects; j++) {
            section_64_t *sect = (section_64_t *)((uintptr_t)cmd + sizeof(segment_64_t)) + j;
            fprintf(fout, "section %s 0x%llx 0x%llx 0x%llx 0x%llx\n", sect->sectname, sect->addr, sect->addr + sect->size, addr2file(sect->addr, cache), sect->size);
          }
        } else if (cmd->cmd == LC_SYMTAB) {
          mach_stab_t *stab = (mach_stab_t *)cmd;
          nlist64_t *syms = (nlist64_t *)((uintptr_t)cache + stab->symoff);
          char *strs = (char *)((uintptr_t)cache + stab->stroff);
          for (size_t n = 0; n < stab->nsyms; ++n) {
            if ((syms[n].n_type & N_TYPE) != N_UNDF && (syms[n].n_type & N_EXT)) {
              if (strs[syms[n].n_un.n_strx] != '_') {
                LOG("Not a C symbol: %s", &strs[syms[n].n_un.n_strx]);
              } else {
                fprintf(fout, "symbol %s 0x%llx\n", &strs[syms[n].n_un.n_strx + 1], syms[n].n_value);
              }
            }
          }
        }
      }
    } else {
      LOG("Unknown magic %08x, skipping.", *(uint32_t *)ptr);
    }
  }

  free(output);
  munmap(cache, s.st_size);
  fclose(fout);
  return 0;
}