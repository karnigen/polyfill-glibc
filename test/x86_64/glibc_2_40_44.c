#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include "../../src/common.h"

static void* polyfill(void* lib, const char* name) {
  void* fn = dlvsym(lib, name, "POLYFILL");
  if (!fn) FATAL("Could not find polyfill %s", name);
  return fn;
}

int main(int argc, const char** argv) {
  ASSERT(argc >= 2);
  void* lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!lib) FATAL("Could not dlopen %s", argv[1]);

  size_t (*memalignment_fn)(const void*) = polyfill(lib, "memalignment");
  ASSERT(memalignment_fn(NULL) == 0);
  ASSERT(memalignment_fn((const void*)(uintptr_t)0x123400) == 0x400);

  unsigned int (*uabs_fn)(int) = polyfill(lib, "uabs");
  unsigned long (*ulabs_fn)(long) = polyfill(lib, "ulabs");
  unsigned long long (*ullabs_fn)(long long) = polyfill(lib, "ullabs");
  uintmax_t (*uimaxabs_fn)(intmax_t) = polyfill(lib, "uimaxabs");
  ASSERT(uabs_fn(INT_MIN) == (unsigned int)INT_MAX + 1);
  ASSERT(ulabs_fn(LONG_MIN) == (unsigned long)LONG_MAX + 1);
  ASSERT(ullabs_fn(LLONG_MIN) == (unsigned long long)LLONG_MAX + 1);
  ASSERT(uimaxabs_fn(INTMAX_MIN) == (uintmax_t)INTMAX_MAX + 1);

  void* (*memset_explicit_fn)(void*, int, size_t) = polyfill(lib, "memset_explicit");
  void* (*memset_explicit_chk_fn)(void*, int, size_t, size_t) =
    polyfill(lib, "__memset_explicit_chk");
  char bytes[8] = {0};
  ASSERT(memset_explicit_fn(bytes, 0x5a, sizeof(bytes)) == bytes);
  for (size_t i = 0; i < sizeof(bytes); ++i) ASSERT(bytes[i] == 0x5a);
  ASSERT(memset_explicit_chk_fn(bytes, 0x2a, 4, sizeof(bytes)) == bytes);
  for (size_t i = 0; i < 4; ++i) ASSERT(bytes[i] == 0x2a);

  void (*free_sized_fn)(void*, size_t) = polyfill(lib, "free_sized");
  void (*free_aligned_sized_fn)(void*, size_t, size_t) =
    polyfill(lib, "free_aligned_sized");
  free_sized_fn(malloc(32), 32);
  free_aligned_sized_fn(aligned_alloc(64, 128), 64, 128);

  int (*sched_getattr_fn)(pid_t, void*, unsigned int, unsigned int) =
    polyfill(lib, "sched_getattr");
  int (*sched_setattr_fn)(pid_t, void*, unsigned int) =
    polyfill(lib, "sched_setattr");
  uint64_t sched_attr[16] = {sizeof(sched_attr)};
  ASSERT(sched_getattr_fn(0, sched_attr, sizeof(sched_attr), 0) == 0);
  errno = 0;
  ASSERT(sched_setattr_fn(0, sched_attr, 1) == -1 && errno == EINVAL);

  int (*openat2_fn)(int, const char*, const void*, size_t) = polyfill(lib, "openat2");
  uint64_t open_how[3] = {O_RDONLY | O_CLOEXEC, 0, 0};
  int fd = openat2_fn(AT_FDCWD, "/dev/null", open_how, sizeof(open_how));
  if (fd >= 0) close(fd);
  else ASSERT(errno == ENOSYS);

  const char* (*inet_ntop_chk_fn)(int, const void*, char*, socklen_t, size_t) =
    polyfill(lib, "__inet_ntop_chk");
  int (*inet_pton_chk_fn)(int, const char*, void*, size_t) =
    polyfill(lib, "__inet_pton_chk");
  const unsigned char address[4] = {127, 0, 0, 1};
  char text[INET_ADDRSTRLEN];
  ASSERT(inet_ntop_chk_fn(AF_INET, address, text, sizeof(text), sizeof(text)) == text);
  unsigned char parsed[16];
  ASSERT(inet_pton_chk_fn(AF_INET, text, parsed, sizeof(parsed)) == 1);
  ASSERT(memcmp(address, parsed, sizeof(address)) == 0);

  int (*mseal_fn)(void*, size_t, unsigned int) = polyfill(lib, "mseal");
  size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
  void* page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT(page != MAP_FAILED);
  if (mseal_fn(page, page_size, 0) != 0) {
    ASSERT(errno == ENOSYS);
    ASSERT(munmap(page, page_size) == 0);
  }

  FILE* f = argv[2] ? fopen(argv[2], "w") : stdout;
  fputs("OK\n", f);
  fclose(f);
  return 0;
}
