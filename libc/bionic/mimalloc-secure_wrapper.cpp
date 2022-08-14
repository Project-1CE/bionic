/*
 * Copyright (C) 2021 The ProtonAOSP Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <errno.h>
#include <stdio.h>

#include "mimalloc-secure_wrapper.h"

int mi_secure_mallopt(int param, int value) {
  if (param == M_DECAY_TIME) {
    long decay_time_ms;
    if (value < 0) {
      decay_time_ms = -1;
    } else if (value) {
      decay_time_ms = 100;
    } else {
      decay_time_ms = 0;
    }
    mi_secure_option_set(mi_option_purge_delay, decay_time_ms);
    return 1;
  }
  else if (param == M_PURGE || param == M_PURGE_ALL) {
    mi_secure_collect(true);
    return 1;
  }

  /* not implemented */
  return 0;
}

// Info dumps are not supported
int mi_secure_malloc_info(int /*options*/, FILE* /*fp*/) {
  errno = ENOTSUP;
  return -1;
}

struct mallinfo mi_secure_mallinfo() {
  struct mallinfo info {};
  return info;
}

// libmemunreachable is not supported
void mi_secure_malloc_disable() {
}

void mi_secure_malloc_enable() {
}

int mi_secure_malloc_iterate(uintptr_t, size_t, void (*)(uintptr_t, size_t, void*), void*) {
  return 0;
}
