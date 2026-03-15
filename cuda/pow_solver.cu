#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sha256.cuh"

namespace {

constexpr int kThreadsPerBlock = 256;
constexpr int kMaxInputLength = 256;

template <typename F>
struct Defer {
  F f;
  explicit Defer(F f) : f(f) {}
  ~Defer() {
    f();
  }
};

template <typename F>
Defer<F> MakeDefer(F f) {
  return Defer<F>(f);
}

#define DEFER_CONCAT_IMPL(x, y) x##y
#define DEFER_CONCAT(x, y) DEFER_CONCAT_IMPL(x, y)
#define defer(code) auto DEFER_CONCAT(_defer_, __LINE__) = MakeDefer([&]() { code; })

__device__ int CountLeadingZeros(const uint8_t *hash) {
  int count = 0;
  for (int i = 0; i < 32; i++) {
    const uint8_t byte = hash[i];
    const uint8_t high_nibble = (byte >> 4) & 0xF;
    const uint8_t low_nibble = byte & 0xF;

    if (high_nibble == 0) {
      count++;
      if (low_nibble == 0) {
        count++;
      } else {
        break;
      }
    } else {
      break;
    }
  }
  return count;
}

__global__ void ProofOfWorkKernel(const char *nonce, const int nonce_len, const char *challenge_key,
                                  const int challenge_key_len, const uint32_t difficulty,
                                  const uint64_t max_attempts, int *found,
                                  uint64_t *result_counter) {
  uint64_t idx = blockIdx.x * blockDim.x + threadIdx.x;
  const uint64_t stride = blockDim.x * gridDim.x;

  while (idx < max_attempts) {
    if (atomicAdd(found, 0) != 0) {
      return;
    }

    char input[kMaxInputLength];
    int pos = 0;

    for (int i = 0; i < nonce_len && pos < kMaxInputLength - 1; i++) {
      input[pos++] = nonce[i];
    }

    for (int i = 0; i < challenge_key_len && pos < kMaxInputLength - 1; i++) {
      input[pos++] = challenge_key[i];
    }

    const uint64_t counter = idx;
    char counter_str[32];
    int counter_len = 0;

    if (counter == 0) {
      counter_str[counter_len++] = '0';
    } else {
      uint64_t temp = counter;
      const int temp_len = [&]() {
        int len = 0;
        uint64_t t = temp;
        while (t > 0) {
          t /= 10;
          len++;
        }
        return len;
      }();
      counter_len = temp_len;
      temp = counter;
      for (int i = temp_len - 1; i >= 0; i--) {
        counter_str[i] = '0' + (temp % 10);
        temp /= 10;
      }
    }

    for (int i = 0; i < counter_len && pos < kMaxInputLength - 1; i++) {
      input[pos++] = counter_str[i];
    }

    Sha256Context ctx;
    Sha256Init(&ctx);
    Sha256Update(&ctx, reinterpret_cast<const uint8_t *>(input), pos);
    uint8_t hash[32];
    Sha256Final(&ctx, hash);

    const int leading_zeros = CountLeadingZeros(hash);

    if (leading_zeros >= static_cast<int>(difficulty)) {
      if (atomicCAS(found, 0, 1) == 0) {
        *result_counter = idx;
      }
      return;
    }

    idx += stride;
  }
}

}  // namespace

extern "C" {

__declspec(dllexport) int SolvePowCuda(const char *nonce, const int nonce_len,
                                       const char *challenge_key, const int challenge_key_len,
                                       const uint32_t difficulty, const uint64_t max_attempts,
                                       uint64_t *result_counter) {
  // Validate input length to prevent buffer overflow.
  // Maximum counter is 20 digits for uint64_t max value (18446744073709551615).
  // Reserve space: nonce + challenge_key + counter (20 chars max) + null terminator.
  if (nonce_len + challenge_key_len + 20 >= kMaxInputLength) {
    return 0;
  }

  char *d_nonce = nullptr;
  char *d_challenge_key = nullptr;
  int *d_found = nullptr;
  uint64_t *d_result_counter = nullptr;
  cudaError_t err;

  // Allocate d_nonce.
  err = cudaMalloc(reinterpret_cast<void **>(&d_nonce), nonce_len);
  if (err != cudaSuccess) {
    return 0;
  }
  defer(cudaFree(d_nonce));

  // Allocate d_challenge_key.
  err = cudaMalloc(reinterpret_cast<void **>(&d_challenge_key), challenge_key_len);
  if (err != cudaSuccess) {
    return 0;
  }
  defer(cudaFree(d_challenge_key));

  // Allocate d_found.
  err = cudaMalloc(reinterpret_cast<void **>(&d_found), sizeof(int));
  if (err != cudaSuccess) {
    return 0;
  }
  defer(cudaFree(d_found));

  // Allocate d_result_counter.
  err = cudaMalloc(reinterpret_cast<void **>(&d_result_counter), sizeof(uint64_t));
  if (err != cudaSuccess) {
    return 0;
  }
  defer(cudaFree(d_result_counter));

  // Copy nonce to device.
  err = cudaMemcpy(d_nonce, nonce, nonce_len, cudaMemcpyHostToDevice);
  if (err != cudaSuccess) {
    return 0;
  }

  // Copy challenge_key to device.
  err = cudaMemcpy(d_challenge_key, challenge_key, challenge_key_len, cudaMemcpyHostToDevice);
  if (err != cudaSuccess) {
    return 0;
  }

  // Initialize and copy host variables to device.
  int host_found = 0;
  uint64_t host_counter = 0;

  err = cudaMemcpy(d_found, &host_found, sizeof(int), cudaMemcpyHostToDevice);
  if (err != cudaSuccess) {
    return 0;
  }

  err = cudaMemcpy(d_result_counter, &host_counter, sizeof(uint64_t), cudaMemcpyHostToDevice);
  if (err != cudaSuccess) {
    return 0;
  }

  // Launch kernel.
  constexpr int threads_per_block = kThreadsPerBlock;
  const uint64_t needed_blocks = (max_attempts + threads_per_block - 1) / threads_per_block;
  const int blocks = (needed_blocks > 65535) ? 65535 : static_cast<int>(needed_blocks);

  ProofOfWorkKernel<<<blocks, threads_per_block>>>(d_nonce, nonce_len, d_challenge_key,
                                                   challenge_key_len, difficulty, max_attempts,
                                                   d_found, d_result_counter);
  cudaDeviceSynchronize();

  // Copy results back to host.
  cudaMemcpy(&host_found, d_found, sizeof(int), cudaMemcpyDeviceToHost);
  cudaMemcpy(&host_counter, d_result_counter, sizeof(uint64_t), cudaMemcpyDeviceToHost);

  // defer() statements automatically clean up all allocated memory here.

  if (host_found == 1) {
    *result_counter = host_counter;
    return 1;
  }
  return 0;
}

__declspec(dllexport) int CudaAvailable() {
  int device_count = 0;
  const cudaError_t error = cudaGetDeviceCount(&device_count);
  return (error == cudaSuccess && device_count > 0) ? 1 : 0;
}

__declspec(dllexport) const char *CudaDeviceName() {
  // Use thread_local to ensure thread-safety (C++11 feature).
  thread_local static cudaDeviceProp prop;
  thread_local static bool initialized = false;

  if (!initialized) {
    int device_count = 0;
    if (cudaGetDeviceCount(&device_count) == cudaSuccess && device_count > 0) {
      cudaGetDeviceProperties(&prop, 0);
    }
    initialized = true;
  }
  return prop.name;  // prop.name is char[256] in cudaDeviceProp struct, guaranteed null-terminated.
}

}  // extern "C"
