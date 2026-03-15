#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sha256.cuh"

namespace {

constexpr int kThreadsPerBlock = 256;
constexpr int kMaxInputLength = 256;

__device__ int CountLeadingZeros(const uint8_t* hash) {
  int count = 0;
  for (int i = 0; i < 32; i++) {
    uint8_t byte = hash[i];
    uint8_t high_nibble = (byte >> 4) & 0xF;
    uint8_t low_nibble = byte & 0xF;

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

__global__ void ProofOfWorkKernel(const char* nonce, int nonce_len,
                                  const char* challenge_key,
                                  int challenge_key_len, uint32_t difficulty,
                                  uint64_t max_attempts, int* found,
                                  uint64_t* result_counter) {
  uint64_t idx = blockIdx.x * blockDim.x + threadIdx.x;
  uint64_t stride = blockDim.x * gridDim.x;

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

    uint64_t counter = idx;
    char counter_str[32];
    int counter_len = 0;

    if (counter == 0) {
      counter_str[counter_len++] = '0';
    } else {
      uint64_t temp = counter;
      int temp_len = 0;
      while (temp > 0) {
        temp /= 10;
        temp_len++;
      }
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
    Sha256Update(&ctx, reinterpret_cast<const uint8_t*>(input), pos);
    uint8_t hash[32];
    Sha256Final(&ctx, hash);

    int leading_zeros = CountLeadingZeros(hash);

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

__declspec(dllexport) int SolvePowCuda(const char* nonce, int nonce_len,
                                       const char* challenge_key,
                                       int challenge_key_len,
                                       uint32_t difficulty,
                                       uint64_t max_attempts,
                                       uint64_t* result_counter) {
  char* d_nonce = nullptr;
  char* d_challenge_key = nullptr;
  int* d_found = nullptr;
  uint64_t* d_result_counter = nullptr;

  cudaMalloc(reinterpret_cast<void**>(&d_nonce), nonce_len);
  cudaMalloc(reinterpret_cast<void**>(&d_challenge_key), challenge_key_len);
  cudaMalloc(reinterpret_cast<void**>(&d_found), sizeof(int));
  cudaMalloc(reinterpret_cast<void**>(&d_result_counter), sizeof(uint64_t));

  cudaMemcpy(d_nonce, nonce, nonce_len, cudaMemcpyHostToDevice);
  cudaMemcpy(d_challenge_key, challenge_key, challenge_key_len,
             cudaMemcpyHostToDevice);

  int host_found = 0;
  uint64_t host_counter = 0;
  cudaMemcpy(d_found, &host_found, sizeof(int), cudaMemcpyHostToDevice);
  cudaMemcpy(d_result_counter, &host_counter, sizeof(uint64_t),
             cudaMemcpyHostToDevice);

  int threads_per_block = kThreadsPerBlock;
  uint64_t needed_blocks =
      (max_attempts + threads_per_block - 1) / threads_per_block;
  int blocks =
      (needed_blocks > 65535) ? 65535 : static_cast<int>(needed_blocks);

  ProofOfWorkKernel<<<blocks, threads_per_block>>>(
      d_nonce, nonce_len, d_challenge_key, challenge_key_len, difficulty,
      max_attempts, d_found, d_result_counter);
  cudaDeviceSynchronize();

  cudaMemcpy(&host_found, d_found, sizeof(int), cudaMemcpyDeviceToHost);
  cudaMemcpy(&host_counter, d_result_counter, sizeof(uint64_t),
             cudaMemcpyDeviceToHost);

  cudaFree(d_nonce);
  cudaFree(d_challenge_key);
  cudaFree(d_found);
  cudaFree(d_result_counter);

  if (host_found == 1) {
    *result_counter = host_counter;
    return 1;
  }
  return 0;
}

__declspec(dllexport) int CudaAvailable() {
  int device_count = 0;
  cudaError_t error = cudaGetDeviceCount(&device_count);
  return (error == cudaSuccess && device_count > 0) ? 1 : 0;
}

__declspec(dllexport) const char* CudaDeviceName() {
  static cudaDeviceProp prop;
  static char device_name[256] = "Unknown";

  int device_count = 0;
  if (cudaGetDeviceCount(&device_count) == cudaSuccess && device_count > 0) {
    if (cudaGetDeviceProperties(&prop, 0) == cudaSuccess) {
      strncpy(device_name, prop.name, sizeof(device_name) - 1);
      return device_name;
    }
  }
  return device_name;
}

}  // extern "C"
