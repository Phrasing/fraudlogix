#ifndef FRAUDLOGIX_CUDA_POW_SOLVER_H_
#define FRAUDLOGIX_CUDA_POW_SOLVER_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int SolvePowCuda(const char* nonce, int nonce_len,
                 const char* challenge_key, int challenge_key_len,
                 uint32_t difficulty, uint64_t max_attempts,
                 uint64_t* result_counter);

int CudaAvailable();

const char* CudaDeviceName();

#ifdef __cplusplus
}
#endif

#endif  // FRAUDLOGIX_CUDA_POW_SOLVER_H_
