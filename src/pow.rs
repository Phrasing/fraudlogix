use crate::types::Challenge;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};

const KEY: &str = "iows8gfni4bqru7";

static USE_CUDA: AtomicBool = AtomicBool::new(true);

/// Set whether to use CUDA for PoW solving.
pub fn set_solver_preference(use_cuda: bool) {
    USE_CUDA.store(use_cuda, Ordering::Relaxed);
}

/// Check if CUDA GPU acceleration is available.
pub fn is_cuda_available() -> bool {
    #[cfg(feature = "cuda")]
    {
        unsafe { CudaAvailable() != 0 }
    }
    #[cfg(not(feature = "cuda"))]
    {
        false
    }
}

/// Get the name of the CUDA device (if available).
#[cfg(feature = "cuda")]
pub fn get_cuda_device_name() -> Option<String> {
    unsafe {
        if CudaAvailable() == 0 {
            return None;
        }
        let device_ptr = CudaDeviceName();
        if device_ptr.is_null() {
            return None;
        }
        Some(
            std::ffi::CStr::from_ptr(device_ptr)
                .to_string_lossy()
                .to_string(),
        )
    }
}

#[cfg(feature = "cuda")]
#[link(name = "pow_solver")]
extern "C" {
    fn SolvePowCuda(
        nonce: *const u8,
        nonce_len: i32,
        challenge_key: *const u8,
        challenge_key_len: i32,
        difficulty: u32,
        max_attempts: u64,
        result_counter: *mut u64,
    ) -> i32;

    fn CudaAvailable() -> i32;
    fn CudaDeviceName() -> *const i8;
}

/// Shift character by parameter positions (wrapping).
fn shift_char(c: char, param: i32) -> char {
    let code = c as u32;
    match code {
        48..=57 => {
            let shifted = ((code - 48) as i32 + param).rem_euclid(10);
            char::from_u32(48 + shifted as u32).unwrap()
        }
        97..=122 => {
            let shifted = ((code - 97) as i32 + param).rem_euclid(26);
            char::from_u32(97 + shifted as u32).unwrap()
        }
        _ => c,
    }
}

/// Reverse in chunks of size param.
fn reverse_chunks(nonce: &str, param: i32) -> String {
    let param = param as usize;
    let mut result = String::with_capacity(nonce.len());

    for chunk_start in (0..nonce.len()).step_by(param) {
        let chunk_end = (chunk_start + param).min(nonce.len());
        let chunk = &nonce[chunk_start..chunk_end];
        result.push_str(&chunk.chars().rev().collect::<String>());
    }

    result
}

/// Interleave first and second half (zipper pattern).
fn interleave(nonce: &str) -> String {
    let chars: Vec<char> = nonce.chars().collect();
    let half = chars.len() / 2;
    let mut result = String::with_capacity(nonce.len());

    for i in 0..half {
        result.push(chars[i]);
        result.push(chars[chars.len() - 1 - i]);
    }

    if chars.len() % 2 == 1 {
        result.push(chars[half]);
    }

    result
}

pub fn transform_nonce(nonce: &str, challenge: &Challenge) -> (String, f64) {
    match challenge {
        Challenge::Simple {
            operation,
            parameter,
        } => {
            let transformed = match operation.as_str() {
                "shift" => nonce.chars().map(|c| shift_char(c, *parameter)).collect(),
                "reverse" => reverse_chunks(nonce, *parameter),
                "interleave" => interleave(nonce),
                _ => nonce.to_string(),
            };
            (fingerprint_hash(&transformed, KEY), 0.0)
        }
        Challenge::ProofOfWork {
            difficulty,
            challenge_key,
            verifier,
            ..
        } => {
            let start = std::time::Instant::now();
            let result = solve_proof_of_work(nonce, challenge_key, *difficulty, verifier);
            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            (result, elapsed_ms)
        }
    }
}

/// JavaScript-style hash: reduce((h << 5) - h + ord(c)) & 0xFFFFFFFF.
/// (h << 5) - h = h * 31.
pub fn fingerprint_hash(data: &str, salt: &str) -> String {
    let combined = format!("{}{}", data, salt);
    let hash = combined
        .chars()
        .fold(0u32, |h, c| h.wrapping_mul(31).wrapping_add(c as u32));

    format!("fp_{:08x}", hash)
}

/// Solve Proof of Work challenge.
/// Find a counter that when hashed with nonce+challenge_key produces a hash with 'difficulty' leading zeros.
fn solve_proof_of_work(
    nonce: &str,
    challenge_key: &str,
    difficulty: u32,
    _verifier: &str,
) -> String {
    #[cfg(feature = "cuda")]
    {
        if USE_CUDA.load(Ordering::Relaxed) {
            let result = solve_proof_of_work_cuda(nonce, challenge_key, difficulty);
            if result.is_some() {
                return result.unwrap();
            }
        }
    }

    solve_proof_of_work_cpu(nonce, challenge_key, difficulty)
}

/// CUDA-accelerated PoW solver.
#[cfg(feature = "cuda")]
fn solve_proof_of_work_cuda(nonce: &str, challenge_key: &str, difficulty: u32) -> Option<String> {
    unsafe {
        if CudaAvailable() == 0 {
            return None;
        }

        let max_attempts = 100_000_000u64;
        let mut result_counter = 0u64;

        let success = SolvePowCuda(
            nonce.as_ptr(),
            nonce.len() as i32,
            challenge_key.as_ptr(),
            challenge_key.len() as i32,
            difficulty,
            max_attempts,
            &mut result_counter as *mut u64,
        );

        if success == 1 {
            let input = format!("{}{}{}", nonce, challenge_key, result_counter);
            let mut hasher = Sha256::new();
            hasher.update(input.as_bytes());
            let hash = hasher.finalize();
            let hash_hex = hex::encode(&hash);
            return Some(format!("fp_{}", &hash_hex[..8]));
        }
    }

    None
}

/// CPU-only PoW solver (fallback).
fn solve_proof_of_work_cpu(nonce: &str, challenge_key: &str, difficulty: u32) -> String {
    let mut counter = 0u64;

    loop {
        let input = format!("{}{}{}", nonce, challenge_key, counter);

        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let hash = hasher.finalize();

        let hash_hex = hex::encode(&hash);
        let leading_zeros = hash_hex.chars().take_while(|&c| c == '0').count();

        if leading_zeros >= difficulty as usize {
            return format!("fp_{}", &hash_hex[..8]);
        }

        counter += 1;

        if counter > 10_000_000 {
            eprintln!(
                "PoW solver exceeded max iterations for difficulty {}",
                difficulty
            );
            return format!("fp_{:08x}", counter);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shift_char() {
        assert_eq!(shift_char('a', 1), 'b');
        assert_eq!(shift_char('z', 1), 'a');
        assert_eq!(shift_char('0', 1), '1');
        assert_eq!(shift_char('9', 1), '0');
        assert_eq!(shift_char('m', 13), 'z');
        assert_eq!(shift_char('5', 7), '2');
    }

    #[test]
    fn test_fingerprint_hash() {
        let result = fingerprint_hash("test", "salt");
        assert!(result.starts_with("fp_"));
        assert_eq!(result.len(), 11);
    }

    #[test]
    fn test_reverse_chunks() {
        assert_eq!(reverse_chunks("abcdef", 2), "badcfe");
        assert_eq!(reverse_chunks("abcdefg", 3), "cbafedg");
    }

    #[test]
    fn test_interleave() {
        assert_eq!(interleave("abcd"), "adbc");
        assert_eq!(interleave("abcde"), "aebdc");
    }
}
