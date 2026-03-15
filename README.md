# Fraudlogix IP Fraud Score Checker

High-performance bulk proxy fraud score checker using the Fraudlogix API.

## Features

- **GPU-Accelerated**: CUDA support for 75-500x faster Proof of Work solving
- **Intelligent Rate Limiting**: Exponential backoff with jitter handles API rate limits
- **Fallback IP Detection**: Captures proxy IPs via alternative services when Fraudlogix rate limits
- **High Concurrency**: Test hundreds of proxies simultaneously
- **Resume Support**: Continue interrupted tests from where you left off

## Prerequisites

- Rust 1.70+ ([install here](https://rustup.rs/))
- NVIDIA GPU with CUDA Toolkit 12.x (optional, for GPU acceleration)

## Building

```bash
# CPU-only build
cargo build --release

# GPU-accelerated build (requires CUDA Toolkit)
cargo build --release --features cuda
```

For GPU acceleration setup, see [CUDA_SETUP.md](CUDA_SETUP.md).

## Usage

```bash
# Basic usage (auto-detects CUDA if available)
./target/release/fraudlogix-checker.exe

# Check with high concurrency
./target/release/fraudlogix-checker.exe -c 250 -o results.csv

# Force CPU solver
./target/release/fraudlogix-checker.exe --solver cpu

# Test only first 100 proxies
./target/release/fraudlogix-checker.exe -n 100

# Append to existing results (skip already-tested proxies)
./target/release/fraudlogix-checker.exe --append
```

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-c, --concurrency <N>` | Number of concurrent proxy checks | 10 |
| `-o, --output <FILE>` | Output CSV file path | `results.csv` |
| `-n, --limit <N>` | Test only first N proxies from input file | All |
| `--solver <MODE>` | PoW solver: `auto`, `cuda`, or `cpu` | `auto` |
| `-a, --append` | Append to output file, skip tested proxies | false |
| `-t, --tag <TAG>` | Tag for proxy batch | `default` |

## Proxy Format

Create a `proxies.txt` file with one proxy per line:

```
username:password@host:port
host:port:username:password
host:port
```

Supports HTTP, HTTPS, and SOCKS5 proxies.

## Output

Results are saved to CSV with fraud scores and IP metadata:

```csv
tag,proxy,IP,RiskScore,RecentlySeen,ConnectionType,Proxy,VPN,TOR,DataCenter,...
default,proxy1,1.2.3.4,High,true,Residential,true,false,false,false,...
default,proxy2,5.6.7.8,RATE_LIMITED,,,,,,,,...
```

**Status values:**
- Risk score (High/Medium/Low) = Full fraud check completed
- `RATE_LIMITED` = Proxy works, IP detected via fallback, fraud check rate limited
- `ERROR` = Complete failure

## How It Works

Each proxy goes through the following testing flow:

1. **Proxy Configuration**: HTTP/2 client is configured with the proxy and Chrome 145 browser fingerprint emulation
2. **IP Detection** (`GET /get_user_ip`): Retrieves the proxy's actual IP address and receives an authentication token (`x-fl-new-token`)
3. **Challenge Request** (`GET /get_nonce`): Receives a cryptographic nonce and Proof of Work challenge from the server
4. **PoW Solving**: Finds a valid counter that satisfies the challenge requirements (see below for details)
5. **Browser Fingerprinting**: Generates realistic browser data including TLS fingerprints, client hints, and timing data
6. **Fraud Check** (`POST /ip_response_json`): Submits the solved challenge with browser fingerprint to receive fraud score and IP metadata
7. **Error Handling**: If any step fails:
   - **Retryable errors** (rate limits, network issues): Exponential backoff retry with jitter (1s → 2s → 4s → 8s → 16s → 32s → 60s max)
   - **Permanent errors** (invalid proxy format): Immediate failure, no retries
   - **Final attempt fallback**: If Fraudlogix rate limits, attempts to detect IP via alternative services (ipify.org, ifconfig.me, icanhazip.com)
8. **Result Recording**: Writes fraud score, IP metadata, and PoW solve time to CSV

The entire flow typically completes in 1-3 seconds per proxy (depending on PoW difficulty and network latency).

## Proof of Work Solving

Fraudlogix uses Proof of Work (PoW) challenges to rate-limit automated requests. The challenge requires finding a counter value that, when combined with the nonce and challenge key, produces a SHA-256 hash with a specified number of leading zeros.

### Algorithm

```
Input: nonce, challenge_key, difficulty (e.g., 4 leading zeros)
Goal: Find counter where SHA256(nonce + challenge_key + counter) starts with 0000...

Example:
SHA256("abc123" + "xyz789" + "0") = "a3f2..." ❌ (no leading zeros)
SHA256("abc123" + "xyz789" + "1") = "9c1e..." ❌ (no leading zeros)
...
SHA256("abc123" + "xyz789" + "14523") = "0000d8..." ✅ (4 leading zeros!)
```

### CPU vs GPU Implementation

**CPU Solver** (`--solver cpu`):
- Sequential search: tests counter = 0, 1, 2, 3, ...
- Single-threaded SHA-256 hashing
- Performance: ~50-150ms for difficulty 4 (typical)
- Fallback when CUDA unavailable

**GPU Solver** (`--solver cuda`, requires CUDA build):
- **Massive parallelization**: 65,535 blocks × 256 threads = **16,777,216 simultaneous attempts**
- Each GPU thread tests a different counter value in parallel
- Atomic operations signal when solution found
- Performance: ~0.3-2ms for difficulty 4 (**75-500x faster** than CPU)
- Automatically falls back to CPU if GPU unavailable

### Performance Impact

| Difficulty | Leading Zeros | CPU Time | GPU Time | Speedup |
|------------|---------------|----------|----------|---------|
| 3 | `000...` | ~10-50ms | ~0.2-1ms | ~50x |
| 4 | `0000...` | ~50-150ms | ~0.3-2ms | ~100x |
| 5 | `00000...` | ~500-1500ms | ~2-10ms | ~200x |
| 6 | `000000...` | ~5-15s | ~20-100ms | ~300x |

Higher difficulty = exponentially more attempts needed = greater GPU advantage.

The application displays per-proxy PoW solve times in the output, allowing you to monitor performance in real-time.

## Performance

**CPU**: ~50-150ms per PoW solve
**GPU (CUDA)**: ~0.3-2ms per PoW solve (~75-500x faster)

Actual speedup depends on GPU model and difficulty level.

## License

MIT
