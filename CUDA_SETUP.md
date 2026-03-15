# CUDA PoW Solver Setup Guide

Enable GPU-accelerated Proof of Work solving for dramatically faster proxy checking.

## Expected Performance

Typical performance improvements with CUDA:
- **CPU**: ~50-150ms per PoW solve (difficulty 4)
- **GPU**: ~0.3-2ms per PoW solve (**~75-500x faster**)

Actual speedup depends on your GPU model and difficulty level. The application displays per-proxy PoW solve times in the output.

## Prerequisites

**IMPORTANT:** You need **both** CUDA Toolkit AND Visual Studio C++ compiler.

### Required Software

1. **Visual Studio Build Tools** - 2022, 2026, or newer (install FIRST)
2. **CUDA Toolkit 12.x** (install SECOND)
3. **NVIDIA GPU** - Compute Capability 6.0+ (GTX 1000 series or newer)

## Installation Steps

### 1. Install Visual Studio C++ Build Tools

**This is required BEFORE installing CUDA!**

Download and install Visual Studio 2022 Build Tools:
https://aka.ms/vs/17/release/vs_BuildTools.exe

**Installation steps:**
1. Run `vs_BuildTools.exe`
2. Select **"Desktop development with C++"** workload
3. On the right panel, ensure these are checked:
   - MSVC v143 - VS 2022 C++ x64/x86 build tools
   - Windows 11 SDK (or Windows 10 SDK)
4. Click Install (requires ~6-8 GB disk space)
5. **Restart your computer** after installation

**Verify installation:**
```bash
# Open "Developer Command Prompt for VS 2022" (or VS 2026)
cl.exe
# Should show: Microsoft (R) C/C++ Optimizing Compiler Version 19.xx
```

### 2. Install CUDA Toolkit

Download and install CUDA Toolkit 12.x for Windows:
https://developer.nvidia.com/cuda-downloads

**Direct link for Windows:**
https://developer.download.nvidia.com/compute/cuda/12.6.3/local_installers/cuda_12.6.3_561.17_windows.exe

**Installation options:**
- Choose "Custom" installation
- **Required components:**
  - CUDA Toolkit
  - CUDA Compiler (nvcc)
  - CUDA Runtime Libraries
- Optional (but recommended):
  - Visual Studio Integration
  - CUDA Documentation

### 3. Verify CUDA Installation

Open a new terminal (important - to reload PATH) and run:

```bash
nvcc --version
```

You should see output like:
```
nvcc: NVIDIA (R) Cuda compiler driver
Copyright (c) 2005-2024 NVIDIA Corporation
Built on ...
Cuda compilation tools, release 12.6, V12.6.xxx
```

### 4. Rebuild with CUDA Support

**IMPORTANT:** Use "Developer Command Prompt for VS" (not regular terminal)

1. Open **"Developer Command Prompt for VS 2022"** (or VS 2026) from Start Menu
2. Navigate to project:
   ```bash
   cd /w/fraudlogix
   ```
3. Clean and rebuild:
   ```bash
   cargo clean
   cargo build --release
   ```

**Success indicators:**
```
warning: CUDA detected - building GPU-accelerated PoW solver
...
warning: ✓ CUDA PoW solver compiled successfully!
warning: Copied DLL to: target\release\pow_solver.dll
```

**If you see errors:**
- "cl.exe not found" → Reinstall VS Build Tools, use Developer Command Prompt
- "CUDA compilation failed" → Check CUDA Toolkit installation
- "nvcc not found" → Restart terminal after CUDA installation

### 5. Test GPU Acceleration

Run a quick test:

```bash
./target/release/fraudlogix-checker.exe --solver cuda -c 5 -o test_cuda.csv
```

**Output should show:**
```
[GPU] Using CUDA device: NVIDIA GeForce RTX xxxx
[default] Checking 5 proxies (concurrency: 5)...
[1/5] [OK] proxy:1234 -> 1.2.3.4 | High [Proxy] (PoW: 1.23ms)
```

The `(PoW: X.XXms)` shows GPU-accelerated solve time (should be <5ms).

You can verify CUDA is being used by checking GPU utilization:

```bash
# Open a second terminal and run:
nvidia-smi -l 1
```

You should see the `fraudlogix-checker.exe` process using GPU resources.

## Solver Selection

The application supports three solver modes:

```bash
# Automatic (default) - Uses CUDA if available, falls back to CPU
./target/release/fraudlogix-checker.exe

# Force CUDA - Requires GPU, warns and falls back if unavailable
./target/release/fraudlogix-checker.exe --solver cuda

# Force CPU - Disables CUDA even if available
./target/release/fraudlogix-checker.exe --solver cpu
```

The startup message shows which solver is active:
- `[GPU] Using CUDA device: <name>` - GPU acceleration enabled
- `[CPU] Using CPU-only PoW solver` - CPU fallback

## Troubleshooting

### "nvcc: command not found"

- CUDA Toolkit not installed, or PATH not updated
- **Solution**: Restart your terminal after installing CUDA, or manually add to PATH:
  ```
  C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.6\bin
  ```

### "CUDA compilation failed"

- Visual Studio C++ compiler might be missing
- **Solution**: Install "Desktop development with C++" workload from Visual Studio 2022

### "CUDA not detected" warning persists

- Restart terminal after CUDA installation
- Verify `nvcc --version` works
- Try `cargo clean` before rebuilding

### GPU not being utilized

- Check if DLL was created:
  ```bash
  ls target/release/pow_solver.dll
  ```
- If missing, check CUDA installation and rebuild
- Try forcing CUDA mode: `--solver cuda`

### PoW times still slow (>10ms)

- CUDA may not be enabled - check startup message for `[GPU]` or `[CPU]`
- Try rebuilding: `cargo clean && cargo build --release`
- Verify GPU is detected: application should show device name on startup

## Architecture Details

The CUDA implementation:
- Launches 65,535 blocks × 256 threads = **16.7 million parallel computations**
- Each thread tests different counter values simultaneously
- Uses atomic operations to signal when solution found
- Automatically falls back to CPU if CUDA unavailable

### Key Files

- `cuda/pow_solver.cu` - Main CUDA kernel (Google C++ style)
- `cuda/sha256.cuh` - GPU SHA-256 implementation
- `cuda/sha256.h` - SHA-256 context definitions
- `cuda/pow_solver.h` - C interface for Rust FFI
- `src/pow.rs` - Rust wrapper with CUDA/CPU selection
- `build.rs` - Build script that compiles CUDA code

The speedup factor depends on:
- **PoW difficulty**: Higher difficulty = larger speedup
- **Concurrency**: Multiple simultaneous requests can fully utilize GPU
