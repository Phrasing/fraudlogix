use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Check if CUDA toolkit is available.
    let cuda_available = Command::new("nvcc").arg("--version").output().is_ok();

    if cuda_available {
        println!("cargo:warning=CUDA detected - building GPU-accelerated PoW solver");

        // Check if we're in a Visual Studio environment (any version).
        // VS sets these environment variables in Developer Command Prompt.
        let msvc_available = env::var("VSINSTALLDIR").is_ok()
            || env::var("VCToolsInstallDir").is_ok()
            || Command::new("cl.exe").arg("/?").output().is_ok();

        if !msvc_available {
            println!("cargo:warning=");
            println!(
                "cargo:warning=╔══════════════════════════════════════════════════════════════╗"
            );
            println!(
                "cargo:warning=║  CUDA found but missing Visual C++ compiler (cl.exe)        ║"
            );
            println!(
                "cargo:warning=║                                                              ║"
            );
            println!(
                "cargo:warning=║  Install Visual Studio 2022 Build Tools:                    ║"
            );
            println!(
                "cargo:warning=║  1. Download: https://aka.ms/vs/17/release/vs_BuildTools.exe║"
            );
            println!(
                "cargo:warning=║  2. Run installer                                            ║"
            );
            println!(
                "cargo:warning=║  3. Select 'Desktop development with C++'                    ║"
            );
            println!(
                "cargo:warning=║  4. Restart terminal and rebuild                             ║"
            );
            println!(
                "cargo:warning=║                                                              ║"
            );
            println!(
                "cargo:warning=║  Falling back to CPU-only PoW solver for now...             ║"
            );
            println!(
                "cargo:warning=╚══════════════════════════════════════════════════════════════╝"
            );
            println!("cargo:warning=");
            return;
        }

        // Get output directory.
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let dll_path = out_dir.join("pow_solver.dll");

        // Find Visual Studio installation directory.
        let vc_tools_dir = env::var("VCToolsInstallDir")
            .ok()
            .or_else(|| env::var("VCINSTALLDIR").ok());

        if let Some(ref vc_dir) = vc_tools_dir {
            let vc_path = PathBuf::from(vc_dir);

            // Set up bin path for PATH.
            let bin_path = vc_path.join("bin").join("Hostx64").join("x64");
            let mut path_env = env::var("PATH").unwrap_or_default();
            if bin_path.exists() {
                let bin_path_str = bin_path.to_str().unwrap();
                if !path_env.contains(bin_path_str) {
                    path_env = format!("{};{}", bin_path_str, path_env);
                    println!("cargo:warning=Adding VS tools to PATH: {}", bin_path_str,);
                }
            }

            // Set up LIB path for x64 libraries.
            let lib_path = vc_path.join("lib").join("x64");
            let mut lib_env = env::var("LIB").unwrap_or_default();
            if lib_path.exists() {
                let lib_path_str = lib_path.to_str().unwrap();
                lib_env = format!("{};{}", lib_path_str, lib_env);
                println!("cargo:warning=Adding VS libraries to LIB: {}", lib_path_str,);
            }

            // Add Windows SDK libraries (kernel32.lib, etc.).
            if let Ok(windows_sdk_dir) = env::var("WindowsSdkDir") {
                if let Ok(windows_sdk_version) = env::var("WindowsSDKVersion") {
                    let sdk_lib_path = PathBuf::from(&windows_sdk_dir)
                        .join("Lib")
                        .join(windows_sdk_version.trim_end_matches('\\'))
                        .join("um")
                        .join("x64");

                    if sdk_lib_path.exists() {
                        let sdk_lib_str = sdk_lib_path.to_str().unwrap();
                        lib_env = format!("{};{}", sdk_lib_str, lib_env); // Prepend, not append
                        println!(
                            "cargo:warning=Adding Windows SDK libraries: {}",
                            sdk_lib_str,
                        );
                    }

                    // Add UCRT libraries.
                    let ucrt_lib_path = PathBuf::from(&windows_sdk_dir)
                        .join("Lib")
                        .join(windows_sdk_version.trim_end_matches('\\'))
                        .join("ucrt")
                        .join("x64");

                    if ucrt_lib_path.exists() {
                        let ucrt_lib_str = ucrt_lib_path.to_str().unwrap();
                        lib_env = format!("{};{}", ucrt_lib_str, lib_env); // Prepend, not append
                        println!("cargo:warning=Adding UCRT libraries: {}", ucrt_lib_str,);
                    }
                }
            }

            // Set up INCLUDE path.
            let include_env = env::var("INCLUDE").unwrap_or_default();

            // Compile CUDA code with explicit environment variables and required libraries.
            let output = Command::new("nvcc")
                .args(&[
                    "-m64", // Force 64-bit compilation
                    "--shared",
                    "-o",
                    dll_path.to_str().unwrap(),
                    "cuda/pow_solver.cu",
                    "-O3",
                    "-use_fast_math",
                    "--cudart",
                    "static", // Statically link CUDA runtime
                    "-Xcompiler",
                    "/MD", // Use dynamic CRT
                    "-Xlinker",
                    "/NODEFAULTLIB:LIBCMT", // Avoid static CRT conflict
                ])
                .env("PATH", &path_env)
                .env("LIB", &lib_env)
                .env("INCLUDE", &include_env)
                .output()
                .expect("Failed to execute nvcc");

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                eprintln!("CUDA compilation failed!");
                eprintln!("STDOUT: {}", stdout);
                eprintln!("STDERR: {}", stderr);
                panic!("CUDA compilation failed - see output above for details");
            }

            println!("cargo:warning=✓ CUDA PoW solver compiled successfully!");

            // Copy DLL to target directory so it can be found at runtime.
            let target_dir = env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
            let profile = env::var("PROFILE").unwrap();
            let exe_dir = PathBuf::from(&target_dir).join(&profile);
            let dll_dest = exe_dir.join("pow_solver.dll");

            if let Err(e) = std::fs::copy(&dll_path, &dll_dest) {
                println!("cargo:warning=Failed to copy DLL to exe directory: {}", e);
            } else {
                println!("cargo:warning=Copied DLL to: {}", dll_dest.display());
            }

            // Tell cargo to link the DLL.
            println!("cargo:rustc-link-search=native={}", out_dir.display());
            println!("cargo:rustc-link-lib=dylib=pow_solver");
            println!("cargo:rustc-cfg=feature=\"cuda\"");

            println!("cargo:rerun-if-changed=cuda/pow_solver.cu");
            println!("cargo:rerun-if-changed=cuda/pow_solver.h");
            println!("cargo:rerun-if-changed=cuda/sha256.cuh");
            println!("cargo:rerun-if-changed=cuda/sha256.h");
        } else {
            panic!("Could not find Visual Studio installation directory");
        }
    } else {
        println!("cargo:warning=CUDA not detected - using CPU-only PoW solver");
        println!("cargo:warning=Install CUDA Toolkit to enable GPU acceleration");
        println!("cargo:warning=See CUDA_SETUP.md for installation instructions");
    }
}
