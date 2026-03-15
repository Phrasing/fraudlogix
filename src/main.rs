use clap::Parser;
use fraudlogix_checker::{csv_handler, pow, types, worker};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, Semaphore};

#[derive(Default)]
struct Statistics {
    risk_low: usize,
    risk_medium: usize,
    risk_high: usize,
    risk_extreme: usize,
    risk_error: usize,
    risk_rate_limited: usize,
    flag_proxy: usize,
    flag_vpn: usize,
    flag_tor: usize,
    flag_datacenter: usize,
}

#[derive(Parser)]
#[command(name = "fraudlogix-checker")]
#[command(about = "Bulk proxy IP fraud score checker")]
struct Args {
    #[arg(long, default_value = "default")]
    tag: String,

    #[arg(short, long, default_value = "50")]
    concurrency: usize,

    #[arg(short, long, default_value = "results.csv")]
    output: String,

    #[arg(short, long)]
    append: bool,

    #[arg(short = 'n', long)]
    limit: Option<usize>,

    #[arg(long, default_value = "auto", value_parser = ["auto", "cuda", "cpu"])]
    solver: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let proxy_file = "proxies.txt";
    anyhow::ensure!(Path::new(proxy_file).exists(), "proxies.txt not found");

    let content = std::fs::read_to_string(proxy_file)?;
    let mut proxies: Vec<String> = content
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    anyhow::ensure!(!proxies.is_empty(), "proxies.txt is empty");

    if let Some(limit) = args.limit {
        proxies.truncate(limit);
    }

    let mut done_set = HashSet::new();
    let append = if args.append && Path::new(&args.output).exists() {
        let mut reader = csv::Reader::from_path(&args.output)?;
        for result in reader.deserialize() {
            let record: types::CsvRecord = result?;
            done_set.insert(record.proxy);
        }

        proxies.retain(|p| !done_set.contains(p));
        println!(
            "Resuming: {} done, {} remaining",
            done_set.len(),
            proxies.len()
        );

        if proxies.is_empty() {
            println!("All proxies already checked");
            return Ok(());
        }
        true
    } else {
        false
    };

    let use_cuda = match args.solver.as_str() {
        "cuda" => {
            if pow::is_cuda_available() {
                true
            } else {
                eprintln!(
                    "Warning: --solver=cuda specified but CUDA not available, falling back to CPU"
                );
                false
            }
        }
        "cpu" => false,
        "auto" | _ => pow::is_cuda_available(),
    };

    pow::set_solver_preference(use_cuda);

    if use_cuda {
        #[cfg(feature = "cuda")]
        {
            if let Some(device_name) = pow::get_cuda_device_name() {
                println!("[GPU] Using CUDA device: {}", device_name);
            } else {
                println!("[GPU] CUDA solver enabled");
            }
        }
    } else {
        println!("[CPU] Using CPU-only PoW solver");
    }

    println!(
        "[{}] Checking {} proxies (concurrency: {})...",
        args.tag,
        proxies.len(),
        args.concurrency
    );

    let start = Instant::now();

    let writer = Arc::new(Mutex::new(csv_handler::CsvWriter::new(
        &args.output,
        append,
        proxies.len(),
    )?));

    let stats = Arc::new(Mutex::new(Statistics::default()));
    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    let mut handles = vec![];

    for proxy in proxies {
        let sem = Arc::clone(&semaphore);
        let writer = Arc::clone(&writer);
        let stats = Arc::clone(&stats);
        let tag = args.tag.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let record = worker::check_proxy_with_retries(&proxy, &tag).await;
            let is_error = record.risk_score == "ERROR";

            // Update statistics
            let mut stats_guard = stats.lock().await;
            match record.risk_score.as_str() {
                "Low" => stats_guard.risk_low += 1,
                "Medium" => stats_guard.risk_medium += 1,
                "High" => stats_guard.risk_high += 1,
                "Extreme" => stats_guard.risk_extreme += 1,
                "ERROR" => stats_guard.risk_error += 1,
                "RATE_LIMITED" => stats_guard.risk_rate_limited += 1,
                _ => {}
            }
            if record.proxy_flag == "true" || record.proxy_flag == "True" {
                stats_guard.flag_proxy += 1;
            }
            if record.vpn == "true" || record.vpn == "True" {
                stats_guard.flag_vpn += 1;
            }
            if record.tor == "true" || record.tor == "True" {
                stats_guard.flag_tor += 1;
            }
            if record.data_center == "true" || record.data_center == "True" {
                stats_guard.flag_datacenter += 1;
            }
            drop(stats_guard);

            let mut writer_guard = writer.lock().await;
            if let Err(e) = writer_guard.write_record(&record) {
                eprintln!("Error writing to CSV: {}", e);
            }
            writer_guard.increment_done(is_error);

            // Get progress and release lock before printing
            let (done, total, _errors) = writer_guard.get_progress();
            drop(writer_guard);

            if is_error {
                println!(
                    "[{}/{}] [ERR] {} -> {}",
                    done,
                    total,
                    proxy,
                    &record.ip[..record.ip.len().min(80)]
                );
            } else {
                let flags: Vec<&str> = ["Proxy", "VPN", "TOR", "DataCenter"]
                    .iter()
                    .filter(|&&k| match k {
                        "Proxy" => {
                            record.proxy_flag == "true" || record.proxy_flag == "True"
                        }
                        "VPN" => record.vpn == "true" || record.vpn == "True",
                        "TOR" => record.tor == "true" || record.tor == "True",
                        "DataCenter" => {
                            record.data_center == "true"
                                || record.data_center == "True"
                        }
                        _ => false,
                    })
                    .copied()
                    .collect();

                let flags_str = if flags.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", flags.join("/"))
                };

                println!(
                    "[{}/{}] [OK] {} -> {} | {}{} (PoW: {:.2}ms)",
                    done,
                    total,
                    proxy,
                    record.ip,
                    record.risk_score,
                    flags_str,
                    record.pow_solve_ms
                );
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.await?;
    }

    let mut writer_guard = writer.lock().await;
    let (done, _, errors) = writer_guard.get_progress();

    // Explicitly flush the CSV writer before program exit.
    if let Err(e) = writer_guard.flush() {
        eprintln!("Error flushing CSV file: {}", e);
    }
    drop(writer_guard);

    let elapsed = start.elapsed().as_secs_f64();
    let rate = done as f64 / elapsed.max(0.001);

    println!(
        "\nDone! {} results -> {} ({} errors) in {:.1}s ({:.1}/s)",
        done, args.output, errors, elapsed, rate
    );

    // Print statistics summary
    let stats_guard = stats.lock().await;
    println!("\n=== Summary ===");
    println!("Risk Scores:");
    if stats_guard.risk_low > 0 {
        println!("  Low:          {}", stats_guard.risk_low);
    }
    if stats_guard.risk_medium > 0 {
        println!("  Medium:       {}", stats_guard.risk_medium);
    }
    if stats_guard.risk_high > 0 {
        println!("  High:         {}", stats_guard.risk_high);
    }
    if stats_guard.risk_extreme > 0 {
        println!("  Extreme:      {}", stats_guard.risk_extreme);
    }
    if stats_guard.risk_error > 0 {
        println!("  ERROR:        {}", stats_guard.risk_error);
    }
    if stats_guard.risk_rate_limited > 0 {
        println!("  RATE_LIMITED: {}", stats_guard.risk_rate_limited);
    }

    let total_flags = stats_guard.flag_proxy
        + stats_guard.flag_vpn
        + stats_guard.flag_tor
        + stats_guard.flag_datacenter;
    if total_flags > 0 {
        println!("\nFlags:");
        if stats_guard.flag_proxy > 0 {
            println!("  Proxy:      {}", stats_guard.flag_proxy);
        }
        if stats_guard.flag_vpn > 0 {
            println!("  VPN:        {}", stats_guard.flag_vpn);
        }
        if stats_guard.flag_tor > 0 {
            println!("  TOR:        {}", stats_guard.flag_tor);
        }
        if stats_guard.flag_datacenter > 0 {
            println!("  DataCenter: {}", stats_guard.flag_datacenter);
        }
    }

    Ok(())
}
