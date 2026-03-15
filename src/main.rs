use clap::Parser;
use fraudlogix_checker::{csv_handler, pow, types, worker};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, Semaphore};

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

    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    let mut handles = vec![];

    for proxy in proxies {
        let sem = Arc::clone(&semaphore);
        let writer = Arc::clone(&writer);
        let tag = args.tag.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let record = worker::check_proxy_with_retries(&proxy, &tag).await;
            let is_error = record.result.risk_score == "ERROR";

            let mut writer_guard = writer.lock().await;
            writer_guard.write_record(&record);
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
                    &record.result.ip[..record.result.ip.len().min(80)]
                );
            } else {
                let flags: Vec<&str> = ["Proxy", "VPN", "TOR", "DataCenter"]
                    .iter()
                    .filter(|&&k| match k {
                        "Proxy" => {
                            record.result.proxy_flag == "true" || record.result.proxy_flag == "True"
                        }
                        "VPN" => record.result.vpn == "true" || record.result.vpn == "True",
                        "TOR" => record.result.tor == "true" || record.result.tor == "True",
                        "DataCenter" => {
                            record.result.data_center == "true"
                                || record.result.data_center == "True"
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
                    record.result.ip,
                    record.result.risk_score,
                    flags_str,
                    record.result.pow_solve_ms
                );
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.await?;
    }

    let writer_guard = writer.lock().await;
    let (done, _, errors) = writer_guard.get_progress();
    drop(writer_guard);

    let elapsed = start.elapsed().as_secs_f64();
    let rate = done as f64 / elapsed.max(0.001);

    println!(
        "\nDone! {} results -> {} ({} errors) in {:.1}s ({:.1}/s)",
        done, args.output, errors, elapsed, rate
    );

    Ok(())
}
