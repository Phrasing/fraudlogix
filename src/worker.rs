use crate::backoff::ExponentialBackoff;
use crate::client::FraudlogixClient;
use crate::fallback_ip::FallbackIpDetector;
use crate::types::*;

const MAX_RETRIES: u32 = 6;

pub async fn check_proxy_with_retries(proxy_str: &str, tag: &str) -> CsvRecord {
    let proxy = match ProxyConfig::parse(proxy_str) {
        Ok(p) => p,
        Err(_) => {
            return CsvRecord {
                tag: tag.to_string(),
                proxy: proxy_str.to_string(),
                result: FraudResult {
                    ip: "invalid format".to_string(),
                    risk_score: "ERROR".to_string(),
                    ..Default::default()
                },
            };
        }
    };

    let mut backoff = ExponentialBackoff::new();
    let mut last_error = String::new();
    let mut fallback_ip: Option<String> = None;

    for attempt in 0..=MAX_RETRIES {
        if attempt > 0 {
            let delay = backoff.next_delay();
            eprintln!(
                "[RETRY] {} (attempt {}/{}, waiting {:.1}s): {}",
                &proxy.original[..proxy.original.len().min(60)],
                attempt,
                MAX_RETRIES,
                delay.as_secs_f64(),
                last_error
            );
            tokio::time::sleep(delay).await;
        }

        match FraudlogixClient::new(&proxy) {
            Ok(client) => match client.check_ip().await {
                Ok(result) => {
                    return CsvRecord {
                        tag: tag.to_string(),
                        proxy: proxy.original.clone(),
                        result,
                    };
                }
                Err(e) => {
                    last_error = e.to_string();

                    if !e.is_retryable() {
                        break;
                    }

                    if attempt == MAX_RETRIES && fallback_ip.is_none() {
                        if let Ok(detector) = FallbackIpDetector::new(&proxy) {
                            fallback_ip = detector.detect_ip().await;
                        }
                    }
                }
            },
            Err(e) => {
                last_error = e.to_string();
                if !e.is_retryable() {
                    break;
                }
            }
        }
    }

    if let Some(ip) = fallback_ip {
        return CsvRecord {
            tag: tag.to_string(),
            proxy: proxy.original.clone(),
            result: FraudResult {
                ip,
                risk_score: "RATE_LIMITED".to_string(),
                ..Default::default()
            },
        };
    }

    CsvRecord {
        tag: tag.to_string(),
        proxy: proxy.original,
        result: FraudResult {
            ip: last_error,
            risk_score: "ERROR".to_string(),
            ..Default::default()
        },
    }
}
