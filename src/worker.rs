use crate::backoff::ExponentialBackoff;
use crate::client::FraudlogixClient;
use crate::types::*;

const MAX_RETRIES: u32 = 6;

pub async fn check_proxy_with_retries(proxy_str: &str, tag: &str) -> CsvRecord {
    let proxy = match ProxyConfig::parse(proxy_str) {
        Ok(p) => p,
        Err(_) => {
            let err_result = FraudResult {
                ip: "invalid format".to_string(),
                risk_score: "ERROR".to_string(),
                ..Default::default()
            };
            return CsvRecord {
                tag: tag.to_string(),
                proxy: proxy_str.to_string(),
                ip: err_result.ip,
                risk_score: err_result.risk_score,
                pow_solve_ms: 0.0,
                recently_seen: err_result.recently_seen,
                connection_type: err_result.connection_type,
                proxy_flag: err_result.proxy_flag,
                vpn: err_result.vpn,
                tor: err_result.tor,
                data_center: err_result.data_center,
                search_engine_bot: err_result.search_engine_bot,
                masked_devices: err_result.masked_devices,
                abnormal_traffic: err_result.abnormal_traffic,
                asn: err_result.asn,
                isp: err_result.isp,
                organization: err_result.organization,
                city: err_result.city,
                region: err_result.region,
                country: err_result.country,
                country_code: err_result.country_code,
                timezone: err_result.timezone,
            };
        }
    };

    let mut backoff = ExponentialBackoff::new();
    let mut last_error = String::new();

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
                        ip: result.ip,
                        risk_score: result.risk_score,
                        pow_solve_ms: result.pow_solve_ms,
                        recently_seen: result.recently_seen,
                        connection_type: result.connection_type,
                        proxy_flag: result.proxy_flag,
                        vpn: result.vpn,
                        tor: result.tor,
                        data_center: result.data_center,
                        search_engine_bot: result.search_engine_bot,
                        masked_devices: result.masked_devices,
                        abnormal_traffic: result.abnormal_traffic,
                        asn: result.asn,
                        isp: result.isp,
                        organization: result.organization,
                        city: result.city,
                        region: result.region,
                        country: result.country,
                        country_code: result.country_code,
                        timezone: result.timezone,
                    };
                }
                Err(e) => {
                    last_error = e.to_string();

                    if !e.is_retryable() {
                        break;
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

    let final_error = FraudResult {
        ip: last_error,
        risk_score: "ERROR".to_string(),
        ..Default::default()
    };
    CsvRecord {
        tag: tag.to_string(),
        proxy: proxy.original,
        ip: final_error.ip,
        risk_score: final_error.risk_score,
        pow_solve_ms: 0.0,
        recently_seen: final_error.recently_seen,
        connection_type: final_error.connection_type,
        proxy_flag: final_error.proxy_flag,
        vpn: final_error.vpn,
        tor: final_error.tor,
        data_center: final_error.data_center,
        search_engine_bot: final_error.search_engine_bot,
        masked_devices: final_error.masked_devices,
        abnormal_traffic: final_error.abnormal_traffic,
        asn: final_error.asn,
        isp: final_error.isp,
        organization: final_error.organization,
        city: final_error.city,
        region: final_error.region,
        country: final_error.country,
        country_code: final_error.country_code,
        timezone: final_error.timezone,
    }
}
