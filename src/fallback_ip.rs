use crate::types::ProxyConfig;
use std::time::Duration;
use wreq_util::Emulation;

const FALLBACK_SERVICES: [&str; 3] = [
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
];

pub struct FallbackIpDetector {
    client: wreq::Client,
}

impl FallbackIpDetector {
    pub fn new(proxy: &ProxyConfig) -> Result<Self, wreq::Error> {
        let proxy_url = proxy.to_url();

        let client = wreq::Client::builder()
            .emulation(Emulation::Chrome145)
            .proxy(wreq::Proxy::all(&proxy_url)?)
            .timeout(Duration::from_secs(10))
            .build()?;

        Ok(Self { client })
    }

    pub async fn detect_ip(&self) -> Option<String> {
        for service_url in &FALLBACK_SERVICES {
            match self.try_service(service_url).await {
                Ok(ip) if !ip.is_empty() => {
                    return Some(ip);
                }
                Ok(_) => continue,
                Err(_) => continue,
            }
        }
        None
    }

    async fn try_service(&self, url: &str) -> Result<String, wreq::Error> {
        let resp = self.client.get(url).send().await?;

        let text = resp.text().await?;

        if url.contains("ipify") {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(ip) = json.get("ip").and_then(|v| v.as_str()) {
                    return Ok(ip.trim().to_string());
                }
            }
        }

        let ip = text.trim().to_string();

        if Self::is_valid_ip(&ip) {
            Ok(ip)
        } else {
            Ok(String::new())
        }
    }

    fn is_valid_ip(s: &str) -> bool {
        s.contains('.') || s.contains(':')
    }
}
