use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub original: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserFingerprint {
    pub plugins: &'static str,
    #[serde(rename = "mimeTypes")]
    pub mime_types: &'static str,
    #[serde(rename = "doNotTrack")]
    pub do_not_track: &'static str,
    #[serde(rename = "hardwareConcurrency")]
    pub hardware_concurrency: u8,
    #[serde(rename = "deviceMemory")]
    pub device_memory: u8,
    pub language: &'static str,
    pub languages: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScreenInfo {
    pub width: u32,
    pub height: u32,
    #[serde(rename = "colorDepth")]
    pub color_depth: u8,
    pub orientation: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct BehaviorMetrics {
    #[serde(rename = "mouseMovements")]
    pub mouse_movements: u32,
    pub keystrokes: u32,
    #[serde(rename = "scrollEvents")]
    pub scroll_events: u32,
    #[serde(rename = "clickEvents")]
    pub click_events: u32,
    #[serde(rename = "touchEvents")]
    pub touch_events: u32,
    #[serde(rename = "timeOnPage")]
    pub time_on_page: u32,
    #[serde(rename = "focusChanges")]
    pub focus_changes: u32,
}

#[derive(Debug, Deserialize)]
pub struct NonceResponse {
    pub nonce: String,
    pub challenge: Challenge,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Challenge {
    Simple {
        operation: String,
        parameter: i32,
    },
    ProofOfWork {
        #[serde(rename = "type")]
        challenge_type: String,
        difficulty: u32,
        challenge_key: String,
        verifier: String,
    },
}

#[derive(Debug, Deserialize)]
pub struct IpResponse {
    pub ip: String,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct FraudResult {
    #[serde(rename = "IP", default)]
    pub ip: String,
    #[serde(rename = "RiskScore", default)]
    pub risk_score: String,
    #[serde(skip)]
    pub pow_solve_ms: f64,
    #[serde(
        rename = "RecentlySeen",
        default,
        deserialize_with = "deserialize_int_or_string"
    )]
    pub recently_seen: String,
    #[serde(rename = "ConnectionType", default)]
    pub connection_type: String,
    #[serde(
        rename = "Proxy",
        default,
        deserialize_with = "deserialize_bool_or_string"
    )]
    pub proxy_flag: String,
    #[serde(
        rename = "VPN",
        default,
        deserialize_with = "deserialize_bool_or_string"
    )]
    pub vpn: String,
    #[serde(
        rename = "TOR",
        default,
        deserialize_with = "deserialize_bool_or_string"
    )]
    pub tor: String,
    #[serde(
        rename = "DataCenter",
        default,
        deserialize_with = "deserialize_bool_or_string"
    )]
    pub data_center: String,
    #[serde(
        rename = "SearchEngineBot",
        default,
        deserialize_with = "deserialize_bool_or_string"
    )]
    pub search_engine_bot: String,
    #[serde(
        rename = "MaskedDevices",
        default,
        deserialize_with = "deserialize_bool_or_string"
    )]
    pub masked_devices: String,
    #[serde(
        rename = "AbnormalTraffic",
        default,
        deserialize_with = "deserialize_bool_or_string"
    )]
    pub abnormal_traffic: String,
    #[serde(rename = "ASN", default)]
    pub asn: String,
    #[serde(rename = "ISP", default)]
    pub isp: String,
    #[serde(rename = "Organization", default)]
    pub organization: String,
    #[serde(rename = "City", default)]
    pub city: String,
    #[serde(rename = "Region", default)]
    pub region: String,
    #[serde(rename = "Country", default)]
    pub country: String,
    #[serde(rename = "CountryCode", default)]
    pub country_code: String,
    #[serde(rename = "Timezone", default)]
    pub timezone: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CsvRecord {
    pub tag: String,
    pub proxy: String,
    #[serde(rename = "IP")]
    pub ip: String,
    #[serde(rename = "RiskScore")]
    pub risk_score: String,
    #[serde(skip)]
    pub pow_solve_ms: f64,
    #[serde(rename = "RecentlySeen")]
    pub recently_seen: String,
    #[serde(rename = "ConnectionType")]
    pub connection_type: String,
    #[serde(rename = "Proxy")]
    pub proxy_flag: String,
    #[serde(rename = "VPN")]
    pub vpn: String,
    #[serde(rename = "TOR")]
    pub tor: String,
    #[serde(rename = "DataCenter")]
    pub data_center: String,
    #[serde(rename = "SearchEngineBot")]
    pub search_engine_bot: String,
    #[serde(rename = "MaskedDevices")]
    pub masked_devices: String,
    #[serde(rename = "AbnormalTraffic")]
    pub abnormal_traffic: String,
    #[serde(rename = "ASN")]
    pub asn: String,
    #[serde(rename = "ISP")]
    pub isp: String,
    #[serde(rename = "Organization")]
    pub organization: String,
    #[serde(rename = "City")]
    pub city: String,
    #[serde(rename = "Region")]
    pub region: String,
    #[serde(rename = "Country")]
    pub country: String,
    #[serde(rename = "CountryCode")]
    pub country_code: String,
    #[serde(rename = "Timezone")]
    pub timezone: String,
}

#[derive(Error, Debug)]
pub enum CheckError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] wreq::Error),

    #[error("JSON parsing failed: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Missing header: {0}")]
    MissingHeader(String),

    #[error("Proxy format error: {0}")]
    ProxyFormat(String),

    #[error("Rate limited by server: {0}")]
    RateLimited(String),
}

impl CheckError {
    pub fn is_retryable(&self) -> bool {
        match self {
            CheckError::ProxyFormat(_) => false,
            CheckError::RateLimited(_) => true,
            CheckError::MissingHeader(_) => true,
            CheckError::JsonError(e) => {
                let msg = e.to_string().to_lowercase();
                msg.contains("eof") || msg.contains("unexpected end")
            }
            CheckError::InvalidResponse(msg) => {
                // Retry if empty IP response
                if msg.contains("Empty IP") {
                    return true;
                }

                // Retry on 5xx server errors (500, 502, 503, 504, etc.)
                msg.contains("failed with status 5")
            }
            CheckError::HttpError(e) => {
                let msg = e.to_string();
                // Don't retry proxy connection errors (wrong credentials or proxy down)
                !msg.contains("ProxyConnect")
            }
        }
    }

    pub fn is_rate_limit(&self) -> bool {
        match self {
            CheckError::RateLimited(_) => true,
            CheckError::MissingHeader(h) if h == "x-fl-new-token" => true,
            _ => false,
        }
    }
}

// Helper function to deserialize bool or string.
fn deserialize_bool_or_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BoolOrString {
        Bool(bool),
        String(String),
    }

    match BoolOrString::deserialize(deserializer)? {
        BoolOrString::Bool(b) => Ok(b.to_string()),
        BoolOrString::String(s) => Ok(s),
    }
}

// Helper function to deserialize int or string.
fn deserialize_int_or_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum IntOrString {
        Int(i64),
        String(String),
    }

    match IntOrString::deserialize(deserializer)? {
        IntOrString::Int(i) => Ok(i.to_string()),
        IntOrString::String(s) => Ok(s),
    }
}
