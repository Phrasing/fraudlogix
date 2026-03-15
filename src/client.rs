use crate::fingerprint::*;
use crate::pow::transform_nonce;
use crate::types::*;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use std::time::Duration;
use wreq::http2::{Http2Options, StreamDependency, StreamId};
use wreq_util::Emulation;

const BASE_URL: &str = "https://ipui.fraudlogix.com";
const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36";

pub struct FraudlogixClient {
    client: wreq::Client,
}

impl FraudlogixClient {
    pub fn new(proxy: &ProxyConfig) -> Result<Self, CheckError> {
        let proxy_url = proxy.to_url();

        // Match Chrome 145 HTTP/2 fingerprint from tls.peet.ws.
        let http2_options = Http2Options::builder()
            .header_table_size(65536) // HEADER_TABLE_SIZE
            .enable_push(false) // ENABLE_PUSH = 0
            .initial_window_size(6291456) // INITIAL_WINDOW_SIZE
            .max_header_list_size(262144) // MAX_HEADER_LIST_SIZE
            .initial_connection_window_size(15663105) // WINDOW_UPDATE frame increment
            .headers_stream_dependency(StreamDependency::new(
                StreamId::from(0), // depends_on = 0
                255,               // weight = 256 (stored as 255 in [0,255] range)
                true,              // exclusive = 1
            ))
            .build();

        let client = wreq::Client::builder()
            .emulation(Emulation::Chrome145)
            .http2_options(http2_options)
            .proxy(wreq::Proxy::all(&proxy_url)?)
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self { client })
    }

    fn base_headers(&self) -> wreq::header::HeaderMap {
        let mut headers = wreq::header::HeaderMap::new();

        // Client Hints headers (CRITICAL for Chrome fingerprinting).
        headers.insert(
            "sec-ch-ua-platform",
            wreq::header::HeaderValue::from_static("\"Windows\""),
        );
        headers.insert(
            "sec-ch-ua",
            wreq::header::HeaderValue::from_static(
                "\"Not:A-Brand\";v=\"99\", \"Google Chrome\";v=\"145\", \"Chromium\";v=\"145\"",
            ),
        );
        headers.insert(
            "sec-ch-ua-mobile",
            wreq::header::HeaderValue::from_static("?0"),
        );

        headers.insert(
            "user-agent",
            wreq::header::HeaderValue::from_static(USER_AGENT),
        );
        headers.insert("accept", wreq::header::HeaderValue::from_static("*/*"));
        headers.insert(
            "origin",
            wreq::header::HeaderValue::from_static("https://www.fraudlogix.com"),
        );
        headers.insert(
            "sec-fetch-site",
            wreq::header::HeaderValue::from_static("same-site"),
        );
        headers.insert(
            "sec-fetch-mode",
            wreq::header::HeaderValue::from_static("cors"),
        );
        headers.insert(
            "sec-fetch-dest",
            wreq::header::HeaderValue::from_static("empty"),
        );
        headers.insert(
            "referer",
            wreq::header::HeaderValue::from_static("https://www.fraudlogix.com/"),
        );
        headers.insert(
            "accept-language",
            wreq::header::HeaderValue::from_static("en-US,en;q=0.9"),
        );
        headers.insert("priority", wreq::header::HeaderValue::from_static("u=1, i"));
        headers.insert(
            "x-fl-request-id",
            wreq::header::HeaderValue::from_str(&random_request_id()).unwrap(),
        );
        headers
    }

    pub async fn check_ip(&self) -> Result<FraudResult, CheckError> {
        let headers = self.base_headers();
        let resp = self
            .client
            .get(&format!("{}/get_user_ip", BASE_URL))
            .headers(headers.clone())
            .send()
            .await?;

        let status = resp.status();
        if status.as_u16() == 429 || status.as_u16() == 503 || status.as_u16() == 504 {
            return Err(CheckError::RateLimited(format!("Status {}", status)));
        }

        let token = resp
            .headers()
            .get("x-fl-new-token")
            .ok_or_else(|| {
                CheckError::RateLimited("Missing x-fl-new-token (rate limited)".to_string())
            })?
            .to_str()
            .map_err(|_| CheckError::InvalidResponse("Invalid token encoding".to_string()))?
            .to_string();

        let ip_text = resp.text().await?;
        let ip_resp: IpResponse = serde_json::from_str(&ip_text)?;
        let ip = ip_resp.ip;

        let mut headers = self.base_headers();
        headers.insert(
            "x-fl-auth-token",
            wreq::header::HeaderValue::from_str(&token).unwrap(),
        );

        let nonce_resp = self
            .client
            .get(&format!("{}/get_nonce", BASE_URL))
            .headers(headers.clone())
            .send()
            .await?;

        let nonce_text = nonce_resp.text().await?;
        let nonce_data: NonceResponse = serde_json::from_str(&nonce_text)?;
        let (transformed, pow_solve_ms) = transform_nonce(&nonce_data.nonce, &nonce_data.challenge);

        let mut headers = self.base_headers();
        headers.insert(
            "content-type",
            wreq::header::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        headers.insert(
            "x-fl-auth-token",
            wreq::header::HeaderValue::from_str(&token).unwrap(),
        );
        headers.insert(
            "x-fl-nonce-id",
            wreq::header::HeaderValue::from_str(
                &nonce_data.nonce[..16.min(nonce_data.nonce.len())],
            )
            .unwrap(),
        );
        headers.insert(
            "x-fl-nonce-transform",
            wreq::header::HeaderValue::from_str(&transformed).unwrap(),
        );

        let browser_data = generate_browser_data(&nonce_data.nonce, &transformed, USER_AGENT);
        headers.insert(
            "x-fl-browser-data",
            wreq::header::HeaderValue::from_str(&browser_data).unwrap(),
        );

        let body = format!("ip={}", utf8_percent_encode(&ip, NON_ALPHANUMERIC));

        let result_resp = self
            .client
            .post(&format!("{}/ip_response_json", BASE_URL))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let result_text = result_resp.text().await?;
        let mut result: FraudResult = serde_json::from_str(&result_text)?;

        result.pow_solve_ms = pow_solve_ms;

        if result.ip.is_empty() {
            return Err(CheckError::InvalidResponse(
                "Empty IP in response".to_string(),
            ));
        }

        Ok(result)
    }
}
