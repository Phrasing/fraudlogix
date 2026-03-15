use crate::types::{CheckError, ProxyConfig};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

impl ProxyConfig {
    pub fn parse(proxy_str: &str) -> Result<Self, CheckError> {
        let parts: Vec<&str> = proxy_str.trim().split(':').collect();

        if parts.len() != 4 {
            return Err(CheckError::ProxyFormat(format!(
                "Expected format host:port:user:pass, got {} parts",
                parts.len()
            )));
        }

        let port = parts[1]
            .parse::<u16>()
            .map_err(|_| CheckError::ProxyFormat("Invalid port number".to_string()))?;

        Ok(ProxyConfig {
            host: parts[0].to_string(),
            port,
            username: parts[2].to_string(),
            password: parts[3].to_string(),
            original: proxy_str.to_string(),
        })
    }

    pub fn to_url(&self) -> String {
        let user = utf8_percent_encode(&self.username, NON_ALPHANUMERIC);
        let pass = utf8_percent_encode(&self.password, NON_ALPHANUMERIC);
        format!("http://{}:{}@{}:{}", user, pass, self.host, self.port)
    }
}
