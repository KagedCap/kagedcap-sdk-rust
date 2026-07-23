//! Official KagedCap Rust SDK — solve reCAPTCHA v3 tokens with an API key.
//!
//! ```no_run
//! use kagedcap::{KagedCapClient, SolveParams};
//!
//! let kc = KagedCapClient::new(std::env::var("KAGEDCAP_API_KEY").unwrap());
//! let res = kc.solve(SolveParams {
//!     sitekey: "6Lc...".into(),
//!     url: "https://www.ticketmaster.com".into(),
//!     action: "Event".into(),
//!     enterprise: true,
//!     ..Default::default()
//! }).unwrap();
//! println!("{}", res.token);
//! ```

use serde::Deserialize;
use serde_json::{json, Map, Value};

pub const DEFAULT_BASE_URL: &str = "https://api.kagedcap.io";

/// Returned on any non-2xx response or transport failure.
#[derive(Debug, Clone)]
pub struct KagedCapError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for KagedCapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "kagedcap: {} (code={}, status={})", self.message, self.code, self.status)
    }
}
impl std::error::Error for KagedCapError {}

/// Parameters for a solve. Set `enterprise` and/or `proxy` and the task is chosen
/// for you, or set `task` explicitly.
#[derive(Debug, Default, Clone)]
pub struct SolveParams {
    pub sitekey: String,
    pub url: String,
    /// reCAPTCHA action — required for v3, ignored (leave empty) for v2.
    pub action: String,
    pub task: Option<String>,
    /// reCAPTCHA version: `None`/`"v3"` (default) or `"v2"` (invisible). Ignored if `task` is set.
    pub version: Option<String>,
    pub enterprise: bool,
    pub proxy: Option<String>,
    pub user_agent: Option<String>,
    pub device: Option<String>,
    pub enhanced: bool,
    pub secret_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SolveResult {
    pub success: bool,
    pub token: String,
    pub task: String,
    pub score: Option<f64>,
    pub verification: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct Balance {
    pub amount_micros: String,
    pub held_micros: String,
    pub available_micros: String,
    pub display: String,
}

/// Pick the task string from version, the enterprise flag, and whether a proxy is set.
/// version `Some("v2")` selects reCAPTCHA v2 invisible (no enterprise variant yet).
pub fn derive_task(enterprise: bool, has_proxy: bool, version: Option<&str>) -> String {
    let suffix = if has_proxy { "Task" } else { "TaskProxyLess" };
    if version == Some("v2") {
        return format!("ReCaptchaV2{}", suffix);
    }
    let base = if enterprise { "ReCaptchaV3Enterprise" } else { "ReCaptchaV3" };
    format!("{}{}", base, suffix)
}

pub struct KagedCapClient {
    api_key: String,
    base_url: String,
    agent: ureq::Agent,
}

impl KagedCapClient {
    pub fn new(api_key: impl Into<String>) -> Self {
        let api_key = api_key.into();
        assert!(!api_key.is_empty(), "kagedcap: api_key is required");
        Self {
            api_key,
            base_url: DEFAULT_BASE_URL.to_string(),
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(120))
                .build(),
        }
    }

    /// Override the API base URL.
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').to_string();
        self
    }

    /// Solve a captcha and return the token.
    pub fn solve(&self, params: SolveParams) -> Result<SolveResult, KagedCapError> {
        let task = params
            .task
            .clone()
            .unwrap_or_else(|| derive_task(params.enterprise, params.proxy.is_some(), params.version.as_deref()));
        let mut body = Map::new();
        body.insert("task".into(), json!(task));
        body.insert("url".into(), json!(params.url));
        body.insert("sitekey".into(), json!(params.sitekey));
        // Omit action when empty — v2 has no action, and "" fails server validation.
        if !params.action.is_empty() {
            body.insert("action".into(), json!(params.action));
        }
        if let Some(p) = &params.proxy {
            body.insert("proxy".into(), json!(p));
        }
        if let Some(ua) = &params.user_agent {
            body.insert("userAgent".into(), json!(ua));
        }
        if let Some(d) = &params.device {
            body.insert("device".into(), json!(d));
        }
        if params.enhanced {
            body.insert("enhanced".into(), json!(true));
        }
        if let Some(sk) = &params.secret_key {
            body.insert("secretKey".into(), json!(sk));
        }
        self.request("POST", "/solve", Some(Value::Object(body)))
    }

    /// Current balance for the API key's account.
    pub fn check_balance(&self) -> Result<Balance, KagedCapError> {
        self.request("GET", "/v1/balance", None)
    }

    fn request<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<T, KagedCapError> {
        let url = format!("{}{}", self.base_url, path);
        let req = self
            .agent
            .request(method, &url)
            .set("x-api-key", &self.api_key)
            .set("content-type", "application/json");
        let result = match body {
            Some(v) => req.send_json(v),
            None => req.call(),
        };
        match result {
            Ok(resp) => resp.into_json::<T>().map_err(|e| KagedCapError {
                status: 0,
                code: "decode_error".into(),
                message: e.to_string(),
            }),
            Err(ureq::Error::Status(code, resp)) => {
                let payload: Value = resp.into_json().unwrap_or_else(|_| json!({}));
                Err(KagedCapError {
                    status: code,
                    code: payload["error"].as_str().unwrap_or("error").to_string(),
                    message: payload["message"]
                        .as_str()
                        .unwrap_or("request failed")
                        .to_string(),
                })
            }
            Err(ureq::Error::Transport(t)) => Err(KagedCapError {
                status: 0,
                code: "network_error".into(),
                message: t.to_string(),
            }),
        }
    }
}
