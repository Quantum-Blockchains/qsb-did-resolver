use crate::{did::RawDidDetails, error::ResolverResult};
use anyhow::{anyhow, Context};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

#[derive(Clone)]
pub struct RpcClient {
    base_url: String,
    http: Client,
}

impl RpcClient {
    pub fn new(base_url: String, timeout_secs: u64) -> ResolverResult<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self { base_url, http })
    }

    pub async fn did_by_string(&self, did: &str) -> ResolverResult<Option<RawDidDetails>> {
        let request = RpcRequest {
            jsonrpc: "2.0",
            id: 1u32,
            method: "did_getByString",
            params: json!([did]),
        };

        let response = self
            .http
            .post(&self.base_url)
            .json(&request)
            .send()
            .await
            .with_context(|| format!("failed to call node RPC at {}", self.base_url))?;

        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!(
                "node RPC returned non-success HTTP status: {}",
                status
            ));
        }

        let body: RpcResponse<Option<RawDidDetails>> = response
            .json()
            .await
            .context("failed to decode node RPC response")?;

        if let Some(err) = body.error {
            return Err(anyhow!(
                "node RPC returned error code {}: {}",
                err.code,
                err.message
            ));
        }

        body.result
            .ok_or_else(|| anyhow!("node RPC response missing result"))
    }
}

#[derive(Debug, Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'a str,
    id: u32,
    method: &'a str,
    params: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u32,
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}
