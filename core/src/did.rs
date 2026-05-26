use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawDidKey {
    pub key_id: Vec<u8>,
    pub multicodec: Option<u64>,
    pub public_key: Vec<u8>,
    pub roles: Vec<RawKeyRole>,
    pub controller: Option<Vec<u8>>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RawKeyRole {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: Vec<u8>,
    #[serde(rename = "type")]
    pub service_type: Vec<u8>,
    #[serde(rename = "serviceEndpoint")]
    pub endpoint: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawDidDetails {
    pub version: u64,
    pub deactivated: bool,
    pub keys: Vec<RawDidKey>,
    pub services: Vec<ServiceEndpoint>,
    pub metadata: Vec<serde_json::Value>,
    pub next_key_index: u32,
}
