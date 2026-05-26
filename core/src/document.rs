use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidVerificationMethod {
    pub id: Vec<u8>,
    #[serde(rename = "type")]
    pub vm_type: Vec<u8>,
    pub controller: Vec<u8>,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<Vec<u8>>,
    pub id: Vec<u8>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<DidVerificationMethod>,
    pub authentication: Vec<Vec<u8>>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<Vec<u8>>,
    #[serde(rename = "keyAgreement")]
    pub key_agreement: Vec<Vec<u8>>,
    #[serde(rename = "capabilityInvocation")]
    pub capability_invocation: Vec<Vec<u8>>,
    #[serde(rename = "capabilityDelegation")]
    pub capability_delegation: Vec<Vec<u8>>,
    pub service: Vec<crate::did::ServiceEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocumentMetadata {
    pub deactivated: bool,
    #[serde(rename = "versionId")]
    pub version_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidResolutionMetadata {
    #[serde(rename = "contentType")]
    pub content_type: Option<Vec<u8>>,
    pub error: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidResolutionResult {
    #[serde(rename = "didDocument")]
    pub did_document: Option<DidDocument>,
    #[serde(rename = "didDocumentMetadata")]
    pub did_document_metadata: DidDocumentMetadata,
    #[serde(rename = "didResolutionMetadata")]
    pub did_resolution_metadata: DidResolutionMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidResolutionResultHttp {
    #[serde(rename = "didDocument")]
    pub did_document: Option<serde_json::Value>,
    #[serde(rename = "didDocumentMetadata")]
    pub did_document_metadata: serde_json::Value,
    #[serde(rename = "didResolutionMetadata")]
    pub did_resolution_metadata: serde_json::Value,
}

impl DidResolutionResult {
    pub fn into_http(self) -> DidResolutionResultHttp {
        DidResolutionResultHttp {
            did_document: self.did_document.map(|d| {
                rewrite_bytes_to_strings(serde_json::to_value(d).expect("serialize did document"))
            }),
            did_document_metadata: rewrite_bytes_to_strings(
                serde_json::to_value(self.did_document_metadata)
                    .expect("serialize did document metadata"),
            ),
            did_resolution_metadata: rewrite_bytes_to_strings(
                serde_json::to_value(self.did_resolution_metadata)
                    .expect("serialize did resolution metadata"),
            ),
        }
    }
}

pub fn rewrite_bytes_to_strings(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(a) => {
            if a.iter().all(|v| v.as_u64().is_some()) {
                let bytes: Vec<u8> = a
                    .iter()
                    .map(|v| v.as_u64().expect("checked as_u64") as u8)
                    .collect();
                serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned())
            } else {
                serde_json::Value::Array(a.into_iter().map(rewrite_bytes_to_strings).collect())
            }
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, rewrite_bytes_to_strings(v)))
                .collect(),
        ),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::rewrite_bytes_to_strings;

    #[test]
    fn rewrites_byte_arrays_to_utf8_strings() {
        let input = serde_json::json!({
            "id": [100, 105, 100, 58, 113, 115, 98, 58, 97],
            "nested": { "arr": [[35, 107, 101, 121, 45, 49]] }
        });
        let output = rewrite_bytes_to_strings(input);
        assert_eq!(output["id"], serde_json::json!("did:qsb:a"));
        assert_eq!(output["nested"]["arr"][0], serde_json::json!("#key-1"));
    }
}
