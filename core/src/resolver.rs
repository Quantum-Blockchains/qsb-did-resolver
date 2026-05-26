use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use crate::did::{RawDidDetails, RawKeyRole, RawVerificationMethodType};
use crate::document::{
    DidDocument, DidDocumentMetadata, DidResolutionMetadata, DidResolutionResult,
    DidVerificationMethod,
};

pub fn is_qsb_did(did: &str) -> bool {
    did.starts_with("did:qsb:")
}

fn encode_uvarint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

fn multibase_from_public_key(public_key: &[u8], codec: u64) -> Vec<u8> {
    let mut prefixed = encode_uvarint(codec);
    prefixed.extend_from_slice(public_key);
    let encoded = URL_SAFE_NO_PAD.encode(prefixed);
    let mut out = Vec::with_capacity(encoded.len() + 1);
    out.push(b'u');
    out.extend_from_slice(encoded.as_bytes());
    out
}

pub fn map_raw_to_resolution(did: &str, details: RawDidDetails) -> DidResolutionResult {
    let did_bytes = did.as_bytes().to_vec();
    let mut verification_method = Vec::new();
    let mut authentication = Vec::new();
    let mut assertion_method = Vec::new();
    let mut key_agreement = Vec::new();
    let mut capability_invocation = Vec::new();
    let mut capability_delegation = Vec::new();

    for key in details.keys.into_iter().filter(|k| !k.revoked) {
        let vm_id = key.key_id.clone();
        let controller = key.controller.clone().unwrap_or_else(|| did_bytes.clone());
        let vm_type_label = match key.vm_type {
            RawVerificationMethodType::Multikey => b"Multikey".to_vec(),
            RawVerificationMethodType::JsonWebKey2020 => b"JsonWebKey2020".to_vec(),
        };

        let (public_key_multibase, public_key_jwk) = match key.vm_type {
            RawVerificationMethodType::Multikey => {
                (
                    key.multicodec
                        .map(|codec| multibase_from_public_key(&key.public_key, codec)),
                    None,
                )
            }
            RawVerificationMethodType::JsonWebKey2020 => (None, Some(key.public_key.clone())),
        };

        verification_method.push(DidVerificationMethod {
            id: vm_id.clone(),
            vm_type: vm_type_label,
            controller,
            public_key_multibase,
            public_key_jwk,
        });

        for role in key.roles {
            match role {
                RawKeyRole::Authentication => authentication.push(vm_id.clone()),
                RawKeyRole::AssertionMethod => assertion_method.push(vm_id.clone()),
                RawKeyRole::KeyAgreement => key_agreement.push(vm_id.clone()),
                RawKeyRole::CapabilityInvocation => capability_invocation.push(vm_id.clone()),
                RawKeyRole::CapabilityDelegation => capability_delegation.push(vm_id.clone()),
            }
        }
    }

    DidResolutionResult {
        did_document: Some(DidDocument {
            context: vec![
                b"https://www.w3.org/ns/did/v1".to_vec(),
                b"https://w3id.org/security/multikey/v1".to_vec(),
                b"https://w3id.org/security/suites/jws-2020/v1".to_vec(),
            ],
            id: did_bytes,
            verification_method,
            authentication,
            assertion_method,
            key_agreement,
            capability_invocation,
            capability_delegation,
            service: details.services,
        }),
        did_document_metadata: DidDocumentMetadata {
            deactivated: details.deactivated,
            version_id: details.version,
        },
        did_resolution_metadata: DidResolutionMetadata {
            content_type: Some(b"application/did+ld+json".to_vec()),
            error: None,
        },
    }
}

pub fn invalid_did_result() -> DidResolutionResult {
    DidResolutionResult {
        did_document: None,
        did_document_metadata: DidDocumentMetadata {
            deactivated: false,
            version_id: 0,
        },
        did_resolution_metadata: DidResolutionMetadata {
            content_type: None,
            error: Some(b"invalidDid".to_vec()),
        },
    }
}

pub fn not_found_result() -> DidResolutionResult {
    DidResolutionResult {
        did_document: None,
        did_document_metadata: DidDocumentMetadata {
            deactivated: false,
            version_id: 0,
        },
        did_resolution_metadata: DidResolutionMetadata {
            content_type: None,
            error: Some(b"notFound".to_vec()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{invalid_did_result, map_raw_to_resolution, not_found_result};
    use crate::did::{RawDidDetails, RawDidKey, RawKeyRole, RawVerificationMethodType, ServiceEndpoint};

    fn sample_did() -> &'static str {
        "did:qsb:6QWeT6FpJrm8AF1btu6WH2k2Xhq6t5vbYf7uV5mG4NfN"
    }

    #[test]
    fn maps_resolution_success_shape() {
        let did = sample_did();
        let details = RawDidDetails {
            version: 7,
            deactivated: false,
            keys: vec![RawDidKey {
                key_id: format!("{did}#update").into_bytes(),
                vm_type: RawVerificationMethodType::Multikey,
                multicodec: Some(0x1210),
                public_key: vec![0x11; 1312],
                roles: vec![RawKeyRole::Authentication, RawKeyRole::AssertionMethod],
                controller: None,
                revoked: false,
            }],
            services: vec![ServiceEndpoint {
                id: b"#messaging".to_vec(),
                service_type: b"Messaging".to_vec(),
                endpoint: b"https://example.org/messages".to_vec(),
            }],
            metadata: vec![],
            next_key_index: 8,
        };

        let out = map_raw_to_resolution(did, details).into_http();
        assert_eq!(
            out.did_resolution_metadata["contentType"],
            serde_json::json!("application/did+ld+json")
        );
        assert_eq!(out.did_resolution_metadata["error"], serde_json::Value::Null);
        assert_eq!(out.did_document_metadata["versionId"], serde_json::json!(7));
        assert_eq!(out.did_document_metadata["deactivated"], serde_json::json!(false));

        let doc = out.did_document.expect("did document must exist");
        assert_eq!(doc["id"], serde_json::json!(did));
        assert_eq!(doc["verificationMethod"][0]["id"], serde_json::json!(format!("{did}#update")));
        assert_eq!(doc["verificationMethod"][0]["controller"], serde_json::json!(did));
        assert_eq!(doc["verificationMethod"][0]["type"], serde_json::json!("Multikey"));
        assert_eq!(doc["service"][0]["id"], serde_json::json!("#messaging"));
        assert_eq!(
            doc["service"][0]["serviceEndpoint"],
            serde_json::json!("https://example.org/messages")
        );
    }

    #[test]
    fn invalid_did_error_shape() {
        let out = invalid_did_result().into_http();
        assert!(out.did_document.is_none());
        assert_eq!(out.did_resolution_metadata["error"], serde_json::json!("invalidDid"));
    }

    #[test]
    fn not_found_error_shape() {
        let out = not_found_result().into_http();
        assert!(out.did_document.is_none());
        assert_eq!(out.did_resolution_metadata["error"], serde_json::json!("notFound"));
    }
}
