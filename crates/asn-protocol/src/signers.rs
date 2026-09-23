//! Purpose-specific seams for keys and credential holders. Implementations can
//! delegate every operation to non-exportable hardware or external wallets.

use thiserror::Error;

#[derive(Debug, Error)]
#[error("signer operation failed: {message}")]
pub struct SignerError {
    pub message: String,
}

impl SignerError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub trait JwsSigner {
    fn key_id(&self) -> &str;
    fn public_jwk(&self) -> crate::identity::PublicJwk;
    fn sign_es256(&self, signing_input: &[u8]) -> Result<[u8; 64], SignerError>;
}

pub trait EvmTypedDataSigner {
    fn address(&self) -> &str;
    fn sign_eip712(&self, typed_data: &[u8]) -> Result<Vec<u8>, SignerError>;
}

pub trait CredentialHolder {
    fn create_presentation(&self, request: &[u8]) -> Result<Vec<u8>, SignerError>;
}

pub trait DataKeyWrapper {
    fn key_id(&self) -> &str;
    fn wrap_data_key(&self, data_key: &[u8]) -> Result<Vec<u8>, SignerError>;
    fn unwrap_data_key(&self, wrapped_key: &[u8]) -> Result<Vec<u8>, SignerError>;
}
