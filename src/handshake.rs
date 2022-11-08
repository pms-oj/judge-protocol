use bincode::Options;
use k256::PublicKey;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandshakeRequest {
    pub client_pubkey: PublicKey,
    pub pass: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum HandshakeResult {
    Success,
    PasswordNotMatched,
    Unknown,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandshakeResponse {
    pub result: HandshakeResult,
    pub node_id: Option<Uuid>, // asigned
    pub server_pubkey: Option<PublicKey>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BodyAfterHandshake<T> {
    pub node_id: Uuid,
    pub client_pubkey: PublicKey,
    pub req: T,
}

impl<T> BodyAfterHandshake<T>
where
    T: Serialize + DeserializeOwned + Clone,
{
    pub fn bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn from_bytes(&self, bytes: Vec<u8>) -> bincode::Result<Self> {
        bincode::deserialize::<Self>(&bytes)
    }
}
