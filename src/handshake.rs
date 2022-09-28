use bincode::Options;
use k256::PublicKey;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandshakeRequest {
    pub client_pubkey: PublicKey,
    pub pass: String,
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
    pub node_id: Option<u32>, // asigned
    pub server_pubkey: Option<PublicKey>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BodyAfterHandshake<T> {
    pub node_id: u32,
    pub client_pubkey: PublicKey,
    pub req: T,
}

impl<T> BodyAfterHandshake<T>
where
    T: Serialize + DeserializeOwned + Clone,
{
    pub fn bytes(&self) -> Vec<u8> {
        bincode::DefaultOptions::new()
            .with_big_endian()
            .with_fixint_encoding()
            .serialize(self)
            .unwrap()
    }

    pub fn from_bytes(&self, bytes: Vec<u8>) -> bincode::Result<Self> {
        bincode::DefaultOptions::new()
            .with_big_endian()
            .with_fixint_encoding()
            .deserialize::<Self>(&bytes)
    }
}
