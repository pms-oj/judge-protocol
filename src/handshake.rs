use serde::{Serialize, Deserialize, de::DeserializeOwned};
use k256::PublicKey;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandshakeResult {
    pub node_id: u32, // asigned
    pub server_pubkey: PublicKey,
}

#[derive(Serialize, Debug, Clone)]
pub struct BodyAfterHandshake<T> where T: Serialize + DeserializeOwned + Clone {
    pub node_id: u32,
    pub req: T,
}

