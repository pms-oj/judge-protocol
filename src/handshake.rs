use serde::{Serialize, Deserialize};
use k256::PublicKey;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandshakeResult {
    pub node_id: u32, // asigned
    pub server_pubkey: PublicKey,
}