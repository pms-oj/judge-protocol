use chacha20poly1305::consts::{U12, U32};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    AeadCore, ChaCha8Poly1305,
};
use generic_array::GenericArray;
use k256::ecdh::SharedSecret;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;

// The standard encryption method is round-reduced ChaChaPoly1305 (8 rounds)

pub fn expand_key(shared: &SharedSecret) -> GenericArray<u8, U12> {
    let extracted = shared.extract::<Sha3_256>(None);
    let mut ret: Vec<u8> = vec![];
    extracted.expand(&[], ret.as_mut_slice()).ok();
    ret.into_iter().collect()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncMessage {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl EncMessage {
    pub fn generate(key: &GenericArray<u8, U32>, plaintext: &[u8]) -> Self {
        let nonce = ChaCha8Poly1305::generate_nonce(thread_rng());
        Self {
            nonce: nonce.to_vec(),
            ciphertext: standard_encrypt(key, &nonce, plaintext),
        }
    }

    pub fn decrypt(&self, key: &GenericArray<u8, U32>) -> Vec<u8> {
        let nonce = GenericArray::<u8, U12>::from_slice(&self.nonce);
        standard_decrypt(key, nonce, &self.ciphertext)
    }
}

pub fn standard_encrypt(
    key: &GenericArray<u8, U32>,
    nonce: &GenericArray<u8, U12>,
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = ChaCha8Poly1305::new(key);
    cipher.encrypt(nonce, plaintext).unwrap()
}

pub fn standard_decrypt(
    key: &GenericArray<u8, U32>,
    nonce: &GenericArray<u8, U12>,
    ciphertext: &[u8],
) -> Vec<u8> {
    let cipher = ChaCha8Poly1305::new(key);
    cipher.decrypt(nonce, ciphertext).unwrap()
}
