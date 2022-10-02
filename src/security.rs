use chacha20poly1305::consts::{U12, U32};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha8Poly1305,
};
use generic_array::GenericArray;
use k256::ecdh::SharedSecret;
use sha3::Sha3_256;

// The standard encryption method is round-reduced ChaChaPoly1305 (8 rounds)

pub fn expand_key(shared: &SharedSecret) -> GenericArray<u8, U12> {
    let extracted = shared.extract::<Sha3_256>(None);
    let mut ret: Vec<u8>  = vec![];
    extracted.expand(&[], ret.as_mut_slice()).ok();
    ret.into_iter().collect()
}

pub fn standard_encrypt(
    key: GenericArray<u8, U32>,
    nonce: GenericArray<u8, U12>,
    plaintext: Vec<u8>,
) -> Vec<u8> {
    let cipher = ChaCha8Poly1305::new(&key);
    cipher.encrypt(&nonce, plaintext.as_ref()).unwrap()
}

pub fn standard_decrypt(
    key: GenericArray<u8, U32>,
    nonce: GenericArray<u8, U12>,
    ciphertext: Vec<u8>,
) -> Vec<u8> {
    let cipher = ChaCha8Poly1305::new(&key);
    cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap()
}
