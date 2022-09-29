use chacha20poly1305::consts::{U32, U12};
use generic_array::GenericArray;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha8Poly1305,
};

// The standard encryption method is round-reduced ChaChaPoly1305 (8 rounds)

pub fn standard_encrypt(key: GenericArray<u8, U32>, nonce: GenericArray<u8, U12>, plaintext: Vec<u8>) -> Vec<u8> {
    let cipher = ChaCha8Poly1305::new(&key);
    cipher.encrypt(&nonce, plaintext.as_ref()).unwrap()
}

pub fn standard_decrypt(key: GenericArray<u8, U32>, nonce: GenericArray<u8, U12>, ciphertext: Vec<u8>) -> Vec<u8> {
    let cipher = ChaCha8Poly1305::new(&key);
    cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap()
}