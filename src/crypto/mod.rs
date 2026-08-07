// src/crypto/mod.rs

mod security;

pub use security::Security;

use argon2::{Argon2, ParamsBuilder, password_hash::SaltString};
use rand::rngs::OsRng;

pub fn derive_key(shared_key: &str, iterations: u32) -> [u8; 32] {
    let salt = SaltString::generate(&mut OsRng);
    let params = ParamsBuilder::new()
        .p_cost(1)
        .m_cost(19456)
        .t_cost(iterations)
        .output_len(32)
        .build()
        .unwrap();

    let argon2 = Argon2::new(&argon2::Algorithm::Argon2id, &argon2::Version::V0x13, params);
    let mut output = [0u8; 32];
    argon2.hash_password_into(shared_key.as_bytes(), salt.as_bytes(), &mut output).unwrap();
    output
}