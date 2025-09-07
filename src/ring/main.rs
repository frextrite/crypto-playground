use ring::{
    aead::{Aad, Algorithm, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    agreement::{self, EphemeralPrivateKey, PublicKey, UnparsedPublicKey},
    hkdf::{HKDF_SHA256, Salt},
    rand::{SecureRandom, SystemRandom},
};

mod error;
use error::{CryptoResult, Error};

struct KeyPair {
    private_key: EphemeralPrivateKey,
    public_key: PublicKey,
}

/// Generate a new X25519 key pair
fn generate_key_pair(rng: &SystemRandom) -> CryptoResult<KeyPair> {
    let private_key = EphemeralPrivateKey::generate(&agreement::X25519, rng)?;
    let public_key = private_key.compute_public_key()?;
    Ok(KeyPair {
        private_key,
        public_key,
    })
}

fn compute_derived_key(
    private_key: EphemeralPrivateKey,
    peer_public_key: &PublicKey,
) -> CryptoResult<Vec<u8>> {
    agreement::agree_ephemeral(
        private_key,
        &UnparsedPublicKey::new(&agreement::X25519, peer_public_key.as_ref()),
        |key_material| key_material.to_vec(),
    )
}

fn derive_symmetric_key(
    shared_secret: &[u8],
    salt_value: &str,
    info: &str,
    encryption_algo: &'static Algorithm,
) -> CryptoResult<Vec<u8>> {
    let salt = Salt::new(HKDF_SHA256, salt_value.as_bytes());

    // extract to generate a pseudo random key
    let prk = salt.extract(shared_secret);

    // expand to generate the final key
    let info = &[info.as_bytes()];
    let okm = prk.expand(info, encryption_algo)?;

    let mut key = vec![0u8; encryption_algo.key_len()];
    okm.fill(&mut key)?;

    Ok(key)
}

fn generate_nonce_bytes(rng: &SystemRandom) -> CryptoResult<Vec<u8>> {
    let mut nonce_bytes = vec![0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)?;
    Ok(nonce_bytes)
}

fn convert_to_nonce(nonce_bytes: &[u8]) -> CryptoResult<Nonce> {
    Nonce::try_assume_unique_for_key(nonce_bytes)
}

fn encrypt_message(
    plaintext: &[u8],
    nonce: Nonce,
    encryption_key: UnboundKey,
) -> CryptoResult<Vec<u8>> {
    let sealing_key = LessSafeKey::new(encryption_key);

    let mut in_out = plaintext.to_vec();
    sealing_key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)?;

    Ok(in_out)
}

fn decrypt_message(
    ciphertext: &[u8],
    nonce: Nonce,
    decryption_key: UnboundKey,
) -> CryptoResult<Vec<u8>> {
    let opening_key = LessSafeKey::new(decryption_key);

    let mut in_out = ciphertext.to_vec();
    let plaintext_bytes = opening_key.open_in_place(nonce, Aad::empty(), &mut in_out)?;

    Ok(plaintext_bytes.to_vec())
}

fn main() -> Result<(), Error> {
    let rng = SystemRandom::new();

    // 1. Generate key pairs for Alice and Bob
    let alice_keys = generate_key_pair(&rng)?;
    println!(
        "Alice's Public Key: 0x{}",
        hex::encode(alice_keys.public_key.as_ref())
    );

    let bob_keys = generate_key_pair(&rng)?;
    println!(
        "Bob's Public Key: 0x{}",
        hex::encode(bob_keys.public_key.as_ref())
    );

    // 2. Compute shared secret (ECDH)
    let alice_shared_secret = compute_derived_key(alice_keys.private_key, &bob_keys.public_key)?;
    let bob_shared_secret = compute_derived_key(bob_keys.private_key, &alice_keys.public_key)?;
    assert_eq!(
        alice_shared_secret, bob_shared_secret,
        "Generated shared secrets do not match!"
    );

    // 3. Derive symmetric key (HKDF)
    let symmetric_key_algo = &CHACHA20_POLY1305;
    let salt_value = "secret-salt";
    let info = "encryption-key";
    let symmetric_key_bytes =
        derive_symmetric_key(&alice_shared_secret, salt_value, info, symmetric_key_algo)?;
    println!("Derived encryption key!");
    println!("Symmetric key length: {}", symmetric_key_bytes.len());

    // 4. Encrypt a message (ChaCha20-Poly1305)
    let nonce_bytes = generate_nonce_bytes(&rng)?;

    let plaintext = "sphinx of black quartz, judge my vow";
    println!("Plaintext: {}", plaintext);
    println!("Plaintext (hex): 0x{}", hex::encode(plaintext.as_bytes()));
    println!("Plaintext len: {} bytes", plaintext.len());

    let encryption_key = UnboundKey::new(symmetric_key_algo, &symmetric_key_bytes)?;
    let nonce = convert_to_nonce(&nonce_bytes)?;

    let ciphertext = encrypt_message(plaintext.as_bytes(), nonce, encryption_key)?;
    println!("Ciphertext (hex): 0x{}", hex::encode(&ciphertext));
    println!("Ciphertext len: {} bytes", ciphertext.len());

    // 5. Decrypt the message
    let decryption_key = UnboundKey::new(symmetric_key_algo, &symmetric_key_bytes)?;
    let nonce = convert_to_nonce(&nonce_bytes)?;

    let decrypted_bytes = decrypt_message(&ciphertext, nonce, decryption_key)?;
    let decrypted_message = std::str::from_utf8(&decrypted_bytes)?;
    println!("Decrypted message: {}", decrypted_message);
    println!(
        "Decrypted message (hex): 0x{}",
        hex::encode(&decrypted_bytes)
    );
    assert_eq!(
        decrypted_message, plaintext,
        "Decrypted message does not match the original plaintext!"
    );

    Ok(())
}
