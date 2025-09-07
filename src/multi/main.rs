use aead::{Aead, AeadCore, KeyInit, KeySizeUser, OsRng, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

fn main() -> anyhow::Result<()> {
    let rng = OsRng;

    // 1. Generate public / private key pair using curve25519
    // Alice and Bob each generate a key pair independently
    println!("Generating key pairs...");

    let alice_secret = EphemeralSecret::random_from_rng(rng);
    let alice_public = PublicKey::from(&alice_secret);
    println!(
        "Alice Public Key: 0x{}",
        hex::encode(alice_public.as_bytes())
    );

    let bob_secret = EphemeralSecret::random_from_rng(rng);
    let bob_public = PublicKey::from(&bob_secret);
    println!("Bob Public Key: 0x{}", hex::encode(bob_public.as_bytes()));

    println!("✅ Key pairs generated.");

    // 2. Compute shared secret using Elliptic-curve Diffie-Hellman (ECDH)
    // Alice and Bob share their public keys with each other over unsecured channel
    // They each compute the shared secret independently using their own private key and the other party's public key
    println!("Computing shared secret...");

    let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
    let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);
    assert_eq!(
        alice_shared_secret.as_bytes(),
        bob_shared_secret.as_bytes(),
        "Shared secrets do not match!"
    );

    println!(
        "Shared Secret: 0x{}",
        hex::encode(alice_shared_secret.as_bytes())
    );

    println!("✅ Shared secret computed successfully");

    // 3. Derive symmetric key from shared secret using HKDF (HMAC-based Key Derivation Function)
    // The shared secret is not used directly as a symmetric key, instead we derive a key from it
    // using HKDF.
    // This is important because the secret derived using ECDH
    //  - may have a different length than required by the symmetric cipher
    //  - may not be uniformly distributed
    //  - may not have sufficient entropy
    //  - may be vulnerable to certain attacks if used directly
    println!("Deriving symmetric key from shared secret using HKDF SHA256...");

    // Input Keying Material (IKM) is the shared secret
    let ikm = alice_shared_secret.as_bytes();
    // Optional salt value (a non-secret random value)
    let salt = Some(b"magic-nacl".as_slice());
    // Optional context and application specific information
    // (info) string should be different for different applications to ensure
    // that the derived keys are different even if the same IKM and salt are used
    let info = b"encryption-key";

    // 3.1 Extract step
    // Hkdf::new emulates the extract logic
    let hkdf = Hkdf::<Sha256>::new(salt, ikm);

    // Output Keying Material (OKM) is the derived symmetric key used for encryption/decryption
    let mut okm = vec![0u8; ChaCha20Poly1305::key_size()];
    // 3.2 Expand step
    hkdf.expand(info.as_slice(), &mut okm)
        .expect("okm should be generated");

    println!("Derived Symmetric Key: 0x{}", hex::encode(&okm));

    println!(
        "✅ Successfully derived symmetric key of length {}",
        okm.len()
    );

    // 4. Encrypt message using symmetric key (ChaCha20-Poly1305)
    // ChaCha20-Poly103 is an AEAD (Authenticated Encryption with Associated Data) cipher
    let plaintext = "sphinx of black quartz, judge my vow";
    println!("Plaintext: {}", plaintext);
    println!("Plaintext length: {}", plaintext.len());
    println!("Encrypting message...");

    let encryption_key = chacha20poly1305::Key::from_slice(okm.as_slice());
    let cipher = ChaCha20Poly1305::new(encryption_key);

    // A unique nonce must be used for each encryption operation with the same key
    let nonce = ChaCha20Poly1305::generate_nonce(rng);

    // The encrypted message (ciphertext) includes the authentication tag (suffixed)
    let encrypted_message = cipher
        .encrypt(&nonce, Payload::from(plaintext.as_ref()))
        .expect("encryption should succeed");

    println!("✅ Message encrypted successfully.");
    println!("Ciphertext: 0x{}", hex::encode(&encrypted_message));
    println!("Ciphertext length: {}", encrypted_message.len());

    // 5. Decrypt message using symmetric key (ChaCha20-Poly1305)
    println!("Decrypting message...");

    let decryption_key = chacha20poly1305::Key::from_slice(okm.as_slice());
    let cipher = ChaCha20Poly1305::new(decryption_key);

    let decrypted_bytes = cipher
        .decrypt(&nonce, Payload::from(encrypted_message.as_ref()))
        .expect("decryption should succeed");
    let decrypted_message =
        String::from_utf8(decrypted_bytes).expect("decrypted plaintext should be valid UTF-8");

    assert_eq!(
        decrypted_message, plaintext,
        "Decrypted plaintext does not match original plaintext!"
    );

    println!("Decrypted plaintext: {}", decrypted_message);
    println!("Decrypted plaintext length: {}", decrypted_message.len());

    println!("✅ Message decrypted successfully and matches the original plaintext.");

    Ok(())
}
