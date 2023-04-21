use bip39::{Language, Mnemonic, Seed};
use rand::rngs::OsRng;
use secp256k1::{Secp256k1, SecretKey};



pub fn generate_ecc_keypair_from_bip39(mnemonic: &str, password: &str) -> (String, SecretKey) {
    // println!("private_key: {:?}",mnemonic);

    // Generate a seed from the mnemonic and password
    let mnemonic = Mnemonic::from_phrase(mnemonic, Language::English).expect("invalid mnemonic");
    let seed = Seed::new(&mnemonic, password);
    // println!("seed: {:?}",seed.as_bytes());
    // println!("len seeds :{:?} ",seed.as_bytes().len());
    // Generate a secret key from the seed

    let mut csprng = OsRng {};
    let secp = Secp256k1::new();


    let secret_key = SecretKey::from_slice( &seed.as_bytes()[..32]).unwrap();

    // Return the hex-encoded private key and secret key
    let private_key = hex::encode(secret_key.as_ref());
    (private_key, secret_key)
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_generate_ecc_keypair_from_bip39() {
//         let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//         let password = "";
//         let seed = bip39::Seed::new(&mnemonic, &password);

//         let (public_key, private_key) = generate_ecc_keypair_from_bip39(seed.as_bytes());

//         assert_eq!(public_key.len(), 33);
//         assert_eq!(private_key.len(), 32);
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keychain;    
    #[test]
    fn test_generate_ecc_keypair_from_bip39() {
        let mut key_chain: Keychain = Keychain{};

        for _ in 0..100 {
            let  (mnemonic, keypair) =  key_chain.create_ed25519_key_bip39("").unwrap();

            // println!("mnemonic: {:?}",mnemonic);        
            let password = "";
        
    
            let (public_key, private_key) = generate_ecc_keypair_from_bip39(&mnemonic,password);
    
            assert_eq!(public_key.len(), 64);
        }

    }
}