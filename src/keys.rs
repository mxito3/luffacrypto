//! Handles storage and retrieval of public & private keys.

use std::{path::{Path, PathBuf}, string};

use libp2p::PeerId;
use ssh_key::LineEnding;
use zeroize::Zeroizing;
use bip39::{Mnemonic, MnemonicType, Language, Seed};
use anyhow::{anyhow, Result};
use hex;

/// Supported keypairs.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Keypair {
    Ed25519(ssh_key::private::Ed25519Keypair),
}

impl Keypair {
    /// Encodes the private part of the keypair into the ssh-key file format.
    fn to_private_openssh(&self) -> Result<Zeroizing<String>> {
        match self {
            Keypair::Ed25519(kp) => {
                let res = ssh_key::private::PrivateKey::from(kp.clone())
                    .to_openssh(LineEnding::default())?;
                Ok(res)
            }
        }
    }

    fn algorithm(&self) -> ssh_key::Algorithm {
        match self {
            Keypair::Ed25519(_) => ssh_key::Algorithm::Ed25519,
        }
    }
    
    pub fn name(&self) -> String {
        match self {
            Keypair::Ed25519(key) => {
                let pk = key.public;
                let pk = libp2p::identity::ed25519::PublicKey::decode(&pk.0).unwrap();
                let pk = libp2p::identity::PublicKey::Ed25519(pk);
                let peer_id = PeerId::from_public_key(&pk);

                let mut digest = crc64fast::Digest::new();
                digest.write(&peer_id.to_bytes());
                let u_id = digest.sum64();
                bs58::encode(u_id.to_be_bytes()).into_string()
            },
        }
    }

    pub fn public_key(&self) -> String{
        match self {
            Keypair::Ed25519(key) => {
                let pk = key.public;
                pk.to_string()
            },
            
        }
    }

    pub fn private_key(&self) ->String{
        match self {
            Keypair::Ed25519(key) => {
                let mut pk = &key.private;
                hex::encode(pk.to_bytes())
                // bs58::encode(pk.to_bytes()).into_string()
            },  
            
        }
    }
}

impl TryFrom<&'_ ssh_key::private::PrivateKey> for Keypair {
    type Error = anyhow::Error;

    fn try_from(key: &ssh_key::private::PrivateKey) -> Result<Self, Self::Error> {
        match key.key_data() {
            ssh_key::private::KeypairData::Ed25519(kp) => Ok(Keypair::Ed25519(kp.clone())),
            _ => Err(anyhow!("unsupported key format: {}", key.algorithm())),
        }
    }
}

impl From<Keypair> for libp2p::identity::Keypair {
    fn from(kp: Keypair) -> Self {
        match kp {
            Keypair::Ed25519(kp) => {
                let mut bytes = kp.to_bytes();
                let kp = libp2p::identity::ed25519::Keypair::decode(&mut bytes)
                    .expect("invalid encoding");
                libp2p::identity::Keypair::Ed25519(kp)
            }
        }
    }
}

/// A keychain to manage your keys.
#[derive(Debug,Clone)]
pub struct Keychain{
}

impl Keychain {
    /// Creates a new Ed25519 based key and stores it.
    pub  fn create_ed25519_key(&mut self) -> Result<Keypair> {

        let keypair = ssh_key::private::Ed25519Keypair::random(rand::thread_rng());
        let keypair = Keypair::Ed25519(keypair);
        
        Ok(keypair)
    }
    /// Creates a new Ed25519 based key and stores it.
    pub  fn create_ed25519_key_bip39(&mut self,password:&str) -> Result<(String,Keypair)> {
        // create a new randomly generated mnemonic phrase
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        
        // get the HD wallet seed
        let seed = Seed::new(&mnemonic, password);
        let mut seed_data = [0u8;ssh_key::private::Ed25519PrivateKey::BYTE_SIZE];
        let seed_bytes: &[u8] = seed.as_bytes();
        seed_data.clone_from_slice(&seed_bytes[..32]);
        // get the HD wallet seed as raw bytes

        let keypair = ssh_key::private::Ed25519Keypair::from_seed(&seed_data);
        let keypair = Keypair::Ed25519(keypair);

        Ok((mnemonic.into_phrase(),keypair))
    }
    
    pub  fn create_ed25519_key_from_seed(&mut self,phrase:&str,password:&str)-> Result<Keypair> {
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English)?;
        let seed = Seed::new(&mnemonic, password);
        let mut seed_data = [0u8;ssh_key::private::Ed25519PrivateKey::BYTE_SIZE];
        let seed_bytes: &[u8] = seed.as_bytes();
        seed_data.clone_from_slice(&seed_bytes[..32]);
        let keypair = ssh_key::private::Ed25519Keypair::from_seed(&seed_data);
        let keypair = Keypair::Ed25519(keypair);
        Ok(keypair)
    }
    pub  fn create_ed25519_key_from_bytes(&mut self,data:&[u8;64])-> Result<Keypair> {
        let keypair = ssh_key::private::Ed25519Keypair::from_bytes(data)?;
        let keypair = Keypair::Ed25519(keypair);
        Ok(keypair)
    }

}
