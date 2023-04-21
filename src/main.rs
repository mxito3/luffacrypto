use aes_en::aes_util;
use des_en::des_util;
use  keys::Keychain;
mod aes_en;
mod des_en;
mod keys;
fn main() {
    // aes_util();
    // des_util();
    let mut key_chain = Keychain{};
    // let res: keys::Keypair = key_chain.create_ed25519_key().unwrap();


    let  (mnemonic, keypair) =  key_chain.create_ed25519_key_bip39("").unwrap();

    println!("mnemonic: {:?}",mnemonic);

    println!("public_key: {:?}",keypair.public_key());
    println!("private_key: {:?}",keypair.private_key());

}
                
                
                