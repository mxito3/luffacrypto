use aes_en::AesUtil;
use des_en::DesUtil;
use crate::avatar_nickname::avatar::generate_avatar;
use crate::avatar_nickname::nickname::generate_nickname;

pub mod aes_en;
pub mod des_en;
pub mod avatar_nickname;

fn new_aes_key() -> String {
    AesUtil::new_key()
}

fn aes_encrypt(origin_data: String,hex_key: String ) -> String {
    AesUtil::encrypt(origin_data,hex_key)
}

fn aes_decrypt(ciphertext: String,hex_key: String ) -> String {
    AesUtil::decrypt(ciphertext,hex_key)
}


fn des_encrypt(origin_data: String,hex_key: String ) -> String {
    DesUtil::encrypt(origin_data,hex_key)
}

fn des_decrypt(ciphertext: String,hex_key: String ) -> String {
    DesUtil::decrypt(ciphertext,hex_key)
}

fn new_des_key() -> String {
    DesUtil::new_key()
}

