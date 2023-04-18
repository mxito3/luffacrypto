use std::result;

use aes::Aes128;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,

};
use aes::cipher::generic_array::typenum::U16;
use rand::{Rng, thread_rng};
use base64::{encode, decode};

use rand::distributions::Alphanumeric;
use uuid::Uuid;
use hex;


pub struct AesUtil {

}


impl AesUtil {

    pub fn group_data(data: &[u8]) -> Vec<GenericArray<u8,U16>> {
        let block_size=16 as usize;
        let mut blocks = vec![];
        let num_blocks;
        if  data.len() % block_size ==0{
            num_blocks = data.len() / block_size;
        }
        else{
            num_blocks = data.len() / block_size + 1;
        }
        
        for i in 0..num_blocks {
            let offset = i * block_size;
            let mut block: GenericArray<u8, U16> = GenericArray::default();
            for (j, byte) in data[offset..].iter().enumerate() {
                if j == block_size {
                    break;
                }
                block[j] = *byte;
            }
    
            blocks.push(block);
        }
        blocks
    }

    // fn bytes_to_hex_string(bytes: &[u8]) -> String {
    //     bytes.iter().map(|b| format!("{:02X}", b)).collect()
    // }

    
    pub fn new_key() -> String{
        let mut raw_key = [0u8; 16];
        let mut rng = thread_rng();
        rng.fill(&mut raw_key);
        let key = GenericArray::from(raw_key);
        let hex_key= hex::encode(key);
        println!("hex_key {} ",hex_key);
        hex_key
    }

    pub fn encrypt(origin_data: String,hex_key: String ) -> String{
        let data = origin_data.as_bytes();
        let mut raw_key = [0u8; 16];
        let hex_key_str =hex::decode(hex_key).unwrap();

        for (i, byte) in hex_key_str.iter().enumerate() {
            raw_key[i] = *byte;
        }

        let key = GenericArray::from(raw_key);

        let cipher = Aes128::new(&key);
        let mut ciphertext = data.to_vec();    
        let group_amount = ciphertext.len() / 16 + 1 ;            
 
        let mut blocks= AesUtil::group_data(data);
        cipher.encrypt_blocks(&mut blocks);

        let  mut result: String = String::new();
        let mut bytes_vec=vec![];
        for block in  blocks.iter_mut() {
            bytes_vec.extend(*block);
        }

        let res= encode(&bytes_vec);
        // println!("bytes_vec {:?}",bytes_vec);
        res
    }

    pub fn str_to_blocks(ciphertext: &str) -> Vec<GenericArray<u8,U16>>{
        let bytes = decode(ciphertext).unwrap();
        let mut blocks= AesUtil::group_data(&bytes);
        blocks
    }

    
    pub fn decrypt(ciphertext:String,hex_key:String) -> String{
        let mut raw_key = [0u8; 16];
        let hex_key_str =hex::decode(hex_key).unwrap();

        for (i, byte) in hex_key_str.iter().enumerate() {
            raw_key[i] = *byte;
        }

        let key = GenericArray::from(raw_key);

        let cipher = Aes128::new(&key);
        let mut blocks= AesUtil::str_to_blocks(&ciphertext);

        let  mut result: String = String::new();
        for block in blocks.iter_mut() {
            cipher.decrypt_block(block);
            let str=std::str::from_utf8(&block).unwrap();
            result.push_str(str);
            // println!("block {:?}",);
            // assert_eq!(block, &block_copy);
        }
    
        result =result.trim_matches('\0').to_string();
        result
    }

}


pub fn test_one() {
    let mut data = Uuid::new_v4().to_string();
    let origin_data = data.clone();

    println!("origin data {}",std::str::from_utf8(data.as_bytes()).unwrap());

    //generate key
    let key=   AesUtil::new_key();
    let copyed_key = key.clone();


    //encrypt
    let mut ciphertext= AesUtil::encrypt(data,key);
    println!("ciphertext {}",ciphertext);


    // //decrypt
    let plaintext :String= AesUtil::decrypt(ciphertext,copyed_key);

    println!("plaintext {}",plaintext);

    
    assert_eq!(plaintext,origin_data);

}

pub fn aes_util() {
    // test 1000 times
    for _ in 0..5 {
        test_one();
    }
}