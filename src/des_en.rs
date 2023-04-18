use  des::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray, Block
};


use uuid::Uuid;
use des::Des;
use des::cipher::generic_array::typenum::U8;
use base64::{encode, decode};
use rand::{Rng, thread_rng};

pub struct DesUtil {

}


impl DesUtil {
    pub fn new_key() -> String{
        let mut raw_key = [0u8; 8];
        let mut rng = thread_rng();
        rng.fill(&mut raw_key);
        let key = GenericArray::from(raw_key);
        let hex_key= hex::encode(key);
        println!("hex_key {} ",hex_key);
        hex_key
    }
    pub fn group_data(data: &[u8]) -> Vec<GenericArray<u8,U8>> {
        let block_size=8 as usize;
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
            let mut block: GenericArray<u8, U8> = GenericArray::default();
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

    pub fn encrypt(origin_data: String,hex_key: String ) -> String{
        let data = origin_data.as_bytes();
        let mut raw_key = [0u8; 8];
        let hex_key_str =hex::decode(hex_key).unwrap();

        for (i, byte) in hex_key_str.iter().enumerate() {
            raw_key[i] = *byte;
        }

        let key = GenericArray::from(raw_key);

        let cipher = Des::new(&key);
        let mut ciphertext = data.to_vec();    
         
 
        let mut blocks= DesUtil::group_data(data);
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

    pub fn str_to_blocks(ciphertext: &str) -> Vec<GenericArray<u8,U8>>{
        let bytes = decode(ciphertext).unwrap();
        let mut blocks= DesUtil::group_data(&bytes);
        blocks
    }

    
    pub fn decrypt(ciphertext:String,hex_key:String) -> String{
        let mut raw_key = [0u8; 8];
        let hex_key_str =hex::decode(hex_key).unwrap();

        for (i, byte) in hex_key_str.iter().enumerate() {
            raw_key[i] = *byte;
        }

        let key = GenericArray::from(raw_key);

        let cipher = Des::new(&key);
        let mut blocks= DesUtil::str_to_blocks(&ciphertext);

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
    let key=   DesUtil::new_key();
    let copyed_key = key.clone();


    //encrypt
    let mut ciphertext= DesUtil::encrypt(data,key);
    println!("ciphertext {}",ciphertext);


    // //decrypt
    let plaintext :String= DesUtil::decrypt(ciphertext,copyed_key);

    println!("plaintext {}",plaintext);

    
    assert_eq!(plaintext,origin_data);

}

pub fn des_util() {
    // test 1000 times
    for _ in 0..5 {
        test_one();
    }
}