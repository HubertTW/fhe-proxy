use std::fs;
use std::fs::File;
use std::io::{BufReader, Cursor, Read, Write};
use std::ops::Deref;
use tfhe::integer::{gen_keys_radix, IntegerRadixCiphertext, RadixCiphertext, RadixClientKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use bincode;

fn main() -> Result<(), Box<dyn std::error::Error>>{
    my_key_gen()?;

    println!("reading client key...");
    let mut byte_vec = fs::read("client_key.txt")?;
    println!("deserializing client key...");
    let ck = deserialize_ck(&byte_vec.into_boxed_slice().deref())?;
    println!("encrypting string...");
    let enc_data = encryptStr("linux", &ck);
    println!("serializing ciphertext...");
    let mut serialized_enc_str = Vec::new();
    for i in enc_data {
        bincode::serialize_into(&mut serialized_enc_str, &i)?;
    }
    let mut file_str = File::create("encrypted_str.txt")?;
    file_str.write(serialized_enc_str.as_slice())?;
    println!("done");

    Ok(())

}

pub fn encryptStr(content: &str, ck: &RadixClientKey) -> Vec<RadixCiphertext> {
    let mut v = vec![];
    for byte in content.bytes() {
        v.push(ck.encrypt(byte));
    }
    v
}


fn deserialize_ck(serialized_data: &[u8]) -> Result<RadixClientKey, Box<dyn std::error::Error>> {
    let mut to_des_data = Cursor::new(serialized_data);
    let ck: RadixClientKey= bincode::deserialize_from(&mut to_des_data)?;
    Ok(ck)
}

fn my_key_gen() -> Result<(), Box<dyn std::error::Error>> {
    let num_block = 4;
    let (client_key, server_key) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block);
    let mut serialized_client_key = Vec::new();
    bincode::serialize_into(&mut serialized_client_key, &client_key)?;
    let mut file_ck = File::create("client_key.txt")?;
    let box_ck = serialized_client_key.into_boxed_slice();
    file_ck.write_all(box_ck.deref())?;

    let mut serialized_server_key = Vec::new();
    bincode::serialize_into(&mut serialized_server_key, &server_key)?;
    let mut file_sk = File::create("server_key.txt")?;
    let box_sk = serialized_server_key.into_boxed_slice();
    file_sk.write_all(box_sk.deref())?;

    println!("finished serialization");
    Ok(())


}