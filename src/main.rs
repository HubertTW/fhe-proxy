use bincode;
use std::fs;
use std::env;
use std::fs::File;
use glob::glob;
use std::io::BufRead;
use std::io::{BufReader, Cursor, Write};
use std::ops::Deref;
use std::time::{Duration, Instant};
use rayon::prelude::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use tfhe::integer::{RadixCiphertext};
use tfhe::prelude::*;
use tfhe::prelude::{FheDecrypt, FheEncrypt, FheTrivialEncrypt};
use tfhe::{set_server_key, ClientKey, FheUint, FheUint16, FheUint16Id, FheUint8, FheUint8Id, ServerKey, FheUint32Id, FheUint32};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let string_size = args[1].parse::<u8>().expect("Not a valid u8");;

    let mut file = fs::read("server_key.bin")?;
    let sk = deserialize_sk(file.as_slice())?;

    rayon::broadcast(|_| set_server_key(sk.clone()));
    set_server_key(sk);
    let args: Vec<String> = env::args().collect();
    println!("DEBUG: deserializing client key...");
    let mut byte_vec = fs::read("client_key.bin")?;
    let ck = deserialize_ck(&byte_vec.into_boxed_slice().deref())?;

    /*
    println!("deserializing encrypted_str.bin...");
    let file = fs::read("encrypted_str.bin")?;
    let enc_str = deserialize_str(&file, string_size)?;
    */

    println!("deserializing encrypted_ascii.bin...");
    let file = fs::read("encrypted_ascii.bin")?;
    let mut enc_ascii = deserialize_str(&file, string_size)?;
    let mut enc_str =  enc_ascii.clone();

    //let file = fs::read("encrypted_ascii.bin")?;
    //let mut enc_ascii = deserialize_str(&file, string_size)?;

    //let mut v_string = vec![];
    //let mut v_lastchar = vec![];

/*
    println!("encoding...");
    let mut enc_zero = FheUint16::encrypt_trivial(0u8);
    let mut enc_one = FheUint16::encrypt_trivial(1u8);
    let encoding_bytes: Vec<u8> = encoding.iter().map(|&c| c as u8).collect();
    //let mut enc_chars = vec![];

    let mut enc_encoding =vec![];
    for i in encoding_bytes.clone(){
       enc_encoding.push(FheUint16::encrypt_trivial(i));
    }
    let mut enc_code = vec![];
    for i in 1..27{
        enc_code.push(FheUint16::encrypt_trivial(i as u8));
    }


    for (i,ascii_val) in enc_str.clone().iter().enumerate(){
        for (j,chars_val) in enc_encoding.clone().iter().enumerate() {

            let enc_cmp = ascii_val.eq(chars_val);
            enc_str[i] = enc_cmp.if_then_else(&enc_code[j], &enc_str[i]);

        }
    }

    let mut encoding_clear:Vec<u8> = vec![];
    for i in enc_str.clone(){
        encoding_clear.push(i.decrypt(&ck));
    }
    println!("[debug] the encoding is {:?}", encoding_clear);

*/

    let file_path = "space_indices.txt";
    let loaded_indices = load_from_file(file_path);
    println!("Loaded indices: {:?}", loaded_indices);

    let mut enc_string_arrays = Vec::new();
    let mut start = 0;

    for &index in &loaded_indices {
        if index > start {
            // 將非空格部分加入結果
            enc_string_arrays.push(enc_ascii[start..index].to_vec());
        }
        start = index + 1; // 跳過空格
    }

    // 添加最後一段
    if start < enc_ascii.len() {
        enc_string_arrays.push(enc_ascii[start..].to_vec());
    }

    println!("slice string serialization...");
    let mut count = 0 as u8;
    for arr in  enc_string_arrays{
        let mut serialized_enc_str = Vec::new();
        for i in &arr {
            bincode::serialize_into(&mut serialized_enc_str, &i)?;
        }
        let file_name = format!("slice_string_{}.bin", count);
        let mut file_str = File::create(&file_name)?;
        file_str.write(serialized_enc_str.as_slice())?;
        count+=1;
    }



    Ok(())




}
fn load_from_file(file_path: &str) -> Vec<usize> {
    if let Ok(file) = File::open(file_path) {
        let reader = BufReader::new(file);
        let mut indices = Vec::new();

        for line in reader.lines() {

            if let Ok(line) = line {

                if let Ok(value) = line.parse::<usize>() {
                    indices.push(value);
                }
            }
        }
        indices
    } else {
        Vec::new()
    }
}


fn extract_number(file_name: &str) -> u32 {
    file_name
        .split('_')
        .last() // 取得最後一部分，例如 "0.bin"
        .and_then(|s| s.strip_suffix(".bin")) // 去除後綴
        .and_then(|s| s.parse::<u32>().ok()) // 轉換成數字
        .unwrap_or(0) // 預設為 0
}

pub fn decryptStr(content: Vec<FheUint<FheUint16Id>>, ck: &ClientKey) -> String {
    let mut v = vec![];

    for byte in &content {
        v.push(byte.decrypt(&ck));
    }

    let measurements = 100;
    let mut elapsed_times: Vec<Duration> = Vec::new();

    for _ in 0..measurements {
        let start = Instant::now();
        for byte in &content {
            let temp: u8 = byte.decrypt(&ck);
        }
        let elapsed = start.elapsed();
        elapsed_times.push(elapsed);
        //println!("Elapsed time: {:?}", elapsed);
    }

    // 計算平均經過時間
    let total_elapsed: Duration = elapsed_times.iter().sum();
    let average_elapsed = total_elapsed / (measurements as u32);

    println!("Average decryption elapsed time: {:?}", average_elapsed);

    println!("{:?}", v);
    String::from_utf8(v).unwrap()

}
fn deserialize_sk(serialized_data: &[u8]) -> Result<ServerKey, Box<dyn std::error::Error>> {
    let mut to_des_data = Cursor::new(serialized_data);
    let sk: ServerKey = bincode::deserialize_from(&mut to_des_data)?;
    Ok(sk)
}

fn deserialize_ck(serialized_data: &[u8]) -> Result<ClientKey, Box<dyn std::error::Error>> {
    let mut to_des_data = Cursor::new(serialized_data);
    let ck: ClientKey = bincode::deserialize_from(&mut to_des_data)?;
    Ok(ck)
}

fn deserialize_str(
    serialized_data: &[u8],
    content_size: u8
) -> Result<Vec<FheUint<FheUint16Id>>, Box<dyn std::error::Error>> {
    let mut to_des_data = Cursor::new(serialized_data);
    let mut v: Vec<FheUint<FheUint16Id>> = vec![];
    for _ in 0..content_size{
        // length of received string
        v.push(bincode::deserialize_from(&mut to_des_data)?);
    }
    Ok(v)
}


