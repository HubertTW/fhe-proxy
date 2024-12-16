use bincode;
use std::fs;
use std::env;
use std::fs::File;
use glob::glob;
use std::io::{Cursor, Write};
use std::ops::Deref;
use std::time::{Duration, Instant};
use tfhe::integer::{RadixCiphertext};
use tfhe::prelude::*;
use tfhe::prelude::{FheDecrypt, FheEncrypt, FheTrivialEncrypt};
use tfhe::{set_server_key, ClientKey, FheUint, FheUint16, FheUint16Id, FheUint8, FheUint8Id, ServerKey, FheUint32Id, FheUint32};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let mut k = 3 ;
    let mut modulo = 47u16;
    let final_state:Vec<u16> = vec![1];
    let string_size = args[1].parse::<u8>().expect("Not a valid u8");;
    let string_number = args[2].parse::<usize>().expect("Not a valid usize");
    let mut coef: Vec<u16> = vec![41, 13, 42, 36, 38, 39, 16, 35, 23];
    let chars = ['f',' '];//consistent with python
    let code:Vec<u8> = vec![1,2,3];

    let mut file = fs::read("server_key.bin")?;
    let sk = deserialize_sk(file.as_slice())?;
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

    let file = fs::read("encrypted_ascii.bin")?;
    let mut enc_ascii = deserialize_str(&file, string_size)?;

    let mut v_string = vec![];
    let mut v_lastchar = vec![];

    for entry in glob("string*").expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => {
                println!("Reading file: {:?}", path.display());
                let mut file = fs::read(&path)?;
                v_string.push(deserialize_str(&file, string_size)?);
            },
            Err(e) => println!("Error reading file: {:?}", e),
        }
    }
    for entry in glob("last*").expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => {
                println!("Reading file: {:?}", path.display());
                let mut file = fs::read(&path)?;
                v_lastchar.push(deserialize_str(&file, string_size)?);
            },
            Err(e) => println!("Error reading file: {:?}", e),
        }
    }
    println!("encoding...");
    let mut enc_zero = FheUint16::encrypt_trivial(0u8);
    let mut enc_one = FheUint16::encrypt_trivial(1u8);
    let ascii_bytes: Vec<u8> = chars.iter().map(|&c| c as u8).collect();
    let mut enc_chars = vec![];
    let mut enc_code = vec![];
    for i in ascii_bytes.clone(){
        enc_chars.push(FheUint16::encrypt_trivial(i));
    }
    for i in code.clone(){
        enc_code.push(FheUint16::encrypt_trivial(i));
    }

    for (i,ascii_val) in enc_str.clone().iter().enumerate(){
        let mut count = enc_zero.clone();
        for (j,chars_val) in enc_chars.clone().iter().enumerate() {

            let enc_cmp = ascii_val.eq(chars_val);
            enc_str[i] = enc_cmp.if_then_else(&enc_code[j], &enc_str[i]);
            count = &count + &enc_cmp.cast_into();
        }
        let enc_final_cmp = &count.eq(&enc_zero);
        enc_str[i] = enc_final_cmp.if_then_else(&enc_code[code.len()-1], &enc_str[i]);

    }

    let mut encoding_clear:Vec<u8> = vec![];
    for i in enc_str.clone(){
        encoding_clear.push(i.decrypt(&ck));
    }
    println!("[debug] the encoding is {:?}", encoding_clear);


    let mut len_coef = coef.len();
    println!("poly degree: {}", len_coef);
    let mut enc_coef = vec![];
    for i in coef.clone() {
        enc_coef.push(FheUint16::encrypt_trivial(i)); //FheUint16::encrypt(i, &ck)
    }

    //let mut enc_modulo = FheUint16::encrypt_trivial(modulo);
    let mut enc_final_state = vec![];

    for i in final_state.clone(){
       enc_final_state.push(FheUint16::encrypt_trivial(i)); //FheUint16::encrypt(i, &ck)
    }


    println!("calculating poly...");
    //let mut state_debug = vec![];
    //let mut curr_m_debug = vec![];
    let mut v_states = vec![];
    let mut curr_state = FheUint16::encrypt_trivial(0u8);

    let measurements = 1;
    let mut elapsed_times: Vec<Duration> = Vec::new();
    for _ in 0..measurements {

        curr_state = FheUint16::encrypt_trivial(0u8);
        let start = Instant::now();

        for enc_x in &enc_str {

            let mut curr_m = enc_x + &curr_state * k;
            let mut x = vec![];
            x.push(curr_m.clone());
            //curr_m_debug.push(curr_m.clone());

            //1+x
            let mut sum = enc_coef[0].clone();;
            let mut temp = &x[0] * coef[1];
            sum = &sum + &temp;

            for i in 2..len_coef {
                let mut temp_x = x[i - 2].clone();
                x.push(&temp_x * &curr_m % modulo);
                let mut temp = &x[i - 1] * coef[i];
                sum = &sum + &temp;
            }

            //let start_mod = Instant::now();
            println!("final modulo...");
            curr_state = &sum % modulo;
            //let duration_mod = start_mod.elapsed();
            //println!("the mod duration is {:?}", duration_mod);

            //state_debug.push(curr_state.clone());
            v_states.push(curr_state.clone());
        }

        let elapsed = start.elapsed();
        elapsed_times.push(elapsed);

        println!("Elapsed time: {:?}", elapsed);
    }

    let total_elapsed: Duration = elapsed_times.iter().sum();
    let average_elapsed = total_elapsed / (measurements as u32);

    println!("Average poly elapsed time: {:?}", average_elapsed);

    //let debug_state:u8 = curr_state.decrypt(&ck);
    //println!("debug curr state {:?}", debug_state);



    println!("sanitization...");

    let measurements = 3;
    let mut elapsed_times: Vec<Duration> = Vec::new();
    for _ in 0..measurements {
        let start = Instant::now();

        for i in 0..string_number {
            for (idx, val) in v_states.iter().enumerate() {
                v_lastchar[i][idx] = &v_lastchar[i][idx] * val.clone();
            }
            let mut string_final_state = enc_zero.clone();
            for val in v_lastchar[i].clone() {
                string_final_state += val;
            }

            println!("checking accepting state...");
            let mut matching_count: FheUint16 = enc_zero.clone();
            for i in enc_final_state.clone() {
                matching_count = matching_count + FheUint16::cast_from(string_final_state.eq(i));
            }
            let matching_res = matching_count.eq(enc_zero.clone());
            //let matching_res: FheUint16 = FheUint16::cast_from(matching_count.eq(enc_zero.clone()));
            /* 1: not matching; 0: matching */

            for idx in 0..string_size {
                let idx_usize = idx as usize;
                let position_check = v_string[i][idx_usize.clone()].eq(&enc_zero);
                v_string[i][idx_usize.clone()] = position_check.if_then_else(&matching_res.if_then_else(&enc_one, &enc_zero), &enc_one);
                enc_ascii[idx_usize.clone()] = &v_string[i][idx_usize.clone()] * &enc_ascii[idx_usize.clone()];
            }
        }

        let elapsed = start.elapsed();
        elapsed_times.push(elapsed);

        println!("sanitization elapsed time: {:?}", elapsed);
    }

    let total_elapsed: Duration = elapsed_times.iter().sum();
    let average_elapsed = total_elapsed / (measurements as u32);

    println!("Average sanitization elapsed time: {:?}", average_elapsed);


    println!("serialization...");
    let mut serialized_enc_str = Vec::new();
    for i in &enc_ascii {
        bincode::serialize_into(&mut serialized_enc_str, &i)?;
    }
    let mut file_str = File::create("sanitized_payload.bin")?;
    file_str.write(serialized_enc_str.as_slice())?;
    println!("done");

    println!("[debug] decrypt sanitized result");
    let s = decryptStr(enc_ascii, &ck);
    println!("the sanitized res is {:?}", s);

    /*
    let mut result_clear:Vec<u8>  = vec![];
    for i in sanitized_v{
        result_clear.push(i.decrypt(&ck));
    }
    println!("the sanitized res is {:?}", result_clear);
    */



    //println!("[debug] decryption...");
    //let mut clear: u8 = matching_res.decrypt(&ck);
    /*

    let mut n_clear:Vec<u16> = vec![];
    for i in state_debug{
        n_clear.push(i.decrypt(&ck));
    }
    let mut m_clear:Vec<u16> = vec![];
    for i in curr_m_debug{
        m_clear.push(i.decrypt(&ck));
    }
    println!("the m is {:?}", m_clear);
    println!("the n is {:?}", n_clear);
    */
    //let mut x_debug:Vec<u64> = vec![];
    //for i in x{
    //    x_debug.push(i.decrypt(&ck));
    //}
    //println!("the result is {:?}", clear);
    //println!("the sum is {:?}", sum_debug);


    Ok(())

    /* server decryption */
    /*
    println!("reading client key...");
    let mut byte_vec = fs::read("client_key.bin")?;
    println!("deserializing client key...");
    let ck = deserialize_ck(&byte_vec.into_boxed_slice().deref())?;
    let file = fs::read("sanitized_payload.bin")?;
    let enc_str = deserialize_str(&file)?;
    let mut v:Vec<u8> = vec![];
    for i in enc_str{
        v.push(i.decrypt(&ck));
    }
    println!("{:?}", v);


    Ok(())
    */
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


