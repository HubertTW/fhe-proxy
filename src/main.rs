use bincode;
use std::fs;
use std::fs::File;
use std::io::{Cursor, Write};
use std::ops::Deref;
use std::time::{Duration, Instant};
use tfhe::integer::{RadixCiphertext};
use tfhe::prelude::*;
use tfhe::prelude::{FheDecrypt, FheEncrypt, FheTrivialEncrypt};
use tfhe::{set_server_key, ClientKey, FheUint, FheUint16, FheUint16Id, FheUint8, FheUint8Id, ServerKey, FheUint32Id, FheUint32};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut k = 3;
    let mut modulo = 47u64;
    let final_state = 1u16;
    let string_size = 3;
    let mut coef: Vec<u64> = vec![40, 23, 32, 5, 38, 22, 25, 18, 33, 8, 28, 9, 0, 43, 8];
    let chars = ['a','t'];
    let code:Vec<u8> = vec![1,2,3];

    let mut file = fs::read("server_key.bin")?;
    let sk = deserialize_sk(file.as_slice())?;
    set_server_key(sk);

    println!("deserializing client key...");
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

    println!("encoding...");


    let ascii_bytes: Vec<u8> = chars.iter().map(|&c| c as u8).collect();
    let mut enc_chars = vec![];
    let mut enc_code = vec![];
    for i in ascii_bytes.clone(){
        enc_chars.push(FheUint16::encrypt_trivial(i));
    }
    for i in code.clone(){
        enc_code.push(FheUint16::encrypt_trivial(i));
    }
    let mut enc_zero = FheUint16::encrypt_trivial(0u8);
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
    for i in coef {
        enc_coef.push(FheUint16::encrypt(i, &ck));
    }

    let mut enc_modulo = FheUint16::encrypt(modulo, &ck);
    let mut enc_final_state = FheUint16::encrypt(final_state, &ck);

    println!("calculating poly...");
    //let mut state_debug = vec![];
    //let mut curr_m_debug = vec![];
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
            let mut sum = enc_coef[0].clone();
            let mut temp = &x[0] * &enc_coef[1];
            sum = &sum + &temp;

            for i in 2..len_coef {
                let mut temp_x = x[i - 2].clone();
                x.push(&temp_x * &curr_m % &enc_modulo);
                let mut temp = &x[i - 1] * &enc_coef[i];
                sum = &sum + &temp;
            }

            //let start_mod = Instant::now();
            println!("modulo...");
            curr_state = &sum % &enc_modulo;
            //let duration_mod = start_mod.elapsed();
            //println!("the mod duration is {:?}", duration_mod);


            //state_debug.push(curr_state.clone());
        }

        let elapsed = start.elapsed();
        elapsed_times.push(elapsed);

        println!("Elapsed time: {:?}", elapsed);
    }

    let total_elapsed: Duration = elapsed_times.iter().sum();
    let average_elapsed = total_elapsed / (measurements as u32);

    println!("Average poly elapsed time: {:?}", average_elapsed);

    //TODO: multi final states
    let matching_res: FheUint16 = curr_state.ne(enc_final_state).cast_into();



    println!("sanitization...");

    let measurements = 10;
    let mut elapsed_times: Vec<Duration> = Vec::new();

    let mut sanitized_v = vec![];
    for enc_x in enc_ascii.clone() {
        sanitized_v.push(&matching_res * enc_x);
    }

    for _ in 0..measurements {

        let start = Instant::now();
        for enc_x in enc_ascii.clone() {
            &matching_res * enc_x;
        }

        let elapsed = start.elapsed();
        elapsed_times.push(elapsed);

        println!("sanitization Elapsed time: {:?}", elapsed);
    }

    // 計算平均經過時間
    let total_elapsed: Duration = elapsed_times.iter().sum();
    let average_elapsed = total_elapsed / (measurements as u32);

    println!("Average sanitization elapsed time: {:?}", average_elapsed);




    println!("serialization...");
    let mut serialized_enc_str = Vec::new();
    for i in &sanitized_v {
        bincode::serialize_into(&mut serialized_enc_str, &i)?;
    }
    let mut file_str = File::create("sanitized_payload.bin")?;
    file_str.write(serialized_enc_str.as_slice())?;
    println!("done");

    println!("[debug] decrypt sanitized result");
    let s = decryptStr(sanitized_v, &ck);
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

/* PROXY SERVER COMPUTING */
pub fn sanitizer(content: &mut Vec<RadixCiphertext>, sk: tfhe::integer::ServerKey) {
    println!("start sanitizing...");
    let target = "he";
    let mut target_bytes = vec![];
    for i in target.bytes() {
        target_bytes.push(i);
    }
    for shift in 0..(content.len() - target_bytes.len() + 1) {
        let mut byte_comp: Vec<RadixCiphertext> = vec![];
        for j in 0..target_bytes.len() {
            byte_comp.push(
                sk.smart_scalar_eq_parallelized(&mut content[shift + j], target_bytes[j])
                    .into_radix(4, &sk),
            );
        }
        /* if len of target == 1? */
        let mut b1: RadixCiphertext = byte_comp[0].clone();
        let mut b2: RadixCiphertext = byte_comp[1].clone();
        let mut mask = sk.smart_bitand_parallelized(&mut b1, &mut b2);
        //let mut mask = sk.smart_bitand_parallelized(&mut byte_comp[0],&mut byte_comp[1]);
        for j in 2..target_bytes.len() - 1 {
            mask = sk.smart_bitand_parallelized(&mut mask, &mut byte_comp[j]);
        }
        mask = sk
            .smart_scalar_eq_parallelized(&mut mask, 0 as u8)
            .into_radix(4, &sk);
        for j in 0..target_bytes.len() {
            content[shift + j] = sk.smart_mul_parallelized(&mut mask, &mut content[shift + j]);
        }
    }
    println!("sanitizing finished");
}
