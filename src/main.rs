use bincode;
use std::fs;
use std::fs::File;
use std::io::{Cursor, Write};
use std::ops::Deref;
use std::time::Instant;
use tfhe::integer::{gen_keys_radix, IntegerRadixCiphertext, RadixCiphertext, RadixClientKey};
use tfhe::prelude::*;
use tfhe::prelude::{FheDecrypt, FheEncrypt, FheTrivialEncrypt};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use tfhe::{set_server_key, ClientKey, FheUint, FheUint16, FheUint16Id, FheUint8, FheUint8Id, ServerKey, FheUint32Id, FheUint32};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = fs::read("server_key.bin")?;
    let sk = deserialize_sk(file.as_slice())?;
    set_server_key(sk);

    println!("deserializing client key...");
    let mut byte_vec = fs::read("client_key.bin")?;
    let ck = deserialize_ck(&byte_vec.into_boxed_slice().deref())?;

    println!("deserializing intercepted_payload.bin...");
    let file = fs::read("encrypted_str.bin")?;
    let enc_str = deserialize_str(&file)?;

    let mut coef: Vec<u64> = vec![13, 14, 3, 15, 17, 13, 22, 14, 17, 21, 11, 12, 1, 1, 9, 21, 21, 7];
    let mut len_coef = coef.len();
    println!("{}", len_coef);
    let mut enc_coef = vec![];
    for i in coef {
        enc_coef.push(FheUint32::encrypt(i, &ck));
    }
    let mut modulo = 23u64;
    let mut enc_modulo = FheUint32::encrypt(modulo, &ck);
    let final_state = 1u16;
    let mut enc_final_state = FheUint32::encrypt(final_state, &ck);

    println!("calculating poly...");
    let mut state_debug = vec![];
    let mut curr_m_debug = vec![];
    let mut curr_state = FheUint32::encrypt_trivial(0u8);
    for enc_x in &enc_str {
        let start = Instant::now();

        let mut curr_m = enc_x + &curr_state * 3;//k
        let mut x = vec![];
        x.push(curr_m.clone());
        curr_m_debug.push(curr_m.clone());

        //1+x
        let mut sum = enc_coef[0].clone();
        let mut temp = &x[0] * &enc_coef[1];
        sum = &sum + &temp;

        for i in 2..len_coef {
            let mut temp_x = x[i - 2].clone();
            x.push(&temp_x * &curr_m);
            let mut temp = &x[i - 1] * &enc_coef[i];
            sum = &sum + &temp;
        }

        let start_mod = Instant::now();
        println!("modulo...");
        curr_state = &sum % &enc_modulo;
        let duration_mod = start_mod.elapsed();
        println!("the mod duration is {:?}", duration_mod);

        let duration = start.elapsed();
        println!("the poly duration is {:?}", duration);

        state_debug.push(curr_state.clone());
    }

    //let matching_res: FheUint32 = curr_state.eq(enc_final_state).cast_into();

    /*

    println!("sanitization...");
    let start = Instant::now();
    let mut sanitized_v = vec![];
    for enc_x in enc_str {
        sanitized_v.push(&matching_res * enc_x);
    }
    let duration = start.elapsed();
    println!("the sanitization duration is {:?}", duration);

    println!("serialization...");
    let mut serialized_enc_str = Vec::new();
    for i in sanitized_v {
        bincode::serialize_into(&mut serialized_enc_str, &i)?;
    }
    let mut file_str = File::create("sanitized_payload.bin")?;
    file_str.write(serialized_enc_str.as_slice())?;
    println!("done");



     */

    //println!("[debug] decryption...");
    //let mut clear: u8 = matching_res.decrypt(&ck);

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
) -> Result<Vec<FheUint<FheUint32Id>>, Box<dyn std::error::Error>> {
    let mut to_des_data = Cursor::new(serialized_data);
    let mut v: Vec<FheUint<FheUint32Id>> = vec![];
    for _ in 0..2{
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
