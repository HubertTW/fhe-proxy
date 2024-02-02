use std::time::Instant;
use tfhe::integer::{gen_keys_radix, IntegerRadixCiphertext, RadixCiphertext, RadixClientKey};
use tfhe::ServerKey;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let num_block = 4;
    let (client_key, server_key) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block);
    //let one = 1u8;
    //let zero = 0u8;
    let mut c = encryptStr("the secret", &client_key);
    let start = Instant::now();
    sanitizer(&mut c, server_key);
    let duration = start.elapsed();
    let output = decryptStr(c,&client_key);
    println!("the output is {:?}",output);
    println!("the elapsed time of sanitization is {:?}", duration);
}
pub fn encryptStr(content: &str, ck: &RadixClientKey) -> Vec<RadixCiphertext> {
    let mut v = vec![];
    for byte in content.bytes() {
        v.push(ck.encrypt(byte));
    }
    v
}
pub fn decryptStr(content: Vec<RadixCiphertext>, ck: &RadixClientKey) -> String {
    let mut v = vec![];
    for byte in content {
        v.push(ck.decrypt(&byte));
    }
    String::from_utf8(v).unwrap()

}
/* PROXY SERVER COMPUTING */
pub fn sanitizer(content : &mut Vec<RadixCiphertext>, sk: tfhe::integer::ServerKey) {
       println!("start sanitizing...");
       let target = "sec";
       let mut target_bytes = vec![];
       for i in target.bytes(){
           target_bytes.push(i);
       }
       for shift in 0..(content.len() - target_bytes.len()) {
           let mut byte_comp:Vec<RadixCiphertext> = vec![];
           for j in 0..target_bytes.len() {
               byte_comp.push(sk.smart_scalar_eq_parallelized(&mut content[shift+j], target_bytes[j]).into_radix(4,&sk));
           }
           /* if len of target == 1? */
           let mut b1: RadixCiphertext = byte_comp[0].clone();
           let mut b2: RadixCiphertext = byte_comp[1].clone();
           let mut mask = sk.smart_bitand_parallelized(&mut b1,&mut b2);
           //let mut mask = sk.smart_bitand_parallelized(&mut byte_comp[0],&mut byte_comp[1]);
           for j in 2..target_bytes.len() -1 {
               mask = sk.smart_bitand_parallelized(&mut mask,&mut byte_comp[j]);
           }
           mask = sk.smart_scalar_eq_parallelized(&mut mask, 0 as u8).into_radix(4,&sk);
           for j in 0..target_bytes.len(){
               content[shift+j] = sk.smart_mul_parallelized(&mut mask, &mut content[shift+j]);
           }
           

       }
        println!("sanitizing finished");

}