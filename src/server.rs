
fn main(){

let mut enc_vec = fs::read("encrypted_str.txt")?;
let mut to_des_data = Cursor::new(serialized_enc_str);
let mut v = vec ! [];
for _ in 0..5{
v.push(bincode::deserialize_from( & mut to_des_data) ? );
}
let output = decryptStr(v, & ck );
println ! ("the output is {:?}", output);

}

pub fn decryptStr(content: Vec<RadixCiphertext>, ck: &RadixClientKey) -> String {
    let mut v = vec![];
    for byte in content {
        v.push(ck.decrypt(&byte));
    }
    String::from_utf8(v).unwrap()

}
