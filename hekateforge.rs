use rand::TryRngCore;
use std::{env, fs::{File}, io::{Read, Write, stdin, stdout}};
use base64::{encode, decode, DecodeError};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use rayon::prelude::*;
use rand_chacha::ChaCha8Rng;
use rand::prelude::IndexedRandom;
use rand::{Rng, SeedableRng};
use rand::rngs::{OsRng, StdRng};
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};

#[derive(Debug)]
enum Mode {
    Encode,
    Decode,
}

#[derive(Serialize)]
struct PoolKeyJson {
    TTL: u64,
    GeneratedAt: u64,
    EnSrc: String,
    SHA256: String,
    PoolKey: String,
}

fn xor_reduce(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &byte| acc ^ byte)
}

fn expand_key_8_to_32(key: &[u8; 8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key);
    let result = hasher.finalize();
    let mut expanded_key = [0u8; 32];
    expanded_key.copy_from_slice(&result);
    expanded_key
}

fn expand_key_64_to_2048(input_key: &[u8; 64]) -> [u8; 2048] {
    let mut expanded = [0u8; 2048];
    let mut offset = 0;
    for i in 0..64 {
        let mut hasher = Sha256::new();
        hasher.update(input_key);
        hasher.update(&(i as u32).to_be_bytes());
        let digest = hasher.finalize();
        expanded[offset..offset + 32].copy_from_slice(&digest);
        offset += 32;
    }
    expanded
}

fn expand_key_16_to_32(input: &[u8; 8]) -> [u8; 32] {
    let mut expanded = [0u8; 32];
    for i in 0..4 {
        expanded[i * 8..(i + 1) * 8].copy_from_slice(input);
    }
    expanded
}

pub fn pool_generator(timeout: u64, mut pool_key: Vec<u8>, magic_number: &u8) -> (String, Vec<u8>) {
    let mut all_bytes: Vec<u8> = (0..=255).collect();
    let mut poolbytedata = Vec::new();

    for (i, byte) in pool_key.iter_mut().enumerate() {
        *byte ^= magic_number;
    }

    for chunk in pool_key.chunks(8) {
        if let Ok(seed_slice) = chunk.try_into() {
            let expanded_key = expand_key_16_to_32(seed_slice);
            let mut seed_rng = StdRng::from_seed(expanded_key);
            let mut this_byte_shuffle = all_bytes.clone();
            for i in (0..256).rev() {
                let j = seed_rng.gen_range(0..=i);
                this_byte_shuffle.swap(i, j);
            }
            poolbytedata.extend(this_byte_shuffle);
        } else {
            eprintln!("Warning: Skipping a chunk that isn't exactly 8 bytes.");
        }
    }

    let pool_data_b64 = encode(&poolbytedata);
    let mut hasher = Sha256::new();
    hasher.update(pool_data_b64.as_bytes());
    let pool_hash_hex = format!("{:x}", hasher.finalize());

    let generated_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let expiry_at = generated_at + timeout;

    let pool_key_json = PoolKeyJson {
        TTL: expiry_at,
        GeneratedAt: generated_at,
        EnSrc: "V3.5".to_string(),
        SHA256: pool_hash_hex,
        PoolKey: encode(pool_key),
    };

    let pool_json_str = serde_json::to_string(&pool_key_json).unwrap();
    (pool_json_str, poolbytedata)
}


pub fn digester(entropy_pool_bytes: &[u8]) -> HashMap<u8, Vec<usize>> {
    let mut pool_index_list: HashMap<u8, Vec<usize>> = HashMap::with_capacity(256);
    for b in 0..=255 {
        pool_index_list.insert(b as u8, Vec::new());
    }

    for (i, &byte) in entropy_pool_bytes.iter().enumerate() {
        if let Some(vec) = pool_index_list.get_mut(&byte) {
            vec.push(i);
        } else {
            pool_index_list.insert(byte, vec![i]);
        }
    }

    pool_index_list
}

pub fn reference_mapper(pool_index_list: &HashMap<u8, Vec<usize>>, raw_bytes: &[u8]) -> Result<Vec<u8>, String> {

    let mut seed = [0u8; 32];
    OsRng.try_fill_bytes(&mut seed);

    let mut chacha_rng = ChaCha8Rng::from_seed(seed);

    let mut host_payload_index_map: Vec<usize> = Vec::with_capacity(raw_bytes.len());

    for &byt in raw_bytes {
        match pool_index_list.get(&byt) {
            Some(indexes) if !indexes.is_empty() => {

                let choice = indexes.choose(&mut chacha_rng).expect("non-empty slice");
                host_payload_index_map.push(*choice);
            }
            Some(_) => {
                return Err(format!("No indices available for byte value {}", byt));
            }
            None => {
                return Err(format!("Byte value {} not present in pool index list", byt));
            }
        }
    }

    let mut pld: Vec<u8> = Vec::with_capacity(host_payload_index_map.len() * 2);
    for idx in host_payload_index_map {
        if idx > u16::MAX as usize {
            return Err(format!("Index {} too large to fit into 2 bytes", idx));
        }
        let be = (idx as u16).to_be_bytes();
        pld.extend_from_slice(&be);
    }

    Ok(pld)
}

pub fn decoder(indices: &[usize], entropy_pool_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut payload: Vec<u8> = Vec::with_capacity(indices.len());
    let pool_len = entropy_pool_bytes.len();

    for &idx in indices {
        payload.push(entropy_pool_bytes[idx]);
    }

    Ok(payload)
}

pub fn unpack_pld_to_indices(pld: &[u8]) -> Result<Vec<usize>, String> {
    if pld.len() % 2 != 0 {
        return Err("Payload length is not even; expected 2-byte pairs".into());
    }
    let mut indices = Vec::with_capacity(pld.len() / 2);
    let mut i = 0;
    while i < pld.len() {
        let hi = pld[i] as u16;
        let lo = pld[i + 1] as u16;
        let combined = (hi << 8) | lo;
        indices.push(combined as usize);
        i += 2;
    }
    Ok(indices)
}

fn decode_base64(encoded: &str) -> Result<Vec<u8>, DecodeError> {
    decode(encoded)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::BufReader;

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: <program> <encode|decode> <base64_pool_key>");
        return Ok(());
    }

    let mode = match args[1].as_str() {
        "encode" => Mode::Encode,
        "decode" => Mode::Decode,
        _ => {
            eprintln!("Invalid mode. Use 'encode' or 'decode'.");
            return Ok(());
        }
    };

    let base64_pool_key = &args[2];
    let decoded_key = match decode_base64(base64_pool_key) {
        Ok(decoded) => decoded,
        Err(e) => {
            eprintln!("Failed to decode base64 pool_key: {}", e);
            return Ok(());
        }
    };

    if decoded_key.len() != 64 {
        eprintln!("Error: pool_key should be 512 bits.");
        return Ok(());
    }

    let expanded_key_array = expand_key_64_to_2048(&decoded_key.try_into().unwrap());
    let mut pool_key = expanded_key_array.to_vec();

    let magic_number = xor_reduce(&pool_key);
    let (pool_key_json, pool_bytes) = pool_generator(600, pool_key, &magic_number);
    let pool_index_list = digester(&pool_bytes);

    let stdin = stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut buffer = [0u8; 512];

    let stdout = stdout();
    let mut handle = stdout.lock();

    match mode {
        Mode::Encode => {
            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 {
                    break;
                }

                let chunk = &buffer[..n];
                let encoded_chunk = reference_mapper(&pool_index_list, chunk)?;

                handle.write_all(&encoded_chunk)?;
            }
        }
        Mode::Decode => {
            let mut decode_buf = Vec::new();
            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 {
                    break;
                }

                decode_buf.extend_from_slice(&buffer[..n]);

                while decode_buf.len() >= 2 {
                    let chunk_len = (decode_buf.len() / 2) * 2;
                    let (process_chunk, remaining) = decode_buf.split_at(chunk_len);

                    let indices = unpack_pld_to_indices(process_chunk)?;
                    let decoded_data = decoder(&indices, &pool_bytes)?;

                    handle.write_all(&decoded_data)?;
                    decode_buf = remaining.to_vec();
                }
            }

            if !decode_buf.is_empty() {
                return Err("Decode error: leftover bytes that do not make a full 2-byte pair".into());
            }
        }
    }

    Ok(())
}
