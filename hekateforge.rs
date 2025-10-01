use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{env, fs::{File}, io::{Read, Write, stdin, stdout}};
use base64::{encode, decode, DecodeError};
use std::collections::HashMap;
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use rand::seq::SliceRandom;
use rayon::prelude::*;

#[derive(Serialize, Deserialize)]
struct PoolKeyJson {
    TTL: u64,
    GeneratedAt: u64,
    EnSrc: String,
    SHA256: String,
    PoolKey: String,
}

#[derive(Debug)]
enum Mode {
    Encode,
    Decode,
}

fn expand_key_16_to_32(key: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key);
    let result = hasher.finalize();
    let mut expanded_key = [0u8; 32];
    expanded_key.copy_from_slice(&result);
    expanded_key
}

pub fn pool_generator(timeout: u64, pool_key: &[u8]) -> (String, Vec<u8>) {
    let mut all_bytes: Vec<u8> = (0..=255).collect();
    let mut poolbytedata = Vec::new();
    for chunk in pool_key.chunks(16) {
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
            eprintln!("Warning: Skipping a chunk that isn't exactly 16 bytes.");
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
        EnSrc: "V3.0".to_string(),
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


pub fn reference_mapper(pool_index_list: &HashMap<u8, Vec<usize>>, raw_bytes: &[u8],last_idx_flag: bool, last_idx_arg: Option<Vec<u16>>) -> Result<Vec<u8>, String> {
    let last_idx = last_idx_arg
        .and_then(|v| v.first().cloned()).unwrap_or_else(|| 65535u16);
    let mut rng = rand::rngs::OsRng;
    let mut host_payload_index_map: Vec<usize> = Vec::with_capacity(raw_bytes.len());
    for &byt in raw_bytes {
        match pool_index_list.get(&byt) {
            Some(indexes) if !indexes.is_empty() => {
                let choice = indexes.choose(&mut rng).expect("non-empty slice");
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
    for (i, idx) in host_payload_index_map.iter().enumerate() {
        let be = (*idx as u16).to_be_bytes();
        pld.extend_from_slice(&be);
    }
    Ok(pld)
}

pub fn decoder(indices: &[usize], entropy_pool_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut payload: Vec<u8> = Vec::with_capacity(indices.len());
    let pool_len = entropy_pool_bytes.len();

    for &idx in indices {
        if idx >= pool_len {
            return Err(format!("Index {} out of range (entropy pool length {})", idx, pool_len));
        }
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
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: <program> <mode> <base64_pool_key>");
        eprintln!("Modes: encode | decode");
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
    let pool_key = match decode_base64(base64_pool_key) {
        Ok(decoded_key) => decoded_key,
        Err(e) => {
            eprintln!("Failed to decode base64 pool_key: {}", e);
            return Ok(());
        }
    };
    let mut seed: u16 = 0;
    for intpair in pool_key.chunks(2) {
        let pair = u16::from_le_bytes([intpair[0], intpair[1]]);
        seed ^= pair;
    }

    let (pool_key_json, pool_bytes) = pool_generator(600, &pool_key);
    let pool_index_list = digester(&pool_bytes);
    let mut input_stream = stdin();
    let mut raw_bytes = Vec::new();
    input_stream.read_to_end(&mut raw_bytes)?;

    let chunk_size = raw_bytes.len() / 8;
    let chunks: Vec<&[u8]> = (0..8).map(|i| {
        let start = i * chunk_size;
        let end = if i == 7 { raw_bytes.len() } else { (i + 1) * chunk_size };
        &raw_bytes[start..end]
    }).collect();

    let last_bytes: Vec<u8> = chunks.iter().map(|chunk| {
        *chunk.last().unwrap_or(&0)
    }).collect();

    match mode {
        Mode::Encode => {
            let mut last_byte_results: Vec<u16> = vec![seed];
            let results: Vec<Vec<u8>> = chunks.par_iter()
                .zip(last_bytes.par_iter())
                .enumerate()
                .map(|(i, (chunk, last_byte))| {
                    let fourth_arg = if i == 0 {
                        seed
                    } else {
                        *last_byte_results.last().unwrap()
                    };
                    let result = reference_mapper(&pool_index_list, chunk, false, Some(vec![fourth_arg]));

                    match result {
                        Ok(data) => data,
                        Err(err) => {
                            eprintln!("Error: {}", err);
                            vec![]
                        }
                    }
                })
                .collect();
            let mut flattened_results = Vec::new();
            for (i, data) in results.iter().enumerate() {
                if i > 0 {
                    let last_byte = *data.last().unwrap_or(&0);
                    last_byte_results.push(last_byte as u16);
                }
                flattened_results.extend(data);
            }
       
            stdout().write_all(&flattened_results)?;
        }
        Mode::Decode => {
            let unpacked_indices = unpack_pld_to_indices(&raw_bytes)?;
            let decoded_data = decoder(&unpacked_indices, &pool_bytes)?;
            stdout().write_all(&decoded_data)?;
        }
    }

    Ok(())
    }
