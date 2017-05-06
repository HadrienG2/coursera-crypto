//! This module provides tools related to block ciphers: implementation of some
//! ciphers, various operating modes, padding...

pub mod aes;
pub mod modes;
pub mod padding;

// This is a 128-bit block, which is for now the only block size that we support
pub const BLOCK_SIZE_128: usize = 128/8;
pub type Block128 = [u8; BLOCK_SIZE_128];

// Convert a properly sized slice into a block
pub fn as_block_128(slice: &[u8]) -> Block128 {
    assert!(slice.len() == BLOCK_SIZE_128);
    let mut block = [0; BLOCK_SIZE_128];
    for (input, output) in slice.iter().zip(block.iter_mut()) {
        *output = *input;
    }
    block
}

// Convert a stream of blocks back into a vector of bytes
pub fn into_vec_128<I>(block_iter: I) -> Vec<u8>
    where I: Iterator<Item=Block128>
{
    let result_size = block_iter.size_hint().0 * BLOCK_SIZE_128;
    let mut result = Vec::with_capacity(result_size);
    for block in block_iter {
        result.extend_from_slice(&block[..]);
    }
    result
}
