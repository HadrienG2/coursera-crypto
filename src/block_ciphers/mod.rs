//! This module provides tools related to block ciphers: implementation of some
//! ciphers, various operating modes, padding...

pub mod aes;
pub mod modes;


// This is a 128-bit block of bytes, the only block type we currently support
pub const BLOCK_SIZE_128_U8: usize = 128/8;
pub type Block128u8 = [u8; BLOCK_SIZE_128_U8];


// Convert a properly sized slice into a reference to a block
pub fn as_block_128u8(slice: &[u8]) -> &Block128u8 {
    assert_eq!(slice.len(), BLOCK_SIZE_128_U8);
    array_ref!(slice, 0, BLOCK_SIZE_128_U8)
}
//
pub fn as_mut_block_128u8(slice: &mut [u8]) -> &mut Block128u8 {
    assert_eq!(slice.len(), BLOCK_SIZE_128_U8);
    array_mut_ref!(slice, 0, BLOCK_SIZE_128_U8)
}


// Convert a stream of blocks back into a vector of bytes
pub fn into_vec_128u8<I>(block_iter: I) -> Vec<u8>
    where I: Iterator<Item=Block128u8>
{
    let result_size = block_iter.size_hint().0 * BLOCK_SIZE_128_U8;
    let mut result = Vec::with_capacity(result_size);
    for block in block_iter {
        result.extend_from_slice(&block[..]);
    }
    result
}
