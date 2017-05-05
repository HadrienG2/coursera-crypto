//! This module implements padding schemes for turning arbitrary slices of bytes
//! into streams of fixed-size blocks usable as inputs to a block cipher.

pub mod pkcs7;

use block_ciphers::Block128;


// A padding scheme starts from a message (represented as a slice of bytes) and
// produces a stream of blocks. For now, we only support 128-bit blocks
pub trait Padding128<'a> : Iterator<Item=Block128> {
    // Padded output is produced from an input message (slice of bytes)
    fn new(bytes: &'a [u8]) -> Self;
}
