//! This module implements padding schemes for turning arbitrary slices of bytes
//! into streams of fixed-size blocks.

pub mod pkcs7;


// A padding scheme starts from a message (represented as a slice of bytes) and
// produces a stream of fixed-size blocks (= arrays of unsigned numbers).
//
// A conforming implementation should provide an appropriate override of
// size_hint in order to tell exactly how many blocks it is going to produce.
//
// TODO: Once Rust offers genericity over arrays, clarify what a block is
//
pub trait PaddingScheme<'a, Block> : Iterator<Item=Block> {
    // Padded output is produced from an input message (slice of bytes)
    fn new(bytes: &'a [u8]) -> Self;
}
