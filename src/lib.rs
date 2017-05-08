//! This is just a bunch of tools I built to solve the exercises of Coursera's
//! crypto MOOC. It does not take the required precautions to be used as a
//! serious crypto tool (e.g. clearing memory before returning it, making sure
//! that all operations on secret data take constant time), and should therefore
//! not be used as such. You have been warned.

#[macro_use]
extern crate arrayref;

pub mod blocks;
pub mod block_ciphers;
pub mod display;
pub mod hash;
pub mod hexfile;
pub mod padding;


// Compute the maximum length of a set of messages, if non-empty
pub fn max_length(messages: &[Vec<u8>]) -> Option<usize> {
    messages.iter()
            .map(|message| message.len())
            .max()
}


// XOR two messages with one another. If one of the input messages is shorter
// than the other, only the shortest subset of the XORed bytes will be returned
pub fn xor_bytes(bytes1: &[u8], bytes2: &[u8]) -> Vec<u8> {
    bytes1.iter().zip(bytes2.iter())
                 .map(|(b1, b2)| b1 ^ b2)
                 .collect()
}


// Perform an in-place XOR, i.e. XOR the bytes from the first slice with those
// of the second slice and store the result in the first slice. Unlike in
// xor_bytes, if the second message is shorter, the function will need to abort,
// as doing otherwise would leave the accumulator in a garbled state.
pub fn inplace_xor_bytes(accumulator: &mut [u8], operand: &[u8]) {
    assert!(accumulator.len() <= operand.len());
    for (acc, byte) in accumulator.iter_mut().zip(operand.iter()) {
        *acc ^= *byte;
    }
}
