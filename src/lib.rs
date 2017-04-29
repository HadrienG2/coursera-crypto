//! This is just a bunch of tools I built to solve the exercises of Coursera's
//! crypto MOOC. It does not take the required precautions to be used as a
//! serious crypto tool (e.g. clearing memory before returning it, making sure
//! that all operations on secret data take constant time), and should therefore
//! not be used as such. You have been warned.

pub mod display;
pub mod hexfile;

use std::ops::BitXor;


// Compute the maximum length of a set of messages, if non-empty
pub fn max_length(messages: &[Vec<u8>]) -> Option<usize> {
    messages.iter()
            .map(|message| message.len())
            .max()
}

// XOR the common sublength of two messages
pub fn xor_bytes(bytes1: &[u8], bytes2: &[u8]) -> Vec<u8> {
    bytes1.iter().zip(bytes2.iter())
                 .map(|(b1, b2)| b1.bitxor(b2))
                 .collect()
}
