//! This is just a bunch of tools I built to solve the exercises of Coursera's
//! crypto MOOC. It does not take the required precautions to be used as a
//! serious crypto tool (e.g. clearing memory before returning it, making sure
//! that all operations on secret data take constant time), and should therefore
//! not be used as such. You have been warned.

pub mod hexfile;

use std::ops::BitXor;


// XOR the common sublength of two streams of bytes
pub fn xor_bytes(bytes1: &[u8], bytes2: &[u8]) -> Vec<u8> {
    bytes1.iter().zip(bytes2.iter())
                 .map(|(b1, b2)| b1.bitxor(b2))
                 .collect()
}

// If the requested byte maps to a printable ASCII character, returns it.
// Otherwise, return an unambiguously non-ASCII printable character.
pub fn as_printable_char(byte: u8) -> char {
    match byte {
        // Can be interpreted as a printable ASCII character
        b if b >= 0x20 && b <= 0x7E => b as char,
        // Cannot be interpreted as printable ASCII
        _ => '࿕',
    }
}
