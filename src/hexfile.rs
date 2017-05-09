//! Facilities for manipulating hexadecimal data stored in files
//!
//! As part of the week 1 assignment of Coursera's Cryptography 1 course, one
//! must manipulate hex-encoded ciphertext. This module is dedicated to loading
//! such ciphertext from a file, into a more convenient array of bytes.

use std::fs::File;
use std::io::{self, Read};
use std::result::Result;


/// Possible errors when trying to load the hexadecimal data
#[derive(Debug)]
pub enum Error {
    /// The string could not be loaded from the file
    Loading(io::Error),

    /// The file contains an odd number of characters, and thus cannot be
    /// interpreted as the hexadecimal representation of a stream of bytes
    OddLength,

    /// The file contains characters which are not valid hexadecimal digits
    InvalidChars
}


/// Load hex-encoded bytes from a file
pub fn load_bytes(filename: &str) -> Result<Vec<u8>, Error> {
    // Fetch string data from a file, and strip any trailing newline
    let mut raw_str = String::new();
    {
        let mut input_file = File::open(filename).map_err(Error::Loading)?;
        input_file.read_to_string(&mut raw_str).map_err(Error::Loading)?;
    }
    let trimmed_str = raw_str.trim_right();

    // Parse the result as a hex string
    parse_hex(&trimmed_str)
}


// Parse a string of hex-encoded bytes
pub fn parse_hex(string: &str) -> Result<Vec<u8>, Error> {
    // Check that the string has a plausible length
    if string.len() % 2 != 0 { return Err(Error::OddLength); }

    // Decode it into a vector of bytes
    let mut chars = string.chars();
    let mut bytes = Vec::new();
    while let (Some(ch1), Some(ch2)) = (chars.next(), chars.next()) {
        let digit1 = ch1.to_digit(16).ok_or(Error::InvalidChars)?;
        let digit2 = ch2.to_digit(16).ok_or(Error::InvalidChars)?;
        bytes.push((digit1 * 16 + digit2) as u8);
    }

    // Return the bytes
    Ok(bytes)
}


// Convert a sequence of bytes to a string
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX_DIGITS: &'static [char] = &['0', '1', '2', '3',
                                          '4', '5', '6', '7',
                                          '8', '9', 'a', 'b',
                                          'c', 'd', 'e', 'f'];
    let mut result = String::with_capacity(2 * bytes.len());
    for b in bytes {
        result.push(HEX_DIGITS[(b >> 4) as usize]);
        result.push(HEX_DIGITS[(b & 0xf) as usize]);
    }
    result
}
